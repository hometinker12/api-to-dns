"""SSL/TLS certificate management for the api-to-dns admin UI.

SSL is off by default. No certificate is auto-generated at startup. Admins
opt in by either creating a self-signed certificate (via the system
``openssl`` binary) or uploading a PEM key/cert pair from the
**Settings -> SSL Certificate Management** section, then enabling SSL and
restarting the application.

The active listener (HTTP or HTTPS) is chosen at process start by
``bootstrap()``; toggling SSL in the UI updates the DB immediately but
requires a restart to swap listeners.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import NameOID

from .activity_logging import get_app_dns_name
from .db import SessionLocal, init_db
from .settings_store import get_setting, set_setting

LOGGER = logging.getLogger("api_to_dns")

SETTING_SSL_ENABLED = "ssl_enabled"

CERT_FILENAME = "server.crt"
KEY_FILENAME = "server.key"
SOURCE_FILENAME = "server.source"

SOURCE_SELF_SIGNED = "self_signed"
SOURCE_UPLOADED = "uploaded"
SOURCE_LETSENCRYPT = "letsencrypt"

DEFAULT_HTTP_PORT = 8000
DEFAULT_TLS_PORT = 8443
DEFAULT_CERT_VALIDITY_DAYS = 825

_DOCKER_DEFAULT_CERT_DIR = "/app/data/ssl"
_LOCAL_DEFAULT_CERT_DIR = "./data/ssl"

# OpenSSL uses SSL_CERT_DIR for CA certificate lookup. Do not use that name for
# app server cert storage — read legacy value once, then remove from the process
# environment so outbound HTTPS (e.g. Cloudflare API) keeps the system CA bundle.
_LEGACY_SSL_CERT_DIR = os.environ.pop("SSL_CERT_DIR", None)


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _running_in_docker() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", "rt", encoding="utf-8") as handle:
            return any("docker" in line or "kubepods" in line or "containerd" in line for line in handle)
    except OSError:
        return False


def _default_cert_dir() -> str:
    return _DOCKER_DEFAULT_CERT_DIR if _running_in_docker() else _LOCAL_DEFAULT_CERT_DIR


def cert_dir() -> Path:
    raw = os.getenv("APP_SSL_DIR") or _LEGACY_SSL_CERT_DIR or _default_cert_dir()
    path = Path(raw).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def cert_paths() -> Tuple[Path, Path]:
    directory = cert_dir()
    return directory / KEY_FILENAME, directory / CERT_FILENAME


def cert_exists() -> bool:
    key_path, cert_path = cert_paths()
    return key_path.is_file() and cert_path.is_file()


def _source_path() -> Path:
    return cert_dir() / SOURCE_FILENAME


def _write_source(value: str) -> None:
    _source_path().write_text(value.strip() + "\n", encoding="utf-8")


def _read_source() -> Optional[str]:
    path = _source_path()
    if not path.is_file():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return value if value in {SOURCE_SELF_SIGNED, SOURCE_UPLOADED, SOURCE_LETSENCRYPT} else None


def _coerce_truthy(raw: Optional[str]) -> Optional[bool]:
    if raw is None:
        return None
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on", "enabled"}:
        return True
    if value in {"0", "false", "no", "off", "disabled"}:
        return False
    return None


# ---------------------------------------------------------------------------
# Settings: ssl_enabled
# ---------------------------------------------------------------------------


def is_ssl_enabled(db) -> bool:
    stored = get_setting(db, SETTING_SSL_ENABLED)
    coerced = _coerce_truthy(stored)
    return bool(coerced) if coerced is not None else False


def set_ssl_enabled(db, enabled: bool) -> bool:
    set_setting(db, SETTING_SSL_ENABLED, "true" if enabled else "false")
    return bool(enabled)


# ---------------------------------------------------------------------------
# Self-signed generation (uses system openssl)
# ---------------------------------------------------------------------------


def _openssl_executable() -> Optional[str]:
    return shutil.which("openssl")


class OpenSSLUnavailableError(RuntimeError):
    """Raised when the system ``openssl`` binary is required but missing."""


class CertificateInstallError(ValueError):
    """Raised when an uploaded PEM key/cert pair fails validation."""


def _write_atomic(path: Path, data: bytes, mode: int) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "wb") as handle:
        handle.write(data)
    try:
        os.chmod(tmp_path, mode)
    except OSError:
        # chmod is best-effort on Windows; ignore.
        pass
    os.replace(tmp_path, path)


def create_self_signed_cert(db) -> Dict[str, Any]:
    """Generate a self-signed certificate via the system ``openssl`` binary.

    Uses the configured App DNS Name as CN and as a DNS SAN, plus ``localhost``
    as an additional DNS SAN. Returns the resulting certificate metadata.
    """
    openssl = _openssl_executable()
    if not openssl:
        raise OpenSSLUnavailableError(
            "The 'openssl' command was not found on PATH. Install OpenSSL or upload a PEM certificate instead."
        )

    app_dns_name = (get_app_dns_name(db) or "").strip() or "apitodns.local"

    directory = cert_dir()
    key_path, cert_path = cert_paths()
    key_tmp = directory / (KEY_FILENAME + ".new")
    cert_tmp = directory / (CERT_FILENAME + ".new")
    for stale in (key_tmp, cert_tmp):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass

    san_value = f"DNS:{app_dns_name},DNS:localhost"
    subject = f"/CN={app_dns_name}/O=api-to-dns"

    cmd = [
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_tmp),
        "-out",
        str(cert_tmp),
        "-days",
        str(DEFAULT_CERT_VALIDITY_DAYS),
        "-subj",
        subject,
        "-addext",
        f"subjectAltName={san_value}",
    ]

    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise OpenSSLUnavailableError(f"Failed to invoke openssl: {exc}") from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        for stale in (key_tmp, cert_tmp):
            try:
                stale.unlink()
            except FileNotFoundError:
                pass
        raise RuntimeError(f"openssl failed (exit {completed.returncode}): {stderr}")

    try:
        os.chmod(key_tmp, 0o600)
    except OSError:
        pass
    try:
        os.chmod(cert_tmp, 0o644)
    except OSError:
        pass

    os.replace(key_tmp, key_path)
    os.replace(cert_tmp, cert_path)
    _write_source(SOURCE_SELF_SIGNED)
    metadata = cert_metadata() or {}
    metadata["app_dns_name"] = app_dns_name
    return metadata


def regenerate_self_signed_cert(db) -> Dict[str, Any]:
    """Delete any existing cert files, then create a fresh self-signed pair."""
    for path in cert_paths():
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    return create_self_signed_cert(db)


# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------


def _load_private_key(pem: bytes):
    try:
        return serialization.load_pem_private_key(pem, password=None)
    except TypeError as exc:
        raise CertificateInstallError(
            "Encrypted private keys are not supported. Decrypt the key before uploading."
        ) from exc
    except ValueError as exc:
        raise CertificateInstallError("Private key is not a valid PEM file or is encrypted.") from exc


def _load_pem_certificates(pem: bytes):
    try:
        certs = x509.load_pem_x509_certificates(pem)
    except ValueError as exc:
        raise CertificateInstallError("Certificate file is not a valid PEM bundle.") from exc
    if not certs:
        raise CertificateInstallError("Certificate file did not contain any PEM certificates.")
    return certs


def _public_keys_match(private_key, certificate) -> bool:
    cert_pub = certificate.public_key()
    key_pub = private_key.public_key()
    if isinstance(cert_pub, rsa.RSAPublicKey) and isinstance(key_pub, rsa.RSAPublicKey):
        return cert_pub.public_numbers() == key_pub.public_numbers()
    if isinstance(cert_pub, ec.EllipticCurvePublicKey) and isinstance(key_pub, ec.EllipticCurvePublicKey):
        return cert_pub.public_numbers() == key_pub.public_numbers()
    if isinstance(cert_pub, dsa.DSAPublicKey) and isinstance(key_pub, dsa.DSAPublicKey):
        return cert_pub.public_numbers() == key_pub.public_numbers()
    cert_bytes = cert_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_bytes = key_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return cert_bytes == key_bytes


def install_uploaded_cert(key_pem: bytes, cert_pem: bytes) -> Dict[str, Any]:
    """Validate and atomically install an uploaded PEM key/cert pair.

    The first certificate in ``cert_pem`` is treated as the leaf certificate;
    any additional PEM blocks are preserved (treated as the chain) and written
    into ``server.crt`` exactly as uploaded.
    """
    if not key_pem or not key_pem.strip():
        raise CertificateInstallError("Private key file is empty.")
    if not cert_pem or not cert_pem.strip():
        raise CertificateInstallError("Certificate file is empty.")

    private_key = _load_private_key(key_pem)
    certificates = _load_pem_certificates(cert_pem)
    leaf = certificates[0]

    if not _public_keys_match(private_key, leaf):
        raise CertificateInstallError("Private key does not match the certificate.")

    not_after = leaf.not_valid_after_utc if hasattr(leaf, "not_valid_after_utc") else leaf.not_valid_after.replace(
        tzinfo=timezone.utc
    )
    if not_after <= datetime.now(timezone.utc):
        raise CertificateInstallError("Certificate is expired. Upload a current certificate.")

    key_path, cert_path = cert_paths()
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _write_atomic(key_path, key_bytes, 0o600)
    _write_atomic(cert_path, cert_pem, 0o644)
    _write_source(SOURCE_UPLOADED)

    metadata = cert_metadata() or {}
    return metadata


def install_letsencrypt_cert(key_pem: bytes, cert_pem: bytes) -> Dict[str, Any]:
    """Validate and install a Let's Encrypt-issued key/certificate pair."""
    metadata = install_uploaded_cert(key_pem, cert_pem)
    _write_source(SOURCE_LETSENCRYPT)
    metadata = cert_metadata() or metadata
    metadata["source"] = SOURCE_LETSENCRYPT
    return metadata


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def _common_name(certificate) -> str:
    try:
        attrs = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return attrs[0].value
    except Exception:  # noqa: BLE001 — defensive against malformed subject
        pass
    return ""


def _subject_alt_names(certificate) -> list:
    try:
        ext = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return [str(name.value) for name in ext.value]
    except x509.ExtensionNotFound:
        return []
    except Exception:  # noqa: BLE001
        return []


def cert_metadata() -> Optional[Dict[str, Any]]:
    if not cert_exists():
        return None
    _, cert_path = cert_paths()
    try:
        cert_bytes = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except Exception as exc:  # noqa: BLE001 — surface a generic error in UI/logs
        LOGGER.warning("Failed to parse certificate %s: %s", cert_path, exc)
        return {
            "common_name": "",
            "not_after": None,
            "fingerprint": "",
            "source": _read_source() or SOURCE_SELF_SIGNED,
            "expired": True,
            "subject_alt_names": [],
            "error": "Unable to parse certificate file.",
        }

    not_after = (
        cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after.replace(tzinfo=timezone.utc)
    )
    fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    formatted_fp = ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2))
    return {
        "common_name": _common_name(cert),
        "not_after": not_after,
        "not_after_iso": not_after.isoformat(),
        "fingerprint": formatted_fp,
        "source": _read_source() or SOURCE_SELF_SIGNED,
        "expired": not_after <= datetime.now(timezone.utc),
        "subject_alt_names": _subject_alt_names(cert),
    }


# ---------------------------------------------------------------------------
# Bootstrap / CLI
# ---------------------------------------------------------------------------


def _resolved_ssl_enabled(db) -> bool:
    override = _coerce_truthy(os.getenv("SSL_ENABLED"))
    if override is not None:
        return override
    return is_ssl_enabled(db)


def http_port() -> int:
    raw = os.getenv("HTTP_PORT")
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return DEFAULT_HTTP_PORT


def tls_port() -> int:
    raw = os.getenv("TLS_PORT")
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return DEFAULT_TLS_PORT


def _display_host(db) -> str:
    return (get_app_dns_name(db) or "").strip() or "localhost"


def _format_url(scheme: str, host: str, port: int) -> str:
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    port_part = "" if default else f":{port}"
    return f"{scheme}://{host}{port_part}/login"


def access_url(db, *, use_env_override: bool = False) -> str:
    enabled = _resolved_ssl_enabled(db) if use_env_override else is_ssl_enabled(db)
    if enabled:
        return _format_url("https", _display_host(db), tls_port())
    return _format_url("http", _display_host(db), http_port())


def bootstrap() -> str:
    """Return the listener mode for this process: ``"http"`` or ``"https"``.

    Initializes the DB, applies any ``SSL_ENABLED`` env override on top of
    the persisted toggle, and (when SSL is enabled) verifies that cert files
    exist on disk. If SSL is enabled with no cert, prints a clear error and
    exits non-zero so a broken HTTPS listener never starts.
    """
    init_db()
    cert_dir()  # ensure directory exists for downstream readers
    with SessionLocal() as db:
        enabled = _resolved_ssl_enabled(db)
    if not enabled:
        return "http"
    if not cert_exists():
        key_path, cert_path = cert_paths()
        message = (
            "SSL is enabled in settings but certificate files are missing.\n"
            f"Expected key:  {key_path}\n"
            f"Expected cert: {cert_path}\n"
            "Open Settings -> System Settings -> SSL Certificate Management and either\n"
            "create a self-signed certificate or upload a PEM key/cert pair, then\n"
            "restart the application."
        )
        print(message, file=sys.stderr)
        sys.exit(2)
    return "https"


def _uvicorn_command(mode: str) -> list:
    base = [sys.executable, "-m", "uvicorn", "src.app:app", "--host", "0.0.0.0"]
    extra = (os.getenv("UVICORN_EXTRA_ARGS") or "").split()
    if mode == "https":
        key_path, cert_path = cert_paths()
        return base + [
            "--port",
            str(tls_port()),
            *extra,
            "--ssl-keyfile",
            str(key_path),
            "--ssl-certfile",
            str(cert_path),
        ]
    return base + ["--port", str(http_port()), *extra]


def serve() -> int:
    mode = bootstrap()
    cmd = _uvicorn_command(mode)
    LOGGER.info("Starting uvicorn in %s mode: %s", mode, " ".join(cmd))
    return subprocess.call(cmd)


def healthcheck() -> int:
    import urllib.error
    import urllib.request

    init_db()
    with SessionLocal() as db:
        enabled = _resolved_ssl_enabled(db)
    if enabled and cert_exists():
        port = tls_port()
        scheme = "https"
    else:
        port = http_port()
        scheme = "http"
    url = f"{scheme}://127.0.0.1:{port}/login"
    try:
        if scheme == "https":
            import ssl as _ssl

            context = _ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = _ssl.CERT_NONE
            with urllib.request.urlopen(url, timeout=3, context=context) as resp:
                return 0 if resp.status < 500 else 1
        else:
            with urllib.request.urlopen(url, timeout=3) as resp:
                return 0 if resp.status < 500 else 1
    except urllib.error.HTTPError as exc:
        return 0 if exc.code < 500 else 1
    except Exception as exc:  # noqa: BLE001
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1


def _cli(argv: list) -> int:
    if not argv:
        print("usage: python -m src.ssl_certs {bootstrap|serve|healthcheck}", file=sys.stderr)
        return 2
    command = argv[0]
    if command == "bootstrap":
        mode = bootstrap()
        print(mode)
        return 0
    if command == "serve":
        return serve()
    if command == "healthcheck":
        return healthcheck()
    print(f"unknown command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover — CLI dispatch
    raise SystemExit(_cli(sys.argv[1:]))
