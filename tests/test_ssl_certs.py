"""Tests for the SSL certificate management module."""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src import ssl_certs
from src.db import SessionLocal, init_db


@pytest.fixture
def ssl_workspace(monkeypatch: pytest.MonkeyPatch) -> Path:
    tmp = tempfile.mkdtemp(prefix="api-to-dns-ssl-test-")
    monkeypatch.setenv("APP_SSL_DIR", tmp)
    # bootstrap()/serve() honour SSL_ENABLED; default the env override off for
    # unit tests and let individual tests opt in by setting the DB toggle.
    monkeypatch.delenv("SSL_ENABLED", raising=False)
    init_db()
    with SessionLocal() as db:
        ssl_certs.set_ssl_enabled(db, False)
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


def _generate_pem_pair(
    *,
    common_name: str = "test.example",
    not_after: datetime | None = None,
    not_before: datetime | None = None,
) -> tuple[bytes, bytes, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if not_after is None:
        not_after = datetime.now(UTC) + timedelta(days=30)
    if not_before is None:
        not_before = min(
            datetime.now(UTC) - timedelta(minutes=5),
            not_after - timedelta(days=1),
        )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name), x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem, key


def test_is_ssl_enabled_defaults_false(ssl_workspace: Path) -> None:
    with SessionLocal() as db:
        assert ssl_certs.is_ssl_enabled(db) is False


def test_set_ssl_enabled_round_trip(ssl_workspace: Path) -> None:
    with SessionLocal() as db:
        ssl_certs.set_ssl_enabled(db, True)
        assert ssl_certs.is_ssl_enabled(db) is True
        ssl_certs.set_ssl_enabled(db, False)
        assert ssl_certs.is_ssl_enabled(db) is False


def test_cert_paths_under_configured_dir(ssl_workspace: Path) -> None:
    key_path, cert_path = ssl_certs.cert_paths()
    assert key_path.parent == ssl_workspace
    assert cert_path.parent == ssl_workspace
    assert key_path.name == "server.key"
    assert cert_path.name == "server.crt"


def test_bootstrap_returns_http_when_disabled(ssl_workspace: Path) -> None:
    with SessionLocal() as db:
        ssl_certs.set_ssl_enabled(db, False)
    assert ssl_certs.bootstrap() == "http"


def test_bootstrap_exits_when_enabled_without_cert(ssl_workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with SessionLocal() as db:
        ssl_certs.set_ssl_enabled(db, True)
    with pytest.raises(SystemExit) as exc_info:
        ssl_certs.bootstrap()
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "SSL is enabled" in captured.err
    assert "certificate files are missing" in captured.err


def test_bootstrap_returns_https_when_enabled_and_cert_present(ssl_workspace: Path) -> None:
    key_pem, cert_pem, _ = _generate_pem_pair()
    ssl_certs.install_uploaded_cert(key_pem, cert_pem)
    with SessionLocal() as db:
        ssl_certs.set_ssl_enabled(db, True)
    assert ssl_certs.bootstrap() == "https"


def test_bootstrap_env_override_forces_http(ssl_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with SessionLocal() as db:
        ssl_certs.set_ssl_enabled(db, True)
    monkeypatch.setenv("SSL_ENABLED", "0")
    assert ssl_certs.bootstrap() == "http"


def test_install_uploaded_cert_round_trip(ssl_workspace: Path) -> None:
    key_pem, cert_pem, _ = _generate_pem_pair(common_name="upload.example")
    metadata = ssl_certs.install_uploaded_cert(key_pem, cert_pem)
    assert ssl_certs.cert_exists()
    assert metadata["common_name"] == "upload.example"
    assert metadata["source"] == "uploaded"
    assert metadata["expired"] is False
    assert metadata["fingerprint"]
    key_path, cert_path = ssl_certs.cert_paths()
    assert key_path.read_bytes()
    assert cert_path.read_bytes() == cert_pem


def test_install_uploaded_cert_rejects_mismatched_key(ssl_workspace: Path) -> None:
    _, cert_pem, _ = _generate_pem_pair(common_name="leaf.example")
    other_key_pem, _, _ = _generate_pem_pair(common_name="other.example")
    with pytest.raises(ssl_certs.CertificateInstallError) as exc:
        ssl_certs.install_uploaded_cert(other_key_pem, cert_pem)
    assert "does not match" in str(exc.value).lower()


def test_install_uploaded_cert_rejects_invalid_pem(ssl_workspace: Path) -> None:
    with pytest.raises(ssl_certs.CertificateInstallError):
        ssl_certs.install_uploaded_cert(b"not a key", b"not a cert")


def test_install_uploaded_cert_rejects_expired(ssl_workspace: Path) -> None:
    key_pem, cert_pem, _ = _generate_pem_pair(
        common_name="old.example",
        not_before=datetime.now(UTC) - timedelta(days=10),
        not_after=datetime.now(UTC) - timedelta(days=1),
    )
    with pytest.raises(ssl_certs.CertificateInstallError) as exc:
        ssl_certs.install_uploaded_cert(key_pem, cert_pem)
    assert "expired" in str(exc.value).lower()


def test_install_uploaded_cert_rejects_empty(ssl_workspace: Path) -> None:
    with pytest.raises(ssl_certs.CertificateInstallError):
        ssl_certs.install_uploaded_cert(b"", b"")


def test_cert_metadata_none_without_cert(ssl_workspace: Path) -> None:
    assert ssl_certs.cert_metadata() is None


def _openssl_supports_addext() -> bool:
    import subprocess

    exe = ssl_certs._openssl_executable()  # type: ignore[attr-defined]
    if not exe:
        return False
    try:
        result = subprocess.run([exe, "version"], check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    parts = (result.stdout or "").split()
    if len(parts) < 2:
        return False
    version = parts[1]
    major = version.split(".", 1)[0]
    try:
        return int(major) >= 1 and version >= "1.1.1"
    except ValueError:
        return False


def test_create_self_signed_cert_uses_openssl(ssl_workspace: Path) -> None:
    if not _openssl_supports_addext():
        pytest.skip("openssl with -addext support is not installed on PATH")
    with SessionLocal() as db:
        metadata = ssl_certs.create_self_signed_cert(db)
    assert ssl_certs.cert_exists()
    assert metadata["source"] == "self_signed"
    assert metadata["common_name"]


def test_regenerate_self_signed_cert_overwrites_uploaded(ssl_workspace: Path) -> None:
    if not _openssl_supports_addext():
        pytest.skip("openssl with -addext support is not installed on PATH")
    key_pem, cert_pem, _ = _generate_pem_pair(common_name="upload.example")
    ssl_certs.install_uploaded_cert(key_pem, cert_pem)
    with SessionLocal() as db:
        new_meta = ssl_certs.regenerate_self_signed_cert(db)
    assert new_meta["source"] == "self_signed"
    assert ssl_certs.cert_metadata()["source"] == "self_signed"


def test_create_self_signed_raises_when_openssl_missing(ssl_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssl_certs, "_openssl_executable", lambda: None)
    with SessionLocal() as db, pytest.raises(ssl_certs.OpenSSLUnavailableError):
        ssl_certs.create_self_signed_cert(db)


def test_install_uploaded_cert_rejects_oversized(ssl_workspace: Path) -> None:
    oversized = b"A" * (ssl_certs.MAX_SSL_KEY_UPLOAD_BYTES + 1)
    with pytest.raises(ssl_certs.CertificateInstallError, match="maximum allowed size"):
        ssl_certs.install_uploaded_cert(oversized, b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----")


def test_read_upload_bounded_accepts_within_limit() -> None:
    class _Upload:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload
            self._offset = 0

        async def read(self, size: int = -1) -> bytes:
            if self._offset >= len(self._payload):
                return b""
            if size < 0:
                chunk = self._payload[self._offset :]
                self._offset = len(self._payload)
                return chunk
            chunk = self._payload[self._offset : self._offset + size]
            self._offset += len(chunk)
            return chunk

    payload = b"A" * 1024
    assert asyncio.run(ssl_certs.read_upload_bounded(_Upload(payload), 2048)) == payload


def test_read_upload_bounded_rejects_oversized_key_and_cert() -> None:
    class _Upload:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload
            self._offset = 0

        async def read(self, size: int = -1) -> bytes:
            if self._offset >= len(self._payload):
                return b""
            if size < 0:
                chunk = self._payload[self._offset :]
                self._offset = len(self._payload)
                return chunk
            chunk = self._payload[self._offset : self._offset + size]
            self._offset += len(chunk)
            return chunk

    oversized_key = b"K" * (ssl_certs.MAX_SSL_KEY_UPLOAD_BYTES + 1)
    with pytest.raises(ssl_certs.CertificateInstallError, match="maximum allowed size"):
        asyncio.run(ssl_certs.read_upload_bounded(_Upload(oversized_key), ssl_certs.MAX_SSL_KEY_UPLOAD_BYTES))

    oversized_cert = b"C" * (ssl_certs.MAX_SSL_CERT_UPLOAD_BYTES + 1)
    with pytest.raises(ssl_certs.CertificateInstallError, match="maximum allowed size"):
        asyncio.run(ssl_certs.read_upload_bounded(_Upload(oversized_cert), ssl_certs.MAX_SSL_CERT_UPLOAD_BYTES))


def test_create_self_signed_rejects_bad_hostname_without_openssl(
    ssl_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = {"openssl": False}

    def boom(*_args, **_kwargs):
        called["openssl"] = True
        raise AssertionError("openssl must not be invoked for invalid hostnames")

    monkeypatch.setattr(ssl_certs, "_openssl_executable", lambda: "openssl")
    monkeypatch.setattr(ssl_certs.subprocess, "run", boom)
    monkeypatch.setattr(ssl_certs, "get_app_dns_name", lambda _db: "bad name;rm -rf /")
    with SessionLocal() as db, pytest.raises(ValueError, match="Hostname"):
        ssl_certs.create_self_signed_cert(db)
    assert called["openssl"] is False


def test_cli_bootstrap_prints_mode(ssl_workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with SessionLocal() as db:
        ssl_certs.set_ssl_enabled(db, False)
    rc = ssl_certs._cli(["bootstrap"])  # type: ignore[attr-defined]
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "http"


def test_cli_unknown_command_returns_error(capsys: pytest.CaptureFixture[str]) -> None:
    rc = ssl_certs._cli(["nope"])  # type: ignore[attr-defined]
    assert rc == 2
    captured = capsys.readouterr()
    assert "unknown command" in captured.err
