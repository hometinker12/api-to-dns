"""Let's Encrypt enrollment and renewal state.

The live ACME calls are isolated behind small private functions so tests can
mock issuance without talking to Let's Encrypt. DNS automation reuses the same
configured zone plugins as the public DNS API.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .activity_logging import get_app_dns_name
from .models import DnsRecordRequest, DnsZoneConfig
from .settings_store import delete_setting, get_setting, set_setting
from .ssl_certs import SOURCE_LETSENCRYPT, _read_source, cert_dir, cert_metadata, install_letsencrypt_cert
from .zone_service import (
    create_dns_client_from_settings,
    decode_zone_config,
    list_dns_zones,
    normalize_zone_name,
    provider_dns_zone,
)

SETTING_CONFIG = "letsencrypt_config"
SETTING_ENROLLMENT = "letsencrypt_enrollment"
SETTING_ENROLLMENT_PROGRESS = "letsencrypt_enrollment_progress"

ProgressCallback = Callable[[str, int, str], None]

CHALLENGE_DNS = "dns-01"
CHALLENGE_HTTP = "http-01"
RENEW_OPTIONS = [7, 14, 21, 30, 45, 60]
DEFAULT_RENEW_BEFORE_DAYS = 30
DEFAULT_SCHEDULED_RESTART_TIME = "03:00"
DNS_TXT_VERIFY_DELAY_SECONDS = 30
DNS_TXT_VERIFY_MAX_ATTEMPTS = 5
DNS_TXT_CHALLENGE_TTL = 1
ACME_ACCOUNT_KEY_FILENAME = "acme_account.key"

_sleep_fn: Callable[[float], None] = time.sleep

PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"


class LetsEncryptError(RuntimeError):
    """Raised when enrollment or renewal cannot proceed."""


def _read_json_setting(db, name: str) -> Optional[Dict[str, Any]]:
    raw = get_setting(db, name)
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _write_json_setting(db, name: str, value: Dict[str, Any]) -> None:
    set_setting(db, name, json.dumps(value, sort_keys=True))


def get_config(db) -> Optional[Dict[str, Any]]:
    raw = _read_json_setting(db, SETTING_CONFIG)
    if not raw:
        return None
    return _normalize_config(raw, app_dns_name=get_app_dns_name(db), db=db)


def get_enrollment(db) -> Optional[Dict[str, Any]]:
    return _read_json_setting(db, SETTING_ENROLLMENT)


def clear_enrollment(db) -> None:
    delete_setting(db, SETTING_ENROLLMENT)


def write_enrollment_progress(
    db,
    *,
    phase: str,
    percent: int,
    message: str,
    done: bool = False,
    error: Optional[str] = None,
    result_status: Optional[str] = None,
) -> None:
    payload = {
        "phase": phase,
        "percent": max(0, min(100, int(percent))),
        "message": message,
        "done": bool(done),
        "error": error,
        "result_status": result_status,
    }
    _write_json_setting(db, SETTING_ENROLLMENT_PROGRESS, payload)


def get_enrollment_progress(db) -> Dict[str, Any]:
    raw = _read_json_setting(db, SETTING_ENROLLMENT_PROGRESS)
    if not raw:
        return {
            "phase": "idle",
            "percent": 0,
            "message": "Idle",
            "done": False,
            "error": None,
            "result_status": None,
        }
    return {
        "phase": raw.get("phase") or "idle",
        "percent": max(0, min(100, int(raw.get("percent") or 0))),
        "message": raw.get("message") or "",
        "done": bool(raw.get("done")),
        "error": raw.get("error"),
        "result_status": raw.get("result_status"),
    }


def clear_enrollment_progress(db) -> None:
    delete_setting(db, SETTING_ENROLLMENT_PROGRESS)


def _noop_progress(_phase: str, _percent: int, _message: str) -> None:
    return None


def _normalize_hostname(value: str) -> str:
    return str(value or "").strip().strip(".").lower()


def _split_names(names: str | List[str]) -> List[str]:
    if isinstance(names, str):
        parts = names.replace("\n", ",").split(",")
    else:
        parts = names
    cleaned: List[str] = []
    for part in parts:
        domain = _normalize_hostname(part)
        if domain and domain not in cleaned:
            cleaned.append(domain)
    return cleaned


def _name_under_root(name: str, root: str) -> bool:
    normalized = normalize_zone_name(name)
    root_name = normalize_zone_name(root)
    return normalized == root_name or normalized.endswith("." + root_name)


def _cert_identities(config: Dict[str, Any]) -> List[str]:
    identities: List[str] = []
    common_name = _normalize_hostname(config.get("common_name") or "")
    if common_name:
        identities.append(common_name)
    subject_alt_names = config.get("subject_alt_names") or []
    if isinstance(subject_alt_names, str):
        subject_alt_names = _split_names(subject_alt_names)
    for name in subject_alt_names:
        normalized = _normalize_hostname(name)
        if normalized and normalized not in identities:
            identities.append(normalized)
    return identities


def _normalize_config(config: Dict[str, Any], *, app_dns_name: str = "", db=None) -> Dict[str, Any]:
    default_cn = _normalize_hostname(app_dns_name)
    if "root_dns_domain" in config:
        normalized = dict(config)
        normalized["root_dns_domain"] = _normalize_hostname(normalized.get("root_dns_domain") or "")
        normalized["common_name"] = _normalize_hostname(normalized.get("common_name") or "") or default_cn
        raw_sans = normalized.get("subject_alt_names") or []
        if isinstance(raw_sans, str):
            normalized["subject_alt_names"] = _split_names(raw_sans)
        else:
            normalized["subject_alt_names"] = [
                _normalize_hostname(name) for name in raw_sans if _normalize_hostname(name)
            ]
        normalized.pop("domains", None)
        return normalized

    legacy = config.get("domains") or []
    if isinstance(legacy, str):
        legacy = _split_names(legacy)
    common_name = legacy[0] if legacy else _normalize_hostname(app_dns_name)
    subject_alt_names = legacy[1:] if len(legacy) > 1 else (
        [_normalize_hostname(app_dns_name)] if _normalize_hostname(app_dns_name) else []
    )
    root_dns_domain = ""
    zone_id = config.get("zone_id")
    if zone_id and db is not None:
        zone = _zone_row(db, zone_id)
        if zone:
            root_dns_domain = zone.zone_name
    normalized = dict(config)
    normalized["root_dns_domain"] = _normalize_hostname(root_dns_domain)
    normalized["common_name"] = _normalize_hostname(common_name)
    normalized["subject_alt_names"] = subject_alt_names
    normalized.pop("domains", None)
    return normalized


def validate_renew_before_days(value: Any) -> int:
    try:
        days = int(value)
    except (TypeError, ValueError) as exc:
        raise LetsEncryptError("Renew before expiry must be a number of days.") from exc
    if days < 1 or days > 89:
        raise LetsEncryptError("Renew before expiry must be between 1 and 89 days.")
    return days


def _valid_time(value: str) -> bool:
    try:
        datetime.strptime(value, "%H:%M")
    except ValueError:
        return False
    return True


def _zone_row(db, zone_id: Optional[int]) -> Optional[DnsZoneConfig]:
    if not zone_id:
        return None
    return db.get(DnsZoneConfig, zone_id)


def _relative_acme_name(domain: str, zone_name: str) -> str:
    domain = normalize_zone_name(domain)
    zone_name = normalize_zone_name(zone_name)
    prefix = domain[: -(len(zone_name) + 1)] if domain.endswith("." + zone_name) else ""
    return f"_acme-challenge.{prefix}".rstrip(".") or "_acme-challenge"


def create_dns_txt_challenge(db, *, zone_id: int, domain: str, value: str, ttl: int = DNS_TXT_CHALLENGE_TTL) -> Dict[str, str]:
    zone = _zone_row(db, zone_id)
    if zone is None:
        raise LetsEncryptError("Selected DNS zone was not found.")
    cfg = decode_zone_config(zone)
    record_name = _relative_acme_name(domain, zone.zone_name)
    client = create_dns_client_from_settings(cfg)
    client.create_or_update_record(
        DnsRecordRequest(zone_name=zone.zone_name, record_type="TXT", record_name=record_name, ttl=ttl, values=[value]),
        dns_server=cfg.get("dns_server"),
        dns_zone=zone.zone_name,
    )
    return {"zone_name": zone.zone_name, "record_name": record_name, "value": value}


def delete_dns_txt_challenge(db, *, zone_id: int, domain: str) -> None:
    zone = _zone_row(db, zone_id)
    if zone is None:
        return
    cfg = decode_zone_config(zone)
    record_name = _relative_acme_name(domain, zone.zone_name)
    client = create_dns_client_from_settings(cfg)
    client.create_or_update_record(
        DnsRecordRequest(zone_name=zone.zone_name, record_type="DELETE", record_name=record_name, ttl=120, values=["TXT"]),
        dns_server=cfg.get("dns_server"),
        dns_zone=zone.zone_name,
    )


def _txt_record_matches(records: List[Any], expected_value: str) -> bool:
    for row in records:
        values = getattr(row, "values", None) or []
        if expected_value in values:
            return True
    return False


def _verify_dns_txt_challenge(
    db,
    *,
    zone_id: int,
    domain: str,
    expected_value: str,
    progress_cb: Optional[ProgressCallback] = None,
    attempt_offset: int = 0,
    attempt_total: Optional[int] = None,
) -> None:
    zone = _zone_row(db, zone_id)
    if zone is None:
        raise LetsEncryptError("Selected DNS zone was not found.")
    cfg = decode_zone_config(zone)
    record_name = _relative_acme_name(domain, zone.zone_name)
    client = create_dns_client_from_settings(cfg)
    total = attempt_total or DNS_TXT_VERIFY_MAX_ATTEMPTS
    for attempt in range(total):
        if progress_cb:
            attempt_num = attempt_offset + attempt + 1
            percent = 25 + int(50 * attempt_num / max(total, 1))
            progress_cb(
                "verify_dns",
                percent,
                f"Waiting for DNS propagation (attempt {attempt_num}/{total})...",
            )
        _sleep_fn(DNS_TXT_VERIFY_DELAY_SECONDS)
        records = client.get_record(
            record_name=record_name,
            record_type="TXT",
            dns_server=cfg.get("dns_server"),
            dns_zone=zone.zone_name,
        )
        if _txt_record_matches(records, expected_value):
            return
    raise LetsEncryptError("DNS TXT record for _acme-challenge did not propagate after 2 minutes.")


def _cleanup_dns_txt_challenges(db, *, zone_id: int, domains: List[str]) -> None:
    for domain in domains:
        try:
            delete_dns_txt_challenge(db, zone_id=zone_id, domain=domain)
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass


def _directory_url(staging: bool) -> str:
    return STAGING_DIRECTORY if staging else PRODUCTION_DIRECTORY


def _private_key_pem(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _load_pem_private_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


def _load_or_create_account_key():
    path = cert_dir() / ACME_ACCOUNT_KEY_FILENAME
    if path.is_file():
        return _load_pem_private_key(path.read_bytes())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_bytes(_private_key_pem(key))
    try:
        os.chmod(tmp_path, 0o600)
    except OSError:
        pass
    os.replace(tmp_path, path)
    return key


def _csr_pem(private_key, common_name: str, subject_alt_names: List[str]) -> bytes:
    identities = _cert_identities({"common_name": common_name, "subject_alt_names": subject_alt_names})
    if not identities:
        raise LetsEncryptError("At least one certificate identity is required.")
    cn = identities[0]
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(name) for name in identities]),
        critical=False,
    )
    return builder.sign(private_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def _acme_imports():
    try:
        import josepy as jose
        from acme import errors, messages
        from acme.client import ClientNetwork, ClientV2
    except ImportError as exc:
        raise LetsEncryptError("ACME dependencies are not installed. Install requirements.txt and retry.") from exc
    return jose, errors, messages, ClientNetwork, ClientV2


def _acme_client(config: Dict[str, Any]):
    jose, errors, messages, ClientNetwork, ClientV2 = _acme_imports()
    account_key = _load_or_create_account_key()
    account_jwk = jose.JWKRSA(key=account_key)
    net = ClientNetwork(account_jwk, user_agent="api-to-dns")
    directory = ClientV2.get_directory(config.get("directory_url") or _directory_url(bool(config.get("staging"))), net)
    client = ClientV2(directory, net)
    try:
        registration = messages.NewRegistration.from_data(
            email=config.get("email") or None,
            terms_of_service_agreed=True,
        )
        client.new_account(registration)
    except errors.ConflictError:
        existing = messages.NewRegistration.from_data(
            email=config.get("email") or None,
            terms_of_service_agreed=True,
            only_return_existing=True,
        )
        response = client._post(client.directory["newAccount"], existing)  # noqa: SLF001 - acme has no public helper.
        client.net.account = client._regr_from_response(response)  # noqa: SLF001
    return client, account_jwk, messages


def _challenge_type(challb: Any) -> str:
    return str(getattr(challb, "typ", "") or getattr(getattr(challb, "chall", None), "typ", ""))


def _challenge_uri(challb: Any) -> str:
    return str(getattr(challb, "uri", "") or "")


def _challenge_token(challb: Any) -> str:
    path = str(getattr(getattr(challb, "chall", None), "path", "") or "")
    if path:
        return path.rsplit("/", 1)[-1]
    token = getattr(getattr(challb, "chall", None), "token", "")
    if isinstance(token, bytes):
        try:
            return token.decode("ascii")
        except UnicodeDecodeError:
            return ""
    return str(token or "")


def _order_challenges(order_resource: Any, account_jwk: Any, challenge_type: str) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    for authz in order_resource.authorizations:
        domain = str(authz.body.identifier.value)
        challb = next((body for body in authz.body.challenges if _challenge_type(body) == challenge_type), None)
        if challb is None:
            raise LetsEncryptError(f"ACME server did not offer {challenge_type} for {domain}.")
        validation = challb.validation(account_jwk)
        challenge: Dict[str, Any] = {
            "domain": domain,
            "type": challenge_type,
            "uri": _challenge_uri(challb),
            "validation": validation,
        }
        if challenge_type == CHALLENGE_DNS:
            challenge["dns_value"] = validation
            challenge["name"] = f"_acme-challenge.{domain}"
        else:
            token = _challenge_token(challb)
            challenge["token"] = token
            challenge["key_authorization"] = validation
            challenge["response"] = validation
            challenge["url"] = f"http://{domain}/.well-known/acme-challenge/{token}"
        selected.append(challenge)
    return selected


def _acme_prepare_order(config: Dict[str, Any]) -> Dict[str, Any]:
    """Create an ACME order and return serializable challenge details.

    The generated certificate private key is stored with the transient order so
    the manual continue step can finalize the same CSR.
    """
    try:
        client, account_jwk, _messages = _acme_client(config)
        cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert_key_pem = _private_key_pem(cert_key)
        identities = _cert_identities(config)
        order_resource = client.new_order(
            _csr_pem(cert_key, config["common_name"], config.get("subject_alt_names") or [])
        )
        challenges = _order_challenges(order_resource, account_jwk, str(config["challenge_type"]))
        return {
            "order_resource": order_resource.to_json(),
            "private_key_pem": cert_key_pem.decode("utf-8"),
            "challenges": challenges,
            "challenge": challenges[0] if challenges else {},
            "domain": challenges[0]["domain"] if challenges else config["common_name"],
        }
    except LetsEncryptError:
        raise
    except Exception as exc:  # noqa: BLE001 - ACME libraries raise several rich exception types.
        raise LetsEncryptError(f"Failed to create ACME order: {exc}") from exc


def _acme_finalize_order(enrollment: Dict[str, Any]) -> Dict[str, bytes]:
    try:
        config = enrollment.get("config") or {}
        order = enrollment.get("order") or {}
        client, _account_jwk, messages = _acme_client(config)
        order_resource_json = order.get("order_resource")
        private_key_pem = str(order.get("private_key_pem") or "").encode("utf-8")
        if not order_resource_json or not private_key_pem:
            raise LetsEncryptError("ACME enrollment is missing order state. Start enrollment again.")
        order_resource = messages.OrderResource.from_json(order_resource_json)
        selected_uris = {challenge.get("uri") for challenge in order.get("challenges", []) if challenge.get("uri")}
        for authz in order_resource.authorizations:
            for challb in authz.body.challenges:
                if _challenge_uri(challb) in selected_uris:
                    client.answer_challenge(challb, challb.response(client.net.key))
                    break
        deadline = datetime.now() + timedelta(seconds=180)
        finalized = client.poll_and_finalize(order_resource, deadline=deadline)
        fullchain_pem = (finalized.fullchain_pem or "").encode("utf-8")
        if not fullchain_pem:
            raise LetsEncryptError("ACME order finalized without a certificate chain.")
        return {"key_pem": private_key_pem, "cert_pem": fullchain_pem}
    except LetsEncryptError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise LetsEncryptError(f"Failed to finalize ACME order: {exc}") from exc


def save_config(
    db,
    *,
    email: str,
    root_dns_domain: str,
    common_name: str,
    subject_alt_names: str | List[str],
    challenge_type: str,
    zone_id: Optional[int],
    staging: bool,
    renew_before_expiry_days: Any = DEFAULT_RENEW_BEFORE_DAYS,
    scheduled_restart_enabled: bool = True,
    scheduled_restart_time: str = DEFAULT_SCHEDULED_RESTART_TIME,
    auto_renew_enabled: bool = True,
) -> Dict[str, Any]:
    challenge = challenge_type if challenge_type in {CHALLENGE_DNS, CHALLENGE_HTTP} else CHALLENGE_DNS
    schedule_time = scheduled_restart_time if _valid_time(scheduled_restart_time) else DEFAULT_SCHEDULED_RESTART_TIME
    root = _normalize_hostname(root_dns_domain)
    cn = _normalize_hostname(common_name) or _normalize_hostname(get_app_dns_name(db))
    sans = _split_names(subject_alt_names)
    if not root:
        raise LetsEncryptError("Root DNS Domain is required.")
    if not cn:
        raise LetsEncryptError("Common Name is required.")
    for name in _cert_identities({"common_name": cn, "subject_alt_names": sans}):
        if not _name_under_root(name, root):
            raise LetsEncryptError(f"Certificate name {name!r} must be within root DNS domain {root!r}.")
    if challenge == CHALLENGE_DNS and zone_id:
        zone = _zone_row(db, zone_id)
        if zone is None:
            raise LetsEncryptError("Selected DNS zone was not found.")
        try:
            configured_domain = provider_dns_zone(decode_zone_config(zone))
        except ValueError as exc:
            raise LetsEncryptError(str(exc)) from exc
        if configured_domain != normalize_zone_name(root):
            raise LetsEncryptError("Selected zone configuration DNS domain must match Root DNS Domain.")
    config = {
        "email": email.strip(),
        "root_dns_domain": root,
        "common_name": cn,
        "subject_alt_names": sans,
        "challenge_type": challenge,
        "zone_id": zone_id,
        "staging": bool(staging),
        "renew_before_expiry_days": validate_renew_before_days(renew_before_expiry_days),
        "scheduled_restart_enabled": bool(scheduled_restart_enabled),
        "scheduled_restart_time": schedule_time,
        "auto_renew_enabled": bool(auto_renew_enabled),
        "directory_url": _directory_url(bool(staging)),
    }
    if not config["email"]:
        raise LetsEncryptError("Email is required.")
    _write_json_setting(db, SETTING_CONFIG, config)
    return config


def start_enrollment(db, *, progress_cb: Optional[ProgressCallback] = None, **kwargs: Any) -> Dict[str, Any]:
    report = progress_cb or _noop_progress
    report("save_config", 5, "Saving configuration...")
    config = save_config(db, **kwargs)
    report("prepare_order", 15, "Preparing ACME order...")
    order = _acme_prepare_order(config)
    enrollment = {
        "status": "awaiting_validation",
        "config": config,
        "order": order,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    challenges = order.get("challenges") or ([order.get("challenge")] if order.get("challenge") else [])
    challenge = challenges[0] if challenges else {}
    primary_name = config["common_name"]
    if config["challenge_type"] == CHALLENGE_DNS:
        if config.get("zone_id"):
            provisioned_domains: List[str] = []
            try:
                report("create_dns_records", 25, "Creating DNS TXT records...")
                enrollment["dns_records"] = []
                verify_total = DNS_TXT_VERIFY_MAX_ATTEMPTS * max(len(challenges), 1)
                verify_attempt = 0
                for entry in challenges:
                    domain = entry.get("domain") or primary_name
                    value = entry.get("dns_value") or entry.get("value") or ""
                    record = create_dns_txt_challenge(
                        db,
                        zone_id=int(config["zone_id"]),
                        domain=domain,
                        value=value,
                    )
                    enrollment["dns_records"].append(record)
                    provisioned_domains.append(domain)
                    _verify_dns_txt_challenge(
                        db,
                        zone_id=int(config["zone_id"]),
                        domain=domain,
                        expected_value=value,
                        progress_cb=progress_cb,
                        attempt_offset=verify_attempt,
                        attempt_total=verify_total,
                    )
                    verify_attempt += DNS_TXT_VERIFY_MAX_ATTEMPTS
                enrollment["status"] = "ready"
            except LetsEncryptError:
                _cleanup_dns_txt_challenges(db, zone_id=int(config["zone_id"]), domains=provisioned_domains)
                clear_enrollment(db)
                raise
        else:
            enrollment["manual"] = {
                "type": CHALLENGE_DNS,
                "challenges": [
                    {
                        "name": entry.get("name") or f"_acme-challenge.{entry.get('domain') or primary_name}",
                        "value": entry.get("dns_value") or entry.get("value") or "",
                    }
                    for entry in challenges
                ],
                "name": challenge.get("name") or f"_acme-challenge.{challenge.get('domain') or primary_name}",
                "value": challenge.get("dns_value") or challenge.get("value") or "",
            }
            enrollment["status"] = "awaiting_manual"
    else:
        token = challenge.get("token") or ""
        response = challenge.get("key_authorization") or challenge.get("response") or ""
        enrollment["manual"] = {
            "type": CHALLENGE_HTTP,
            "challenges": [
                {
                    "url": entry.get("url") or f"http://{entry.get('domain') or primary_name}/.well-known/acme-challenge/{entry.get('token') or ''}",
                    "response": entry.get("key_authorization") or entry.get("response") or "",
                }
                for entry in challenges
            ],
            "url": f"http://{primary_name}/.well-known/acme-challenge/{token}",
            "token": token,
            "response": response,
        }
        enrollment["http_challenges"] = [
            {"token": entry.get("token") or "", "response": entry.get("key_authorization") or entry.get("response") or ""}
            for entry in challenges
        ]
        enrollment["http_challenge"] = {"token": token, "response": response}
        enrollment["status"] = "awaiting_manual"
    _write_json_setting(db, SETTING_ENROLLMENT, enrollment)
    if enrollment["status"] == "ready":
        return continue_enrollment(db, progress_cb=progress_cb)
    return enrollment


def continue_enrollment(db, *, progress_cb: Optional[ProgressCallback] = None) -> Dict[str, Any]:
    report = progress_cb or _noop_progress
    enrollment = get_enrollment(db)
    if not enrollment:
        raise LetsEncryptError("No Let's Encrypt enrollment is in progress.")
    report("finalize_order", 85, "Finalizing certificate...")
    issued = _acme_finalize_order(enrollment)
    report("install_cert", 95, "Installing certificate...")
    metadata = install_letsencrypt_cert(issued["key_pem"], issued["cert_pem"])
    config = enrollment.get("config") or {}
    _write_json_setting(db, SETTING_CONFIG, config)
    clear_enrollment(db)
    for entry in (enrollment.get("order") or {}).get("challenges", []):
        if config.get("zone_id") and entry.get("domain"):
            delete_dns_txt_challenge(db, zone_id=int(config["zone_id"]), domain=entry["domain"])
    return {"status": "issued", "metadata": metadata, "config": config}


def cancel_enrollment(db) -> None:
    enrollment = get_enrollment(db)
    config = (enrollment or {}).get("config") or {}
    if enrollment and config.get("zone_id"):
        for entry in (enrollment.get("order") or {}).get("challenges", []):
            if entry.get("domain"):
                delete_dns_txt_challenge(db, zone_id=int(config["zone_id"]), domain=entry["domain"])
    clear_enrollment(db)


def http_challenge_response(db, token: str) -> Optional[str]:
    enrollment = get_enrollment(db)
    challenge = (enrollment or {}).get("http_challenge") or {}
    if challenge.get("token") == token:
        return challenge.get("response") or ""
    for challenge in (enrollment or {}).get("http_challenges", []):
        if challenge.get("token") == token:
            return challenge.get("response") or ""
    return None


def should_renew_cert(metadata: Optional[Dict[str, Any]], renew_before_days: int) -> bool:
    if not metadata or metadata.get("source") != SOURCE_LETSENCRYPT:
        return False
    not_after = metadata.get("not_after")
    if isinstance(not_after, str):
        try:
            not_after = datetime.fromisoformat(not_after)
        except ValueError:
            return False
    if not isinstance(not_after, datetime):
        return False
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    return not_after <= datetime.now(timezone.utc) + timedelta(days=renew_before_days)


def maybe_renew_certificate(db) -> Optional[Dict[str, Any]]:
    if _read_source() != SOURCE_LETSENCRYPT:
        return None
    config = get_config(db)
    if not config:
        return None
    if not config.get("auto_renew_enabled", True):
        return None
    renew_days = validate_renew_before_days(
        config.get("renew_before_expiry_days") or os.getenv("LETSENCRYPT_RENEW_DAYS") or DEFAULT_RENEW_BEFORE_DAYS
    )
    if not should_renew_cert(cert_metadata(), renew_days):
        return None
    order = _acme_prepare_order(config)
    enrollment = {"status": "renewing", "config": config, "order": order}
    issued = _acme_finalize_order(enrollment)
    metadata = install_letsencrypt_cert(issued["key_pem"], issued["cert_pem"])
    return {"status": "renewed", "metadata": metadata, "config": config}


def config_view(db) -> Dict[str, Any]:
    config = get_config(db) or {}
    app_dns_name = get_app_dns_name(db)
    metadata = cert_metadata()
    renewal_hint = ""
    auto_renew_enabled = config.get("auto_renew_enabled", True)
    not_after = metadata.get("not_after") if metadata else None
    if auto_renew_enabled and isinstance(not_after, datetime):
        days = validate_renew_before_days(config.get("renew_before_expiry_days") or DEFAULT_RENEW_BEFORE_DAYS)
        renewal_hint = (not_after - timedelta(days=days)).date().isoformat()
    return {
        "config": config,
        "defaults": {
            "common_name": app_dns_name,
            "subject_alt_names": app_dns_name,
        },
        "enrollment": get_enrollment(db),
        "renew_options": RENEW_OPTIONS,
        "renewal_hint": renewal_hint,
        "zones": [{"id": z.id, "zone_name": z.zone_name} for z in list_dns_zones(db)],
    }
