"""Let's Encrypt enrollment and renewal state.

The live ACME calls are isolated behind small private functions so tests can
mock issuance without talking to Let's Encrypt. DNS automation reuses the same
configured zone plugins as the public DNS API.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .models import DnsRecordRequest, DnsZoneConfig
from .settings_store import delete_setting, get_setting, set_setting
from .ssl_certs import SOURCE_LETSENCRYPT, _read_source, cert_dir, cert_metadata, install_letsencrypt_cert
from .zone_service import create_dns_client_from_settings, decode_zone_config, list_dns_zones, normalize_zone_name

SETTING_CONFIG = "letsencrypt_config"
SETTING_ENROLLMENT = "letsencrypt_enrollment"

CHALLENGE_DNS = "dns-01"
CHALLENGE_HTTP = "http-01"
RENEW_OPTIONS = [7, 14, 21, 30, 45, 60]
DEFAULT_RENEW_BEFORE_DAYS = 30
DEFAULT_SCHEDULED_RESTART_TIME = "03:00"
ACME_ACCOUNT_KEY_FILENAME = "acme_account.key"

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
    return _read_json_setting(db, SETTING_CONFIG)


def get_enrollment(db) -> Optional[Dict[str, Any]]:
    return _read_json_setting(db, SETTING_ENROLLMENT)


def clear_enrollment(db) -> None:
    delete_setting(db, SETTING_ENROLLMENT)


def _split_domains(domains: str | List[str]) -> List[str]:
    if isinstance(domains, str):
        parts = domains.replace("\n", ",").split(",")
    else:
        parts = domains
    cleaned = []
    for part in parts:
        domain = str(part).strip().strip(".").lower()
        if domain and domain not in cleaned:
            cleaned.append(domain)
    if not cleaned:
        raise LetsEncryptError("At least one domain is required.")
    return cleaned


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


def create_dns_txt_challenge(db, *, zone_id: int, domain: str, value: str, ttl: int = 120) -> Dict[str, str]:
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


def _csr_pem(private_key, domains: List[str]) -> bytes:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]), critical=False)
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
        order_resource = client.new_order(_csr_pem(cert_key, list(config["domains"])))
        challenges = _order_challenges(order_resource, account_jwk, str(config["challenge_type"]))
        return {
            "order_resource": order_resource.to_json(),
            "private_key_pem": cert_key_pem.decode("utf-8"),
            "challenges": challenges,
            "challenge": challenges[0] if challenges else {},
            "domain": challenges[0]["domain"] if challenges else config["domains"][0],
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
    domains: str | List[str],
    challenge_type: str,
    zone_id: Optional[int],
    staging: bool,
    renew_before_expiry_days: Any = DEFAULT_RENEW_BEFORE_DAYS,
    scheduled_restart_enabled: bool = True,
    scheduled_restart_time: str = DEFAULT_SCHEDULED_RESTART_TIME,
) -> Dict[str, Any]:
    challenge = challenge_type if challenge_type in {CHALLENGE_DNS, CHALLENGE_HTTP} else CHALLENGE_DNS
    schedule_time = scheduled_restart_time if _valid_time(scheduled_restart_time) else DEFAULT_SCHEDULED_RESTART_TIME
    config = {
        "email": email.strip(),
        "domains": _split_domains(domains),
        "challenge_type": challenge,
        "zone_id": zone_id,
        "staging": bool(staging),
        "renew_before_expiry_days": validate_renew_before_days(renew_before_expiry_days),
        "scheduled_restart_enabled": bool(scheduled_restart_enabled),
        "scheduled_restart_time": schedule_time,
        "directory_url": _directory_url(bool(staging)),
    }
    if not config["email"]:
        raise LetsEncryptError("Email is required.")
    if challenge == CHALLENGE_DNS and zone_id:
        if _zone_row(db, zone_id) is None:
            raise LetsEncryptError("Selected DNS zone was not found.")
    _write_json_setting(db, SETTING_CONFIG, config)
    return config


def start_enrollment(db, **kwargs: Any) -> Dict[str, Any]:
    config = save_config(db, **kwargs)
    order = _acme_prepare_order(config)
    enrollment = {
        "status": "awaiting_validation",
        "config": config,
        "order": order,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    challenges = order.get("challenges") or ([order.get("challenge")] if order.get("challenge") else [])
    challenge = challenges[0] if challenges else {}
    if config["challenge_type"] == CHALLENGE_DNS:
        if config.get("zone_id"):
            enrollment["dns_records"] = [
                create_dns_txt_challenge(
                    db,
                    zone_id=int(config["zone_id"]),
                    domain=entry.get("domain") or config["domains"][0],
                    value=entry.get("dns_value") or entry.get("value") or "",
                )
                for entry in challenges
            ]
            enrollment["status"] = "ready"
        else:
            enrollment["manual"] = {
                "type": CHALLENGE_DNS,
                "challenges": [
                    {
                        "name": entry.get("name") or f"_acme-challenge.{entry.get('domain') or config['domains'][0]}",
                        "value": entry.get("dns_value") or entry.get("value") or "",
                    }
                    for entry in challenges
                ],
                "name": challenge.get("name") or f"_acme-challenge.{challenge.get('domain') or config['domains'][0]}",
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
                    "url": entry.get("url") or f"http://{entry.get('domain') or config['domains'][0]}/.well-known/acme-challenge/{entry.get('token') or ''}",
                    "response": entry.get("key_authorization") or entry.get("response") or "",
                }
                for entry in challenges
            ],
            "url": f"http://{config['domains'][0]}/.well-known/acme-challenge/{token}",
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
        return continue_enrollment(db)
    return enrollment


def continue_enrollment(db) -> Dict[str, Any]:
    enrollment = get_enrollment(db)
    if not enrollment:
        raise LetsEncryptError("No Let's Encrypt enrollment is in progress.")
    issued = _acme_finalize_order(enrollment)
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
    renew_days = validate_renew_before_days(config.get("renew_before_expiry_days") or os.getenv("LETSENCRYPT_RENEW_DAYS") or DEFAULT_RENEW_BEFORE_DAYS)
    if not should_renew_cert(cert_metadata(), renew_days):
        return None
    order = _acme_prepare_order(config)
    enrollment = {"status": "renewing", "config": config, "order": order}
    issued = _acme_finalize_order(enrollment)
    metadata = install_letsencrypt_cert(issued["key_pem"], issued["cert_pem"])
    return {"status": "renewed", "metadata": metadata, "config": config}


def config_view(db) -> Dict[str, Any]:
    config = get_config(db) or {}
    metadata = cert_metadata()
    renewal_hint = ""
    not_after = metadata.get("not_after") if metadata else None
    if isinstance(not_after, datetime):
        days = validate_renew_before_days(config.get("renew_before_expiry_days") or DEFAULT_RENEW_BEFORE_DAYS)
        renewal_hint = (not_after - timedelta(days=days)).date().isoformat()
    return {
        "config": config,
        "enrollment": get_enrollment(db),
        "renew_options": RENEW_OPTIONS,
        "renewal_hint": renewal_hint,
        "zones": [{"id": z.id, "zone_name": z.zone_name} for z in list_dns_zones(db)],
    }
