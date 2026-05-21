from typing import Any, Dict, List, Optional

import httpx
from ..models import DnsRecordInfo, DnsRecordRequest

from .base import DnsProviderPlugin, PluginField
from .utils import lookup_record_types_to_query


CLOUDFLARE_API_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_TIMEOUT_SECONDS = 30.0
SUPPORTED_RECORD_TYPES = ("A", "AAAA", "CNAME", "TXT")


def _truthy(value: Optional[str]) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _fqdn(zone_name: str, record_name: str) -> str:
    z = zone_name.strip().rstrip(".")
    r = (record_name or "").strip().rstrip(".")
    if not r or r == "@":
        return z
    suffix = "." + z
    if r.lower().endswith(suffix.lower()) or r.lower() == z.lower():
        return r
    return f"{r}.{z}"


def _relative_name(zone_name: str, fqdn: str) -> str:
    z = zone_name.strip().rstrip(".")
    f = (fqdn or "").strip().rstrip(".")
    if f.lower() == z.lower():
        return "@"
    suffix = "." + z
    if f.lower().endswith(suffix.lower()):
        return f[: -len(suffix)] or "@"
    return f


def _normalize_txt_value(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    return v


def _cloudflare_txt_content(value: str) -> str:
    return f'"{_normalize_txt_value(value)}"'


class CloudflareDnsClient:
    """Cloudflare API v4 DNS records client using an API Token (Bearer auth)."""

    def __init__(
        self,
        api_token: str,
        zone_id: Optional[str] = None,
        proxied: bool = False,
        base_url: str = CLOUDFLARE_API_BASE_URL,
    ):
        if not api_token:
            raise ValueError("Cloudflare DNS requires an API token (zone DNS Edit/Read).")
        self._api_token = api_token
        self._zone_id = (zone_id or "").strip() or None
        self._proxied = bool(proxied)
        self._base_url = base_url.rstrip("/")

    def create_or_update_record(
        self,
        payload: DnsRecordRequest,
        dns_server: Optional[str] = None,
        dns_zone: Optional[str] = None,
    ) -> bool:
        if dns_server:
            raise ValueError(
                "Cloudflare DNS ignores per-server host settings; use the Cloudflare fields on the zone configuration."
            )
        zone_name = (dns_zone or payload.zone_name or "").strip().rstrip(".")
        if not zone_name:
            raise ValueError("Zone name is required for Cloudflare DNS.")

        record_type = payload.record_type.upper()
        ttl = int(payload.ttl or 300)
        fqdn = _fqdn(zone_name, payload.record_name)

        with self._client() as client:
            zone_id = self._resolve_zone_id(client, zone_name)

            if record_type == "DELETE":
                inner = payload.values[0].strip().upper()
                if inner not in SUPPORTED_RECORD_TYPES:
                    raise ValueError(f"Unsupported record type for Cloudflare: {inner}")
                existing = self._list_records(client, zone_id, fqdn, inner)
                if not existing:
                    return False
                for row in existing:
                    self._delete_record(client, zone_id, row["id"])
                return True

            if record_type not in SUPPORTED_RECORD_TYPES:
                raise ValueError(f"Unsupported record type for Cloudflare: {record_type}")

            existing = self._list_records(client, zone_id, fqdn, record_type)
            existed = bool(existing)
            desired_values = self._desired_values(record_type, payload.values)
            self._sync_records(
                client,
                zone_id=zone_id,
                fqdn=fqdn,
                record_type=record_type,
                ttl=ttl,
                desired_values=desired_values,
                existing=existing,
            )
            return existed

    def get_record(
        self,
        *,
        record_name: str,
        record_type: Optional[str] = None,
        dns_server: Optional[str] = None,
        dns_zone: Optional[str] = None,
    ) -> List[DnsRecordInfo]:
        if dns_server:
            raise ValueError(
                "Cloudflare DNS ignores per-server host settings; use the Cloudflare fields on the zone configuration."
            )
        if not dns_zone:
            raise ValueError("Zone name is required for Cloudflare DNS.")

        zone_name = dns_zone.strip().rstrip(".")
        fqdn = _fqdn(zone_name, record_name)
        display_name = _relative_name(zone_name, fqdn)
        types_to_query = lookup_record_types_to_query(record_type)

        results: List[DnsRecordInfo] = []
        with self._client() as client:
            zone_id = self._resolve_zone_id(client, zone_name)
            for rt in types_to_query:
                rows = self._list_records(client, zone_id, fqdn, rt)
                if not rows:
                    continue
                results.append(self._rows_to_info(display_name, rt, rows))
        return results

    def _client(self) -> httpx.Client:
        headers = {
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        return httpx.Client(base_url=self._base_url, headers=headers, timeout=DEFAULT_TIMEOUT_SECONDS)

    def _request(
        self,
        client: httpx.Client,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            response = client.request(method, path, params=params, json=json_body)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Cloudflare API request failed: {exc}") from exc

        try:
            body = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Cloudflare API returned non-JSON response (HTTP {response.status_code})."
            ) from exc

        if not isinstance(body, dict) or not body.get("success"):
            message = self._first_error_message(body) or f"HTTP {response.status_code}"
            raise RuntimeError(f"Cloudflare API error: {message}")
        return body

    @staticmethod
    def _first_error_message(body: Any) -> Optional[str]:
        if not isinstance(body, dict):
            return None
        errors = body.get("errors") or []
        if errors and isinstance(errors[0], dict):
            msg = errors[0].get("message")
            if msg:
                return str(msg)
        return None

    def _resolve_zone_id(self, client: httpx.Client, zone_name: str) -> str:
        if self._zone_id:
            return self._zone_id
        body = self._request(client, "GET", "/zones", params={"name": zone_name})
        rows = body.get("result") or []
        for row in rows:
            if str(row.get("name", "")).rstrip(".").lower() == zone_name.lower():
                zone_id = row.get("id")
                if zone_id:
                    return str(zone_id)
        raise ValueError(f"Cloudflare zone {zone_name!r} not found for this API token.")

    def _list_records(
        self,
        client: httpx.Client,
        zone_id: str,
        fqdn: str,
        record_type: str,
    ) -> List[Dict[str, Any]]:
        body = self._request(
            client,
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"name": fqdn, "type": record_type},
        )
        rows = body.get("result") or []
        return [row for row in rows if isinstance(row, dict)]

    def _create_record(
        self,
        client: httpx.Client,
        zone_id: str,
        *,
        fqdn: str,
        record_type: str,
        content: str,
        ttl: int,
    ) -> None:
        self._request(
            client,
            "POST",
            f"/zones/{zone_id}/dns_records",
            json_body=self._record_body(fqdn, record_type, content, ttl),
        )

    def _update_record(
        self,
        client: httpx.Client,
        zone_id: str,
        record_id: str,
        *,
        fqdn: str,
        record_type: str,
        content: str,
        ttl: int,
    ) -> None:
        self._request(
            client,
            "PUT",
            f"/zones/{zone_id}/dns_records/{record_id}",
            json_body=self._record_body(fqdn, record_type, content, ttl),
        )

    def _delete_record(self, client: httpx.Client, zone_id: str, record_id: str) -> None:
        self._request(client, "DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

    def _record_body(self, fqdn: str, record_type: str, content: str, ttl: int) -> Dict[str, Any]:
        api_content = _cloudflare_txt_content(content) if record_type == "TXT" else content
        body: Dict[str, Any] = {
            "type": record_type,
            "name": fqdn,
            "content": api_content,
            "ttl": ttl,
        }
        if record_type in {"A", "AAAA", "CNAME"}:
            body["proxied"] = self._proxied
        return body

    @staticmethod
    def _desired_values(record_type: str, values: List[str]) -> List[str]:
        if record_type == "CNAME":
            if len(values) != 1:
                raise ValueError("CNAME requires exactly one value.")
            return [values[0].strip().rstrip(".")]
        if not values:
            raise ValueError("values is required and must contain at least one entry.")
        if record_type == "TXT":
            return [_normalize_txt_value(v) for v in values]
        return [v for v in values]

    def _sync_records(
        self,
        client: httpx.Client,
        *,
        zone_id: str,
        fqdn: str,
        record_type: str,
        ttl: int,
        desired_values: List[str],
        existing: List[Dict[str, Any]],
    ) -> None:
        if record_type == "CNAME":
            content = desired_values[0]
            if existing:
                # CNAME is single-valued; update the first row, delete extras.
                first = existing[0]
                self._update_record(
                    client,
                    zone_id,
                    str(first["id"]),
                    fqdn=fqdn,
                    record_type=record_type,
                    content=content,
                    ttl=ttl,
                )
                for row in existing[1:]:
                    self._delete_record(client, zone_id, str(row["id"]))
            else:
                self._create_record(
                    client,
                    zone_id,
                    fqdn=fqdn,
                    record_type=record_type,
                    content=content,
                    ttl=ttl,
                )
            return

        desired_set = set(desired_values)
        existing_by_content: Dict[str, Dict[str, Any]] = {}
        stale: List[Dict[str, Any]] = []
        normalize_content = _normalize_txt_value if record_type == "TXT" else str
        for row in existing:
            content = normalize_content(str(row.get("content", "")))
            if content in desired_set and content not in existing_by_content:
                existing_by_content[content] = row
            else:
                stale.append(row)

        for row in stale:
            self._delete_record(client, zone_id, str(row["id"]))

        for content in desired_values:
            row = existing_by_content.get(content)
            if row is not None:
                self._update_record(
                    client,
                    zone_id,
                    str(row["id"]),
                    fqdn=fqdn,
                    record_type=record_type,
                    content=content,
                    ttl=ttl,
                )
            else:
                self._create_record(
                    client,
                    zone_id,
                    fqdn=fqdn,
                    record_type=record_type,
                    content=content,
                    ttl=ttl,
                )

    @staticmethod
    def _rows_to_info(display_name: str, record_type: str, rows: List[Dict[str, Any]]) -> DnsRecordInfo:
        ttls = [int(row["ttl"]) for row in rows if isinstance(row.get("ttl"), (int, float))]
        # Use the minimum TTL when multiple Cloudflare rows back one logical RRset;
        # this matches how recursive resolvers cap the effective TTL.
        ttl = min(ttls) if ttls else None
        values = [str(row.get("content", "")) for row in rows if row.get("content") is not None]
        if record_type == "CNAME":
            values = [v.rstrip(".") for v in values]
        elif record_type == "TXT":
            values = [_normalize_txt_value(v) for v in values]
        return DnsRecordInfo(
            record_name=display_name,
            record_type=record_type,
            ttl=ttl,
            values=values,
        )


def create_client(settings: Dict[str, Optional[str]]) -> CloudflareDnsClient:
    return CloudflareDnsClient(
        api_token=settings.get("cloudflare_api_token") or "",
        zone_id=settings.get("cloudflare_zone_id") or "",
        proxied=_truthy(settings.get("cloudflare_proxied")),
    )


PLUGIN = DnsProviderPlugin(
    key="cloudflare",
    label="Cloudflare DNS (REST API)",
    heading="Cloudflare DNS",
    help_text=(
        "Use a Cloudflare API token with Zone DNS Read and Edit permissions on the target zone. "
        "Target DNS Server and TSIG settings are not used for Cloudflare DNS."
    ),
    fields=[
        PluginField(
            "cloudflare_api_token",
            "API token",
            type="password",
            autocomplete="new-password",
            preserve_on_blank=True,
            help="Scoped Cloudflare API token with Zone:DNS Read and Edit on this zone.",
        ),
        PluginField(
            "cloudflare_zone_id",
            "Zone ID (optional)",
            autocomplete="off",
            placeholder="Leave blank to look up by zone name",
            help="Skips the zone name lookup when set. Find it on the Cloudflare dashboard overview page.",
        ),
        PluginField(
            "cloudflare_proxied",
            "Proxied (orange cloud)",
            type="checkbox",
            help="When checked, created or updated A, AAAA, and CNAME records use Cloudflare proxying.",
        ),
    ],
    create_client=create_client,
)
