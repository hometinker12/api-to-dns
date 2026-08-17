from typing import Any

import httpx

from ..dns_record_types import (
    LOOKUP_RECORD_TYPES,
    MUTABLE_RECORD_TYPES,
    format_caa,
    format_mx,
    format_srv,
    normalize_hostname,
    normalize_record_values,
    parse_caa,
    parse_mx,
    parse_srv,
)
from ..schemas.dns import DnsRecordInfo, DnsRecordListResult, DnsRecordRequest
from .base import DNS_ZONE_DOMAIN_FIELD, DnsProviderPlugin, PluginField
from .utils import lookup_record_types_to_query, record_name_matches

CLOUDFLARE_API_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_TIMEOUT_SECONDS = 30.0
SUPPORTED_RECORD_TYPES = LOOKUP_RECORD_TYPES


def _truthy(value: str | None) -> bool:
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


def _canonical_from_row(record_type: str, row: dict[str, Any]) -> str:
    rt = record_type.upper()
    if rt == "MX":
        return format_mx(int(row.get("priority") or 0), str(row.get("content") or ""))
    if rt == "SRV":
        data = row.get("data") or {}
        return format_srv(
            int(data.get("priority") if data.get("priority") is not None else row.get("priority") or 0),
            int(data.get("weight") or 0),
            int(data.get("port") or 0),
            str(data.get("target") or row.get("content") or ""),
        )
    if rt == "CAA":
        data = row.get("data") or {}
        if data:
            return format_caa(int(data.get("flags") or 0), str(data.get("tag") or ""), str(data.get("value") or ""))
        return normalize_record_values("CAA", [str(row.get("content") or "")])[0]
    if rt == "TXT":
        return _normalize_txt_value(str(row.get("content") or ""))
    if rt in {"CNAME", "NS", "PTR"}:
        return normalize_hostname(str(row.get("content") or ""))
    if rt == "SOA":
        return str(row.get("content") or "")
    return str(row.get("content") or "")


class CloudflareDnsClient:
    """Cloudflare API v4 DNS records client using an API Token (Bearer auth)."""

    def __init__(
        self,
        api_token: str,
        zone_id: str | None = None,
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
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> bool:
        if dns_server:
            raise ValueError(
                "Cloudflare DNS ignores per-server host settings; use the Cloudflare fields on the zone configuration."
            )
        zone_name = (dns_zone or "").strip().rstrip(".")
        if not zone_name:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        record_type = payload.record_type.upper()
        ttl = int(payload.ttl or 300)
        fqdn = _fqdn(zone_name, payload.record_name)

        with self._client() as client:
            zone_id = self._resolve_zone_id(client, zone_name)

            if record_type == "DELETE":
                inner = payload.values[0].strip().upper()
                if inner not in MUTABLE_RECORD_TYPES:
                    raise ValueError(f"Unsupported record type for Cloudflare: {inner}")
                existing = self._list_records(client, zone_id, fqdn, inner)
                if not existing:
                    return False
                for row in existing:
                    self._delete_record(client, zone_id, row["id"])
                return True

            if record_type not in MUTABLE_RECORD_TYPES:
                raise ValueError(f"Unsupported record type for Cloudflare: {record_type}")

            existing = self._list_records(client, zone_id, fqdn, record_type)
            existed = bool(existing)
            desired_values = normalize_record_values(record_type, list(payload.values))
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
        record_type: str | None = None,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> list[DnsRecordInfo]:
        if dns_server:
            raise ValueError(
                "Cloudflare DNS ignores per-server host settings; use the Cloudflare fields on the zone configuration."
            )
        if not dns_zone:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        zone_name = dns_zone.strip().rstrip(".")
        fqdn = _fqdn(zone_name, record_name)
        display_name = _relative_name(zone_name, fqdn)
        types_to_query = lookup_record_types_to_query(record_type)

        results: list[DnsRecordInfo] = []
        with self._client() as client:
            zone_id = self._resolve_zone_id(client, zone_name)
            for rt in types_to_query:
                if rt not in SUPPORTED_RECORD_TYPES:
                    continue
                rows = self._list_records(client, zone_id, fqdn, rt)
                if not rows:
                    continue
                results.append(self._rows_to_info(display_name, rt, rows))
        return results

    def list_records(
        self,
        *,
        name_pattern: str | None = None,
        record_type: str | None = None,
        limit: int = 100,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> DnsRecordListResult:
        if dns_server:
            raise ValueError(
                "Cloudflare DNS ignores per-server host settings; use the Cloudflare fields on the zone configuration."
            )
        if not dns_zone:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        zone_name = dns_zone.strip().rstrip(".")
        result_limit = max(1, int(limit))
        requested_type = record_type.upper() if record_type else None
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        page = 1
        truncated = False

        with self._client() as client:
            zone_id = self._resolve_zone_id(client, zone_name)
            while True:
                params: dict[str, Any] = {
                    "page": page,
                    "per_page": 100,
                    "order": "name",
                    "direction": "asc",
                }
                if requested_type:
                    params["type"] = requested_type
                body = self._request(client, "GET", f"/zones/{zone_id}/dns_records", params=params)
                rows = [row for row in (body.get("result") or []) if isinstance(row, dict)]
                appended_existing = False

                for row in rows:
                    row_type = str(row.get("type") or "").upper()
                    if row_type not in SUPPORTED_RECORD_TYPES or (requested_type and row_type != requested_type):
                        continue
                    display_name = _relative_name(zone_name, str(row.get("name") or ""))
                    if not record_name_matches(name_pattern, display_name):
                        continue
                    key = (display_name, row_type)
                    if key in grouped:
                        grouped[key].append(row)
                        appended_existing = True
                        continue
                    if len(grouped) >= result_limit:
                        # Keep paging only long enough to finish already-open RRsets.
                        # Cloudflare pages are ordered by name, so same-name values may
                        # continue across page boundaries after later types appear.
                        truncated = True
                        continue
                    grouped[key] = [row]
                    appended_existing = True

                info = body.get("result_info") or {}
                total_pages = int(info.get("total_pages") or 0)
                if truncated and not appended_existing:
                    break
                if not rows or (total_pages and page >= total_pages) or (not total_pages and len(rows) < 100):
                    break
                page += 1

        return DnsRecordListResult(
            records=[
                self._rows_to_info(display_name, rr_type, record_rows)
                for (display_name, rr_type), record_rows in grouped.items()
            ],
            truncated=truncated,
        )

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
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            response = client.request(method, path, params=params, json=json_body)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Cloudflare API request failed: {exc}") from exc

        try:
            body = response.json()
        except ValueError as exc:
            raise RuntimeError(f"Cloudflare API returned non-JSON response (HTTP {response.status_code}).") from exc

        if not isinstance(body, dict) or not body.get("success"):
            message = self._first_error_message(body) or f"HTTP {response.status_code}"
            raise RuntimeError(f"Cloudflare API error: {message}")
        return body

    @staticmethod
    def _first_error_message(body: Any) -> str | None:
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
    ) -> list[dict[str, Any]]:
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
        value: str,
        ttl: int,
    ) -> None:
        self._request(
            client,
            "POST",
            f"/zones/{zone_id}/dns_records",
            json_body=self._record_body(fqdn, record_type, value, ttl),
        )

    def _update_record(
        self,
        client: httpx.Client,
        zone_id: str,
        record_id: str,
        *,
        fqdn: str,
        record_type: str,
        value: str,
        ttl: int,
    ) -> None:
        self._request(
            client,
            "PUT",
            f"/zones/{zone_id}/dns_records/{record_id}",
            json_body=self._record_body(fqdn, record_type, value, ttl),
        )

    def _delete_record(self, client: httpx.Client, zone_id: str, record_id: str) -> None:
        self._request(client, "DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

    @staticmethod
    def _srv_parts(fqdn: str) -> tuple[str, str, str]:
        labels = fqdn.strip(".").split(".")
        if len(labels) >= 3 and labels[0].startswith("_") and labels[1].startswith("_"):
            return labels[0], labels[1], ".".join(labels[2:])
        return "_service", "_tcp", fqdn

    def _record_body(self, fqdn: str, record_type: str, value: str, ttl: int) -> dict[str, Any]:
        body: dict[str, Any] = {
            "type": record_type,
            "name": fqdn,
            "ttl": ttl,
        }
        if record_type == "TXT":
            body["content"] = _cloudflare_txt_content(value)
        elif record_type == "MX":
            priority, exchange = parse_mx(value)
            body["content"] = exchange
            body["priority"] = priority
        elif record_type == "SRV":
            priority, weight, port, target = parse_srv(value)
            service, proto, name = self._srv_parts(fqdn)
            body["data"] = {
                "priority": priority,
                "weight": weight,
                "port": port,
                "target": target,
                "service": service,
                "proto": proto,
                "name": name,
            }
        elif record_type == "CAA":
            flags, tag, caa_value = parse_caa(value)
            if caa_value.startswith('"') and caa_value.endswith('"') and len(caa_value) >= 2:
                caa_value = caa_value[1:-1]
            body["data"] = {"flags": flags, "tag": tag, "value": caa_value}
        else:
            body["content"] = value

        if record_type in {"A", "AAAA", "CNAME"}:
            body["proxied"] = self._proxied
        return body

    def _sync_records(
        self,
        client: httpx.Client,
        *,
        zone_id: str,
        fqdn: str,
        record_type: str,
        ttl: int,
        desired_values: list[str],
        existing: list[dict[str, Any]],
    ) -> None:
        if record_type == "CNAME":
            content = desired_values[0]
            if existing:
                first = existing[0]
                self._update_record(
                    client,
                    zone_id,
                    str(first["id"]),
                    fqdn=fqdn,
                    record_type=record_type,
                    value=content,
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
                    value=content,
                    ttl=ttl,
                )
            return

        desired_set = set(desired_values)
        existing_by_content: dict[str, dict[str, Any]] = {}
        stale: list[dict[str, Any]] = []
        for row in existing:
            content = _canonical_from_row(record_type, row)
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
                    value=content,
                    ttl=ttl,
                )
            else:
                self._create_record(
                    client,
                    zone_id,
                    fqdn=fqdn,
                    record_type=record_type,
                    value=content,
                    ttl=ttl,
                )

    @staticmethod
    def _rows_to_info(display_name: str, record_type: str, rows: list[dict[str, Any]]) -> DnsRecordInfo:
        ttls = [int(row["ttl"]) for row in rows if isinstance(row.get("ttl"), (int, float))]
        ttl = min(ttls) if ttls else None
        values = [_canonical_from_row(record_type, row) for row in rows]
        return DnsRecordInfo(
            record_name=display_name,
            record_type=record_type,
            ttl=ttl,
            values=values,
        )


def create_client(settings: dict[str, str | None]) -> CloudflareDnsClient:
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
        DNS_ZONE_DOMAIN_FIELD,
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
