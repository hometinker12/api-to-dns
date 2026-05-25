# Changelog

## [Unreleased]

### Added

- **`dns_zone`** on public API responses: the provider DNS zone domain (e.g. `example.com`) is returned alongside **`zone_name`** (the zone configuration identifier used in requests).
  - `GET /zones` (`DnsZoneSummary`): `id`, `zone_name`, `dns_zone`
  - `GET /dns-record` (`DnsRecordGetResponse`): `dns_zone` at the response envelope (not inside each `records[]` item)
  - `POST` / `PUT` / `PATCH` / `DELETE /dns-record` (`DnsRecordResponse`): `dns_zone` on success and error bodies (409, 404)
- Request bodies for `/dns-record` mutations are unchanged; clients still send **`zone_name`** only. `dns_zone` is derived server-side from the zone configuration.
- **DNS zone (domain)** field on each DNS provider plugin (Azure, BIND, Microsoft, Cloudflare), stored in zone configuration. The unique **zone configuration name** and API `zone_name` are separate from the provider domain, so multiple configurations can target the same DNS zone with different providers.
- SSL Certificate page audit logging: all certificate and Let's Encrypt actions emit `system.ssl_*` activity events at WARNING level in the security category.
- RESTful `/dns-record` resource: `GET`, `POST` (create), `PUT` (full replace), `PATCH` (partial update with merge), and `DELETE` (remove) on a single path.
- Pre-flight `get_record` existence check on every mutation. `POST` returns **409** `record_already_exists` when the record type already exists; `PUT`/`PATCH`/`DELETE` return **404** `not_found` when the record type is missing.
- Public Pydantic request schemas (`DnsRecordCreateRequest`, `DnsRecordReplaceRequest`, `DnsRecordPatchRequest`) documented in OpenAPI; `DELETE` uses query parameters (`zone_name`, `record_name`, `record_type`).
- New activity event `dns.record_already_exists` emitted on 409 conflicts; existing `dns.record_not_found` event now fires on 404 across `PUT`/`PATCH`/`DELETE`.
- `GET /dns-record` returns a `records` array; each found record includes `record_name`, `record_type`, `ttl`, and `values` when available from the provider.

### Changed

- DNS zone delete and API key revoke use restart-style confirmation dialogs with contextual details (API keys per zone / Let's Encrypt warning; zones per key / last used).
- API key “last used” on the revoke dialog now includes successful DNS lookups that return no matching record (`dns.record_lookup` with status `not_found`), not only mutations and lookups that found records.
- `GET /zones` with an API key now emits a `dns.zones_list` activity event so zone listing counts toward last used.
- Deleting a DNS zone configuration that Let's Encrypt references clears the DNS challenge zone (manual), disables auto-renew when it was enabled, and cancels in-progress enrollment for that zone.
- DNS activity log **message** text for record lookups and mutations now references the provider **`dns_zone`** (e.g. `www.example.com`) instead of the configuration **`zone_name`**. The logged **`zone_name`** attribute on DNS events is unchanged and still stores the configuration identifier; the Activity Log UI column label is **Zone Name**.
- Admin dashboard DNS zone list shows each configuration as `zone_name` (`dns_zone`).
- Let's Encrypt enrollment: Root DNS Domain is decoupled from the zone configuration name; DNS-01 automation uses the provider `dns_zone`, and the admin form auto-fills the root domain from the selected API zone.
- Let's Encrypt auto-renew cannot stay enabled with Manual DNS; saving manual DNS disables it (including manual enrollment start).
- HTTP-01 enrollment pauses for manual validation with continue-enrollment instructions (including all HTTP challenge URLs in the banner).
- Let's Encrypt HTTP-01 errors when the ACME server does not offer HTTP for a domain now note that DNS challenge must be used (e.g. after prior DNS-01 validation).
- HTTP-01 Let's Encrypt enrollment defaults automatic renewal to off; success messaging and the SSL settings page note internet reachability and HTTPS redirect requirements for HTTP auto-renew.
- `DELETE` requests now use the HTTP `DELETE` verb with query parameters instead of a JSON body.
- `PUT` requires `ttl`; `PATCH` accepts optional `ttl` and/or `values` and merges omitted fields from the live record.

### Removed

- **Breaking:** the legacy `POST /dns-record` upsert that created-or-updated based on existence.
- **Breaking:** the public `record_type: "DELETE"` pseudo-type (with the inner type in `values[0]`) on `POST /dns-record`. The internal `DnsRecordRequest` schema is no longer exposed in OpenAPI; plugins continue to use it unchanged.

## [0.3.4] - 2026-05-17

### Added

- Role-based access control for user, API key, DNS zone, plugin, and system management areas, including a `global.admin` role that grants all permissions and protects global administrator accounts from lower-privileged account actions.
- A dedicated Settings page with Authentication, Plugin Management, Log Viewing / Searching, and System Backup areas, including self-service password changes and administrator-driven user management.
- Account disable/enable workflow that requires accounts to be disabled before deletion and blocks disabled users from signing in or continuing active sessions.
- Five-minute sliding idle timeout for session cookies, with automatic renewal during authenticated web activity.
- Dynamic DNS provider plugin architecture under `src/plugins/`, with metadata-driven zone forms for Azure DNS, BIND/TSIG, and Microsoft DNS over WinRM.
- Plugin management controls that display discovered providers, allow enabled/disabled state management, and prevent disabling providers still used by configured zones.
- Persistent Docker Compose data volume mapping for `/app/data`.

### Changed

- The admin dashboard now role-gates DNS zone and API key navigation, showing disabled buttons when a user lacks access.
- DNS zone creation and editing now render provider-specific fields from plugin metadata and hide disabled providers from selection.
- API key management and DNS zone management have refreshed modal, table, button, and navigation behavior for a more consistent web UI.
- `/zones` supports API-key-authenticated JSON responses while retaining session-backed HTML rendering for browser requests.
- API key creation, editing, and revocation are restricted to the session-protected web interface and hidden from the OpenAPI surface.
- DNS record requests no longer accept Azure subscription ID or resource group in the request body; those values are stored with the zone configuration.
- Session-backed web pages are excluded from OpenAPI documentation, while `/keycheck` documents both success and failure responses.

## [0.3.1] - 2026-05-17

### Added

- JSON-capable `GET /zones` API that returns the zone IDs and names available to the supplied API key.
- OpenAPI documentation for `GET /keycheck` success and failure responses.

### Changed

- DNS zone management now aligns with the API route naming under `/zones`; legacy `/settings` and `/dns-zones` routes were removed instead of forwarded.
- Azure DNS subscription ID and resource group are configured only on the saved zone, not supplied in `POST /dns-record` request bodies.
- The public OpenAPI surface is limited to API-backed routes (`/keycheck`, `GET /zones`, and `/dns-record`); session-backed web pages and API key management routes are hidden from API docs.
- API keys are managed only through the session-protected web UI; JSON/API callers cannot create, edit, or revoke keys.
- Admin UI styling, navigation, modal API key forms, zone forms, table layout, and button treatments were refreshed for a more consistent web experience.

## [0.3.0] - 2026-05-10

### Added

- **Multiple DNS zones**: each zone name is unique; each row stores its own provider type, connection, and encrypted credentials (`DnsZoneConfig`).
- **API key zone permissions**: `ApiKeyAllowedZone` links keys to allowed zones; create key requires at least one zone; **Edit** on an API key updates label and allowed zones.
- **`POST /dns-record` authorization**: `zone_name` is always required; must match a configured zone **and** be allowed for the API key; otherwise **403** with `detail.error` **`access_denied`** (same message whether the zone is unknown or the key lacks permission).

### Changed

- Replaced single **DNS Settings** form with **DNS zones** list (`/zones`), **Add zone** (`/zones/new`), **Edit zone** (`/zones/{id}/edit`), and **Delete zone**.
- Startup **migration**: if legacy flat `Setting` DNS keys exist and no zones exist yet, one zone row is created and **all active API keys** are granted access to it; legacy settings rows are removed.

### Removed

- Global single-zone DNS settings form (replaced by per-zone configuration).

## [0.2.0] - 2026-05-09

### Added

- DNS provider choice in admin **DNS Settings**: **Azure DNS**, **on-premises Microsoft DNS (WinRM)**, and **BIND** (RFC 2136 dynamic updates with **TSIG**)
- Azure service principal and optional default **subscription** / **resource group** stored encrypted in the database (configured in the UI, not via `AZURE_*` environment variables)
- **`DELETE`** support on `POST /dns-record`: set `record_type` to `DELETE` and put the RR type to remove (`A`, `AAAA`, `CNAME`, or `TXT`) in `values[0]`
- Structured API errors: `HTTPException` responses with a `detail` object (`invalid_request`, `dns_provider_failed`, `dependency_unavailable`, `unexpected`) and HTTP **400** / **502** / **503** / **500** as appropriate instead of a single generic **500** for all failures
- **DELETE** when no matching record: HTTP **404** with `status: "error"` and `action: "not_found"`; successful delete returns **200** with `status: "success"` and `action: "deleted"`
- Dependencies: **dnspython**, **pywinrm**
- Tests: `tests/conftest.py` for isolated SQLite; expanded `tests/test_app.py` (auth, mocked upsert, DELETE not found, provider `RuntimeError` → **502**)

### Changed

- **`.env.example`**: removed optional `AZURE_*` variables; Azure is configured only through **DNS Settings**
- **`README.md`**: environment documentation, **curl** examples for create, update, and delete, response and error behavior, PowerShell note for **404** on DELETE
- **`src/dns_client.py`**: Azure uses `ClientSecretCredential` from settings; BIND TSIG updates; Microsoft WinRM + DnsServer PowerShell for A, AAAA, CNAME, TXT; explicit **`-ComputerName`** / **`-ZoneName`** on `Remove-DnsServerResourceRecord` when piping from `Get-DnsServerResourceRecord`; TXT RR type normalized for PowerShell (`Txt`); upsert behavior for Microsoft (remove then add) and BIND (`replace`)

### Fixed

- WinRM pipeline errors when removing existing records (`Remove-DnsServerResourceRecord` missing mandatory **ZoneName** / **ComputerName** on some DnsServer module versions)

## [0.1.0] - Initial Release

### Added

- Protected admin UI for login and settings management
- API key generation and revocation
- Encrypted storage for DNS server, zone, and Microsoft DNS credentials
- REST endpoint for creating or updating Microsoft DNS records
- Docker Compose deployment support
