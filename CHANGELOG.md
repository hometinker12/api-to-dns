# Changelog

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
