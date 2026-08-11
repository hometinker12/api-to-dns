# Changelog

## [Unreleased]

### Added

- BIND / TSIG DNS browser blank browse and `*` / `?` wildcard search via TSIG-signed zone transfer (AXFR). Requires `allow-transfer { key ...; };` on the BIND zone (see `BINDCONFIG.md`); refused transfers return HTTP 400 with that remediation. Exact-name lookup is unchanged. README, `BINDCONFIG.md`, and DNS browser help text updated for the AXFR requirement; unit and app tests cover browse, glob, truncation, and refused-transfer mapping.
- Operator guide [`BINDCONFIG.md`](BINDCONFIG.md): BIND/TSIG prerequisites for dynamic updates and optional AXFR browse (`allow-update` / `allow-transfer`, key setup, dig checks, troubleshooting).
- Release BIND smoke grants AXFR on `smoke.test` (browse/glob success + truncated browse after 100 RRsets), denies transfer on `denied.test` (browse/glob 400 + exact lookup still works), asserts favicon/logo-mark static SVG delivery on BIND and Microsoft smoke jobs, and covers API key access modes (default read-only mutations → `403 access_denied`, mode edit, backup/legacy restore).
- API keys now support `read_only` and `read_write` access modes in addition to zone restrictions. New keys default to read-only; existing keys and legacy backups retain read/write access. Read-only keys can validate, list allowed zones, and look up records, but DNS mutations return generic `403 access_denied`.

### Changed

- Admin UI favicon (`favicon.svg`) and logo mark (`logo-mark.svg`) redrawn as a higher-resolution 64×64 globe-and-routing SVG (replacing the earlier pulse-line mark) for clearer branding at favicon and header sizes.
- BIND browse/wildcard AXFR no longer materializes the full zone in memory: transfers stream RRsets, stop once the browse limit (or a 5000-RRset scan cap) is reached, close the TCP transfer early, and allow at most two concurrent AXFRs process-wide.

## [0.8.0] - 2026-08-07

### Added

- Admin **DNS browser**: open a zone from the Dashboard; filter by type (A/AAAA/CNAME/TXT/MX/NS/SRV/CAA/PTR/SOA); and add/edit/delete RRsets. Requires `dns_zones.update` for page, search, and mutations (links hidden without it). SOA is view-only; apex NS is blocked for `@` and the zone FQDN; PTR is limited to reverse zones. Rate-limited via `RATE_LIMIT_DNS_BROWSER` (default `60:60`; session identity, ignoring unvalidated API-key headers). Providers share canonical value formats via `src/dns_record_types.py`.
- DNS browser UX and search: configuration name under the page header; aligned Search/Add actions; IP Address labels with browser-side IPv4/IPv6 validation; submission locking/status; unified multi-value editor with red `X` removal; provider name in `<code>`. Cloudflare's zone-controlled **Proxied (orange cloud)** setting is shown for eligible A/AAAA/CNAME writes. Empty browse and case-insensitive relative-name `*`/`?` globs work for Cloudflare, Azure, and Microsoft DNS (capped at 100 complete RRsets with truncation status; Cloudflare pages at 100 rows; Microsoft streams/groups with optional `-RRType`). BIND / TSIG returns a clear exact-name-only message (no AXFR enumeration). Release smoke covers BIND blank-browse and wildcard `400` responses plus Microsoft browse, `*`, and `?` glob paths.
- **Remote Syslog** under **Settings → System Settings** (last entry): optional best-effort forwarding of stored audit/activity events as RFC 5424 messages with JSON payloads over TLS (preferred), UDP, or TCP. Plaintext UDP/TCP require an explicit insecure opt-in. Configurable host, port, protocol, facility, minimum level, timeout, and bounded queue size (max 5000). Delivery is asynchronous and non-durable; failures are rate-limited to operational logs. Saving settings emits `system.syslog_updated`.
- Release BIND/Docker smoke installs `rsyslog`, enables remote syslog via System Settings (UDP with plaintext opt-in), and asserts an end-to-end delivery of a forwarded audit event.
- Admin UI branding: SVG favicon and logo mark on pages (including login), brand wordmark above page titles, and a bottom-right version footer (`<code>api-to-dns vX.Y.Z</code>` linking to the GitHub repository).
- Admin UI dark mode: moon/sun toggle in the page header before API Keys, Dashboard, Settings, and Logout with preference stored in the browser; defaults to system color scheme when unset.

### Fixed

- Microsoft DNS browser browse/search no longer fails with WinRM "command line is too long": long PowerShell payloads are staged to a remote tempfile in short base64 chunks (EncodedCommand-safe), and browse grouping uses `ArrayList` instead of `Generic.List` under WinRM.

### Changed

- Application version metadata aligned to **0.8.0** (`VERSION`, OpenAPI, `pyproject.toml`, Docker label, Compose pin).
- The Dashboard is the single configured-zone management view. Browser `GET /zones` requests redirect to `/admin`, while the JSON `GET /zones` API and all zone-management routes remain available.
- Shared top navigation order is API Keys, Dashboard, Settings, Logout on every authenticated page; API Docs appears on the API Keys page next to Create API Key.
- Authentication role catalog labels wrap in `<code>`; `dns_zones.update` notes admin DNS browser access.
- API Keys page helper text focuses on generating named keys, scoping zones, and copying the key once at creation.

## [0.7.0] - 2026-08-05

### Added

- **Settings → Backup** (global admin): export/import configuration archives (`.atdb`). Outer password encryption is on by default; at-rest Fernet ciphertext is copied as-is with `SECRET_KEY` / `ENCRYPTION_KEY` so restores remain decryptable. Optional audit-log inclusion; destructive restore with Let's Encrypt–style progress dialog; application-secrets restore persists keys and auto-restarts.

### Security

- Bump `cryptography` to 50.0.0 (CVE-2026-69247, CVE-2026-69249).
- Restored `app_secrets.env` is never shell-sourced; the entrypoint exports only known keys via Python `shlex.quote`, and secret values are validated before durable write.
- Backup restore fully validates selected categories before any destructive wipe (including an enabled global admin + bounded password-hash PBKDF2 rounds); DB wipe/restore is one transaction; user restores and secrets-only restores assign a fresh unpredictable `session_version` to block source-session cookie replay.
- Application secrets can only be exported/restored inside password-encrypted archives (blocks forging sessions from mutable plaintext backups).
- Encrypted backup PBKDF2 iterations are capped; decrypt/preflight runs off the event loop; backup uploads are size-limited.

### Changed

- Application version metadata aligned to **0.7.0** (`VERSION`, OpenAPI, `pyproject.toml`, Docker label, Compose pin).
- BIND/Docker smoke asserts persisted `app_secrets.env` overrides Compose `env_file` after restart (PID-1 secret hashes + stale session rejection).

## [0.6.3] - 2026-08-02

### Security

- Bump `cryptography` to 48.0.1 (GHSA-537c-gmf6-5ccf) and `python-multipart` to 0.0.30 (CVE-2026-53539).
- Release BIND/Docker smoke scans the built image with Trivy (High/Critical, same gate as Docker publish).

### Changed

- Application version metadata aligned to **0.6.3** (`VERSION`, OpenAPI, `pyproject.toml`, Docker label, Compose pin).

## [0.6.2] - 2026-08-02

### Security

- Account admins can no longer grant sensitive roles (`global.admin`, `account.*`, `api_keys.update`, `plugin.update`, `system.update`); only `global.admin` may assign those. Account admins may still grant `global.read`, `api_keys.read`, `dns_zones.read`, and `dns_zones.update`.
- Session cookies now carry a `session_version` that is bumped (and other sessions revoked) on password change/reset, disable, and role changes; self-password-change reissues the active browser cookie.
- Microsoft WinRM HTTPS validates TLS certificates by default; per-zone `dns_winrm_insecure_tls` opt-out required for lab/self-signed hosts.
- ACME account key (`acme_account.key`) is Fernet-encrypted at rest; legacy plaintext PEM is migrated atomically and corrupt/wrong-key files fail closed.
- Logout is POST-only; Secure cookie resolution supports `SESSION_COOKIE_SECURE` and trusted `X-Forwarded-Proto`; OpenAPI/docs default off (`OPENAPI_ENABLED`); security response headers and conditional HSTS added.
- CSRF and CORS no longer weaken when `API_TO_DNS_ALLOW_INSECURE_DEFAULTS=1`; use explicit `API_TO_DNS_RELAX_CSRF` only in the test harness. Tracebacks require `DEBUG_ERRORS=1`.
- Rate limits are SQLite-backed (shared across workers) and treat `Authorization: Bearer` like `X-API-Key`.
- SSL uploads are size-bounded; App DNS names are validated before OpenSSL; SMTP defaults to STARTTLS and blocks credentialed cleartext unless `smtp_allow_insecure_auth` is set; SMTP passwords are not rendered into the settings HTML context.
- Container runs as non-root uid/gid 10001 with pinned `python:3.12-slim` digest; Compose pins `hometinker12/api-to-dns:0.6.2`, `read_only`, `cap_drop: ALL`, `no-new-privileges`, localhost-bound ports, and `/tmp` tmpfs.
- Docker publish workflow adds Trivy High/Critical gates, BuildKit SBOM/provenance, and keyless Cosign signing; CI actions pinned to commit SHAs where practical. Pytest moved to `requirements-dev.txt`.

### Changed

- Application version metadata aligned to **0.6.2** (`VERSION`, OpenAPI, `pyproject.toml`, Docker label, Compose pin).
- Docker publish on `main` creates a GitHub Release (`v${VERSION}`) after a successful image publish when that tag does not already exist.

## [0.6.0] - 2026-07-27

### Added

- Fail-fast startup when `ENCRYPTION_KEY` / `SECRET_KEY` are missing or placeholder values (tests may set `API_TO_DNS_ALLOW_INSECURE_DEFAULTS=1`).
- API keys stored as SHA-256 digests with a short display prefix; raw key shown once at creation.
- Shared Let's Encrypt challenge provisioning so auto-renew publishes DNS/HTTP challenges before ACME finalize.
- Same-origin CSRF checks for browser POSTs; configurable `CORS_ORIGINS`; Secure session cookies when SSL is enabled; rate limits for `/login`, `/keycheck`, and `/dns-record`.
- `GET /health` and `GET /ready`; Docker healthcheck probes `/health`.
- DNS API routes extracted to `src/routes/` (and helpers to `src/dns_api_service.py`).

### Changed

- Application version metadata aligned to **0.6.0** (`VERSION`, OpenAPI, `pyproject.toml`, Docker label).
- Provider error messages sanitized for API clients; disabled DNS plugins blocked on the DNS API (503).
- Removed unfinished **System Backup** and **Syslog** settings placeholders from the admin nav (tracked for a future release).
- README documents Let's Encrypt and clarifies `zone_name` (configuration id) vs `dns_zone` (provider domain).
- Pinned `acme==5.7.0` and `josepy==2.2.0`.
- Docker Compose host HTTP mapping changed from `8000:8000` to `8001:8000`; `.env.example` clarifies `SSL_ENABLED`;


## [0.5.0] - 2026-05-26

### Added

- **Cloudflare DNS** provider plugin (API v4 token auth): A, AAAA, CNAME, and TXT records; optional zone ID; optional **Proxied** (orange cloud) for A/AAAA/CNAME.
- **Activity logging**: searchable database audit trail (auth, API keys, users, DNS zones, plugins, DNS API, alerts, SSL/Let's Encrypt); configurable level (`verbose` / `informational` / `warning` / `error`); security events always stored; retention presets with automatic cleanup.
- **Email alerting**: rules matched against activity events (type, category, level, text search, cooldown); SMTP with ordered server failover; placeholder tokens in subject/body; redaction of secrets in stored details and alert email.
- **System settings** sections: App DNS Name, SSL Certificate, SMTP Delivery, Logging Level, Audit Log Retention, Operational Log Rotation (syslog forwarding remains planned).
- **SSL/TLS for the admin app**: optional HTTPS via uploaded PEM key/cert or self-signed generation (`openssl`); cert storage under `APP_SSL_DIR`; HTTP (`HTTP_PORT`, default 8000) or HTTPS (`TLS_PORT`, default 8443); restart required to switch listeners; dedicated Docker volume for cert material.
- **Let's Encrypt**: DNS-01 (automated via configured zone plugins, including Cloudflare TXT) and HTTP-01; staging toggle; async enrollment with progress UI; auto-renew with configurable lead time and scheduled restart window; graceful shutdown hook for renewal restarts.
- **DNS zone (domain)** field on each DNS provider plugin (Azure, BIND, Microsoft, Cloudflare), stored in zone configuration. The unique **zone configuration name** and API `zone_name` are separate from the provider domain, so multiple configurations can target the same DNS zone with different providers.
- **`dns_zone`** on public API responses: the provider DNS zone domain (e.g. `example.com`) is returned alongside **`zone_name`** (the zone configuration identifier used in requests).
  - `GET /zones` (`DnsZoneSummary`): `id`, `zone_name`, `dns_zone`
  - `GET /dns-record` (`DnsRecordGetResponse`): `dns_zone` at the response envelope (not inside each `records[]` item)
  - `POST` / `PUT` / `PATCH` / `DELETE /dns-record` (`DnsRecordResponse`): `dns_zone` on success and error bodies (409, 404)
- Request bodies for `/dns-record` mutations are unchanged; clients still send **`zone_name`** only. `dns_zone` is derived server-side from the zone configuration.
- SSL Certificate page audit logging: all certificate and Let's Encrypt actions emit `system.ssl_*` activity events at WARNING level in the security category.
- RESTful `/dns-record` resource: `GET`, `POST` (create), `PUT` (full replace), `PATCH` (partial update with merge), and `DELETE` (remove) on a single path.
- Pre-flight `get_record` existence check on every mutation. `POST` returns **409** `record_already_exists` when the record type already exists; `PUT`/`PATCH`/`DELETE` return **404** `not_found` when the record type is missing.
- Public Pydantic request schemas (`DnsRecordCreateRequest`, `DnsRecordReplaceRequest`, `DnsRecordPatchRequest`) documented in OpenAPI; `DELETE` uses query parameters (`zone_name`, `record_name`, `record_type`).
- New activity event `dns.record_already_exists` emitted on 409 conflicts; existing `dns.record_not_found` event now fires on 404 across `PUT`/`PATCH`/`DELETE`.
- `GET /dns-record` returns a `records` array; each found record includes `record_name`, `record_type`, `ttl`, and `values` when available from the provider.
- **Docker Compose**: container health check; persistent volumes for data, SSL certs, and operational logs; `DATABASE_URL` and `LOG_FILE` defaults; published port **8443** for TLS.

### Changed

- **Session idle timeout** extended from 5 minutes to **15 minutes** (sliding renewal on authenticated web activity).
- **Settings** areas: Log Viewing / Searching, Email Alerting, and structured System Settings subsections.
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
