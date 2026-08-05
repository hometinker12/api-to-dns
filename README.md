# DNS REST Service

[![License: MIT + Commons Clause](https://img.shields.io/badge/License-MIT%20+%20Commons%20Clause-orange)](LICENSE.md) [![Release](https://img.shields.io/badge/release-0.7.0-blue)](VERSION) [![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/) [![Python](https://img.shields.io/badge/python-3.12-green)](https://www.python.org/) [![AI Assisted](https://img.shields.io/badge/AI%20Assisted-yes-blue)](https://cursor.com)


A Dockerized FastAPI service to manage DNS records through a protected admin web UI and secure API key authentication.

## Table of Contents

- [Supported Backend DNS Providers](#supported-backend-dns-providers)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Quick start](#quick-start)
- [Configuration](#configuration)
  - [Generating the ENCRYPTION_KEY](#generating-the-encryption_key)
- [Admin UI](#admin-ui)
- [Activity Logs, Operational Logs, And Alerts](#activity-logs-operational-logs-and-alerts)
  - [Logging Level And Retention](#logging-level-and-retention)
  - [Email Alerting](#email-alerting)
  - [Planned Infrastructure Settings](#planned-infrastructure-settings)
  - [Optional: HTTPS with self-signed or uploaded certificates](#optional-https-with-self-signed-or-uploaded-certificates)
  - [Local development (HTTP or HTTPS)](#local-development-http-or-https)
  - [Logging Security](#logging-security)
- [API Usage](#api-usage)
  - [Create a new A record (`POST`)](#create-a-new-a-record-post)
  - [Replace an existing record (`PUT`)](#replace-an-existing-record-put)
  - [Partial update (`PATCH`)](#partial-update-patch)
  - [Delete a record (`DELETE`)](#delete-a-record-delete)
  - [Look up records (`GET`)](#look-up-records-get)
- [Publishing a release](#publishing-a-release)
- [License](#license)

## Supported Backend DNS Providers
- **Azure DNS**
- **Cloudflare DNS** (API v4)
- **Microsoft DNS (WinRM)**
- **BIND** (or other servers) using **RFC 2136 dynamic updates with TSIG**.

## Features

- Protected admin interface with username/password login
- Generate and revoke API keys for REST access
- Choose DNS provider (**Azure**, **Cloudflare**, **Microsoft / WinRM**, **BIND / TSIG**) **per zone** and store connection details and credentials **encrypted at rest**
- RESTful `/dns-record` resource with `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` methods
- Pre-flight existence checks return **409** on create-conflict and **404** on missing-record updates/deletes
- Structured JSON errors (for example **502** when the DNS provider fails)
- Searchable database-backed activity logs for sign-ins, API key changes, DNS record activity, provider failures, and alert events
- Email alert rules for matching stored activity events, with SMTP failover across an ordered server list
- Docker Compose-ready deployment

## Getting Started

### Prerequisites

- Docker
- Docker Compose
- Optional: Python 3.12 for local development

### Quick start

```bash
cp .env.example .env
# edit .env and set required values

docker compose up --build
```

> On Windows PowerShell, use `Copy-Item .env.example .env` instead of `cp`.

Open the admin UI at (Compose publishes HTTP on host port **8001** by default):

```
http://127.0.0.1:8001/login
```

> SSL is **off by default**; the container listens on plain HTTP on port `8000` (mapped to host `127.0.0.1:8001`). See **Optional: HTTPS with self-signed or uploaded certificates** below for the enable workflow.
>
> The image runs as non-root uid/gid **10001**. Compose pins `hometinker12/api-to-dns:0.7.0`, enables `read_only`, drops capabilities, and binds published ports to localhost. If you upgrade from a root-owned named volume, fix ownership once (do not start the app as root):
>
> ```bash
> docker run --rm -v api-to-dns_api-to-dns-data:/vol alpine chown -R 10001:10001 /vol
> docker run --rm -v api-to-dns_api-to-dns-ssl:/vol alpine chown -R 10001:10001 /vol
> docker run --rm -v api-to-dns_api-to-dns-logs:/vol alpine chown -R 10001:10001 /vol
> ```

After login, open **DNS zones** to add one row per zone configuration (each row has a **unique configuration name**, its own provider, a **DNS zone (domain)** for that provider, and credentials). You can add multiple configurations with different names that all target the same DNS domain (for example `example-azure` and `example-cloudflare`, both with domain `example.com`). Then open **API Keys**: when you create or edit a key, select which configurations that key may use. Every `/dns-record` request requires a `zone_name` (in the JSON body for `POST`/`PUT`/`PATCH`, in the query string for `GET`/`DELETE`); it must match a configured zone **name** **and** be allowed for that API key, or the API returns **403** with `error: access_denied`. The `zone_name` on API requests is the configuration name, not the provider DNS domain.

## Configuration

Create a `.env` file using `.env.example` and configure the following values:


| Variable         | Description                                                                                       |
| ---------------- | ------------------------------------------------------------------------------------------------- |
| `SECRET_KEY`     | Session signing secret (use a random string)                                                      |
| `ENCRYPTION_KEY` | Key for encrypting settings in the database (must be a valid Fernet key)                          |
| `ADMIN_USER`     | Initial admin username                                                                            |
| `ADMIN_PASSWORD` | Initial admin password                                                                            |
| `DATABASE_URL`   | Optional database URL (default: `sqlite:///./data/app.db`)                                        |
| `LOG_FILE`       | Optional file path for rotating operational logs (Docker Compose sets `/app/logs/api-to-dns.log`) |
| `APP_SSL_DIR`    | Directory holding `server.key` / `server.crt` (default `/app/data/ssl` in Docker, `./data/ssl` locally). Do not use `SSL_CERT_DIR` — OpenSSL uses that name for CA lookup and breaks outbound HTTPS. |
| `HTTP_PORT`      | Listener port when SSL is disabled (default `8000`)                                               |
| `TLS_PORT`       | Listener port when SSL is enabled (default `8443`)                                                |
| `SSL_ENABLED`    | Optional override of the DB `ssl_enabled` toggle (`0`/`1`); used by tests and local dev           |
| `SESSION_COOKIE_SECURE` | Optional force Secure cookies (`1`/`0`); when unset, follows HTTPS / trusted proxy / in-app SSL |
| `TRUST_PROXY_HEADERS` | When `1`, honor `X-Forwarded-Proto=https` for Secure cookies (only behind a trusted proxy) |
| `OPENAPI_ENABLED` | When `1`, expose `/openapi.json`, `/docs`, and `/redoc` (default off) |
| `DEBUG_ERRORS` | When `1`, include exception tracebacks in HTML error pages (dev only) |
| `CORS_ORIGINS` | Comma-separated browser origins; empty disables cross-origin browser access |


### Generating the ENCRYPTION_KEY

The `ENCRYPTION_KEY` must be a 32-byte URL-safe base64-encoded key for Fernet encryption. Generate one with Python or PowerShell and set it in your `.env` file.

**Python (Linux, macOS, or Windows):**

```bash
# Using Python
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Or using Python in a script
python3 -c "
from cryptography.fernet import Fernet
key = Fernet.generate_key().decode()
print(f'ENCRYPTION_KEY={key}')
"
```

On Windows, use `python` instead of `python3` if that is how Python is installed.

**PowerShell (native, no Python required):**

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$key = [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_')
Write-Output "ENCRYPTION_KEY=$key"
```
**Important:** Never use the placeholder value `change-me-before-production` in production. The application **refuses to start** when `ENCRYPTION_KEY` or `SECRET_KEY` is missing or set to a known placeholder (unless `API_TO_DNS_ALLOW_INSECURE_DEFAULTS=1` for local tests). Always generate a unique key for each deployment. If you change `ENCRYPTION_KEY` after data is stored, existing encrypted credentials in the database cannot be decrypted.

## Admin UI

The web interface allows you to:

- Sign in with admin credentials
- Add and edit **DNS zones** (each configuration name is unique; each has its own provider type, DNS domain, server, and credentials). Use the **Test Configuration** button on a zone form to verify credentials and zone access by looking up a known record before saving.
- Create and revoke **API keys**, and **edit** keys to change their label or **allowed zones**
- Review and search activity logs under **Settings → Log Viewing / Searching**
- Export and restore configuration under **Settings → Backup** (global admin only): password-encrypted archives (default) include settings, users, DNS zones, API key hashes, alert rules, SSL files, and `SECRET_KEY` / `ENCRYPTION_KEY`. Audit logs are optional. Restore is destructive for selected categories and shows an inline progress dialog; restoring application secrets writes durable secrets and restarts the app.
- Configure logging level, retention, SMTP delivery, and operational log rotation under **Settings → System Settings**
- Create email alert rules under **Settings → Email Alerting**

## Activity Logs, Operational Logs, And Alerts

The app uses two separate logging paths:

- **Activity logs** are database rows intended for admin review, filtering, retention cleanup, and email alerting. They capture audit events such as login success/failure, logout, API key create/update/revoke, DNS zone changes, plugin enable/disable, user management changes, DNS record create/update/delete/not-found events, invalid requests, access denied events, DNS provider failures, and alert delivery success/failure.
- **Operational logs** are Python/Docker runtime diagnostics intended for container and process troubleshooting. Docker Compose rotates stdout/stderr with the `json-file` driver (`max-size: 10m`, `max-file: 5`). When `LOG_FILE` is configured, the Python logger also writes to a rotating file handler; the provided Compose file stores that file under a separate `api-to-dns-logs` volume mounted at `/app/logs`.

### Logging Level And Retention

The activity logging level is configured under **System Settings**:

- `verbose` stores page requests/API calls as `http.request`, informational events, warning events, and error events.
- `informational` stores informational, warning, and error events, but excludes verbose request noise.
- `warning` stores warning and error events only.
- `error` stores error events only.

Security-category activity is always stored regardless of the selected level. This includes `auth.*`, `api_key.*`, and `user.*` events. DNS API outcomes such as `dns.record_created` use the `dns` category. All other events derive their category from the event type prefix (for example `plugin.disabled` → `plugin`, `http.request` → `http`, `dns_zone.created` → `dns_zone`). In **Log Viewing / Searching**, the text search field is shown by default; level, category, event type, status, zone, actor, and date range live under **Advanced Search**.

Activity log retention is configured under **System Settings** with presets such as 24 hours, 1 week, 30 days, 60 days, 90 days, 180 days, and 365 days. Cleanup runs at startup and opportunistically during activity logging, at most once per day. This is retention cleanup for database rows, not file rotation.

### Email Alerting

Alert rules match stored activity events by event type, category, minimum level, optional text search, recipients, and cooldown. Alert subjects and bodies can use placeholders such as `{event_type}`, `{level}`, `{category}`, `{timestamp}`, `{message}`, `{status}`, `{actor_type}`, `{actor_label}`, `{zone_name}`, `{record_name}`, `{details}`, `{system_dns_name}`, and `{system_ip_address}`.

SMTP delivery settings live under **System Settings**. The SMTP server field accepts an ordered CSV list such as `smtp1.example.com,192.0.2.25,smtp-backup.example.com`; delivery tries each server in order until one succeeds. Anonymous SMTP skips authentication. Successful delivery writes an informational `alert.email_sent` event. If delivery fails for every server, the app writes an `alert.email_failed` activity event without blocking the original action.

### Optional: HTTPS with self-signed, uploaded, or Let's Encrypt certificates

SSL is off by default. A fresh install serves HTTP on port `HTTP_PORT` (default `8000`) and does not create any cert files under `APP_SSL_DIR` until an admin opts in. Only one listener runs at a time — toggling SSL in the UI updates the database immediately but requires a restart of the application (container or `uvicorn` process) to swap listeners.

To enable HTTPS:

1. Sign in as an admin and open **Settings → System Settings → SSL Certificate**.
2. Choose one of:
   - **Upload Certificate** — provide an unencrypted PEM private key and a matching PEM certificate (concatenate any chain intermediates after the leaf certificate in the same file). The app validates the key/cert pair, rejects mismatched or expired material, and writes `server.key` / `server.crt` atomically into `APP_SSL_DIR`.
   - **Create self-signed certificate** — generate an RSA-2048 self-signed certificate (valid 825 days) using the configured App DNS Name as the Common Name and as a DNS SAN, plus `localhost`. Requires the `openssl` command on PATH (installed in the provided Dockerfile; install separately for local dev).
   - **Let's Encrypt** — enroll via **DNS-01** (automated TXT records through a configured DNS zone plugin, or manual TXT) or **HTTP-01** (serve tokens at `/.well-known/acme-challenge/`). Staging mode is available for dry runs. Auto-renew can be enabled for automated DNS-01 (and optionally HTTP-01 when the host is internet-reachable); renewal may schedule an application restart so the new certificate is loaded.
3. Tick **Enable HTTPS** and **Save**.
4. Restart the application:
   - Docker: `docker compose restart` (or `up -d` after rebuild).
   - Local: stop and re-run `python -m src.ssl_certs serve`.

Once restarted the app listens on `https://<app_dns_name>:TLS_PORT` (default `8443`). Self-signed certificates trigger browser warnings until the certificate is trusted on each client device. Disabling SSL does not delete the cert files on disk; the next enable + restart reuses them.

The Docker compose file ships a dedicated `api-to-dns-ssl` named volume mounted at `/app/data/ssl` so cert/key material is isolated from the SQLite data volume and can be backed up independently.

Liveness/readiness: `GET /health` and `GET /ready` (DB). The container healthcheck uses `/health`.

### Local development (HTTP or HTTPS)

For local runs outside Docker:

```bash
python -m src.ssl_certs serve
```

`serve` reads the persisted `ssl_enabled` toggle (and any `SSL_ENABLED` env override), then launches uvicorn on `HTTP_PORT` or `TLS_PORT` with the matching TLS flags. To force HTTP regardless of the DB setting (handy for tests and watch loops), set `SSL_ENABLED=0` in your environment.

Generating a self-signed certificate from the UI requires the `openssl` binary on PATH. On Windows install OpenSSL via [Win64 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html), Chocolatey (`choco install openssl`), or Git for Windows (often ships `openssl.exe`). On Linux/macOS use your distro package manager or Homebrew (`openssl` / `openssl@3`). PEM upload does not require the `openssl` CLI.

### Logging Security

The app redacts secret-looking detail fields before storing activity logs or sending alert emails. It logs API key IDs, labels, and short SHA-256 fingerprints rather than full API key values. **API keys themselves are stored as SHA-256 digests** (the raw key is shown only once at creation). Request bodies are not stored by default, and DNS provider credentials remain encrypted at rest in configuration rows.

## API Usage

Authenticate with `**X-API-Key: <key>`** or `**Authorization: Bearer <key>**`.

All examples target `http://localhost:8000/dns-record` with `Content-Type: application/json`.

`/dns-record` is a single REST resource. Each method has well-defined semantics:


| Method   | Scope            | Idempotent | Behavior                                                                                                                                 |
| -------- | ---------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `GET`    | Lookup           | yes        | Return which supported record types exist at a name.                                                                                     |
| `POST`   | Create           | no         | Create a new record. Returns **409** `record_already_exists` if a record of that type already exists.                                    |
| `PUT`    | Full replacement | yes        | Replace the record's type/TTL/values. Returns **404** `not_found` if the type does not exist.                                            |
| `PATCH`  | Partial update   | no         | Update `ttl` and/or `values`; omitted fields are preserved from the live record. Returns **404** `not_found` if the type does not exist. |
| `DELETE` | Remove           | yes        | Delete the record of the given type. Returns **404** `not_found` if the type does not exist.                                             |


`record_type` accepts `**A`**, `**AAAA**`, `**CNAME**`, or `**TXT**`. The legacy `POST` upsert and `record_type: "DELETE"` pseudo-payload have been removed.

**`zone_name` is required** on every request and must match a **zone configuration name** from **DNS zones** (for example `prod-azure`), **not** the provider DNS domain. Responses also include **`dns_zone`**, the provider domain (for example `example.com`). The API key must include that configuration in its **allowed zones** list (see **API Keys** in the admin UI). If the zone is missing or the key is not allowed, the response is **403** with `{"detail":{"error":"access_denied","message":"..."}}`.

### Create a new A record (`POST`)

Save the Azure **subscription ID** and **resource group** on the zone configuration when using Azure. Requests only include the DNS operation fields. The same body shape works for Azure, Microsoft (WinRM), Cloudflare, and BIND/TSIG.

```bash
curl -sS -X POST "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "prod-azure",
    "record_type": "A",
    "record_name": "www",
    "ttl": 300,
    "values": ["192.0.2.10"]
  }'
```

PowerShell:

```powershell
$body = @{
  zone_name   = "prod-azure"
  record_type = "A"
  record_name = "www"
  ttl         = 300
  values      = @("192.0.2.10")
} | ConvertTo-Json -Compress

Invoke-RestMethod -Method POST `
  "http://localhost:8000/dns-record" `
  -Headers @{ "X-API-Key" = $apiKey } `
  -ContentType "application/json" `
  -Body $body
```

If a record of that type already exists at the name, the response is **409**:

```json
{"status":"error","action":"record_already_exists","zone_name":"prod-azure","record_name":"www","record_type":"A","values":["192.0.2.10"]}
```

### Replace an existing record (`PUT`)

Use `PUT` to replace the entire record (type, TTL, and values). `ttl` is required on `PUT`.

```bash
curl -sS -X PUT "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "prod-azure",
    "record_type": "A",
    "record_name": "www",
    "ttl": 600,
    "values": ["192.0.2.20"]
  }'
```

PowerShell:

```powershell
$body = @{
  zone_name   = "prod-azure"
  record_type = "A"
  record_name = "www"
  ttl         = 600
  values      = @("192.0.2.20")
} | ConvertTo-Json -Compress

Invoke-RestMethod -Method PUT `
  "http://localhost:8000/dns-record" `
  -Headers @{ "X-API-Key" = $apiKey } `
  -ContentType "application/json" `
  -Body $body
```

If no record of that type exists at the name, the response is **404**:

```json
{"status":"error","action":"not_found","zone_name":"prod-azure","record_name":"www","record_type":"A","values":["192.0.2.20"]}
```

### Partial update (`PATCH`)

Use `PATCH` to update `**ttl**`, `**values**`, or **both** on an existing record. At least one field is required. Omitted fields are merged from the live record (the API fetches the current record before applying the change).

Update values only (TTL preserved):

```bash
curl -sS -X PATCH "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "prod-azure",
    "record_type": "A",
    "record_name": "www",
    "values": ["192.0.2.30"]
  }'
```

PowerShell:

```powershell
$body = @{
  zone_name   = "prod-azure"
  record_type = "A"
  record_name = "www"
  values      = @("192.0.2.30")
} | ConvertTo-Json -Compress

Invoke-RestMethod -Method PATCH `
  "http://localhost:8000/dns-record" `
  -Headers @{ "X-API-Key" = $apiKey } `
  -ContentType "application/json" `
  -Body $body
```

Update TTL only (values preserved):

```bash
curl -sS -X PATCH "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "prod-azure",
    "record_type": "A",
    "record_name": "www",
    "ttl": 600
  }'
```

PowerShell:

```powershell
$body = @{
  zone_name   = "prod-azure"
  record_type = "A"
  record_name = "www"
  ttl         = 600
} | ConvertTo-Json -Compress

Invoke-RestMethod -Method PATCH `
  "http://localhost:8000/dns-record" `
  -Headers @{ "X-API-Key" = $apiKey } `
  -ContentType "application/json" `
  -Body $body
```

`PATCH` returns **404** with the same body shape as `PUT` when the record does not exist.

### Delete a record (`DELETE`)

`DELETE` identifies the record via **query parameters** (the same shape as `GET /dns-record`). No JSON body is required.

```bash
curl -sS -X DELETE \
  "http://localhost:8000/dns-record?zone_name=prod-azure&record_name=www&record_type=A" \
  -H "X-API-Key: YOUR_API_KEY"
```

PowerShell:

```powershell
Invoke-RestMethod -Method DELETE `
  "http://localhost:8000/dns-record?zone_name=prod-azure&record_name=www&record_type=A" `
  -Headers @{ "X-API-Key" = $apiKey }
```

If nothing matches, the response is **404** `not_found`.

### Look up records (`GET`)

`GET /dns-record` always returns a `**records` array**. Each element describes one supported record type present at the name. When records exist, every element includes `record_name`, `record_type`, and `ttl`; `values` is included when the provider returns rdata.

Optional `record_type` query parameter filters which types appear in the array; it does not change the per-item shape. When nothing matches, `status` is `not_found` and `records` is `[]`.

Example response when `@` has both `A` and `CNAME` records:

```json
{
  "status": "success",
  "zone_name": "prod-azure",
  "record_name": "@",
  "records": [
    {"record_name": "@", "record_type": "A", "ttl": 500, "values": ["10.0.0.1"]},
    {"record_name": "@", "record_type": "CNAME", "ttl": 1000, "values": ["target.example.com"]}
  ]
}
```

```bash
curl -sS \
  "http://localhost:8000/dns-record?zone_name=prod-azure&record_name=www&record_type=A" \
  -H "X-API-Key: YOUR_API_KEY"
```

PowerShell:

```powershell
Invoke-RestMethod -Method GET `
  "http://localhost:8000/dns-record?zone_name=prod-azure&record_name=www&record_type=A" `
  -Headers @{ "X-API-Key" = $apiKey }
```

## Publishing a release

Promotion to production is a manual **`release` → `main`** pull request. Before merging:

1. Bump [`VERSION`](VERSION) (keep `pyproject.toml`, Dockerfile `ARG VERSION`, Compose image pin, README badge, and version tests in sync).
2. Cut a matching `## [X.Y.Z] - YYYY-MM-DD` section in [`CHANGELOG.md`](CHANGELOG.md) out of `[Unreleased]`.

Push to `main` runs [`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml): tests, container smoke, Docker Hub publish (`latest`, `${VERSION}`, `sha-*`), then a GitHub Release `v${VERSION}` when that tag does not already exist. Release notes are taken from the matching CHANGELOG section (or a short fallback naming the image and commit).

## License

This project is licensed under the **MIT License with the Commons Clause**. The full license text is in [LICENSE.md](LICENSE.md).
