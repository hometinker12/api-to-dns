# DNS REST Service

[![License: MIT + Commons Clause](https://img.shields.io/badge/License-MIT%20+%20Commons%20Clause-orange)](LICENSE.md)
 [Docker](https://www.docker.com/) [Python](https://www.python.org/) [Release](VERSION) [AI Assisted](https://cursor.com)

Current release: `0.3.4`

A Dockerized FastAPI service to manage DNS records through a protected admin web UI and secure API key authentication. Supported backends are **Azure DNS**, **Cloudflare DNS** (API v4), **on-premises Microsoft DNS (WinRM)**, and **BIND** (or other servers) using **RFC 2136 dynamic updates with TSIG**.

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

Open the admin UI at:

```
http://localhost:8000/login
```

After login, open **DNS zones** to add one row per zone (each row is a unique zone name with its own provider and credentials). Then open **API Keys**: when you create or edit a key, select which zones that key may use. Every `/dns-record` request requires a `zone_name` (in the JSON body for `POST`/`PUT`/`PATCH`, in the query string for `GET`/`DELETE`); it must match a configured zone **and** be allowed for that API key, or the API returns **403** with `error: access_denied`.

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


**Azure DNS** (per zone): tenant ID, client ID, client secret, and optional default subscription and resource group are stored on that zone’s row in **DNS zones** (encrypted). They are **not** read from `AZURE_`* environment variables.

**Cloudflare DNS** (per zone): scoped **API token** (Zone → DNS → Read **and** Edit on the target zone), an optional zone ID (skips the zone name lookup when set), and an optional **Proxied** checkbox (orange-cloud on created or updated A, AAAA, and CNAME records) are stored on that zone’s row in **DNS zones** (encrypted). Cloudflare ignores the **Target DNS Server** and TSIG settings.

### Generating the ENCRYPTION_KEY

The `ENCRYPTION_KEY` must be a 32-byte URL-safe base64-encoded key for Fernet encryption. You can generate one using Python:

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

**Important:** Never use the placeholder value `change-me-before-production` in production. Always generate a unique key for each deployment.

## Admin UI

The web interface allows you to:

- Sign in with admin credentials
- Add and edit **DNS zones** (each zone name is unique; each has its own provider type, server, and credentials). Use the **Test Configuration** button on a zone form to verify credentials and zone access by looking up a known record before saving.
- Create and revoke **API keys**, and **edit** keys to change their label or **allowed zones**
- Review and search activity logs under **Settings → Log Viewing / Searching**
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

### Planned Infrastructure Settings

**System Settings** includes placeholders for syslog forwarding and SSL certificate management. Syslog host, port, protocol, facility, and minimum level are planned but not implemented yet. Certificate upload, private key upload, chain management, expiration display, and reload/renewal actions are also planned for a later release.

### Logging Security

The app redacts secret-looking detail fields before storing activity logs or sending alert emails. It logs API key IDs, labels, and short SHA-256 fingerprints rather than full API key values. Request bodies are not stored by default, and DNS provider credentials remain encrypted at rest in configuration rows.

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

`**zone_name` is required** on every request and must match a zone you configured under **DNS zones**. The API key must include that zone in its **allowed zones** list (see **API Keys** in the admin UI). If the zone is missing or the key is not allowed, the response is **403** with `{"detail":{"error":"access_denied","message":"..."}}`.

### Create a new A record (`POST`)

Save the Azure **subscription ID** and **resource group** on the zone configuration when using Azure. Requests only include the DNS operation fields. The same body shape works for Azure, Microsoft (WinRM), and BIND/TSIG.

```bash
curl -sS -X POST "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "example.com",
    "record_type": "A",
    "record_name": "www",
    "ttl": 300,
    "values": ["192.0.2.10"]
  }'
```

PowerShell:

```powershell
$body = @{
  zone_name   = "example.com"
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
{"status":"error","action":"record_already_exists","zone_name":"example.com","record_name":"www","record_type":"A","values":["192.0.2.10"]}
```

### Replace an existing record (`PUT`)

Use `PUT` to replace the entire record (type, TTL, and values). `ttl` is required on `PUT`.

```bash
curl -sS -X PUT "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "example.com",
    "record_type": "A",
    "record_name": "www",
    "ttl": 600,
    "values": ["192.0.2.20"]
  }'
```

PowerShell:

```powershell
$body = @{
  zone_name   = "example.com"
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
{"status":"error","action":"not_found","zone_name":"example.com","record_name":"www","record_type":"A","values":["192.0.2.20"]}
```

### Partial update (`PATCH`)

Use `PATCH` to update `**ttl**`, `**values**`, or **both** on an existing record. At least one field is required. Omitted fields are merged from the live record (the API fetches the current record before applying the change).

Update values only (TTL preserved):

```bash
curl -sS -X PATCH "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "example.com",
    "record_type": "A",
    "record_name": "www",
    "values": ["192.0.2.30"]
  }'
```

PowerShell:

```powershell
$body = @{
  zone_name   = "example.com"
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
    "zone_name": "example.com",
    "record_type": "A",
    "record_name": "www",
    "ttl": 600
  }'
```

PowerShell:

```powershell
$body = @{
  zone_name   = "example.com"
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
  "http://localhost:8000/dns-record?zone_name=example.com&record_name=www&record_type=A" \
  -H "X-API-Key: YOUR_API_KEY"
```

PowerShell:

```powershell
Invoke-RestMethod -Method DELETE `
  "http://localhost:8000/dns-record?zone_name=example.com&record_name=www&record_type=A" `
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
  "zone_name": "example.com",
  "record_name": "@",
  "records": [
    {"record_name": "@", "record_type": "A", "ttl": 500, "values": ["10.0.0.1"]},
    {"record_name": "@", "record_type": "CNAME", "ttl": 1000, "values": ["target.example.com"]}
  ]
}
```

```bash
curl -sS \
  "http://localhost:8000/dns-record?zone_name=example.com&record_name=www&record_type=A" \
  -H "X-API-Key: YOUR_API_KEY"
```

PowerShell:

```powershell
Invoke-RestMethod -Method GET `
  "http://localhost:8000/dns-record?zone_name=example.com&record_name=www&record_type=A" `
  -Headers @{ "X-API-Key" = $apiKey }
```

## License

This project is licensed under the **MIT License with the Commons Clause**. The full license text is in [LICENSE.md](LICENSE.md).