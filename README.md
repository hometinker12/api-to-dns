# DNS REST Service

[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/) [![Python](https://img.shields.io/badge/python-3.12-green)](https://www.python.org/) [![Release](https://img.shields.io/badge/release-0.3.4-blue)](VERSION) [![AI Assisted](https://img.shields.io/badge/AI%20Assisted-yes-blue)](https://cursor.com)

Current release: `0.3.4`

A Dockerized FastAPI service to manage DNS records through a protected admin web UI and secure API key authentication. Supported backends are **Azure DNS**, **on-premises Microsoft DNS (WinRM)**, and **BIND** (or other servers) using **RFC 2136 dynamic updates with TSIG**.

## Features

- Protected admin interface with username/password login
- Generate and revoke API keys for REST access
- Choose DNS provider (**Azure**, **Microsoft / WinRM**, **BIND / TSIG**) **per zone** and store connection details and credentials **encrypted at rest**
- Create, update, or **delete** DNS records via `POST /dns-record`
- Structured JSON errors (for example **404** when a DELETE finds no record, **502** when the DNS provider fails)
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

After login, open **DNS zones** to add one row per zone (each row is a unique zone name with its own provider and credentials). Then open **API Keys**: when you create or edit a key, select which zones that key may use. **`POST /dns-record` always requires `zone_name`** in the JSON body; it must match a configured zone **and** be allowed for that API key, or the API returns **403** with `error: access_denied`.

## Configuration

Create a `.env` file using `.env.example` and configure the following values:

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Session signing secret (use a random string) |
| `ENCRYPTION_KEY` | Key for encrypting settings in the database (must be a valid Fernet key) |
| `ADMIN_USER` | Initial admin username |
| `ADMIN_PASSWORD` | Initial admin password |
| `DATABASE_URL` | Optional database URL (default: `sqlite:///./data/app.db`) |
| `LOG_FILE` | Optional file path for rotating operational logs (Docker Compose sets `/app/logs/api-to-dns.log`) |

**Azure DNS** (per zone): tenant ID, client ID, client secret, and optional default subscription and resource group are stored on that zone’s row in **DNS zones** (encrypted). They are **not** read from `AZURE_*` environment variables.

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
- Add and edit **DNS zones** (each zone name is unique; each has its own provider type, server, and credentials)
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

Security-category activity is always stored regardless of the selected level. This includes `auth.*`, `api_key.*`, `dns.record_*`, and `user.*` events. In **Log Viewing / Searching**, the text search field is shown by default; level, category, event type, status, zone, actor, and date range live under **Advanced Search**.

Activity log retention is configured under **System Settings** with presets such as 24 hours, 1 week, 30 days, 60 days, 90 days, 180 days, and 365 days. Cleanup runs at startup and opportunistically during activity logging, at most once per day. This is retention cleanup for database rows, not file rotation.

### Email Alerting

Alert rules match stored activity events by event type, category, minimum level, optional text search, recipients, and cooldown. Alert subjects and bodies can use placeholders such as `{event_type}`, `{level}`, `{category}`, `{timestamp}`, `{message}`, `{status}`, `{actor_type}`, `{actor_label}`, `{zone_name}`, `{record_name}`, `{details}`, `{system_dns_name}`, and `{system_ip_address}`.

SMTP delivery settings live under **System Settings**. The SMTP server field accepts an ordered CSV list such as `smtp1.example.com,192.0.2.25,smtp-backup.example.com`; delivery tries each server in order until one succeeds. Anonymous SMTP skips authentication. Successful delivery writes an informational `alert.email_sent` event. If delivery fails for every server, the app writes an `alert.email_failed` activity event without blocking the original action.

### Planned Infrastructure Settings

**System Settings** includes placeholders for syslog forwarding and SSL certificate management. Syslog host, port, protocol, facility, and minimum level are planned but not implemented yet. Certificate upload, private key upload, chain management, expiration display, and reload/renewal actions are also planned for a later release.

### Logging Security

The app redacts secret-looking detail fields before storing activity logs or sending alert emails. It logs API key IDs, labels, and short SHA-256 fingerprints rather than full API key values. Request bodies are not stored by default, and DNS provider credentials remain encrypted at rest in configuration rows.

## API Usage

Authenticate with **`X-API-Key: <key>`** or **`Authorization: Bearer <key>`**.

All examples use `POST http://localhost:8000/dns-record` with `Content-Type: application/json`.

**`zone_name` is required** on every request and must match a zone you configured under **DNS zones**. The API key must include that zone in its **allowed zones** list (see **API Keys** in the admin UI). If the zone is missing or the key is not allowed, the response is **403** with `{"detail":{"error":"access_denied","message":"..."}}`.

### Azure DNS: create a new A record

Save the Azure **subscription ID** and **resource group** on the zone configuration. Requests only include the DNS operation fields.

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

### Azure DNS: update an existing A record

The same endpoint performs an upsert. Send the same `record_name` and `record_type` with new `values` (and TTL if you want to change it):

```bash
curl -sS -X POST "http://localhost:8000/dns-record" \
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

### Microsoft DNS (WinRM): create and update an A record

For a zone such as `corp.example`, add a **DNS zones** row with zone name **`corp.example`**, set **Microsoft (WinRM)**, **Target DNS Server**, and credentials. Grant your API key access to that zone under **API Keys**.

Requests **do not** use `subscription_id` or `resource_group`. **`zone_name` in JSON must match** the configured zone (case-insensitive).

**Create** (first `A` for `api` in `corp.example`):

```bash
curl -sS -X POST "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "corp.example",
    "record_type": "A",
    "record_name": "api",
    "ttl": 300,
    "values": ["192.0.2.10"]
  }'
```

**Update** (same name and type, new addresses / TTL):

```bash
curl -sS -X POST "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "corp.example",
    "record_type": "A",
    "record_name": "api",
    "ttl": 600,
    "values": ["192.0.2.20"]
  }'
```

### BIND (TSIG): create and update an A record

Add a **DNS zones** row for the zone (for example **`example.com`**) with **BIND / TSIG**, **Target DNS Server**, TSIG key name, base64 secret, and optional algorithm. Grant the API key access to that zone.

**Create**:

```bash
curl -sS -X POST "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "example.com",
    "record_type": "A",
    "record_name": "dyn",
    "ttl": 300,
    "values": ["192.0.2.10"]
  }'
```

**Update**:

```bash
curl -sS -X POST "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "example.com",
    "record_type": "A",
    "record_name": "dyn",
    "ttl": 600,
    "values": ["192.0.2.30"]
  }'
```

### Delete a record (all providers)

Use **`record_type": "DELETE"`**. The first entry in **`values`** must be the DNS RR type to remove: **`A`**, **`AAAA`**, **`CNAME`**, or **`TXT`**.

**Microsoft / BIND** — include **`zone_name`** that matches a configured zone your key may access.

```bash
curl -sS -X POST "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "example.com",
    "record_type": "DELETE",
    "record_name": "dyn",
    "values": ["A"]
  }'
```

**Azure DNS** — use the same request shape. The Azure subscription ID and resource group come from the saved zone configuration.

```bash
curl -sS -X POST "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "zone_name": "example.com",
    "record_type": "DELETE",
    "record_name": "www",
    "values": ["A"]
  }'
```


## License

MIT
