# Microsoft DNS REST Service

[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/) [![Python](https://img.shields.io/badge/python-3.12-green)](https://www.python.org/) [![Release](https://img.shields.io/badge/release-0.1.0-blue)](VERSION)

Current release: `0.1.0`

A Dockerized FastAPI service to manage DNS records through a protected admin web UI and secure API key authentication. Supported backends are **Azure DNS**, **on-premises Microsoft DNS (WinRM)**, and **BIND** (or other servers) using **RFC 2136 dynamic updates with TSIG**.

## Features

- Protected admin interface with username/password login
- Generate and revoke API keys for REST access
- Choose DNS provider (**Azure**, **Microsoft / WinRM**, **BIND / TSIG**) and store connection details and credentials **encrypted at rest** in the database
- Create, update, or **delete** DNS records via `POST /dns-record`
- Structured JSON errors (for example **404** when a DELETE finds no record, **502** when the DNS provider fails)
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

After login, open **DNS Settings** and configure your provider, zone, and credentials. **Azure service principal fields are no longer set via environment variables**; they are saved in the UI (encrypted in the database).

## Configuration

Create a `.env` file using `.env.example` and configure the following values:

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Session signing secret (use a random string) |
| `ENCRYPTION_KEY` | Key for encrypting settings in the database (must be a valid Fernet key) |
| `ADMIN_USER` | Initial admin username |
| `ADMIN_PASSWORD` | Initial admin password |
| `DATABASE_URL` | Optional database URL (default: `sqlite:///./data/app.db`) |

**Azure DNS** is configured in the **DNS Settings** page (tenant ID, client ID, client secret, optional default subscription and resource group). Those values are **not** read from `AZURE_*` environment variables.

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
- Choose **DNS server type** (Azure, Microsoft WinRM, or BIND / TSIG)
- Set target DNS server and zone, credentials, and (for Azure) service principal defaults
- Create and revoke API keys

## API Usage

Authenticate with **`X-API-Key: <key>`** or **`Authorization: Bearer <key>`**.

All examples use `POST http://localhost:8000/dns-record` with `Content-Type: application/json`.

### Azure DNS: create a new A record

If you saved default **subscription** and **resource group** in DNS Settings, you can omit them from the JSON.

```bash
curl -sS -X POST "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "subscription_id": "11111111-1111-1111-1111-111111111111",
    "resource_group": "my-dns-rg",
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
    "subscription_id": "11111111-1111-1111-1111-111111111111",
    "resource_group": "my-dns-rg",
    "zone_name": "example.com",
    "record_type": "A",
    "record_name": "www",
    "ttl": 600,
    "values": ["192.0.2.20"]
  }'
```

### Delete a record (all providers)

Use **`record_type": "DELETE"`**. The first entry in **`values`** must be the DNS RR type to remove: **`A`**, **`AAAA`**, **`CNAME`**, or **`TXT`**.

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

For **Azure**, include `subscription_id` and `resource_group` in the body (or rely on defaults from DNS Settings) the same way as for creates.

> **PowerShell:** `Invoke-RestMethod` treats HTTP 404 as a terminating error by default. For a DELETE that returns 404 (`not_found`), use `Invoke-RestMethod ... -SkipHttpErrorCheck` (PowerShell 7+) or `Invoke-WebRequest` and inspect the response body.

**Responses**

- Create / update success: HTTP **200**, JSON includes `"status": "success"` and `"action": "created"` or `"updated"`.
- Delete success: HTTP **200**, `"status": "success"`, `"action": "deleted"`.
- Delete when the record does not exist: HTTP **404**, `"status": "error"`, `"action": "not_found"`.
- Provider or validation failure: HTTP **400**, **502**, **503**, or **500** with JSON `detail` object, for example `{"detail": {"error": "dns_provider_failed", "message": "..."}}`.

### Microsoft / BIND

- **Microsoft (WinRM):** omit `subscription_id` and `resource_group`. Ensure **Target DNS Server**, **Target DNS Zone**, and WinRM credentials are set in DNS Settings.
- **BIND (TSIG):** same omit for Azure fields. Use the settings page for TSIG key name and base64 secret.

## Repository Layout

- `Dockerfile` — container build recipe
- `docker-compose.yml` — local deployment configuration
- `.env.example` — environment variable template (app secrets and database only)
- `src/app.py` — FastAPI app, admin routes, and API endpoint
- `src/db.py` — database engine and session management
- `src/security.py` — password hashing and encryption helpers
- `src/auth.py` — session cookie authentication
- `src/dns_client.py` — Azure, BIND (TSIG), and Microsoft WinRM DNS logic
- `src/models.py` — request/response models and SQL models
- `src/templates/` — HTML templates for admin UI
- `src/static/` — CSS styles
- `tests/` — API tests (including provider mocks)

## Pull request summary

### Overview

Multi-provider DNS support (**Azure DNS**, **Microsoft DNS via WinRM**, **BIND / RFC 2136 + TSIG**), **Azure credentials and defaults moved from environment variables into encrypted DNS Settings**, **`DELETE`** support on `/dns-record`, and **structured HTTP errors** instead of a single generic 500 for provider failures.

### DNS providers (`src/dns_client.py`)

- **Azure:** `ClientSecretCredential` using tenant, client ID, and secret from application settings.
- **BIND:** Dynamic DNS updates with TSIG; credentials fields carry TSIG key name and base64 secret; optional TSIG algorithm.
- **Microsoft:** WinRM + DnsServer PowerShell for A, AAAA, CNAME, TXT; optional HTTPS WinRM (5986).
- **Upsert:** Microsoft path removes existing RRs of that type before add; BIND uses TSIG `replace` where applicable.
- **WinRM:** `Remove-DnsServerResourceRecord` receives explicit `-ComputerName` and `-ZoneName` when used in a pipeline.
- **DELETE:** `record_type` `DELETE` with `values[0]` = RR type to remove; implemented for Azure (`record_sets.delete`), BIND (`update.delete`), and Microsoft (Get → Remove).

### Configuration and API (`src/app.py`, `src/models.py`)

- `/dns-record` reads provider from settings; merges default Azure subscription and resource group from settings when omitted on the request.
- `DnsRecordRequest` validates `values` (including DELETE rules).
- DELETE not found: HTTP **404**, body `status: "error"`, `action: "not_found"`; successful delete returns **200** with `status: "success"`, `action: "deleted"`.
- Exceptions mapped to `HTTPException` with structured `detail`: `invalid_request` (400), `dns_provider_failed` (502), `dependency_unavailable` (503), `unexpected` (500).

### Admin UI and environment

- **DNS Settings:** provider selector, server/zone, credentials, TSIG / WinRM options, Azure service principal fields.
- **`.env.example`:** removed `AZURE_*` variables; Azure is configured only through the UI.
- **`requirements.txt`:** `dnspython`, `pywinrm`.

### Tests (`tests/conftest.py`, `tests/test_app.py`)

- Isolated SQLite path for tests; mocks cover success, DELETE not found (404), and provider `RuntimeError` (502).

### Documentation (`README.md`)

- Environment section reflects **no Azure env vars**; points to DNS Settings.
- **curl** examples for **create**, **update**, and **delete**; response and error behavior summarized.

## License

MIT
