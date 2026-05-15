# DNS REST Service

[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/) [![Python](https://img.shields.io/badge/python-3.12-green)](https://www.python.org/) [![Release](https://img.shields.io/badge/release-0.3.0-blue)](VERSION)

Current release: `0.3.0`

A Dockerized FastAPI service to manage DNS records through a protected admin web UI and secure API key authentication. Supported backends are **Azure DNS**, **on-premises Microsoft DNS (WinRM)**, and **BIND** (or other servers) using **RFC 2136 dynamic updates with TSIG**.

## Features

- Protected admin interface with username/password login
- Generate and revoke API keys for REST access
- Choose DNS provider (**Azure**, **Microsoft / WinRM**, **BIND / TSIG**) **per zone** and store connection details and credentials **encrypted at rest**
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

## API Usage

Authenticate with **`X-API-Key: <key>`** or **`Authorization: Bearer <key>`**.

All examples use `POST http://localhost:8000/dns-record` with `Content-Type: application/json`.

**`zone_name` is required** on every request and must match a zone you configured under **DNS zones**. The API key must include that zone in its **allowed zones** list (see **API Keys** in the admin UI). If the zone is missing or the key is not allowed, the response is **403** with `{"detail":{"error":"access_denied","message":"..."}}`.

### Azure DNS: create a new A record

If you saved default **subscription** and **resource group** on that zone’s configuration, you can omit them from the JSON.

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

**Azure DNS** — include **`subscription_id`** and **`resource_group`** unless both are saved on that zone’s configuration.

```bash
curl -sS -X POST "http://localhost:8000/dns-record" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "subscription_id": "11111111-1111-1111-1111-111111111111",
    "resource_group": "my-dns-rg",
    "zone_name": "example.com",
    "record_type": "DELETE",
    "record_name": "www",
    "values": ["A"]
  }'
```

**Responses (short)**

- Create / update success: HTTP **200**, `"status": "success"`, `"action": "created"` or `"updated"`.
- Delete removed a record: **200**, `"status": "success"`, `"action": "deleted"`.
- Delete when nothing matched: **404**, `"status": "error"`, `"action": "not_found"`.
- Zone missing or API key not allowed for that zone: **403**, `"detail": { "error": "access_denied", "message": "..." }`.
- Validation or provider failure: **400**, **502**, **503**, or **500** with JSON `detail` (for example `{"detail": {"error": "dns_provider_failed", "message": "..."}}`).

> **PowerShell:** `Invoke-RestMethod` treats HTTP **404** as a terminating error by default. For a DELETE that returns `not_found`, use `Invoke-RestMethod ... -SkipHttpErrorCheck` (PowerShell 7+) or `Invoke-WebRequest` and read the body.

## License

MIT
