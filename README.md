# DNS REST Service

[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/) [![Python](https://img.shields.io/badge/python-3.12-green)](https://www.python.org/) [![Release](https://img.shields.io/badge/release-0.2.0-blue)](VERSION)

Current release: `0.2.0`

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

## License

MIT
