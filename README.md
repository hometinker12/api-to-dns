# Microsoft DNS REST Service

[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/) [![Python](https://img.shields.io/badge/python-3.12-green)](https://www.python.org/) [![Release](https://img.shields.io/badge/release-0.1.0-blue)](VERSION)

Current release: `0.1.0`

A Dockerized FastAPI service to manage Microsoft DNS records through a protected admin web UI and secure API key authentication.

## Features

- Protected admin interface with username/password login
- Generate and revoke API keys for REST access
- Store DNS target settings and Microsoft DNS credentials encrypted at rest
- Create or update DNS records via `/dns-record`
- Automatic check whether a DNS record already exists before updating
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

## Configuration

Create a `.env` file using `.env.example` and configure the following values:

- `SECRET_KEY` — session signing secret (use a random string)
- `ENCRYPTION_KEY` — encryption key for settings stored in the database (must be a valid Fernet key)
- `ADMIN_USER` — initial admin username
- `ADMIN_PASSWORD` — initial admin password
- `DATABASE_URL` — optional database URL (default: `sqlite:///./data/app.db`)

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

Optional Azure provider values:

- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`
- `AZURE_SUBSCRIPTION_ID`

## Admin UI

The web interface allows you to:

- sign in with admin credentials
- manage DNS server and zone settings
- store Microsoft DNS username/password securely
- create and revoke API keys

## API Usage

Use `X-API-Key` or `Authorization: Bearer <key>` to authenticate requests to `/dns-record`.

```bash
curl -X POST http://localhost:8000/dns-record \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-api-key>" \
  -d '{
    "subscription_id": "<subscription-id>",
    "resource_group": "<resource-group>",
    "zone_name": "example.com",
    "record_type": "A",
    "record_name": "www",
    "ttl": 300,
    "values": ["192.0.2.1"]
  }'
```

## Repository Layout

- `Dockerfile` — container build recipe
- `docker-compose.yml` — local deployment configuration
- `.env.example` — environment variable template
- `src/app.py` — FastAPI app, admin routes, and API endpoint
- `src/db.py` — database engine and session management
- `src/security.py` — password hashing and encryption helpers
- `src/auth.py` — session cookie authentication
- `src/dns_client.py` — DNS create/update logic
- `src/models.py` — request models and SQL models
- `src/templates/` — HTML templates for admin UI
- `src/static/` — CSS styles
- `tests/test_app.py` — basic API validation test

## License

MIT

