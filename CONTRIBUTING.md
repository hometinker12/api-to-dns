# Contributing to API to DNS

Thank you for contributing to API to DNS. This project is a FastAPI service with a web administration interface and pluggable DNS providers.

## Development setup

### Requirements

- Python 3.11 or newer; Python 3.12 is recommended
- Docker and Docker Compose for container testing
- OpenSSL when working on certificate features

Install the development dependencies:

```shell
python -m pip install -r requirements-dev.txt
```

Create a local configuration:

```powershell
Copy-Item .env.example .env
```

Generate unique `SECRET_KEY` and `ENCRYPTION_KEY` values. Never commit `.env`, credentials, API keys, certificates, or DNS provider secrets.

Run the application locally:

```shell
python -m src.ssl_certs serve
```

Alternatively, run it through Docker:

```shell
docker compose up --build
```

## Branch and pull request workflow

- Create feature and fix branches from `develop`.
- Submit pull requests targeting `develop`.
- Keep each pull request focused on one feature or fix.
- Explain the motivation and user-visible behavior.
- Include tests for new or changed behavior.
- Do not include unrelated formatting or refactoring.
- Do not update `VERSION` unless preparing a release.

Maintainers promote tested changes from `develop` to `release` after CI and security checks pass. Promotion from `release` to `main` and image publishing are separate manual release steps.

## Project structure

- `src/routes/` — HTTP route modules; place new routes here where practical.
- `src/plugins/` — DNS provider implementations.
- `src/templates/` and `src/static/` — administration interface.
- `src/models.py` and `src/db.py` — database models and initialization.
- `src/auth.py`, `src/rbac.py`, `src/csrf.py`, and `src/security.py` — security-sensitive components.
- `tests/` — pytest test suite.
- `.github/workflows/` — CI and integration smoke tests.

Avoid adding more routes directly to `src/app.py` when they can be placed in a focused module under `src/routes/`.

When mocking DNS clients in tests, patch `src.zone_service.create_dns_client_from_settings`, not `src.app`.

## Database schema changes

SQLite is the supported production engine. Do not add Alembic. After `SQLModel.metadata.create_all`, add an idempotent `_migrate_*` helper in `src/db.py` and call it from `init_db()`.

Typical sequence:

1. `inspect(engine)` the table.
2. Return early if the table is missing (`create_all` adds new tables).
3. Return early if the column or index already exists.
4. `ALTER TABLE ... ADD COLUMN` or create the index.
5. Backfill existing rows when a column default would otherwise leave legacy data incorrect.
6. Cover the helper in tests (`tests/test_security.py` or a focused test module). Running the helper twice must be a no-op.

Use SQLite SQL only. Postgres and other engines are unsupported; `API_TO_DNS_ALLOW_NON_SQLITE=1` only silences the startup warning.

## Coding standards

Python code is checked with Ruff:

- Maximum line length: 120 characters
- Target compatibility: Python 3.11
- Enabled rule groups: `E`, `F`, `I`, and `UP`
- First-party imports use the `src` package

Format and check the code before submitting:

```shell
python -m ruff format src tests
python -m ruff check src tests
python -m ruff format --check src tests
```

Prefer clear, focused functions and established project patterns over introducing new abstractions.

## Tests

Run the full test suite:

```shell
python -m pytest
```

A complete local check is:

```shell
python -m ruff check src tests
python -m ruff format --check src tests
python -m pytest
```

Before pushing image-affecting changes to `develop`, also build and scan the Docker image with Trivy (same High/Critical gate as CI publish / release smoke). Requires Docker; uses a local `trivy` CLI when installed, otherwise runs via the `aquasec/trivy` image:

```powershell
powershell -File scripts/trivy-local-scan.ps1
```

Test files should be named `tests/test_<module>.py`. Reuse fixtures from `tests/conftest.py` and mock external DNS, WinRM, SMTP, syslog, and ACME services where appropriate.

Changes involving routes, authentication, DNS providers, Docker behavior, or public APIs should include regression or smoke-test coverage.

## DNS provider changes

A provider implementation belongs in `src/plugins/<provider>.py`.

Provider contributions should:

1. Implement the existing provider interface.
2. Be registered in `src/plugins/__init__.py`.
3. Preserve the REST API’s record semantics.
4. Support the applicable `A`, `AAAA`, `CNAME`, and `TXT` behavior.
5. Sanitize provider errors before returning them to clients.
6. Avoid logging credentials, TSIG secrets, tokens, or raw API keys.
7. Include unit tests with external network operations mocked.

Keep zone configuration encoding backward-compatible unless the change is explicitly documented as breaking.

## Security requirements

Security regressions block acceptance. In particular:

- Never commit or log secrets.
- Never return provider credentials in HTTP responses.
- Preserve CSRF checks for browser form submissions.
- Preserve API-key authorization and per-zone access controls.
- Do not weaken TLS verification by default.
- Do not enable OpenAPI, debug tracebacks, or insecure defaults in production.
- Keep API keys hashed and zone credentials encrypted at rest.
- Ensure sensitive error messages are sanitized.
- Preserve the non-root, read-only container configuration.

The following flags are intended only for isolated development or tests and must not be recommended for production:

- `API_TO_DNS_ALLOW_INSECURE_DEFAULTS`
- `API_TO_DNS_DISABLE_RATE_LIMIT`
- `API_TO_DNS_RELAX_CSRF`

Security-sensitive changes may receive an additional adversarial review before release.

## Documentation

Update documentation alongside behavior changes:

- Update `README.md` for user-facing features, configuration, routes, or deployment changes.
- Add user-visible changes to the `[Unreleased]` section of `CHANGELOG.md`.
- Update `.env.example` when environment variables are added or renamed.
- Update API examples when request or response behavior changes.

Release version changes must remain synchronized across:

- `VERSION`
- `pyproject.toml`
- `Dockerfile`
- `docker-compose.yml`
- The README release badge
- Version-related tests

## Pull request checklist

Before opening a pull request, confirm that:

- [ ] The change is based on `develop`.
- [ ] Ruff linting passes.
- [ ] Ruff formatting passes.
- [ ] Relevant pytest tests pass.
- [ ] New behavior has test coverage.
- [ ] Secrets and generated files are excluded.
- [ ] Security implications were considered.
- [ ] README and configuration examples are updated when needed.
- [ ] `CHANGELOG.md` is updated for user-visible changes.
- [ ] The pull request explains what changed and why.

## License

By contributing, you agree that your contribution will be licensed under the repository’s MIT License with the Commons Clause.
