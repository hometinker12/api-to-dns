# api-to-dns Improvement Plan

**Status:** Plan only — no feature or code changes in this deliverable.  
**Reviewed against:** `main` @ `79f2d8f` (post v0.5.0)

---

## 1. Executive summary

api-to-dns is a capable FastAPI control plane for DNS (Azure, Cloudflare, Microsoft WinRM, BIND/TSIG) with RBAC admin UI, activity logging, email alerts, SSL, and Let's Encrypt. Three structured review passes plus Composer synthesis found **critical security foot-guns** (plaintext API keys, weak/ephemeral secrets), a **broken Let's Encrypt auto-renew path**, and **structural debt** centered on a ~3,500-line `src/app.py`.

This plan prioritizes hotfix hardening, then security, then modularization, then product/ops features already advertised (backup, syslog) or naturally expected (record browser, more RR types).

---

## 2. How reviews were conducted

| Pass | Focus | Method |
|------|--------|--------|
| **Pass 1 — Architecture** | Module boundaries, plugins, lifecycle, persistence, deployment | Static review of `src/app.py`, `src/db.py`, `src/plugins/`, Docker/Compose, CI |
| **Pass 2 — Security / correctness** | Secrets, auth, error leakage, LE renew, deps, tests | Line-level review of `security.py`, `auth.py`, `models.py`, `letsencrypt.py`, `http_utils.py`, `tests/` |
| **Pass 3 — Features / ops** | Docs vs code, placeholders, DX, SRE readiness | `README.md`, `CHANGELOG.md`, `rbac.py`, templates, public API surface |
| **Composer** | Independent architecture, security, and roadmap passes; then synthesis | Three Composer explore agents + one synthesis pass; findings cross-checked in-repo |

**Out of review scope:** Live pen-test, provider SLA, host OS hardening beyond app config.

---

## 3. Current strengths (preserve)

| Area | Evidence |
|------|----------|
| Plugin auto-discovery | `src/plugins/__init__.py`, `DnsProviderPlugin` in `base.py` |
| Encrypted zone credentials | `DnsZoneConfig.encrypted_config`, `zone_service.encode_zone_config_dict` |
| Granular RBAC | `src/rbac.py` (role deps, `global.admin` guards) |
| Audit + email alerts | `activity_logging.py` with retention and `redact_details()` |
| Clear DNS REST semantics | Pre-flight 409/404 on `/dns-record`; OpenAPI-limited public surface |
| LE enrollment (DNS-01 / HTTP-01) | `letsencrypt.py` + async progress UI |
| Solid test baseline | ~266 tests; strong RBAC and DNS CRUD coverage |
| Docker packaging | Named volumes for data/ssl/logs; graceful shutdown hooks |

---

## 4. Findings by priority

Deduplicated across all passes. **P0** = exploit / data-loss / broken critical path. **P1** = significant security or reliability. **P2** = maintainability or product gap. **P3** = strategic enhancement.

### P0 — Critical

| ID | Finding | Location | Action |
|----|---------|----------|--------|
| P0-1 | API keys stored **plaintext** | `models.ApiKey.key`; lookups in `zone_service.get_api_key` | Store hash (+ optional prefix); show full key once at create; migrate existing keys |
| P0-2 | `ENCRYPTION_KEY` **auto-generated** when unset (not persisted) | `security.py:7–10` | Fail fast if unset outside tests; never silent generate |
| P0-3 | `SECRET_KEY` insecure default | `auth.py:6` (`please-change-this-secret`) | Fail fast when default in production |
| P0-4 | LE auto-renew **skips challenge publish** | `letsencrypt.maybe_renew_certificate` (~862–881): prepare → finalize with no TXT/HTTP setup (contrast `start_enrollment`) | Share enrollment challenge orchestration; add success-path test |
| P0-5 | Version drift | `VERSION`=`0.5.0`; `app.py` / `pyproject.toml` / Dockerfile ARG = `0.3.4` | Single source of truth from `VERSION` |

### P1 — High

| ID | Finding | Location | Action |
|----|---------|----------|--------|
| P1-1 | No CSRF on session form POSTs | Admin routes in `app.py` | Synchronizer or double-submit token; exempt JSON API |
| P1-2 | CORS `allow_origins=["*"]` | `app.py` CORSMiddleware | Configurable origins; deny `*` in production |
| P1-3 | Session cookie lacks `Secure` | `auth.session_cookie_settings` | Set when SSL enabled |
| P1-4 | No rate limiting / login lockout | `/login`, `/keycheck`, `/dns-record` | Per-IP and per-key limits |
| P1-5 | Provider errors returned verbatim | `http_utils.http_exception_from_dns_error`; plugin `RuntimeError` | Sanitize client `message`; full detail server-side only |
| P1-6 | WinRM `server_cert_validation="ignore"` | `plugins/microsoft.py` | Configurable; default strict when possible |
| P1-7 | `acme` / `josepy` unpinned | `requirements.txt` | Pin; add lock/SBOM hygiene |
| P1-8 | `passlib` unmaintained (PBKDF2) | `security.py` | Migrate to argon2/bcrypt |
| P1-9 | Test gaps | No crypto startup tests; LE renew only skip-paths; no assert secrets absent from `detail.message` | Close gaps tied to P0/P1 |
| P1-10 | Duplicate `api_key_fingerprint` | `http_utils.py` vs `app.py:3462` | Keep one import |
| P1-11 | Duplicated startup init | `lifespan` vs `startup_event` | Shared `_startup_init()` |
| P1-12 | Hand-rolled SQL migrations | `db.py` ALTER helpers | Introduce Alembic |
| P1-13 | Tracebacks in HTML errors | `web.render_error_response` | Log server-side; generic UI in production |
| P1-14 | Disabled plugins not blocked on DNS API | `dns_client.create_dns_client` vs disable list | Reject mutations for disabled providers |

### P2 — Medium

| ID | Finding | Location | Action |
|----|---------|----------|--------|
| P2-1 | God module (~3,473 lines / 50+ routes) | `src/app.py` | Split FastAPI routers; thin composition root |
| P2-2 | `event_types.py` never imported | `src/event_types.py` | Use everywhere or delete |
| P2-3 | No API versioning | `/dns-record`, `/zones` | Add `/v1/` prefix |
| P2-4 | Health probes `/login` only | `ssl_certs.healthcheck` | `/health` + `/ready` (DB) |
| P2-5 | Blocking sync DNS I/O | Mutation path in `app.py` | `asyncio.to_thread` then async clients |
| P2-6 | SQLite default / single-node | `db.py`, Compose | Document Postgres; pool settings |
| P2-7 | No formal plugin Protocol | Duck-typed clients | `Protocol`/`ABC` for get/create/delete |
| P2-8 | Syslog + System Backup placeholders | `rbac.py`, `settings.html` | Implement or hide until ready |
| P2-9 | LE missing from README | README SSL section | Document DNS-01/HTTP-01/auto-renew |
| P2-10 | Only A/AAAA/CNAME/TXT | `models.py` | Add MX/CAA/SRV incrementally |
| P2-11 | No admin DNS record browser | Zone templates | Read-only list via provider |
| P2-12 | Multi-value RR semantics differ by provider | Cloudflare vs Azure plugins | Document + normalize API contract |
| P2-13 | Zone/key CRUD HTML-only | `app.py` admin routes | Optional JSON admin API |
| P2-14 | No metrics | — | Prometheus `/metrics` or OTel |
| P2-15 | Compose claims vs reality | CHANGELOG vs `docker-compose.yml` | Service-level `healthcheck`; pin image tags |
| P2-16 | Activity log query loads all then slices | `activity_logging.query_activity_logs` | SQL COUNT + LIMIT/OFFSET |
| P2-17 | Docker runs as root | `Dockerfile` | Non-root `USER` |

### P3 — Strategic

| ID | Finding | Action |
|----|---------|--------|
| P3-1 | No Route 53 / GCP / PowerDNS plugins | Add when demand justifies |
| P3-2 | Email-only alerts | Webhooks / Slack channels |
| P3-3 | Password-only admin auth | MFA / OIDC |
| P3-4 | No read-only API keys / IP allowlists | Scoped keys |
| P3-5 | No client SDKs / OpenAPI examples for `/dns-record` | Generate examples + optional SDKs |
| P3-6 | Multi-tenancy / HA runbooks | External DB + stateless app tier |

---

## 5. Phased roadmap

### Phase 0 — Hotfix

**Goal:** Stop credential/crypto foot-guns; fix broken LE renew; align versions.

1. Fail-fast for missing/default `ENCRYPTION_KEY` and `SECRET_KEY` (test override allowed).
2. Hash API keys at rest; one-time display; migration strategy for existing plaintext rows.
3. Fix `maybe_renew_certificate` to reuse enrollment DNS/HTTP challenge flow.
4. Unify version from `VERSION` across app, pyproject, Docker labels.
5. Remove duplicate `api_key_fingerprint`.

**Gate:** No production deploy of Phase 0 without an API-key migration story (re-issue or hash-on-read).

### Phase 1 — Harden

**Goal:** Close common web/API attack surface; safe errors; dependency hygiene; critical tests.

1. CSRF for cookie-auth form POSTs.
2. Configurable CORS; Secure cookies when SSL on.
3. Rate limits on login, keycheck, DNS mutations.
4. Sanitize provider errors in API responses and activity `message`.
5. WinRM cert validation option; pin `acme`/`josepy`; plan `passlib` replacement.
6. Block DNS API when provider plugin is disabled.
7. Tests for startup guards, key hashing, LE renew success (mocked), secret non-leakage.
8. Consolidate `lifespan` / `startup_event` init.

### Phase 2 — Structure

**Goal:** Maintainable layout; migrations; I/O and health foundations.

1. Split `app.py` into routers (`dns`, `admin`, `settings`, `auth`, `ssl`); keep `app.py` as factory.
2. Alembic; retire ad-hoc `db.py` ALTERs over time.
3. `DnsProviderProtocol`; wire or delete `event_types.py`.
4. Offload sync DNS work via `to_thread` (then async plugins).
5. `GET /health` + `GET /ready`; update Docker healthcheck.
6. Introduce `/v1/` API prefix with deprecation policy for unversioned paths.

### Phase 3 — Product & ops completeness

**Goal:** Finish advertised settings; operator UX; docs truthfulness.

1. README: Let's Encrypt, `zone_name` vs `dns_zone`, Cloudflare proxied.
2. Implement **System Backup** (export/import DB + SSL dir metadata) or remove nav item.
3. Implement **syslog forwarding** or remove placeholder section.
4. DNS record browser (read-only) in admin UI.
5. Expand RR types (start with MX + CAA).
6. Activity log export (CSV/JSON) for SIEM.
7. Optional JSON admin API for zones/keys.
8. Compose healthcheck + pinned image tags; non-root container user.
9. Document multi-value RR behavior per provider.

### Phase 4 — Scale & enterprise

**Goal:** Multi-instance readiness and integrations.

1. Postgres-first guide + connection pooling.
2. Prometheus metrics (request rate, provider errors, LE expiry).
3. Webhooks on activity events.
4. Additional providers (Route 53, GCP DNS).
5. Read-only / scoped API keys; IP allowlists.
6. OIDC/MFA for admin.
7. HA runbook (shared DB, LE renewal leadership).

---

## 6. Out of scope / not recommended now

| Item | Why |
|------|-----|
| Microservices split | Router extraction is enough at current scale |
| Built-in authoritative DNS | Product is a control plane over providers |
| GraphQL | Versioned REST + OpenAPI is sufficient |
| MFA/SSO before Phase 0–1 | Does not fix plaintext keys or broken renew |
| Replacing SQLite as default in Phase 0 | Document Postgres; migrate when HA is required |
| Removing WinRM plugin | Harden cert validation instead |
| AXFR / DNSSEC management | Outside current charter |

---

## 7. Acceptance criteria by phase

### Phase 0

- App exits non-zero when `ENCRYPTION_KEY`/`SECRET_KEY` unset or default (non-test).
- `ApiKey` table stores hashes only after migration; plaintext never re-persisted.
- Test proves `maybe_renew_certificate` publishes and verifies challenges before finalize.
- `VERSION` == FastAPI `version` == `pyproject.toml` == Docker image version label.
- Single `api_key_fingerprint` definition.

### Phase 1

- CSRF-protected admin POSTs reject missing/invalid tokens.
- Production CORS config does not use `*`.
- DNS provider auth failures do not echo tokens into JSON `message`.
- All direct deps in `requirements.txt` pinned (including `acme`, `josepy`).
- New security/LE renew tests green in CI.

### Phase 2

- `src/app.py` is a thin factory (routers own HTTP).
- Fresh install and upgrade from current schema succeed via Alembic.
- Each plugin satisfies a documented protocol (tests or type check).
- `/ready` returns 503 when DB unreachable.

### Phase 3

- README documents LE enrollment and auto-renew/restart behavior.
- Backup export/import round-trips on a clean DB **or** Backup nav is removed.
- Syslog delivers configured events **or** placeholder section is removed.
- Admin can list supported records for a zone without using an API key.

### Phase 4

- Two app replicas against shared Postgres without SQLite file locks.
- Metrics expose DNS error ratio and cert expiry signal.
- Optional webhook fires on `dns.record_created` within a short delay.

---

## 8. Suggested implementation order (first PRs)

1. **PR A — Secrets & versions:** P0-2, P0-3, P0-5, P1-10 (low risk, high clarity).
2. **PR B — API key hashing:** P0-1 (+ migration + tests).
3. **PR C — LE auto-renew fix:** P0-4 (+ success-path test).
4. **PR D — Error sanitization + plugin-disable check:** P1-5, P1-14.
5. **PR E — CSRF / CORS / Secure cookie / rate limit:** P1-1–P1-4.
6. **PR F — Router split:** P2-1 (mechanical, enables parallel work).
7. **PR G — Docs + placeholders:** P2-8, P2-9 (implement or remove).

---

## Appendix A — Key file map

| Path | Role |
|------|------|
| `src/app.py` | Monolithic routes, middleware, DNS mutations |
| `src/auth.py` / `src/security.py` | Sessions, Fernet, password/API key helpers |
| `src/models.py` | Tables + public DNS schemas |
| `src/db.py` | Engine + ad-hoc migrations |
| `src/zone_service.py` | Zone/key domain helpers |
| `src/letsencrypt.py` | ACME enroll/renew (renew defect at ~862) |
| `src/http_utils.py` | Error mapping, key fingerprint |
| `src/event_types.py` | Unused event constants |
| `src/plugins/*` | Provider clients |
| `src/rbac.py` / `templates/settings.html` | Backup & syslog placeholders |
| `tests/test_letsencrypt.py` | Renew success path missing |
| `VERSION` / `pyproject.toml` / `Dockerfile` | Version drift |

## Appendix B — Verified LE renew defect (P0-4)

Broken path in `maybe_renew_certificate`:

```text
_acme_prepare_order(config) → _acme_finalize_order(enrollment)
```

Working enrollment path publishes `_acme-challenge` TXT (or HTTP challenge state), verifies, then finalizes. Renew must reuse that orchestration.

---

*End of plan. Implementation should land as separate PRs following Phases 0→4; this document intentionally contains no code changes.*
