# Security Policy

## Supported versions

Security fixes are applied on the active development and release lines:

| Version / branch | Supported |
| ---------------- | --------- |
| Latest release on `main` | Yes |
| `release` (integration candidate) | Yes, for confirmed vulnerabilities |
| `develop` | Yes, as the primary fix landing branch |
| Older published tags | Best effort only |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Prefer one of these private channels:

1. **GitHub Security Advisories** (preferred): use
   [Report a vulnerability](../../security/advisories/new) on this repository
   if private vulnerability reporting is enabled.
2. **Private maintainer contact**: message
   [@hometinker12](https://github.com/hometinker12) on GitHub and note that you
   have a security report for API to DNS.

Please include:

- Affected version, commit SHA, or branch
- Description of the issue and impact
- Steps to reproduce, or a minimal proof of concept
- Whether you are aware of public disclosure or active exploitation
- Your preferred credit name (or a request to remain anonymous)

## Scope

High-priority areas for this project include:

- Authentication and session handling
- API key authorization and per-zone access control
- CSRF protection for browser form posts
- Secret handling (`SECRET_KEY`, `ENCRYPTION_KEY`, provider credentials, TSIG)
- Logging that might leak credentials or raw API keys
- DNS provider plugins (command injection, credential abuse, error leakage)
- TLS / certificate handling
- Container hardening (privilege, filesystem, exposed ports)

Out of scope unless there is a clear project-specific impact:

- Issues that require already-compromised admin credentials
- Denial-of-service against third-party DNS providers
- Reports that depend only on insecure local test flags
  (`API_TO_DNS_ALLOW_INSECURE_DEFAULTS`, `API_TO_DNS_RELAX_CSRF`,
  `API_TO_DNS_DISABLE_RATE_LIMIT`)

## What to expect

- Acknowledgement when practical, typically within a few days
- An initial severity assessment and next steps
- A coordinated fix on `develop`, then promotion through `release` as needed
- Credit in release notes or the advisory when you want attribution

Please avoid public disclosure until a fix is available or the maintainers agree
on a disclosure date.

## Safe local testing

When validating fixes locally:

- Use disposable credentials and non-production DNS zones
- Never commit `.env`, certificates, provider secrets, or real API keys
- Prefer mocked provider tests under `tests/` over live mutation of production DNS
