---
name: dns-provider-plugin
description: Add or modify DNS provider plugins in api-to-dns (Azure, Cloudflare, Microsoft WinRM, BIND/TSIG). Use when touching src/plugins/, zone config encoding, or provider-specific DNS semantics.
---

# DNS provider plugin skill

## Plugin contract

1. Implement a client class in `src/plugins/<name>.py` that satisfies the duck-typed interface used by `src/dns_client.py` (get/create/update/delete record operations).
2. Register via auto-discovery in `src/plugins/__init__.py` — follow existing providers as templates.
3. Zone credentials are stored encrypted in `DnsZoneConfig.encrypted_config`; decode/encode through `src/zone_service.py`.

## Provider-specific notes

| Provider | File | Key config fields |
|----------|------|-------------------|
| BIND / TSIG | `src/plugins/bind.py` | `dns_server`, TSIG name/secret, algorithm |
| Microsoft | `src/plugins/microsoft.py` | WinRM host, user, password, optional SSL + insecure TLS flag |
| Cloudflare | `src/plugins/cloudflare.py` | API token, zone id |
| Azure | `src/plugins/azure.py` | subscription, resource group, service principal |

## Error handling

- Raise `RuntimeError` with a concise message for provider failures; `src/http_utils.py` maps these to HTTP **502** with sanitized client text.
- Do not include credentials or raw provider stack traces in exception messages returned to callers.

## Testing checklist

1. Add/extend unit tests in `tests/test_plugins.py` with mocked provider APIs.
2. For behavioral changes affecting REST semantics, update `tests/test_app.py` or DNS API tests.
3. Integration coverage lives in CI:
   - **BIND**: `bind-smoke-linux` job in `.github/workflows/microsoft-dns-smoke.yml`
   - **Microsoft**: `microsoft-dns-smoke-windows` job in the same workflow
4. If adding a new provider type, update README provider list, `.env.example` (if new env keys), and zone create form fields in templates.

## Disabled providers

`dns_client.create_dns_client` must reject mutations when a provider is disabled — mirror existing guard behavior.
