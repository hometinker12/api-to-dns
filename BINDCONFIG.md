# BIND server configuration for api-to-dns

This guide covers everything that must be configured **on the BIND server itself** so that api-to-dns can manage a zone using the **BIND / RFC 2136 (TSIG)** provider. api-to-dns talks to BIND over the standard DNS protocol:

- **Record lookups** — plain DNS queries over TCP port 53 (no authentication).
- **Record create / update / delete** — RFC 2136 dynamic updates over TCP port 53, signed with a **TSIG key**.
- **Browse / wildcard search** (OPTIONAL for admin DNS browser `*` / `?` searches) — a **zone transfer (AXFR)** over TCP port 53, signed with the same TSIG key. Without an `allow-transfer` grant, only exact-name lookups work.

Tested with BIND 9.18+, but the configuration applies to any RFC 2136-compliant server that supports TSIG (including modern BIND 9.x releases).

## 1. Generate a TSIG key

On the BIND server, generate an HMAC-SHA256 key. The key name is arbitrary but must match exactly between `named.conf` and the api-to-dns zone configuration:

```bash
tsig-keygen -a hmac-sha256 api-to-dns > /etc/bind/keys/api-to-dns.key
```

This produces a file like:

```text
key "api-to-dns" {
    algorithm hmac-sha256;
    secret "<BASE64_TSIG_SECRET_FROM_tsig-keygen>";
};
```

- The `secret` value is **base64** — copy it as-is into the api-to-dns zone settings (see [section 6](#6-matching-settings-in-api-to-dns)).
- Restrict file permissions so only the BIND user can read it:

```bash
chown root:bind /etc/bind/keys/api-to-dns.key
chmod 640 /etc/bind/keys/api-to-dns.key
```

> Older tooling (`dnssec-keygen -a HMAC-SHA256 ...`) works too; only the key name, algorithm, and base64 secret matter.

## 2. Load the key in `named.conf`

Include the key file (or paste the `key` block directly) in your main configuration, **outside** any `zone` block:

```text
include "/etc/bind/keys/api-to-dns.key";
```

## 3. Authorize the key on each managed zone

For every zone api-to-dns should manage, grant the key permission for **dynamic updates** and (for browse / wildcard search) **zone transfers**:

```text
zone "example.com" {
    type master;
    file "/var/lib/bind/db.example.com";

    // Required: lets api-to-dns create, update, and delete records (RFC 2136)
    allow-update { key "api-to-dns"; };

    // Required for the DNS browser blank search and */? wildcard search (AXFR).
    // Omit this if you only want exact-name lookups and record mutations.
    allow-transfer { key "api-to-dns"; };
};
```

Notes:

- The zone must be `type master` (primary). Dynamic updates against a secondary are forwarded or refused depending on your setup; point api-to-dns at the primary.
- The zone file's parent directory must be **writable by the BIND user** — dynamic updates create a `.jnl` journal file next to the zone file (for example `/var/lib/bind/` on Debian/Ubuntu; `/etc/bind/` is typically read-only and will not work).
- For finer-grained control, `update-policy` can replace `allow-update`, for example to restrict the key to TXT records or a subdomain:

```text
    update-policy {
        grant api-to-dns zonesub ANY;
    };
```

## 4. Reload and verify BIND

```bash
named-checkconf
named-checkzone example.com /var/lib/bind/db.example.com
rndc reload
```

## 5. Network requirements

- api-to-dns must reach the BIND server on **TCP port 53** (all operations — lookups, updates, and AXFR — use TCP). Open UDP 53 as well if the server also serves normal resolution traffic.
- If the BIND server has multiple listen addresses, ensure `listen-on` includes the address you will use as **Target DNS Server** in api-to-dns.
- TSIG signing is sensitive to clock skew (default fudge is 300 seconds). Keep both hosts synced with NTP; a `BADTIME` / `NOTAUTH` update failure usually means the clocks have drifted.

## 6. Matching settings in api-to-dns

When creating the zone in the api-to-dns admin UI (**DNS Zones → Add**), select provider **BIND / RFC 2136 (TSIG)** and fill in:

| api-to-dns field | Value from this guide |
|---|---|
| DNS zone (domain) | `example.com` |
| Target DNS Server | Hostname or IP of the BIND primary (e.g. `bind01.example.com` or `192.0.2.10`) |
| TSIG key name | `api-to-dns` (must match the `key "..."` name in `named.conf` exactly) |
| TSIG secret (base64) | The base64 `secret` value from the key file |
| TSIG algorithm | `hmac-sha256` (must match the `algorithm` in the key block) |

Use the **Test Configuration** button on the zone form to verify connectivity and credentials before saving.

## 7. Verify from the command line (optional)

From the api-to-dns host (or any machine with `bind9-dnsutils` installed), confirm each capability with the same key:

**Exact-name lookup** (no key needed):

```bash
dig +tcp @192.0.2.10 www.example.com A
```

**Dynamic update** (creates and removes a test record):

```bash
nsupdate -y "hmac-sha256:api-to-dns:<BASE64_TSIG_SECRET_FROM_tsig-keygen>" <<'EOF'
server 192.0.2.10
zone example.com
update add _apitodns-test.example.com 60 TXT "connectivity check"
send
update delete _apitodns-test.example.com TXT
send
EOF
```

**Zone transfer (AXFR)** — required for browse / wildcard search:

```bash
dig +tcp @192.0.2.10 example.com AXFR \
    -y "hmac-sha256:api-to-dns:<BASE64_TSIG_SECRET_FROM_tsig-keygen>"
```

A successful AXFR prints every record in the zone. A `Transfer failed.` / `REFUSED` response means the zone is missing the `allow-transfer { key "api-to-dns"; };` grant.

## 8. Security recommendations

- **Scope the grants**: give the key `allow-update` / `allow-transfer` only on the zones api-to-dns manages — never in the global `options` block.
- **One key per purpose**: use a dedicated key for api-to-dns rather than sharing an existing transfer key with secondaries.
- **AXFR exposes the whole zone**: `allow-transfer { key ...; }` lets any holder of the key enumerate every record. Only add it if you want the DNS browser's blank / wildcard search, and protect the secret accordingly (it is stored encrypted at rest by api-to-dns).
- **Rotate keys** by generating a new key, adding it alongside the old one in `named.conf` and the zone grants, updating the api-to-dns zone settings, then removing the old key.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `DNS UPDATE failed: REFUSED` | Zone missing `allow-update { key ...; };`, or key name/secret mismatch |
| `DNS UPDATE failed: NOTAUTH` | Wrong TSIG key name/secret/algorithm, or clock skew (`BADTIME`) |
| `DNS UPDATE failed: SERVFAIL` | Zone file directory not writable by BIND (journal file cannot be created) |
| Browse / wildcard search fails but exact lookup works | Zone missing `allow-transfer { key ...; };` |
| BIND logs `tsig verify failure (BADKEY)` on browse/wildcard | TSIG key name in api-to-dns zone settings does not match a loaded `key` block. The example name `api-to-dns` in this guide must be replaced with your actual key name (and algorithm) |
| BIND logs `tsig verify failure (BADSIG)` | TSIG secret in api-to-dns does not match the BIND key `secret` |
| Connection timeout | TCP 53 blocked between api-to-dns and the BIND server, or wrong `listen-on` |
