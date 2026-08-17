#!/bin/sh
# Container entrypoint for api-to-dns.
#
# Picks between an HTTP and HTTPS listener at process start based on the
# persisted ssl_enabled setting (overridable via SSL_ENABLED=0|1). When SSL
# is enabled, the bootstrap step exits non-zero if no certificate files
# exist on disk under APP_SSL_DIR; the admin must create or upload a cert
# under Settings -> SSL Certificate Management before enabling SSL.
#
# The process runs as non-root (uid 10001). Existing root-owned volumes must
# be chowned once; this entrypoint fails closed with a clear migration hint.
set -e

DATA_DIR="/app/data"
SSL_DIR="${APP_SSL_DIR:-/app/data/ssl}"
LOG_DIR="/app/logs"

for dir in "$DATA_DIR" "$SSL_DIR" "$LOG_DIR"; do
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir" 2>/dev/null || true
  fi
  if [ ! -w "$dir" ]; then
    echo "ERROR: $dir is not writable by uid $(id -u) gid $(id -g)." >&2
    echo "If this volume was previously created by a root container, fix ownership once:" >&2
    echo "  docker run --rm -v <volume-name>:/vol alpine chown -R 10001:10001 /vol" >&2
    echo "Do not weaken the steady-state image by starting the app as root." >&2
    exit 1
  fi
done

# Persisted secrets (Settings → Backup) live in $DATA_DIR/app_secrets.env.
# Never source that file: Python parses known keys only and emits shell-safe
# export lines. Module import also overlays os.environ for non-entrypoint runs.
if [ -f "$DATA_DIR/app_secrets.env" ]; then
  # shellcheck disable=SC3046,SC1091
  eval "$(python -c "from src.env_bootstrap import shell_export_persisted_secrets; print(shell_export_persisted_secrets())")"
fi

MODE="$(python -m src.ssl_certs bootstrap)"
HTTP_PORT="${HTTP_PORT:-8000}"
TLS_PORT="${TLS_PORT:-8443}"
CERT_DIR="$SSL_DIR"
GRACEFUL_SHUTDOWN="${UVICORN_GRACEFUL_SHUTDOWN_SECONDS:-10}"
EXTRA="${UVICORN_EXTRA_ARGS:-}"

# Single uvicorn worker is required (LE/backup progress, syslog queue, AXFR slots).
# Do not add --workers via UVICORN_EXTRA_ARGS; this entrypoint forces one worker.
if [ "$MODE" = "https" ]; then
  exec uvicorn src.app:app --host 0.0.0.0 --port "$TLS_PORT" \
    --timeout-graceful-shutdown "$GRACEFUL_SHUTDOWN" $EXTRA \
    --ssl-keyfile "$CERT_DIR/server.key" \
    --ssl-certfile "$CERT_DIR/server.crt" \
    --workers 1
else
  exec uvicorn src.app:app --host 0.0.0.0 --port "$HTTP_PORT" \
    --timeout-graceful-shutdown "$GRACEFUL_SHUTDOWN" $EXTRA \
    --workers 1
fi
