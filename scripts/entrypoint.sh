#!/bin/sh
# Container entrypoint for api-to-dns.
#
# Picks between an HTTP and HTTPS listener at process start based on the
# persisted ssl_enabled setting (overridable via SSL_ENABLED=0|1). When SSL
# is enabled, the bootstrap step exits non-zero if no certificate files
# exist on disk under APP_SSL_DIR; the admin must create or upload a cert
# under Settings -> SSL Certificate Management before enabling SSL.
set -e

MODE="$(python -m src.ssl_certs bootstrap)"
HTTP_PORT="${HTTP_PORT:-8000}"
TLS_PORT="${TLS_PORT:-8443}"
CERT_DIR="${APP_SSL_DIR:-/app/data/ssl}"
EXTRA="${UVICORN_EXTRA_ARGS:-}"

if [ "$MODE" = "https" ]; then
  exec uvicorn src.app:app --host 0.0.0.0 --port "$TLS_PORT" $EXTRA \
    --ssl-keyfile "$CERT_DIR/server.key" \
    --ssl-certfile "$CERT_DIR/server.crt"
else
  exec uvicorn src.app:app --host 0.0.0.0 --port "$HTTP_PORT" $EXTRA
fi
