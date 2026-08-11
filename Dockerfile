# api-to-dns — FastAPI DNS REST service and admin UI.
#
# Build:  docker build -t api-to-dns .
# Run:    docker compose up --build  (see docker-compose.yml and .env.example)
#
# Required at runtime (via .env or -e):
#   SECRET_KEY, ENCRYPTION_KEY — session signing and Fernet encryption for stored secrets
#   ADMIN_USER, ADMIN_PASSWORD — seed the first admin account when the database has no users
#
# Optional:
#   DATABASE_URL — default below uses /app/data (mount a volume here in production)
#   LOG_FILE     — rotating operational log file (Compose sets /app/logs/api-to-dns.log)
#   APP_SSL_DIR — directory for server.key / server.crt (default /app/data/ssl)
#   HTTP_PORT    — listener port when SSL is disabled (default 8000)
#   TLS_PORT     — listener port when SSL is enabled (default 8443)
#   SSL_ENABLED  — optional override of the DB-stored ssl_enabled toggle (1/0)
#
# Runs as non-root uid/gid 10001. If upgrading from a previous root-owned named
# volume, fix ownership once (do not keep starting the app as root):
#   docker run --rm -v api-to-dns_api-to-dns-data:/vol alpine chown -R 10001:10001 /vol
#   docker run --rm -v api-to-dns_api-to-dns-ssl:/vol alpine chown -R 10001:10001 /vol
#   docker run --rm -v api-to-dns_api-to-dns-logs:/vol alpine chown -R 10001:10001 /vol

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ARG VERSION=0.8.1

LABEL org.opencontainers.image.title="api-to-dns" \
      org.opencontainers.image.description="DNS REST API and admin UI (Azure, Cloudflare, Microsoft DNS, BIND/TSIG)" \
      org.opencontainers.image.version="${VERSION}"

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    DATABASE_URL=sqlite:////app/data/app.db \
    APP_SSL_DIR=/app/data/ssl \
    HTTP_PORT=8000 \
    TLS_PORT=8443

# openssl is used by the self-signed cert generator in src/ssl_certs.py.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && python -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('pytest') is None else 1)"

COPY VERSION ./VERSION
COPY src ./src
COPY scripts ./scripts
# Strip any CRLF line endings the script may have picked up on a Windows host
# (otherwise the shebang becomes "#!/bin/sh\r" and exec fails with
# "no such file or directory"), then make it executable.
RUN sed -i 's/\r$//' ./scripts/entrypoint.sh \
    && chmod +x ./scripts/entrypoint.sh \
    && mkdir -p /app/data /app/data/ssl /app/logs \
    && chown -R app:app /app

USER app

EXPOSE 8000 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-m", "src.ssl_certs", "healthcheck"]

ENTRYPOINT ["./scripts/entrypoint.sh"]
