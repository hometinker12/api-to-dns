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

FROM python:3.12-slim

ARG VERSION=0.3.4

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
    && rm -rf /var/lib/apt/lists/*

# Persistent state, operational logs, and SSL material.
RUN mkdir -p /app/data /app/data/ssl /app/logs

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY scripts ./scripts
# Strip any CRLF line endings the script may have picked up on a Windows host
# (otherwise the shebang becomes "#!/bin/sh\r" and exec fails with
# "no such file or directory"), then make it executable.
RUN sed -i 's/\r$//' ./scripts/entrypoint.sh \
    && chmod +x ./scripts/entrypoint.sh

EXPOSE 8000 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-m", "src.ssl_certs", "healthcheck"]

ENTRYPOINT ["./scripts/entrypoint.sh"]
