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

FROM python:3.12-slim

ARG VERSION=0.3.4

LABEL org.opencontainers.image.title="api-to-dns" \
      org.opencontainers.image.description="DNS REST API and admin UI (Azure, Cloudflare, Microsoft DNS, BIND/TSIG)" \
      org.opencontainers.image.version="${VERSION}"

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    DATABASE_URL=sqlite:////app/data/app.db

# Persistent state and operational logs
RUN mkdir -p /app/data /app/logs

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/login', timeout=3)"]

CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8000"]
