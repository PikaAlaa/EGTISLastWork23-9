# Pinned exact tag + SHA-256 manifest digest placeholder (replace TO_VERIFY_python via `docker buildx imagetools inspect` before step 5; docs/design/docker-lan-v1.md §10 D1)
FROM python:3.12.10-slim-bookworm@sha256:TO_VERIFY_python
WORKDIR /app
COPY requirements-runtime.txt requirements-models.txt ./
ARG INCLUDE_TENSORFLOW=false
RUN if [ "$INCLUDE_TENSORFLOW" = "true" ]; then pip install --no-cache-dir -r requirements-models.txt; else pip install --no-cache-dir -r requirements-runtime.txt; fi \
    && groupadd --gid 10001 etis \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin etis \
    && mkdir -p /app/ml/models /app/data/external/attack /app/evaluation/reports/2026-10-v3 \
    && chown -R 10001:10001 /app
COPY backend ./backend
COPY data/scripts ./data/scripts
COPY scripts ./scripts
COPY alembic.ini ./
ENV PYTHONPATH=/app/backend \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)"]
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--no-access-log"]
