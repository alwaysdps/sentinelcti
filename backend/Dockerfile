# Pinned minor version: reproducibility belongs at the image level, which is
# why requirements.txt uses lower bounds rather than exact pins.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first so application edits do not invalidate the install layer.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts

# The service runs unprivileged. It handles attacker-supplied files, so root in
# the container is exactly the wrong default -- a container escape should not
# start from uid 0.
RUN useradd --create-home --uid 10001 sentinel \
    && mkdir -p /app/var/quarantine \
    && chown -R sentinel:sentinel /app
USER sentinel

# Quarantine and database live under /app/var, mounted as a volume in compose.
# Note there is no static file mount anywhere: quarantined uploads are not
# reachable over HTTP by construction, not by configuration.
ENV DATABASE_URL=sqlite:////app/var/sentinelcti.db \
    UPLOAD_DIR=/app/var/quarantine

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
