# syntax=docker/dockerfile:1

# ---- Build stage: install dependencies into an isolated virtualenv ----
FROM python:3.13-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY requirements.txt .
# pip is not needed at runtime: removing it from the venv also removes its
# vendored libraries (urllib3, certifi, ...) from the image attack surface.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install -r requirements.txt \
    && /opt/venv/bin/pip uninstall -y pip

# ---- Runtime stage: minimal, non-root image ----
FROM python:3.13-slim

LABEL org.opencontainers.image.title="secureship-demo-api" \
      org.opencontainers.image.description="Flask demo app scanned by the DevSecOps pipeline" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_ENV=production \
    PORT=8080

# Strip the system-wide pip (and its vendored dependencies) and create a dedicated non-root user
RUN python -m pip uninstall -y pip setuptools wheel \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=app:app app.py .

USER app
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status == 200 else 1)"]

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--access-logfile", "-", "app:app"]
