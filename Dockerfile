# REN gateway image for Deplexo (works on any Docker host too).
# Deplexo runs containers with a read-only root filesystem: only /tmp and the
# persistent data mount (/data by default) are writable, so state goes to /data.

# ---- build stage: produce wheels (compiles psutil if no prebuilt wheel) ----
FROM python:3.11-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY requirements.txt .
RUN pip wheel --wheel-dir /wheels -r requirements.txt

# ---- runtime stage ----
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000 \
    DATA_DIR=/data
WORKDIR /app
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-index --find-links=/wheels -r requirements.txt \
 && rm -rf /wheels

COPY main.py deplexo_main.py ./
COPY static ./static

# Unprivileged user. /data is created and owned by it so a fresh named volume
# mounted there inherits writable ownership.
RUN useradd --system --uid 10001 --no-create-home --home-dir /app --shell /usr/sbin/nologin ren \
 && mkdir -p /data \
 && chown ren:ren /data
USER 10001

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '8000'), timeout=4)"]

# Exec form so the server receives SIGTERM and flushes state on shutdown.
CMD ["python", "deplexo_main.py"]
