# Multi-stage build for CloudKill (amd64 + arm64)
FROM --platform=$BUILDPLATFORM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY cloudkill/ cloudkill/
COPY config/ config/

# Install the package
RUN pip install --no-cache-dir --user .

# === Runtime Stage ===
FROM python:3.12-slim

LABEL maintainer="smart-jemy"
LABEL org.opencontainers.image.title="CloudKill"
LABEL org.opencontainers.image.description="Advanced origin IP discovery tool for Cloudflare-protected domains"
LABEL org.opencontainers.image.version="0.7.0"
LABEL org.opencontainers.image.source="https://github.com/smart-jemy/cloudfail-killer"
LABEL org.opencontainers.image.licenses="MIT"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed package from builder
COPY --from=builder /root/.local /root/.local

# Copy package data
COPY cloudkill/ /app/cloudkill/
COPY config/ /app/config/
COPY pyproject.toml /app/pyproject.toml

# Set environment
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV CLOUDKILL_IPV6_PREFERENCE=false
ENV CLOUDKILL_CACHE_DIR=/data/.cache/cloudkill

WORKDIR /data

ENTRYPOINT ["cloudkill"]
CMD ["--help"]
