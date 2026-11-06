# syntax=docker/dockerfile:1.6
# Goose AI Web Interface - gateway + the goose CLI in one image (Linux, amd64/arm64).
#
#   docker compose -f docker/compose.yaml up -d      (from the repository root)
#
# Everything persistent lives in /data (the profiles root): the database, every user's isolated Goose
# profile, and the admin's profile (/data/appdata unless GOOSE_WEB_NATIVE_ROOT points elsewhere).

ARG PYTHON_VERSION=3.13

FROM python:${PYTHON_VERSION}-slim-bookworm AS base
ARG GOOSE_VERSION=1.57.0
ARG TARGETARCH

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Runtime deps for goose (TLS, dbus for keyring probing, libgomp for local inference) and for common
# MCP extensions (git, curl). tini reaps zombie MCP processes.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl bzip2 git tini libssl3 libdbus-1-3 libgomp1 libxcb1 \
 && rm -rf /var/lib/apt/lists/*

# goose CLI from the official release (pin with --build-arg GOOSE_VERSION=x.y.z)
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in amd64) arch=x86_64 ;; arm64) arch=aarch64 ;; *) echo "unsupported arch ${TARGETARCH}"; exit 1 ;; esac; \
    url="https://github.com/aaif-goose/goose/releases/download/v${GOOSE_VERSION}/goose-${arch}-unknown-linux-gnu.tar.bz2"; \
    mkdir -p /tmp/goose; curl -fsSL "$url" -o /tmp/goose/goose.tar.bz2; \
    tar -xjf /tmp/goose/goose.tar.bz2 -C /tmp/goose; \
    install -m 0755 "$(find /tmp/goose -type f -name goose | head -n1)" /usr/local/bin/goose; \
    rm -rf /tmp/goose; \
    goose --version

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY goose_web ./goose_web
RUN pip install . && rm -rf /root/.cache

# Unprivileged runtime user; the gateway refuses to run as root.
RUN useradd --create-home --uid 1000 --shell /bin/bash goose \
 && mkdir -p /data && chown goose:goose /data
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/goose-web-entrypoint

USER goose
ENV HOME=/home/goose \
    GOOSE_WEB__SERVER__HOST=0.0.0.0 \
    GOOSE_WEB__SERVER__PORT=8710 \
    GOOSE_WEB__PATHS__PROFILES_ROOT=/data \
    GOOSE_WEB__GOOSE__BINARY=/usr/local/bin/goose \
    GOOSE_WEB__GOOSE__NATIVE_SCHEDULER=on \
    GOOSE_WEB__GOOSE__DEFAULT_WORKDIR_NATIVE=/data/workspace \
    GOOSE_DISABLE_KEYRING=1

VOLUME ["/data"]
EXPOSE 8710
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8710/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "goose-web-entrypoint"]
CMD ["serve"]

LABEL org.opencontainers.image.title="Goose AI Web Interface" \
      org.opencontainers.image.description="Multi-user web interface for the goose AI agent (goose serve / ACP)" \
      org.opencontainers.image.licenses="Apache-2.0"
