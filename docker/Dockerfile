# syntax=docker/dockerfile:1.6
# Goose AI Web Interface - gateway + the goose CLI in one image (Linux, amd64/arm64).
#
#   docker compose -f docker/compose.yaml up -d      (from the repository root)
#
# Everything persistent lives in /data (the profiles root): the database, every user's isolated Goose
# profile, and the admin's profile (/data/appdata unless GOOSE_WEB_NATIVE_ROOT points elsewhere).
#
# Supply chain: the base image is pinned by digest, the goose release tarball is checked against a SHA-256
# per architecture, and the Python dependencies are installed from requirements.lock with --require-hashes.

# Base image: tag for readability, digest for reproducibility (multi-arch index digest, so amd64 and arm64
# both resolve from it). Dependabot (.github/dependabot.yml) proposes digest bumps. To bump by hand:
#   docker buildx imagetools inspect python:3.13-slim-bookworm      (the "Digest:" line)
FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72 AS base

# goose CLI release and the SHA-256 of its two Linux tarballs. To bump goose, change all three together:
#   1. download https://github.com/aaif-goose/goose/releases/download/v<VERSION>/goose-x86_64-unknown-linux-gnu.tar.bz2
#      and .../goose-aarch64-unknown-linux-gnu.tar.bz2
#   2. sha256sum both files (Windows: certutil -hashfile <file> SHA256) and compare with the "digest" GitHub
#      shows for each asset (release page, or `gh release view v<VERSION> -R aaif-goose/goose --json assets`)
#   3. put the values below (and the version in docker/compose.yaml).
# A build with --build-arg GOOSE_VERSION=x.y.z also needs the matching GOOSE_SHA256_AMD64/ARM64 build args,
# otherwise the checksum check fails the build (on purpose).
ARG GOOSE_VERSION=1.57.0
ARG GOOSE_SHA256_AMD64=e54036f3b7f95d3b0d7854c09465af5ef52a28c7fa03d2497d0ea68a6382282d
ARG GOOSE_SHA256_ARM64=17c6b090db6acc5605da904bbe19cc2765bc7a6786019d85a6d0a361de06dbf7
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

# goose CLI from the official release, verified against the pinned SHA-256 before it is unpacked.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=x86_64;  sum="${GOOSE_SHA256_AMD64}" ;; \
      arm64) arch=aarch64; sum="${GOOSE_SHA256_ARM64}" ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    test -n "$sum"; \
    url="https://github.com/aaif-goose/goose/releases/download/v${GOOSE_VERSION}/goose-${arch}-unknown-linux-gnu.tar.bz2"; \
    mkdir -p /tmp/goose; \
    curl -fsSL --proto '=https' --tlsv1.2 "$url" -o /tmp/goose/goose.tar.bz2; \
    echo "${sum}  /tmp/goose/goose.tar.bz2" | sha256sum -c -; \
    tar -xjf /tmp/goose/goose.tar.bz2 -C /tmp/goose; \
    install -m 0755 "$(find /tmp/goose -type f -name goose | head -n1)" /usr/local/bin/goose; \
    rm -rf /tmp/goose; \
    goose --version

WORKDIR /app
# Dependencies first, hash-locked (regenerate requirements.lock with pip-compile, see its header), wheels only;
# then the app itself without dependency resolution.
COPY requirements.lock ./
RUN pip install --require-hashes --only-binary=:all: -r requirements.lock
COPY pyproject.toml README.md LICENSE ./
COPY goose_web ./goose_web
RUN pip install --no-deps . && rm -rf /root/.cache

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
  CMD curl -fsSk https://127.0.0.1:8710/healthz || curl -fsS http://127.0.0.1:8710/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "goose-web-entrypoint"]
CMD ["serve"]

LABEL org.opencontainers.image.title="Goose AI Web Interface" \
      org.opencontainers.image.description="Multi-user web interface for the goose AI agent (goose serve / ACP)" \
      org.opencontainers.image.licenses="Apache-2.0"
