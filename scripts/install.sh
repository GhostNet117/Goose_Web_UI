#!/usr/bin/env bash
# Installs Goose AI Web Interface for the CURRENT (non-root) user on Linux or macOS.
#   ./scripts/install.sh [--profiles-root DIR] [--goose-appdata DIR|fresh] [--host H] [--port P]
#                        [--public-url URL] [--trusted-proxy IP]... [--systemd]
# The admin is $USER with password ChangeMe (forced change at first sign-in).
# On Linux/macOS the admin starts with a fresh profile under <profiles-root>/appdata unless --goose-appdata
# points at a folder that contains config/ data/ state/ (a GOOSE_PATH_ROOT style layout).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROFILES_ROOT="${HOME}/.local/share/goose-web"
NATIVE="auto"
HOST="127.0.0.1"
PORT=8710
PUBLIC_URL=""
PROXIES=()
SYSTEMD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --profiles-root) PROFILES_ROOT="$2"; shift 2 ;;
    --goose-appdata) NATIVE="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --public-url) PUBLIC_URL="$2"; shift 2 ;;
    --trusted-proxy) PROXIES+=("$2"); shift 2 ;;
    --systemd) SYSTEMD=1; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" = "0" ]; then
  echo "Run this as the normal user that uses goose, not as root." >&2
  exit 3
fi
command -v goose >/dev/null 2>&1 || {
  echo "goose CLI not found on PATH. Install it first:" >&2
  echo "  curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash" >&2
  exit 1
}

cd "$ROOT"
if [ ! -x .venv/bin/python ]; then
  if command -v uv >/dev/null 2>&1; then uv venv --python 3.13 .venv || uv venv .venv
  else python3 -m venv .venv; fi
fi
if command -v uv >/dev/null 2>&1; then uv pip install --python .venv/bin/python -e .
else .venv/bin/python -m pip install --upgrade pip && .venv/bin/python -m pip install -e .; fi

SYS="$PROFILES_ROOT/_system"
CFG="$SYS/config.yaml"
mkdir -p "$SYS"
chmod 700 "$PROFILES_ROOT"
if [ ! -f "$CFG" ]; then
  {
    echo "server:"
    echo "  host: \"$HOST\""
    echo "  port: $PORT"
    echo "  public_url: \"$PUBLIC_URL\""
    echo "  trusted_proxies: [\"127.0.0.1\", \"::1\"$(for p in "${PROXIES[@]:-}"; do [ -n "$p" ] && printf ', "%s"' "$p"; done)]"
    echo "paths:"
    echo "  profiles_root: \"$PROFILES_ROOT\""
    echo "goose:"
    echo "  binary: \"$(command -v goose)\""
    echo "  native_scheduler: auto"
  } > "$CFG"
  echo "==> wrote $CFG"
fi

.venv/bin/python -m goose_web --config "$CFG" init --admin "${USER:-admin}" --native-root "$NATIVE"
.venv/bin/python -m goose_web --config "$CFG" check || true

if [ "$SYSTEMD" = 1 ]; then
  UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/goose-web.service" <<EOF
[Unit]
Description=Goose AI Web Interface
After=network-online.target

[Service]
WorkingDirectory=$ROOT
ExecStart=$ROOT/.venv/bin/python -m goose_web --config $CFG serve
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now goose-web.service
  echo "==> systemd user service goose-web enabled (run 'loginctl enable-linger $USER' to start it at boot)"
fi

echo
echo "Done. Start with: .venv/bin/python -m goose_web --config \"$CFG\" serve"
echo "Then open http://$HOST:$PORT and sign in as '${USER:-admin}' / 'ChangeMe'."
