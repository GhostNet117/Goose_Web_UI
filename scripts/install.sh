#!/usr/bin/env bash
# Installs Goose AI Web Interface for the CURRENT (non-root) user on Linux or macOS.
#   ./scripts/install.sh [--profiles-root DIR] [--goose-appdata DIR|fresh] [--host H] [--port P]
#                        [--public-url URL] [--trusted-proxy IP]... [--systemd]
# The admin is $USER with a random initial password that is shown once at the end (forced change at first
# sign-in). Dependencies are installed from requirements.lock with --require-hashes.
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
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
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
# The gateway runs the code and the venv in this folder: nobody but this user may change them
# ("goose-web check" fails while the folder is writable by others).
chmod -R go-w "$ROOT"
if [ ! -x .venv/bin/python ]; then
  if command -v uv >/dev/null 2>&1; then uv venv --python 3.13 .venv || uv venv .venv
  else python3 -m venv .venv; fi
fi
# Dependencies from the hash-locked requirements.lock, then the app itself without dependency resolution.
if command -v uv >/dev/null 2>&1; then
  uv pip install --python .venv/bin/python --require-hashes -r requirements.lock
  uv pip install --python .venv/bin/python --no-deps -e .
else
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/python -m pip install --require-hashes -r requirements.lock
  .venv/bin/python -m pip install --no-deps -e .
fi
chmod -R go-w "$ROOT/.venv"

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

# init prints the generated initial admin password (first install only); keep its output for the end.
if ! INIT_OUT="$(.venv/bin/python -m goose_web --config "$CFG" init --admin "${USER:-admin}" --native-root "$NATIVE")"; then
  printf '%s\n' "$INIT_OUT"
  echo "goose-web init failed." >&2
  exit 1
fi
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
echo "Then open http://$HOST:$PORT and sign in as '${USER:-admin}'."
echo
printf '%s\n' "$INIT_OUT"
case "$INIT_OUT" in
  *"Already initialised"*) echo "(Existing installation: the admin password was not changed.)" ;;
esac
