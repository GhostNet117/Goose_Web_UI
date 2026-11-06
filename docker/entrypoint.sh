#!/bin/sh
# goose-web container entrypoint: first start creates the database and the admin, then runs the command.
#   GOOSE_WEB_ADMIN                admin username            (default: admin)
#   GOOSE_WEB_NATIVE_ROOT          admin's Goose profile dir (default: fresh -> /data/appdata; mount an existing
#                                  Goose profile with config/ data/ state/ and point this at it to reuse it)
#   GOOSE_WEB_ADMIN_PASSWORD_FILE  file holding the initial admin password, e.g. /run/secrets/goose_web_admin
#   GOOSE_WEB_ADMIN_PASSWORD       the initial admin password itself (prefer the _FILE variant: plain
#                                  environment variables are visible in `docker inspect`)
# Without either, a random initial password is generated and printed to the container log ONCE, on the first
# start only. Either way it must be changed at the first sign-in. Both variables are only read on the first
# start and are removed from the environment before the gateway starts.
set -eu

if [ "$(id -u)" = "0" ]; then
  echo "goose-web: refusing to run as root; use the image's default user (uid 1000)." >&2
  exit 3
fi

umask 077
mkdir -p /data/workspace
if [ ! -f /data/_system/goose-web.db ]; then
  echo "goose-web: first start - initialising /data"
  admin="${GOOSE_WEB_ADMIN:-admin}"
  native="${GOOSE_WEB_NATIVE_ROOT:-fresh}"
  if [ -n "${GOOSE_WEB_ADMIN_PASSWORD_FILE:-}" ]; then
    if [ ! -r "$GOOSE_WEB_ADMIN_PASSWORD_FILE" ]; then
      echo "goose-web: GOOSE_WEB_ADMIN_PASSWORD_FILE=$GOOSE_WEB_ADMIN_PASSWORD_FILE is not readable" >&2
      exit 2
    fi
    python -m goose_web init --admin "$admin" --native-root "$native" --password-file "$GOOSE_WEB_ADMIN_PASSWORD_FILE"
  elif [ -n "${GOOSE_WEB_ADMIN_PASSWORD:-}" ]; then
    # via stdin, so the password never appears in a process command line
    printf '%s\n' "$GOOSE_WEB_ADMIN_PASSWORD" | python -m goose_web init --admin "$admin" --native-root "$native" --password-file -
  else
    python -m goose_web init --admin "$admin" --native-root "$native"
  fi
fi
unset GOOSE_WEB_ADMIN_PASSWORD GOOSE_WEB_ADMIN_PASSWORD_FILE

if [ "$#" -eq 0 ]; then
  set -- serve
fi
case "$1" in
  serve|init|user|check|version) exec python -m goose_web "$@" ;;
  *) exec "$@" ;;
esac
