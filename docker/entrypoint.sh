#!/bin/sh
# goose-web container entrypoint: first start creates the database and the admin, then runs the command.
#   GOOSE_WEB_ADMIN        admin username            (default: admin)
#   GOOSE_WEB_NATIVE_ROOT  admin's Goose profile dir (default: fresh -> /data/appdata; mount an existing
#                          Goose profile with config/ data/ state/ and point this at it to reuse it)
set -eu

if [ "$(id -u)" = "0" ]; then
  echo "goose-web: refusing to run as root; use the image's default user (uid 1000)." >&2
  exit 3
fi

umask 077
mkdir -p /data/workspace
if [ ! -f /data/_system/goose-web.db ]; then
  echo "goose-web: first start - initialising /data"
  python -m goose_web init --admin "${GOOSE_WEB_ADMIN:-admin}" --native-root "${GOOSE_WEB_NATIVE_ROOT:-fresh}"
fi

if [ "$#" -eq 0 ]; then
  set -- serve
fi
case "$1" in
  serve|init|user|check|version) exec python -m goose_web "$@" ;;
  *) exec "$@" ;;
esac
