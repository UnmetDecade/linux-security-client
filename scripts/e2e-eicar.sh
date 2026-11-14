#!/bin/sh
# Real end-to-end check against a running Docker deployment.
# Requires: docker compose stack is up and ClamAV is ready.
set -eu
cd "$(dirname "$0")/.."

if ! docker compose ps --status running --services 2>/dev/null | grep -qx lsec; then
    echo "lsec container is not running; run: docker compose up -d" >&2
    exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf '%s' 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=' \
    | base64 -d > "$tmp"
printf '\n' >> "$tmp"
docker compose cp "$tmp" lsec:/scan/eicar-e2e.txt

echo "== Component status =="
docker compose exec -T lsec lsec components list

echo "== Quick scan (wait for completion) =="
docker compose exec -T lsec lsec scan quick --wait

echo "== Recent events =="
docker compose exec -T lsec lsec events list --limit 5

echo "== Recent tasks =="
docker compose exec -T lsec lsec task list --limit 5

echo "Done. The file remains at /scan/eicar-e2e.txt in the container; isolate it manually from the web UI to verify."
