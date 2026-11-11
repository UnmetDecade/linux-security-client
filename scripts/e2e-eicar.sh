#!/bin/sh
# Real end-to-end check against a running Docker deployment.
# Requires: docker compose stack is up and ClamAV is ready.
set -eu
cd "$(dirname "$0")/.."

if ! docker compose ps --status running --services 2>/dev/null | grep -qx lsec; then
    echo "lsec 容器未运行，请先执行: docker compose up -d" >&2
    exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf '%s' 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=' \
    | base64 -d > "$tmp"
printf '\n' >> "$tmp"
docker compose cp "$tmp" lsec:/scan/eicar-e2e.txt

echo "== 组件状态 =="
docker compose exec -T lsec lsec components list

echo "== 快速扫描（等待完成） =="
docker compose exec -T lsec lsec scan quick --wait

echo "== 最近事件 =="
docker compose exec -T lsec lsec events list --limit 5

echo "== 最近任务 =="
docker compose exec -T lsec lsec task list --limit 5

echo "完成。文件保留在容器的 /scan/eicar-e2e.txt，可在 Web 界面手动隔离验证。"
