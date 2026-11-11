#!/bin/sh
# Container entrypoint: prepare writable state, bootstrap the ClamAV signature
# database on first boot, then hand over to the lsec daemon.
set -eu

mkdir -p /data/logs /data/evidence /data/quarantine /data/secrets /data/clamav \
         /run/clamav /var/lib/clamav /scan
chmod 0700 /data/secrets /data/evidence /data/quarantine 2>/dev/null || true

# Require both the main and daily databases. Checking for any *.cvd would treat
# an interrupted first boot (daily downloaded, main still missing) as complete
# and skip the retry on the next container start.
has_main=0
has_daily=0
for candidate in /var/lib/clamav/main.cvd /var/lib/clamav/main.cld; do
    [ -e "$candidate" ] && has_main=1
done
for candidate in /var/lib/clamav/daily.cvd /var/lib/clamav/daily.cld; do
    [ -e "$candidate" ] && has_daily=1
done

if [ "$has_main" -eq 0 ] || [ "$has_daily" -eq 0 ]; then
    echo "lsec: 未找到 ClamAV 病毒库，首次启动前下载（可能需要数分钟）…" >&2
    if freshclam --datadir=/var/lib/clamav --stdout; then
        echo "lsec: 病毒库下载完成" >&2
    else
        echo "lsec: 病毒库下载失败；守护进程仍会启动，可在 Web 界面中重试更新" >&2
    fi
fi

exec python3 -m lsec.daemon "$@"
