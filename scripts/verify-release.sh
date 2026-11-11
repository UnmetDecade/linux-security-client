#!/bin/sh
# Verify a built release: SHA256SUMS, optional GPG signatures and package
# metadata. Usage: scripts/verify-release.sh [dist-dir]
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST=${1:-"$ROOT/dist"}
[ -d "$DIST" ] || { echo "找不到发布目录: $DIST" >&2; exit 1; }
cd "$DIST"

[ -f SHA256SUMS ] || { echo "缺少 SHA256SUMS" >&2; exit 1; }
sha256sum -c SHA256SUMS

if [ -f SHA256SUMS.asc ]; then
    command -v gpg >/dev/null 2>&1 || { echo "需要 gpg 验证签名" >&2; exit 1; }
    gpg --verify SHA256SUMS.asc SHA256SUMS
else
    echo "提示: 未找到 SHA256SUMS.asc（该构建未签名）" >&2
fi

for deb in *.deb; do
    [ -f "$deb" ] || continue
    if [ -f "$deb.asc" ]; then
        command -v gpg >/dev/null 2>&1 || { echo "需要 gpg 验证签名" >&2; exit 1; }
        gpg --verify "$deb.asc" "$deb"
    fi
    dpkg-deb --info "$deb"
done

cat BUILD-MANIFEST.txt 2>/dev/null || true
