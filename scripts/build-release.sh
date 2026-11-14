#!/bin/sh
# Build the architecture-independent lsec .deb, a source archive, SHA256SUMS and
# optional detached GPG signatures. Must run on Linux (dpkg-deb required).
#
# Usage:
#   scripts/build-release.sh [--sign-key KEYID]
#   LSEC_GPG_KEY=KEYID scripts/build-release.sh
#
# Outputs (in dist/):
#   lsec_<version>_all.deb
#   lsec-<version>-source.tar.gz
#   SHA256SUMS
#   lsec_<version>_all.deb.asc        (when signing)
#   SHA256SUMS.asc                    (when signing)
#   BUILD-MANIFEST.txt                (tool versions and build inputs)
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST="$ROOT/dist"
VERSION=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$ROOT/src/lsec/__init__.py")
SIGN_KEY=${LSEC_GPG_KEY:-}

while [ $# -gt 0 ]; do
    case "$1" in
        --sign-key)
            [ $# -ge 2 ] || { echo "missing --sign-key argument" >&2; exit 2; }
            SIGN_KEY=$2
            shift 2
            ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

[ -n "$VERSION" ] || { echo "cannot read version from src/lsec/__init__.py" >&2; exit 1; }
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required (build on Debian/Ubuntu)" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

# Refuse to build from a tree with syntax errors.
PYTHONPATH="$ROOT/src" python3 -m compileall -q "$ROOT/src" >/dev/null

STAGE=$(mktemp -d)
# mktemp creates 0700; the package root entry should be a normal 0755 directory.
chmod 0755 "$STAGE"
trap 'rm -rf "$STAGE"' EXIT INT TERM

install -d "$STAGE/usr/lib/lsec/src" "$STAGE/usr/bin" "$STAGE/etc/lsec" \
    "$STAGE/lib/systemd/system" "$STAGE/usr/share/doc/lsec" "$STAGE/DEBIAN"
cp -a "$ROOT/src/lsec" "$STAGE/usr/lib/lsec/src/"
find "$STAGE/usr/lib/lsec/src" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$STAGE/usr/lib/lsec/src" -type f -name '*.pyc' -delete

cat > "$STAGE/usr/bin/lsec" <<'LAUNCHER'
#!/bin/sh
PYTHONDONTWRITEBYTECODE=1
PYTHONPATH=/usr/lib/lsec/src${PYTHONPATH:+:$PYTHONPATH}
export PYTHONDONTWRITEBYTECODE PYTHONPATH
exec python3 -m lsec.cli "$@"
LAUNCHER
cat > "$STAGE/usr/bin/lsec-daemon" <<'LAUNCHER'
#!/bin/sh
PYTHONDONTWRITEBYTECODE=1
PYTHONPATH=/usr/lib/lsec/src${PYTHONPATH:+:$PYTHONPATH}
export PYTHONDONTWRITEBYTECODE PYTHONPATH
exec python3 -m lsec.daemon "$@"
LAUNCHER
chmod 0755 "$STAGE/usr/bin/lsec" "$STAGE/usr/bin/lsec-daemon"

install -m 0644 "$ROOT/packaging/debian/lsec.toml" "$STAGE/etc/lsec/lsec.toml"
install -m 0644 "$ROOT/packaging/debian/lsec.service" "$STAGE/lib/systemd/system/lsec.service"
install -m 0644 "$ROOT/packaging/debian/copyright" "$STAGE/usr/share/doc/lsec/copyright"
install -m 0644 "$ROOT/README.md" "$STAGE/usr/share/doc/lsec/README.md"
install -m 0644 "$ROOT/README.zh-CN.md" "$STAGE/usr/share/doc/lsec/README.zh-CN.md"
cp -a "$ROOT/docs" "$STAGE/usr/share/doc/lsec/docs"
find "$STAGE/usr/share/doc/lsec/docs" -type d -name __pycache__ -prune -exec rm -rf {} +

install -m 0755 "$ROOT/packaging/debian/postinst" "$STAGE/DEBIAN/postinst"
install -m 0755 "$ROOT/packaging/debian/prerm" "$STAGE/DEBIAN/prerm"
install -m 0755 "$ROOT/packaging/debian/postrm" "$STAGE/DEBIAN/postrm"

INSTALLED_SIZE=$(du -sk "$STAGE/usr" | awk '{print $1}')
sed -e "s/__VERSION__/$VERSION/" \
    -e "s/__INSTALLED_SIZE__/$INSTALLED_SIZE/" \
    "$ROOT/packaging/debian/control.in" > "$STAGE/DEBIAN/control"
echo "/etc/lsec/lsec.toml" > "$STAGE/DEBIAN/conffiles"

( cd "$STAGE" && find usr etc lib -type f -print0 | xargs -0 md5sum ) > "$STAGE/DEBIAN/md5sums"
chmod 0644 "$STAGE/DEBIAN/control" "$STAGE/DEBIAN/conffiles" "$STAGE/DEBIAN/md5sums"

mkdir -p "$DIST"
DEB="$DIST/lsec_${VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB" >/dev/null

# Source archive: everything needed to rebuild and audit this release.
SOURCE="$DIST/lsec-${VERSION}-source.tar.gz"
tar -C "$ROOT" -czf "$SOURCE" \
    --exclude='__pycache__' --exclude='*.pyc' \
    src tests docs scripts packaging .github \
    README.md README.zh-CN.md CHANGELOG.md CHANGELOG.zh-CN.md \
    CONTRIBUTING.md CONTRIBUTING.zh-CN.md \
    CODE_OF_CONDUCT.md CODE_OF_CONDUCT.zh-CN.md \
    LICENSE SECURITY.md SECURITY.zh-CN.md \
    requirements.txt requirements-dev.txt .coveragerc .editorconfig \
    docker-compose.yml docker-compose.container.yml

cat > "$DIST/BUILD-MANIFEST.txt" <<EOF
package=lsec
version=$VERSION
built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
built_on=$(uname -srm)
python=$(python3 --version 2>&1)
dpkg_deb=$(dpkg-deb --version | head -n 1)
architecture=all
source_archive=lsec-${VERSION}-source.tar.gz
deb=lsec_${VERSION}_all.deb
signed=$([ -n "$SIGN_KEY" ] && echo yes || echo no)
gpg_key=${SIGN_KEY:-none}
EOF

( cd "$DIST" && sha256sum "lsec_${VERSION}_all.deb" "lsec-${VERSION}-source.tar.gz" > SHA256SUMS )

if [ -n "$SIGN_KEY" ]; then
    command -v gpg >/dev/null 2>&1 || { echo "gpg is required for signing" >&2; exit 1; }
    gpg --batch --yes --armor --local-user "$SIGN_KEY" \
        --output "$DEB.asc" --detach-sign "$DEB"
    gpg --batch --yes --armor --local-user "$SIGN_KEY" \
        --output "$DIST/SHA256SUMS.asc" --detach-sign "$DIST/SHA256SUMS"
    gpg --verify "$DEB.asc" "$DEB" >/dev/null
    gpg --verify "$DIST/SHA256SUMS.asc" "$DIST/SHA256SUMS" >/dev/null
fi

echo "Build complete:"
echo "  $DEB"
echo "  $SOURCE"
echo "  $DIST/SHA256SUMS"
if [ -n "$SIGN_KEY" ]; then echo "  $DEB.asc + SHA256SUMS.asc"; fi
dpkg-deb --info "$DEB" | sed -n '1,20p'
