#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# Build a Termux .deb package for ethsy-connect
# Run on Termux/Linux with: dpkg, dpkg-deb, tar, gzip, go

PKG_NAME="ethsy-connect"
ARCH="${ARCH:-aarch64}"
VERSION="${VERSION:-}"
ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT_DIR="${ROOT_DIR}/packaging/termux/repo"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

if [ -z "$VERSION" ]; then
  VERSION="$(git -C "$ROOT_DIR" describe --tags --always 2>/dev/null | sed 's/^v//' || true)"
fi
if [ -z "$VERSION" ]; then
  VERSION="0.0.0"
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb not found. Install: pkg install -y dpkg"
  exit 1
fi

mkdir -p "$OUT_DIR"
PKG_DIR="$WORK_DIR/${PKG_NAME}_${VERSION}_${ARCH}"
mkdir -p "$PKG_DIR/DEBIAN" "$PKG_DIR/data/data/com.termux/files/usr/bin"

cat > "$PKG_DIR/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: devsigner9920
Depends: openssh, curl
Section: utils
Priority: optional
Homepage: https://github.com/devsigner9920/ethsy-ssh
Description: CLI client for ethsy.me remote tmux sessions
EOF

cat > "$PKG_DIR/DEBIAN/postinst" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
set -e
chmod +x /data/data/com.termux/files/usr/bin/ethsy || true
echo "ethsy-connect installed. Run: ethsy"
EOF
chmod 0755 "$PKG_DIR/DEBIAN/postinst"

# Build binary for Termux target
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$PKG_DIR/data/data/com.termux/files/usr/bin/ethsy" "$ROOT_DIR/connect"
chmod 0755 "$PKG_DIR/data/data/com.termux/files/usr/bin/ethsy"

DEB_PATH="$OUT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --build "$PKG_DIR" "$DEB_PATH" >/dev/null

echo "Built: $DEB_PATH"