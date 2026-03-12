#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# Configure custom Termux repo and install ethsy-connect
# Usage: REPO_BASE_URL=https://<your-host>/termux ./install-from-custom-repo.sh

REPO_BASE_URL="${REPO_BASE_URL:-}"
if [ -z "$REPO_BASE_URL" ]; then
  echo "Set REPO_BASE_URL. Example:"
  echo "  REPO_BASE_URL=https://<your-domain>/termux ./install-from-custom-repo.sh"
  exit 1
fi

mkdir -p "$PREFIX/etc/apt/sources.list.d"
cat > "$PREFIX/etc/apt/sources.list.d/ethsy.list" <<EOF
deb [trusted=yes] ${REPO_BASE_URL} ./
EOF

pkg update -y
pkg install -y ethsy-connect

echo "Installed from custom repo: ethsy-connect"