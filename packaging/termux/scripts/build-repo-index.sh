#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# Generate Termux apt repo metadata in packaging/termux/repo
# Requires: dpkg-scanpackages (pkg install dpkg-dev)

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
REPO_DIR="${ROOT_DIR}/packaging/termux/repo"

cd "$REPO_DIR"

if ! command -v dpkg-scanpackages >/dev/null 2>&1; then
  echo "dpkg-scanpackages not found. Install: pkg install -y dpkg-dev"
  exit 1
fi

rm -f Packages Packages.gz Release

dpkg-scanpackages . /dev/null > Packages
gzip -9c Packages > Packages.gz

cat > Release <<EOF
Origin: ethsy
Label: ethsy-termux
Suite: stable
Codename: termux
Architectures: aarch64
Components: main
Description: ethsy-connect Termux repository
Date: $(date -Ru)
EOF

echo "Generated: $REPO_DIR/{Packages,Packages.gz,Release}"