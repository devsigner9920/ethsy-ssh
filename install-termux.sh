#!/data/data/com.termux/files/usr/bin/bash
# Termux installer for ethsy-connect
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/devsigner9920/ethsy-ssh/main/install-termux.sh | bash

set -euo pipefail

if [ -z "${TERMUX_VERSION:-}" ] && [ "${PREFIX:-}" != "/data/data/com.termux/files/usr" ]; then
  echo "This installer is intended for Termux."
  exit 1
fi

pkg update -y
pkg install -y curl tar openssh

curl -fsSL https://raw.githubusercontent.com/devsigner9920/ethsy-ssh/main/install.sh | bash

echo
echo "Done. Run: ethsy"
