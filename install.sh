#!/bin/bash
# ethsy-connect installer for Linux/Termux
# Usage: curl -fsSL https://raw.githubusercontent.com/devsigner9920/ethsy-ssh/main/install.sh | bash

set -e

REPO="devsigner9920/ethsy-ssh"
BINARY="ethsy"

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

case "$OS" in
  linux|darwin) ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

ASSET="ethsy-connect_${OS}_${ARCH}.tar.gz"

echo "Detecting environment: ${OS}/${ARCH}"

# Get latest release tag
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)

if [ -z "$LATEST" ]; then
  echo "Failed to get latest release. Check https://github.com/${REPO}/releases"
  exit 1
fi

echo "Latest version: ${LATEST}"

URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"

# Determine install directory
if [ -n "$PREFIX" ]; then
  # Termux
  INSTALL_DIR="$PREFIX/bin"
elif [ -d "$HOME/.local/bin" ]; then
  INSTALL_DIR="$HOME/.local/bin"
else
  INSTALL_DIR="/usr/local/bin"
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${ASSET}..."
curl -fsSL "$URL" -o "$TMPDIR/$ASSET"

echo "Extracting..."
tar -xzf "$TMPDIR/$ASSET" -C "$TMPDIR"

echo "Installing to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"
mv "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
chmod +x "$INSTALL_DIR/$BINARY"

echo ""
echo "ethsy installed to ${INSTALL_DIR}/${BINARY}"

# Check if install dir is in PATH
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
  echo ""
  echo "Add to PATH:"
  echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

echo ""
echo "Run 'ethsy' to get started!"
