#!/usr/bin/env bash
set -euo pipefail

REPO="seolcu/hostveil"
VERSION="${1:-latest}"
INSTALL_DIR="${2:-/usr/local/bin}"

if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d '"' -f 4)
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

URL="https://github.com/$REPO/releases/download/$VERSION/hostveil_${VERSION#v}_${OS}_${ARCH}"

echo "Downloading hostveil $VERSION for $OS/$ARCH..."
curl -fsSL "$URL" -o "$INSTALL_DIR/hostveil"
chmod +x "$INSTALL_DIR/hostveil"

echo "Installed hostveil $VERSION to $INSTALL_DIR/hostveil"
echo "Run 'hostveil --help' to get started."
