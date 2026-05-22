#!/usr/bin/env bash
#
# hostveil installer
# Usage: curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash
#        curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash -s -- -v v1.0.0 -d /usr/local/bin
#
set -euo pipefail

REPO="seolcu/hostveil"
BINARY="hostveil"

# Default values
VERSION=""
INSTALL_DIR="/usr/local/bin"

# ---- Argument parsing ----
while getopts "v:d:h" opt; do
  case $opt in
    v) VERSION="$OPTARG" ;;
    d) INSTALL_DIR="$OPTARG" ;;
    h)
      echo "Usage: $0 [-v VERSION] [-d DIR]"
      echo ""
      echo "  -v VERSION  Version tag to install (default: latest GitHub release)"
      echo "  -d DIR      Install directory (default: /usr/local/bin)"
      echo ""
      echo "Environment:"
      echo "  TAG         Version fallback if -v is not given"
      exit 0
      ;;
    *) exit 1 ;;
  esac
done

# ---- TAG env var fallback ----
if [ -z "$VERSION" ] && [ -n "${TAG:-}" ]; then
  VERSION="$TAG"
fi

# ---- Resolve latest version ----
if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
  echo "Fetching latest release from $REPO ..."
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | cut -d '"' -f 4) || true
  if [ -z "$VERSION" ]; then
    echo "Error: Failed to fetch latest version from GitHub API."
    echo "Set the TAG environment variable or pass -v VERSION explicitly."
    exit 1
  fi
  echo "Latest version: $VERSION"
fi

# ---- Normalise version (ensure v prefix) ----
case "$VERSION" in
  v*) ;;
  *) VERSION="v$VERSION" ;;
esac

# ---- OS detection ----
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux|darwin) ;;
  *)
    echo "Error: Unsupported OS: $OS (only linux and darwin are supported)"
    exit 1
    ;;
esac

# ---- Arch detection ----
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Error: Unsupported architecture: $ARCH (only amd64 and arm64 are supported)"
    exit 1
    ;;
esac

# ---- Build download URLs ----
ARCHIVE="hostveil-${VERSION}-${OS}-${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$VERSION/$ARCHIVE"
CHECKSUM_URL="$URL.sha256"

# ---- Create temp directory ----
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# ---- Download archive ----
echo ""
echo "Downloading $ARCHIVE ..."
if ! curl -fsSL "$URL" -o "$TMP_DIR/$ARCHIVE"; then
  echo "Error: Failed to download $URL"
  echo ""
  echo "Possible causes:"
  echo "  • The release $VERSION does not exist"
  echo "  • Your platform ($OS/$ARCH) is not included in this release"
  echo "  • Network connectivity issues"
  echo ""
  echo "Check: https://github.com/$REPO/releases/tag/$VERSION"
  exit 1
fi

# ---- SHA256 verification ----
echo ""
echo "Verifying SHA256 checksum ..."
if ! curl -fsSL "$CHECKSUM_URL" -o "$TMP_DIR/$ARCHIVE.sha256" 2>/dev/null; then
  echo "Warning: Checksum file not found at $CHECKSUM_URL"
  echo "Skipping verification."
else
  EXPECTED=$(tr -d ' \n' < "$TMP_DIR/$ARCHIVE.sha256")
  ACTUAL=""

  if command -v sha256sum &>/dev/null; then
    ACTUAL=$(sha256sum "$TMP_DIR/$ARCHIVE" | awk '{print $1}')
  elif command -v shasum &>/dev/null; then
    ACTUAL=$(shasum -a 256 "$TMP_DIR/$ARCHIVE" | awk '{print $1}')
  else
    echo "Warning: Neither sha256sum nor shasum found. Skipping verification."
    ACTUAL="$EXPECTED"
  fi

  if [ -n "$ACTUAL" ] && [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "Error: SHA256 checksum mismatch!"
    echo "  Expected: $EXPECTED"
    echo "  Actual:   $ACTUAL"
    echo "The download may be corrupted or tampered with."
    exit 1
  fi

  echo "Checksum verified successfully."
fi

# ---- Extract archive ----
echo ""
echo "Extracting $BINARY from archive ..."
tar xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR"

if [ ! -f "$TMP_DIR/$BINARY" ]; then
  echo "Error: Binary '$BINARY' not found inside the archive."
  ls -la "$TMP_DIR/"
  exit 1
fi

# ---- Install ----
echo ""
if [ -w "$INSTALL_DIR" ]; then
  cp "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
  chmod +x "$INSTALL_DIR/$BINARY"
  echo "Installed $BINARY $VERSION → $INSTALL_DIR/$BINARY"
else
  echo "$INSTALL_DIR is not writable; attempting sudo ..."
  sudo cp "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
  sudo chmod +x "$INSTALL_DIR/$BINARY"
  echo "Installed $BINARY $VERSION → $INSTALL_DIR/$BINARY (with sudo)"
fi

# ---- Verify ----
echo ""
echo "Verifying installation ..."
"$INSTALL_DIR/$BINARY" --version

echo ""
echo "✓ hostveil $VERSION installed successfully!"
echo "Run '$BINARY --help' to get started."
