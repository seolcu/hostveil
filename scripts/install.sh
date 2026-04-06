#!/usr/bin/env bash
set -euo pipefail

REPO="${HOSTVEIL_REPO:-seolcu/hostveil}"
CHANNEL="${HOSTVEIL_CHANNEL:-preview}"
INSTALL_DIR="${HOSTVEIL_INSTALL_DIR:-}"
DOWNLOAD_BASE_URL="${HOSTVEIL_DOWNLOAD_BASE_URL:-}"
REQUESTED_VERSION=""

usage() {
  cat <<'EOF'
Install hostveil from GitHub Releases.

Usage:
  install.sh [--version TAG] [--channel preview|stable] [--to DIR]

Options:
  --version TAG   install a specific release tag such as v0.1.0-alpha.1
  --channel NAME  choose preview or stable when --version is omitted
  --to DIR        install into a specific binary directory
  -h, --help      show this help message
EOF
}

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --version)
      (($# >= 2)) || fail "missing value for --version"
      REQUESTED_VERSION="$2"
      shift 2
      ;;
    --channel)
      (($# >= 2)) || fail "missing value for --channel"
      CHANNEL="$2"
      shift 2
      ;;
    --to)
      (($# >= 2)) || fail "missing value for --to"
      INSTALL_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

case "$CHANNEL" in
  preview|stable) ;;
  *) fail "unsupported channel: $CHANNEL" ;;
esac

if command -v curl >/dev/null 2>&1; then
  fetch_to_file() {
    curl -fsSL "$1" -o "$2"
  }
  fetch_to_stdout() {
    curl -fsSL "$1"
  }
elif command -v wget >/dev/null 2>&1; then
  fetch_to_file() {
    wget -qO "$2" "$1"
  }
  fetch_to_stdout() {
    wget -qO- "$1"
  }
else
  fail "curl or wget is required"
fi

extract_checksum_hash() {
  local checksums_file="$1"
  local archive_name="$2"

  awk -v archive="$archive_name" '
    NF >= 2 {
      path = $2
      if (path == archive || path == ("./" archive) || path == ("dist/" archive)) {
        print $1
        exit
      }
    }
  ' "$checksums_file"
}

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() {
    sha256sum "$1" | awk '{print $1}'
  }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() {
    shasum -a 256 "$1" | awk '{print $1}'
  }
else
  fail "sha256sum or shasum is required"
fi

verify_checksum() {
  local checksums_file="$1"
  local archive_name="$2"
  local archive_path="$3"
  local expected_hash
  local actual_hash

  expected_hash="$(extract_checksum_hash "$checksums_file" "$archive_name")"
  [[ -n "$expected_hash" ]] || fail "no checksum entry found for ${archive_name}"

  actual_hash="$(hash_file "$archive_path")"
  [[ "$actual_hash" == "$expected_hash" ]] || fail "checksum verification failed for ${archive_name}"
}

normalize_version() {
  if [[ "$1" == v* ]]; then
    printf '%s\n' "$1"
  else
    printf 'v%s\n' "$1"
  fi
}

extract_first_tag() {
  sed -n 's/.*"tag_name":"\([^"]*\)".*/\1/p' | head -n 1
}

resolve_version() {
  if [[ -n "$REQUESTED_VERSION" ]]; then
    normalize_version "$REQUESTED_VERSION"
    return
  fi

  if [[ "$CHANNEL" == "stable" ]]; then
    if tag_json="$(fetch_to_stdout "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null)"; then
      tag_name="$(printf '%s\n' "$tag_json" | extract_first_tag)"
      [[ -n "$tag_name" ]] || fail "failed to resolve the latest stable release"
      printf '%s\n' "$tag_name"
      return
    fi

    log "No stable release was found; falling back to the latest preview release."
  fi

  tag_json="$(fetch_to_stdout "https://api.github.com/repos/${REPO}/releases?per_page=1")"
  tag_name="$(printf '%s\n' "$tag_json" | extract_first_tag)"
  [[ -n "$tag_name" ]] || fail "failed to resolve the latest preview release"
  printf '%s\n' "$tag_name"
}

detect_target() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf '%s\n' "x86_64-unknown-linux-gnu"
      ;;
    aarch64|arm64)
      printf '%s\n' "aarch64-unknown-linux-gnu"
      ;;
    *)
      fail "unsupported architecture: $(uname -m)"
      ;;
  esac
}

resolve_install_dir() {
  if [[ -n "$INSTALL_DIR" ]]; then
    printf '%s\n' "$INSTALL_DIR"
    return
  fi

  if [[ -d "/usr/local/bin" && -w "/usr/local/bin" ]]; then
    printf '%s\n' "/usr/local/bin"
  else
    printf '%s\n' "${HOME}/.local/bin"
  fi
}

tag="$(resolve_version)"
target="$(detect_target)"
install_dir="$(resolve_install_dir)"
archive_name="hostveil-${tag}-${target}.tar.gz"

if [[ -n "$DOWNLOAD_BASE_URL" ]]; then
  download_base_url="$DOWNLOAD_BASE_URL"
else
  download_base_url="https://github.com/${REPO}/releases/download/${tag}"
fi

archive_url="${download_base_url}/${archive_name}"
checksums_url="${download_base_url}/SHA256SUMS"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

mkdir -p "$install_dir"
[[ -w "$install_dir" ]] || fail "install directory is not writable: ${install_dir}"

log "Downloading ${archive_name}"
fetch_to_file "$archive_url" "$tmpdir/$archive_name"
fetch_to_file "$checksums_url" "$tmpdir/SHA256SUMS"
verify_checksum "$tmpdir/SHA256SUMS" "$archive_name" "$tmpdir/$archive_name"

mkdir -p "$tmpdir/extract"
tar -xzf "$tmpdir/$archive_name" -C "$tmpdir/extract"
[[ -f "$tmpdir/extract/hostveil" ]] || fail "release archive does not contain the hostveil binary"

install -m 0755 "$tmpdir/extract/hostveil" "$install_dir/hostveil"

log "Installed hostveil ${tag} to ${install_dir}/hostveil"
if [[ ":$PATH:" != *":${install_dir}:"* ]]; then
  log "Note: ${install_dir} is not currently on PATH."
fi
