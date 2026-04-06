#!/usr/bin/env bash
set -euo pipefail

if [[ -n ${HOSTVEIL_REPO+x} ]]; then
  REPO="$HOSTVEIL_REPO"
  REPO_SET=1
else
  REPO="seolcu/hostveil"
  REPO_SET=0
fi

if [[ -n ${HOSTVEIL_CHANNEL+x} ]]; then
  CHANNEL="$HOSTVEIL_CHANNEL"
  CHANNEL_SET=1
else
  CHANNEL="preview"
  CHANNEL_SET=0
fi

if [[ -n ${HOSTVEIL_INSTALL_DIR+x} ]]; then
  INSTALL_DIR="$HOSTVEIL_INSTALL_DIR"
  INSTALL_DIR_SET=1
else
  INSTALL_DIR=""
  INSTALL_DIR_SET=0
fi

if [[ -n ${HOSTVEIL_INSTALLER_URL+x} ]]; then
  INSTALLER_URL="$HOSTVEIL_INSTALLER_URL"
  INSTALLER_URL_SET=1
else
  INSTALLER_URL=""
  INSTALLER_URL_SET=0
fi

DOWNLOAD_BASE_URL="${HOSTVEIL_DOWNLOAD_BASE_URL:-}"
STATE_DIR="${HOSTVEIL_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/hostveil}"

WRAPPER_NAME="hostveil"
BINARY_NAME="hostveil-bin"
METADATA_PATH="$STATE_DIR/install.env"
MANAGER_SCRIPT_PATH="$STATE_DIR/manage.sh"

REQUESTED_VERSION=""
ACTION="install"
AUTO_UPGRADE_SETTING="enabled"
metadata_loaded=0

usage() {
  cat <<'EOF'
Manage hostveil Linux installs from GitHub Releases.

Usage:
  install.sh [--channel preview|stable] [--version TAG] [--to DIR]
  install.sh --upgrade [--channel preview|stable] [--version TAG] [--to DIR]
  install.sh --disable-auto-upgrade
  install.sh --enable-auto-upgrade
  install.sh --uninstall [--to DIR]

Options:
  --version TAG            install or upgrade to a specific release tag
  --channel NAME           choose preview or stable when --version is omitted
  --to DIR                 install into a specific binary directory
  --upgrade                upgrade an existing install using saved metadata
  --disable-auto-upgrade   stop checking for upgrades when hostveil launches
  --enable-auto-upgrade    resume checking for upgrades when hostveil launches
  --uninstall              remove hostveil and related lifecycle files
  -h, --help               show this help message
EOF
}

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

set_action() {
  local next_action="$1"

  if [[ "$ACTION" != "install" ]]; then
    fail "choose only one lifecycle action"
  fi

  ACTION="$next_action"
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
      CHANNEL_SET=1
      shift 2
      ;;
    --to)
      (($# >= 2)) || fail "missing value for --to"
      INSTALL_DIR="$2"
      INSTALL_DIR_SET=1
      shift 2
      ;;
    --upgrade)
      set_action "upgrade"
      shift
      ;;
    --disable-auto-upgrade)
      set_action "disable-auto-upgrade"
      shift
      ;;
    --enable-auto-upgrade)
      set_action "enable-auto-upgrade"
      shift
      ;;
    --uninstall)
      set_action "uninstall"
      shift
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
  sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

resolve_latest_stable_api_url() {
  if [[ -n ${HOSTVEIL_LATEST_STABLE_API_URL+x} ]]; then
    printf '%s\n' "$HOSTVEIL_LATEST_STABLE_API_URL"
  else
    printf 'https://api.github.com/repos/%s/releases/latest\n' "$REPO"
  fi
}

resolve_releases_api_url() {
  if [[ -n ${HOSTVEIL_RELEASES_API_URL+x} ]]; then
    printf '%s\n' "$HOSTVEIL_RELEASES_API_URL"
  else
    printf 'https://api.github.com/repos/%s/releases?per_page=1\n' "$REPO"
  fi
}

resolve_version() {
  local tag_json
  local tag_name

  if [[ -n "$REQUESTED_VERSION" ]]; then
    normalize_version "$REQUESTED_VERSION"
    return
  fi

  if [[ "$CHANNEL" == "stable" ]]; then
    if tag_json="$(fetch_to_stdout "$(resolve_latest_stable_api_url)" 2>/dev/null)"; then
      tag_name="$(printf '%s\n' "$tag_json" | extract_first_tag)"
      [[ -n "$tag_name" ]] || fail "failed to resolve the latest stable release"
      printf '%s\n' "$tag_name"
      return
    fi

    log "No stable release was found; falling back to the latest preview release."
  fi

  tag_json="$(fetch_to_stdout "$(resolve_releases_api_url)")"
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

resolve_download_base_url() {
  local tag="$1"

  if [[ -n "$DOWNLOAD_BASE_URL" ]]; then
    printf '%s\n' "$DOWNLOAD_BASE_URL"
  else
    printf 'https://github.com/%s/releases/download/%s\n' "$REPO" "$tag"
  fi
}

resolve_installer_url() {
  if [[ -n "$INSTALLER_URL" ]]; then
    printf '%s\n' "$INSTALLER_URL"
  else
    printf 'https://raw.githubusercontent.com/%s/main/scripts/install.sh\n' "$REPO"
  fi
}

resolve_wrapper_path() {
  printf '%s/%s\n' "$INSTALL_DIR" "$WRAPPER_NAME"
}

resolve_binary_path() {
  printf '%s/%s\n' "$INSTALL_DIR" "$BINARY_NAME"
}

load_metadata_if_present() {
  if [[ -f "$METADATA_PATH" ]]; then
    # shellcheck disable=SC1090
    source "$METADATA_PATH"
    metadata_loaded=1
  fi
}

apply_metadata_defaults() {
  if (( metadata_loaded == 0 )); then
    return
  fi

  if (( REPO_SET == 0 )) && [[ -n "${HOSTVEIL_META_REPO:-}" ]]; then
    REPO="$HOSTVEIL_META_REPO"
  fi
  if (( CHANNEL_SET == 0 )) && [[ -n "${HOSTVEIL_META_CHANNEL:-}" ]]; then
    CHANNEL="$HOSTVEIL_META_CHANNEL"
  fi
  if (( INSTALL_DIR_SET == 0 )) && [[ -n "${HOSTVEIL_META_INSTALL_DIR:-}" ]]; then
    INSTALL_DIR="$HOSTVEIL_META_INSTALL_DIR"
  fi
  if (( INSTALLER_URL_SET == 0 )) && [[ -n "${HOSTVEIL_META_INSTALLER_URL:-}" ]]; then
    INSTALLER_URL="$HOSTVEIL_META_INSTALLER_URL"
  fi
  if [[ -n "${HOSTVEIL_META_AUTO_UPGRADE:-}" ]]; then
    AUTO_UPGRADE_SETTING="$HOSTVEIL_META_AUTO_UPGRADE"
  fi
}

detect_installed_entrypoint_path() {
  local candidate

  if (( metadata_loaded == 1 )); then
    if [[ -n "${HOSTVEIL_META_WRAPPER_PATH:-}" ]] && [[ -x "$HOSTVEIL_META_WRAPPER_PATH" ]]; then
      printf '%s\n' "$HOSTVEIL_META_WRAPPER_PATH"
      return
    fi
    if [[ -n "${HOSTVEIL_META_BINARY_PATH:-}" ]] && [[ -x "$HOSTVEIL_META_BINARY_PATH" ]]; then
      printf '%s\n' "$HOSTVEIL_META_BINARY_PATH"
      return
    fi
  fi

  if [[ -n "$INSTALL_DIR" ]]; then
    candidate="$(resolve_wrapper_path)"
    if [[ -x "$candidate" || -e "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi

    candidate="$(resolve_binary_path)"
    if [[ -x "$candidate" || -e "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  fi

  if command -v hostveil >/dev/null 2>&1; then
    command -v hostveil
    return
  fi

  fail "unable to find an existing hostveil install; install hostveil first or pass --to DIR"
}

infer_installed_tag_from_binary() {
  local binary_path="$1"
  local version_output
  local version_value

  if [[ ! -x "$binary_path" ]]; then
    printf 'unknown\n'
    return
  fi

  version_output="$(HOSTVEIL_SKIP_AUTO_UPGRADE=1 "$binary_path" --version 2>/dev/null || true)"
  version_value="${version_output#hostveil }"

  if [[ -n "$version_value" ]] && [[ "$version_value" != "$version_output" ]]; then
    normalize_version "$version_value"
  else
    printf 'unknown\n'
  fi
}

infer_channel_from_tag() {
  local tag="$1"

  if [[ -z "$tag" ]] || [[ "$tag" == "unknown" ]]; then
    printf '%s\n' "$CHANNEL"
  elif [[ "$tag" == *-* ]]; then
    printf 'preview\n'
  else
    printf 'stable\n'
  fi
}

resolve_current_installed_tag() {
  if (( metadata_loaded == 1 )) && [[ -n "${HOSTVEIL_META_INSTALLED_TAG:-}" ]]; then
    printf '%s\n' "$HOSTVEIL_META_INSTALLED_TAG"
  else
    infer_installed_tag_from_binary "$(detect_installed_entrypoint_path)"
  fi
}

write_metadata() {
  local installed_tag="$1"

  mkdir -p "$STATE_DIR"

  {
    printf 'HOSTVEIL_META_REPO=%q\n' "$REPO"
    printf 'HOSTVEIL_META_CHANNEL=%q\n' "$CHANNEL"
    printf 'HOSTVEIL_META_INSTALL_DIR=%q\n' "$INSTALL_DIR"
    printf 'HOSTVEIL_META_WRAPPER_PATH=%q\n' "$(resolve_wrapper_path)"
    printf 'HOSTVEIL_META_BINARY_PATH=%q\n' "$(resolve_binary_path)"
    printf 'HOSTVEIL_META_INSTALLED_TAG=%q\n' "$installed_tag"
    printf 'HOSTVEIL_META_INSTALLER_URL=%q\n' "$(resolve_installer_url)"
    printf 'HOSTVEIL_META_AUTO_UPGRADE=%q\n' "$AUTO_UPGRADE_SETTING"
  } > "$METADATA_PATH"
}

refresh_manager_script() {
  local tmp_path

  mkdir -p "$STATE_DIR"
  tmp_path="$STATE_DIR/manage.sh.tmp"
  fetch_to_file "$(resolve_installer_url)" "$tmp_path"
  install -m 0755 "$tmp_path" "$MANAGER_SCRIPT_PATH"
  rm -f "$tmp_path"
}

write_wrapper_script() {
  local wrapper_path
  local binary_path

  wrapper_path="$(resolve_wrapper_path)"
  binary_path="$(resolve_binary_path)"

  cat > "$wrapper_path" <<EOF
#!/usr/bin/env bash
set -euo pipefail

METADATA_PATH=$(printf '%q' "$METADATA_PATH")
MANAGER_SCRIPT_PATH=$(printf '%q' "$MANAGER_SCRIPT_PATH")
DEFAULT_BINARY_PATH=$(printf '%q' "$binary_path")

if [[ -f "\$METADATA_PATH" ]]; then
  # shellcheck disable=SC1090
  source "\$METADATA_PATH"
fi

binary_path="\${HOSTVEIL_META_BINARY_PATH:-\$DEFAULT_BINARY_PATH}"

if [[ "\${HOSTVEIL_SKIP_AUTO_UPGRADE:-}" != "1" && "\${HOSTVEIL_AUTO_UPGRADE_RUNNING:-}" != "1" && "\${HOSTVEIL_META_AUTO_UPGRADE:-enabled}" != "disabled" && -x "\$MANAGER_SCRIPT_PATH" ]]; then
  HOSTVEIL_AUTO_UPGRADE_RUNNING=1 HOSTVEIL_SKIP_AUTO_UPGRADE=1 "\$MANAGER_SCRIPT_PATH" --upgrade >/dev/null 2>&1 || true
  if [[ -f "\$METADATA_PATH" ]]; then
    # shellcheck disable=SC1090
    source "\$METADATA_PATH"
    binary_path="\${HOSTVEIL_META_BINARY_PATH:-\$DEFAULT_BINARY_PATH}"
  fi
fi

exec "\$binary_path" "\$@"
EOF
  chmod 0755 "$wrapper_path"
}

resolve_existing_install_context() {
  local entrypoint_path
  local installed_tag

  load_metadata_if_present
  apply_metadata_defaults

  entrypoint_path="$(detect_installed_entrypoint_path)"
  INSTALL_DIR="$(dirname "$entrypoint_path")"

  if (( metadata_loaded == 0 )); then
    installed_tag="$(infer_installed_tag_from_binary "$entrypoint_path")"
    if (( CHANNEL_SET == 0 )); then
      CHANNEL="$(infer_channel_from_tag "$installed_tag")"
    fi
    write_metadata "$installed_tag"
    metadata_loaded=0
    load_metadata_if_present
    apply_metadata_defaults
  fi
}

remove_if_exists() {
  local path="$1"

  if [[ -e "$path" || -L "$path" ]]; then
    rm -f "$path"
  fi
}

prune_empty_dir() {
  local path="$1"

  if [[ -d "$path" ]] && [[ -z "$(ls -A "$path")" ]]; then
    rmdir "$path"
  fi
}

perform_install() {
  local tag
  local target
  local archive_name
  local download_base_url
  local archive_url
  local checksums_url
  local tmpdir
  local installed_tag

  case "$CHANNEL" in
    preview|stable) ;;
    *) fail "unsupported channel: $CHANNEL" ;;
  esac

  INSTALL_DIR="$(resolve_install_dir)"
  tag="$(resolve_version)"
  installed_tag="${HOSTVEIL_META_INSTALLED_TAG:-unknown}"

  if [[ "$ACTION" == "upgrade" ]] && [[ "$tag" == "$installed_tag" ]] && [[ -x "$(resolve_wrapper_path)" ]] && [[ -x "$(resolve_binary_path)" ]] && [[ -x "$MANAGER_SCRIPT_PATH" ]]; then
    log "hostveil ${tag} is already installed"
    return
  fi

  target="$(detect_target)"
  archive_name="hostveil-${tag}-${target}.tar.gz"
  download_base_url="$(resolve_download_base_url "$tag")"
  archive_url="${download_base_url}/${archive_name}"
  checksums_url="${download_base_url}/SHA256SUMS"

  tmpdir="$(mktemp -d)"
  trap "rm -rf '$tmpdir'" EXIT

  mkdir -p "$INSTALL_DIR"
  [[ -w "$INSTALL_DIR" ]] || fail "install directory is not writable: ${INSTALL_DIR}"

  log "Downloading ${archive_name}"
  fetch_to_file "$archive_url" "$tmpdir/$archive_name"
  fetch_to_file "$checksums_url" "$tmpdir/SHA256SUMS"
  verify_checksum "$tmpdir/SHA256SUMS" "$archive_name" "$tmpdir/$archive_name"

  mkdir -p "$tmpdir/extract"
  tar -xzf "$tmpdir/$archive_name" -C "$tmpdir/extract"
  [[ -f "$tmpdir/extract/hostveil" ]] || fail "release archive does not contain the hostveil binary"

  install -m 0755 "$tmpdir/extract/hostveil" "$(resolve_binary_path)"
  refresh_manager_script
  write_metadata "$tag"
  write_wrapper_script

  log "Installed hostveil ${tag} to $(resolve_wrapper_path)"
  if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    log "Note: ${INSTALL_DIR} is not currently on PATH."
  fi
}

perform_upgrade() {
  resolve_existing_install_context
  perform_install
}

set_auto_upgrade() {
  local setting="$1"
  local installed_tag

  resolve_existing_install_context
  installed_tag="$(resolve_current_installed_tag)"
  AUTO_UPGRADE_SETTING="$setting"
  write_metadata "$installed_tag"
  write_wrapper_script

  if [[ "$setting" == "enabled" ]]; then
    log "Enabled automatic hostveil upgrades on launch"
  else
    log "Disabled automatic hostveil upgrades on launch"
  fi
}

perform_uninstall() {
  local entrypoint_path

  load_metadata_if_present
  apply_metadata_defaults

  entrypoint_path="$(detect_installed_entrypoint_path)"
  INSTALL_DIR="$(dirname "$entrypoint_path")"

  remove_if_exists "$(resolve_wrapper_path)"
  remove_if_exists "$(resolve_binary_path)"
  remove_if_exists "$MANAGER_SCRIPT_PATH"
  remove_if_exists "$METADATA_PATH"
  prune_empty_dir "$STATE_DIR"

  log "Removed hostveil from ${INSTALL_DIR}"
}

validate_action() {
  case "$ACTION" in
    install|upgrade)
      ;;
    enable-auto-upgrade|disable-auto-upgrade|uninstall)
      if [[ -n "$REQUESTED_VERSION" ]]; then
        fail "--version is not supported with --${ACTION}"
      fi
      ;;
    *)
      fail "unsupported lifecycle action: ${ACTION}"
      ;;
  esac
}

validate_action

case "$ACTION" in
  install)
    perform_install
    ;;
  upgrade)
    perform_upgrade
    ;;
  enable-auto-upgrade)
    set_auto_upgrade enabled
    ;;
  disable-auto-upgrade)
    set_auto_upgrade disabled
    ;;
  uninstall)
    perform_uninstall
    ;;
esac
