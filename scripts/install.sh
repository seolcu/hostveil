#!/usr/bin/env bash
set -euo pipefail

VERSION=""
VERSION_EXPLICIT=false
SKIP_TRIVY=false
FORCE=false
UNINSTALL=false

# The repository every release artifact is fetched from, and the one the
# build provenance attestation must name. One constant so a URL and the
# identity being verified can never drift apart.
REPO="seolcu/hostveil"

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Options:
  --version vX.Y.Z   Install a specific hostveil release (v prefix optional)
  --no-trivy         Skip the optional trivy (image CVE scanner) install
  --no-deps          Install hostveil only (same as --no-trivy)
  --yes, -y          Non-interactive mode (install optional dependencies)
  --uninstall        Remove hostveil, and say where its saved state lives
  --help, -h         Show this help

Re-running this script installs over an existing hostveil, which is the
supported way to upgrade: the binary is replaced and your saved scans and
rollback checkpoints are left alone.
EOF
}

package_owner() {
  local path=$1
  if command -v dpkg >/dev/null 2>&1 && dpkg -S "$path" 2>/dev/null | grep -q '^hostveil:'; then
    echo "the hostveil .deb package"
    return 0
  fi
  if command -v rpm >/dev/null 2>&1 && rpm -qf "$path" 2>/dev/null | grep -q '^hostveil-'; then
    echo "the hostveil RPM package"
    return 0
  fi
  return 1
}

# uninstall removes what this script installed, and nothing else.
#
# It deliberately does not delete the state directory. That is where the
# rollback checkpoints live — the backups of every file hostveil has edited
# on this host — and removing hostveil is not a statement that the operator
# no longer wants the ability to undo what it did. So the path is printed
# with the command to remove it, and the decision stays theirs.
#
# trivy is likewise left in place: this script offers to install it, but it
# is a general-purpose scanner that may well predate hostveil or be used by
# something else, and silently removing another tool is not ours to do.
uninstall() {
  local removed=false

  if [[ -e /usr/bin/hostveil ]]; then
    if owner=$(package_owner /usr/bin/hostveil); then
      echo "ERROR: /usr/bin/hostveil is owned by ${owner}; the install script will not bypass its package database." >&2
      echo "  Use: hostveil uninstall --yes" >&2
      return 1
    fi
    "${SUDO[@]}" rm -f /usr/bin/hostveil
    echo "  ✓ removed /usr/bin/hostveil"
    removed=true
  else
    echo "  hostveil is not installed at /usr/bin/hostveil"
  fi

  local state
  if [[ -d /var/lib/hostveil ]]; then
    state=/var/lib/hostveil
  elif [[ -d "${HOME}/.local/share/hostveil" ]]; then
    state="${HOME}/.local/share/hostveil"
  fi

  if [[ -n "${state:-}" ]]; then
    echo ""
    echo "  Saved scans and rollback checkpoints are still in:"
    echo "    ${state}"
    echo "  Those checkpoints are the backups of every file hostveil edited here."
    echo "  Delete them only if you no longer need to undo any of its fixes:"
    echo "    ${SUDO[*]:+sudo }rm -rf ${state}"
  fi

  if command -v trivy >/dev/null 2>&1; then
    echo ""
    echo "  trivy is still installed. It is a general-purpose scanner, so this"
    echo "  script does not remove it. To remove it: ${SUDO[*]:+sudo }rm -f \"$(command -v trivy)\""
  fi

  if [[ "$removed" == true ]]; then
    echo ""
    echo "  Done."
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --version requires a value" >&2
        usage >&2
        exit 1
      fi
      VERSION="${2#v}"
      VERSION_EXPLICIT=true
      shift 2
      ;;
    --no-trivy) SKIP_TRIVY=true; shift ;;
    --no-deps) SKIP_TRIVY=true; shift ;;
    --yes|-y) FORCE=true; shift ;;
    --uninstall) UNINSTALL=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# ─── privilege ────────────────────────────────────────────────────────────
# Installing into /usr/bin needs root. Which is not the same as needing sudo,
# and the script used to assume it was: it called `sudo install` unconditionally,
# so on a host where you are *already* root and sudo is not installed it got all
# the way through downloading and verifying and then died with
# "sudo: command not found". That is not an exotic host — Debian's own default
# is root-only administration with no sudo, and every `docker run … | bash` is
# the same shape.
#
# An array rather than a string so that the empty case expands to nothing at
# all, instead of to an empty argument that `install` would read as a filename.
SUDO=()
if [[ ${EUID} -ne 0 ]]; then
  if command -v sudo &>/dev/null; then
    SUDO=(sudo)
  else
    echo "ERROR: installing into /usr/bin needs root, and sudo is not available." >&2
    echo "  Re-run this as root, or install sudo first." >&2
    exit 1
  fi
fi

if [[ "$UNINSTALL" == true ]]; then
  uninstall
  exit 0
fi

if [[ "$VERSION_EXPLICIT" == true && -z "$VERSION" ]]; then
  echo "ERROR: --version requires a non-empty version (e.g. v2.6.0)" >&2
  exit 1
fi
if [[ "$VERSION_EXPLICIT" == true && ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: --version must be a release version such as v3.21.0" >&2
  exit 1
fi

# ─── OS / ARCH ────────────────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac
case "$OS" in
  linux|darwin) ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ─── HELPERS ──────────────────────────────────────────────────────────────
github_latest_tag() {
  local repo=$1
  local url tag
  url=$(curl -fsSL --retry 3 -o /dev/null -w '%{url_effective}' \
    "https://github.com/${repo}/releases/latest") || return 1
  tag=${url##*/}
  tag=${tag#v}
  if [[ -z "$tag" || "$tag" == "latest" ]]; then
    return 1
  fi
  echo "$tag"
}

sha256_hash() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
  else
    echo ""
  fi
}

require_sha256() {
  local file=$1
  local actual
  actual=$(sha256_hash "$file")
  if [[ -z "$actual" ]]; then
    echo "  ERROR: no sha256 tool available to verify ${file##*/}" >&2
    exit 1
  fi
  echo "$actual"
}

install_packages() {
  case "$PM" in
    apt) "${SUDO[@]}" apt install -y "$@" ;;
    dnf) "${SUDO[@]}" dnf install -y "$@" ;;
    yum) "${SUDO[@]}" yum install -y "$@" ;;
    pacman) "${SUDO[@]}" pacman -S --noconfirm "$@" ;;
    apk) "${SUDO[@]}" apk add "$@" ;;
    zypper) "${SUDO[@]}" zypper install -y "$@" ;;
    brew) brew install "$@" ;;
    *)
      echo "  • $1: no package manager found, skipping (install manually)"
      return 1
      ;;
  esac
}

package_available() {
  local pkg=$1
  case "$PM" in
    apt) apt-cache show "$pkg" >/dev/null 2>&1 ;;
    *) return 0 ;;
  esac
}

# ─── PACKAGE MANAGER ──────────────────────────────────────────────────────
PM=""
if command -v apt &>/dev/null; then PM="apt"
elif command -v dnf &>/dev/null; then PM="dnf"
elif command -v yum &>/dev/null; then PM="yum"
elif command -v pacman &>/dev/null; then PM="pacman"
elif command -v apk &>/dev/null; then PM="apk"
elif command -v zypper &>/dev/null; then PM="zypper"
elif command -v brew &>/dev/null; then PM="brew"
fi

# ─── OPTIONAL DEPENDENCY: TRIVY ───────────────────────────────────────────
# Trivy enables image CVE scanning. hostveil works fully without it, so it
# is entirely optional and can be added later.
DEP_TRIVY=true
if ! $FORCE && [[ -t 0 ]]; then
  printf "  Install Trivy for optional image CVE scanning? [Y/n] "
  IFS= read -r answer
  case "$answer" in
    n|N|no|NO) DEP_TRIVY=false ;;
  esac
fi

# ─── INSTALL DEPENDENCIES ─────────────────────────────────────────────────
install_tool() {
  local name=$1 && shift
  if command -v "$name" &>/dev/null; then
    echo "  • $name: already installed"
    return 0
  fi
  if [[ -z "$PM" ]]; then
    echo "  • $name: no package manager found, skipping (install manually)"
    return 0
  fi
  if package_available "$name"; then
    echo "  • $name: installing via $PM..."
    if install_packages "$@"; then
      return 0
    fi
    echo "  • $name: package install failed, trying binary download..."
  else
    echo "  • $name: not in $PM repos, downloading binary..."
  fi

  case "$name" in
    trivy)
      TRIVY_VER=$(github_latest_tag aquasecurity/trivy) || {
        echo "  ERROR: failed to determine latest trivy version" >&2
        return 1
      }
      case "$OS" in linux) TRIVY_OS="Linux" ;; darwin) TRIVY_OS="Darwin" ;; esac
      case "$ARCH" in amd64) TRIVY_ARCH="64bit" ;; arm64) TRIVY_ARCH="ARM64" ;; esac
      TRIVY_TAR="trivy_${TRIVY_VER}_${TRIVY_OS}-${TRIVY_ARCH}.tar.gz"
      TRIVY_BASE="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}"
      # Extract into its own directory. A bare `find` over $TMPDIR would also
      # match anything named trivy that another step left there.
      TRIVY_DIR="${TMPDIR}/trivy-unpack"
      mkdir -p "$TRIVY_DIR"

      curl -fsSL --retry 3 "${TRIVY_BASE}/${TRIVY_TAR}" -o "${TRIVY_DIR}/${TRIVY_TAR}" || {
        echo "  ERROR: trivy download failed" >&2
        return 1
      }

      # Verified for the same reason hostveil's own archive is: this is
      # installed to /usr/bin and hostveil then executes it. Trivy publishes
      # checksums with every release, and skipping them here while insisting
      # on them for hostveil would secure the front door and leave the side
      # one open.
      curl -fsSL --retry 3 "${TRIVY_BASE}/trivy_${TRIVY_VER}_checksums.txt" \
        -o "${TRIVY_DIR}/checksums.txt" || {
        echo "  ERROR: could not download trivy's checksums; refusing to install it unverified" >&2
        return 1
      }
      TRIVY_EXPECTED=$(awk -v f="$TRIVY_TAR" '$2 == f || $2 == "*" f {print $1}' "${TRIVY_DIR}/checksums.txt")
      if [[ -z "$TRIVY_EXPECTED" ]]; then
        echo "  ERROR: ${TRIVY_TAR} is not listed in trivy's checksums file" >&2
        return 1
      fi
      TRIVY_ACTUAL=$(require_sha256 "${TRIVY_DIR}/${TRIVY_TAR}")
      if [[ "$TRIVY_EXPECTED" != "$TRIVY_ACTUAL" ]]; then
        echo "  ERROR: checksum mismatch for ${TRIVY_TAR}" >&2
        echo "    expected: $TRIVY_EXPECTED" >&2
        echo "    actual:   $TRIVY_ACTUAL" >&2
        return 1
      fi

      tar xzf "${TRIVY_DIR}/${TRIVY_TAR}" -C "$TRIVY_DIR" -- trivy || {
        echo "  ERROR: trivy extraction failed" >&2
        return 1
      }
      TRIVY_BIN="${TRIVY_DIR}/trivy"
      if [[ -f "$TRIVY_BIN" && ! -L "$TRIVY_BIN" ]]; then
        "${SUDO[@]}" install -m 755 "$TRIVY_BIN" /usr/bin/trivy
      else
        echo "  ERROR: trivy binary not found after extraction" >&2
        return 1
      fi
      ;;
  esac
}

if [[ "$SKIP_TRIVY" != true && "$DEP_TRIVY" == true ]]; then
  # Trivy is optional: a failed install must not abort hostveil's install.
  install_tool trivy trivy || echo "  ⚠ trivy not installed; CVE scanning will be skipped"
fi

# ─── INSTALL HOSTVEIL ────────────────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
  VERSION=$(github_latest_tag "$REPO") || true
  if [[ -z "$VERSION" ]]; then
    echo "  ERROR: failed to determine latest hostveil version" >&2
    echo "  Try again later or specify a version with --version vX.Y.Z" >&2
    exit 1
  fi
fi
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "  ERROR: GitHub returned an invalid release version: ${VERSION}" >&2
  exit 1
fi

if [[ -e /usr/bin/hostveil ]] && owner=$(package_owner /usr/bin/hostveil); then
  echo "  ERROR: /usr/bin/hostveil is owned by ${owner}." >&2
  echo "  Run 'hostveil update' so the package manager remains authoritative." >&2
  exit 1
fi

echo "  • hostveil: downloading v${VERSION}..."
TAR="hostveil-${OS}-${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/v${VERSION}/${TAR}"
curl -fsSL --retry 3 "$URL" -o "${TMPDIR}/${TAR}" || {
  echo "  ERROR: download failed for ${URL}" >&2
  exit 1
}

# Verification is mandatory, and every way it can fail is fatal.
#
# This used to warn and install anyway when the checksums file could not be
# fetched or did not list the archive. That turns a network-level attacker
# who can serve one file and block another into an attacker who can hand you
# any binary they like — and this binary is about to be installed to
# /usr/bin and run as root. There is no partial credit here: either the
# artifact matches what the release published, or it does not get installed.
echo "  • hostveil: verifying checksum..."
CHECKSUM_URL="https://github.com/${REPO}/releases/download/v${VERSION}/hostveil-checksums.txt"
if ! curl -fsSL --retry 3 "$CHECKSUM_URL" -o "${TMPDIR}/hostveil-checksums.txt"; then
  echo "  ERROR: could not download the checksums file for v${VERSION}" >&2
  echo "    ${CHECKSUM_URL}" >&2
  echo "    Refusing to install an unverified binary." >&2
  exit 1
fi
EXPECTED=$(awk -v f="$TAR" '$2 == f || $2 == "*" f {print $1}' "${TMPDIR}/hostveil-checksums.txt")
if [[ -z "$EXPECTED" ]]; then
  echo "  ERROR: ${TAR} is not listed in the release's checksums file" >&2
  echo "    Refusing to install an unverified binary." >&2
  exit 1
fi
ACTUAL=$(require_sha256 "${TMPDIR}/${TAR}")
if [[ "$EXPECTED" != "$ACTUAL" ]]; then
  echo "  ERROR: checksum mismatch for ${TAR}" >&2
  echo "    expected: $EXPECTED" >&2
  echo "    actual:   $ACTUAL" >&2
  exit 1
fi
echo "  ✓ checksum verified"

# The checksums file comes from the same GitHub release as the tarball, so
# matching it proves the download was not corrupted or partially swapped in
# transit — not that the release itself is genuine. The release workflow
# mints a signed build provenance attestation tying the archive to the
# workflow run and commit that produced it, and that is the claim worth
# checking. Verified when the tooling is present; skipped with a note when
# it is not, because gh is not a dependency this installer can require.
if command -v gh >/dev/null 2>&1; then
  if gh attestation verify "${TMPDIR}/${TAR}" --repo "$REPO" >/dev/null 2>&1; then
    echo "  ✓ build provenance verified (built by ${REPO}'s release workflow)"
  else
    echo "  ERROR: build provenance could not be verified for ${TAR}." >&2
    echo "  The checksum matched, but nothing proves this archive came from" >&2
    echo "  ${REPO}'s release workflow. Refusing to install." >&2
    exit 1
  fi
else
  echo "  · provenance not checked (install the GitHub CLI to enable it):"
  echo "      gh attestation verify ${TAR} --repo ${REPO}"
fi

tar xzf "${TMPDIR}/${TAR}" -C "$TMPDIR" -- hostveil || {
  echo "  ERROR: extraction failed" >&2
  exit 1
}
if [[ ! -f "${TMPDIR}/hostveil" || -L "${TMPDIR}/hostveil" ]]; then
  echo "  ERROR: archive entry 'hostveil' is not a regular file" >&2
  exit 1
fi
INSTALL_TMP="/usr/bin/.hostveil-install-${RANDOM}-$$"
"${SUDO[@]}" install -m 755 "${TMPDIR}/hostveil" "$INSTALL_TMP" || {
  echo "  ERROR: install failed" >&2
  exit 1
}
if ! "${SUDO[@]}" mv -f "$INSTALL_TMP" /usr/bin/hostveil; then
  "${SUDO[@]}" rm -f "$INSTALL_TMP" || true
  echo "  ERROR: atomic install failed" >&2
  exit 1
fi

if ! INSTALLED=$(/usr/bin/hostveil --version 2>/dev/null); then
  echo "  ERROR: hostveil installed but --version check failed" >&2
  exit 1
fi
if [[ "${INSTALLED##* }" != "v${VERSION}" ]]; then
  echo "  ERROR: /usr/bin/hostveil reports '${INSTALLED}', expected v${VERSION}" >&2
  exit 1
fi

echo ""
echo "  hostveil v${VERSION} installed (${INSTALLED})."
echo "  Run: hostveil"
echo "  Upgrade later by re-running this script; uninstall with: install.sh --uninstall"
