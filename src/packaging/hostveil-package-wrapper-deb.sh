#!/usr/bin/env bash
set -euo pipefail

export HOSTVEIL_PACKAGE_INSTALL_KIND=deb
exec /usr/libexec/hostveil/hostveil "$@"
