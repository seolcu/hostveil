#!/usr/bin/env bash
set -euo pipefail

export HOSTVEIL_PACKAGE_INSTALL_KIND=rpm
exec /usr/libexec/hostveil/hostveil "$@"
