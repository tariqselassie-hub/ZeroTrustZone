#!/usr/bin/env bash
set -euo pipefail

# ZeroTrustZone (ZTZ) Installer / Updater / Uninstaller for Linux & macOS
# Usage:
#   ./scripts/install.sh [--with-service] [--strict-shield]
#   ./scripts/install.sh --update
#   ./scripts/install.sh --uninstall [--purge-keys]

ACTION="install"
WITH_SERVICE=""
STRICT_SHIELD=""
PURGE_KEYS=""

for arg in "$@"; do
  case "$arg" in
    --update) ACTION="update" ;;
    --uninstall) ACTION="uninstall" ;;
    --with-service) WITH_SERVICE="--with-service" ;;
    --strict-shield) STRICT_SHIELD="--strict-shield" ;;
    --purge-keys) PURGE_KEYS="--purge-keys --yes" ;;
    -h|--help)
      echo "Usage: $0 [--with-service] [--strict-shield] | [--update] | [--uninstall [--purge-keys]]"
      exit 0
      ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

PYTHON_BIN="${PYTHON_BIN:-python3}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$ACTION" = "install" ]; then
  "$PYTHON_BIN" -m pip install -e "$REPO_DIR"
  "$PYTHON_BIN" -m ztz install $WITH_SERVICE $STRICT_SHIELD
elif [ "$ACTION" = "update" ]; then
  "$PYTHON_BIN" -m ztz update
elif [ "$ACTION" = "uninstall" ]; then
  "$PYTHON_BIN" -m ztz uninstall $PURGE_KEYS
  "$PYTHON_BIN" -m pip uninstall -y ztz || true
fi
