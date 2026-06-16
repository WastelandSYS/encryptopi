#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Please run as root: sudo ./uninstall.sh"
  exit 1
fi

BIN_LINK="/usr/local/bin/encryptopi"
DESKTOP_FILE_NAME="encryptopi.desktop"
SYSTEM_DESKTOP_FILE="/usr/share/applications/${DESKTOP_FILE_NAME}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER_SCRIPT="${SCRIPT_DIR}/encryptopi-launcher.sh"
VENV_DIR="${SCRIPT_DIR}/.encryptopi-venv"

remove_if_exists() {
  local target="$1"
  if [[ -e "${target}" || -L "${target}" ]]; then
    rm -f "${target}"
    echo "Removed: ${target}"
  fi
}

remove_if_exists "${BIN_LINK}"
remove_if_exists "${SYSTEM_DESKTOP_FILE}"
remove_if_exists "${LAUNCHER_SCRIPT}"

if [[ -d "${VENV_DIR}" ]]; then
  rm -rf "${VENV_DIR}"
  echo "Removed: ${VENV_DIR}"
fi

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  USER_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"

  if [[ -n "${USER_HOME}" && -d "${USER_HOME}" ]]; then
    USER_DESKTOP_FILE="${USER_HOME}/Desktop/${DESKTOP_FILE_NAME}"
    remove_if_exists "${USER_DESKTOP_FILE}"
  fi
fi

echo "Uninstall complete."
echo "Safety note: shared system Python packages were not removed."
echo "Safety note: user data was preserved."
echo "No keys, backups, input files, encrypted files, decrypted files, or logs were deleted."
