#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Please run as root: sudo ./install.sh"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SCRIPT="${SCRIPT_DIR}/encryptopi.py"
BIN_LINK="/usr/local/bin/encryptopi"
DESKTOP_FILE_NAME="encryptopi.desktop"
SYSTEM_DESKTOP_FILE="/usr/share/applications/${DESKTOP_FILE_NAME}"

if [[ ! -f "${APP_SCRIPT}" ]]; then
  echo "Could not find encryptopi.py in ${SCRIPT_DIR}"
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This installer currently supports Debian/Raspberry Pi OS style systems with apt-get."
  exit 1
fi

echo "[1/5] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-pip python3-cryptography python3-colorama python3-tqdm

echo "[2/5] Ensuring executable permissions..."
chmod +x "${APP_SCRIPT}"

echo "[3/5] Creating command shortcut: ${BIN_LINK}"
ln -sfn "${APP_SCRIPT}" "${BIN_LINK}"

create_desktop_entry() {
  local target="$1"
  local owner_uid="$2"
  local owner_gid="$3"

  cat > "${target}" <<DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=EncryptoPI
Comment=Encrypt and decrypt files with Fernet and AES
Exec=${BIN_LINK}
Terminal=true
Icon=utilities-terminal
Categories=Utility;Security;
DESKTOP

  chmod 644 "${target}"
  chown "${owner_uid}:${owner_gid}" "${target}"
}

echo "[4/5] Creating application launcher..."
create_desktop_entry "${SYSTEM_DESKTOP_FILE}" 0 0

# Create desktop icon for the invoking user when possible (useful on Raspberry Pi desktop installs).
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  USER_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
  if [[ -n "${USER_HOME}" && -d "${USER_HOME}" ]]; then
    USER_DESKTOP="${USER_HOME}/Desktop"
    if [[ -d "${USER_DESKTOP}" ]]; then
      USER_DESKTOP_FILE="${USER_DESKTOP}/${DESKTOP_FILE_NAME}"
      USER_UID="$(id -u "${SUDO_USER}")"
      USER_GID="$(id -g "${SUDO_USER}")"
      create_desktop_entry "${USER_DESKTOP_FILE}" "${USER_UID}" "${USER_GID}"
      chmod +x "${USER_DESKTOP_FILE}"
      echo "    Desktop shortcut created: ${USER_DESKTOP_FILE}"
    fi
  fi
fi

echo "[5/5] Verifying install..."
if command -v encryptopi >/dev/null 2>&1; then
  echo "Install successful. Run: encryptopi"
else
  echo "Install completed, but encryptopi not found in PATH yet. Open a new terminal and run: encryptopi"
fi
