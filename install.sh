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

echo "[1/5] Installing dependencies..."
install_system_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "Detected apt-get. Installing Debian-family packages first..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y python3 python3-pip python3-venv python3-cryptography python3-colorama python3-tqdm
    return 0
  fi
  if command -v dnf >/dev/null 2>&1; then
    echo "Detected dnf. Installing Fedora-family packages..."
    dnf install -y python3 python3-pip python3-cryptography python3-colorama python3-tqdm
    return 0
  fi
  if command -v yum >/dev/null 2>&1; then
    echo "Detected yum. Installing RHEL-family packages..."
    yum install -y python3 python3-pip python3-cryptography python3-colorama python3-tqdm
    return 0
  fi
  if command -v pacman >/dev/null 2>&1; then
    echo "Detected pacman. Installing Arch-family packages..."
    pacman -Sy --noconfirm python python-pip python-cryptography python-colorama python-tqdm
    return 0
  fi
  if command -v zypper >/dev/null 2>&1; then
    echo "Detected zypper. Installing openSUSE packages..."
    zypper --non-interactive install python3 python3-pip python3-cryptography python3-colorama python3-tqdm
    return 0
  fi
  if command -v apk >/dev/null 2>&1; then
    echo "Detected apk. Installing Alpine packages..."
    apk add --no-cache python3 py3-pip py3-cryptography py3-colorama py3-tqdm
    return 0
  fi
  return 1
}

if ! install_system_packages; then
  echo "No supported system package manager detected."
  echo "Proceeding with pip-only dependency installation."
fi

echo "Checking Python dependencies from requirements.txt..."
if [[ ! -f "${SCRIPT_DIR}/requirements.txt" ]]; then
  echo "Warning: requirements.txt not found in ${SCRIPT_DIR}."
  echo "Skipping pip dependency install. System packages (if installed) will be used."
elif python3 -m pip --version >/dev/null 2>&1; then
  if ! python3 -m pip install --upgrade --no-input -r "${SCRIPT_DIR}/requirements.txt"; then
    echo "pip dependency install failed (often due to externally-managed Python environments)."
    if ! python3 -m pip install --break-system-packages --upgrade --no-input -r "${SCRIPT_DIR}/requirements.txt"; then
      echo "Dependency install failed."
      echo "Try creating a virtual environment and running:"
      echo "  python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
      exit 1
    fi
  fi
  echo "Python dependencies installed/verified."
else
  echo "pip not available. If EncryptoPI fails to start, install dependencies from requirements.txt manually."
fi

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
echo "Installer note: existing project data (keys, backups, input, output, decrypted_output, logs) was not modified."
