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
REQUIREMENTS_FILE="${SCRIPT_DIR}/requirements.txt"
VENV_DIR="${SCRIPT_DIR}/.encryptopi-venv"
LAUNCHER_SCRIPT="${SCRIPT_DIR}/encryptopi-launcher.sh"
USE_VENV=0

if [[ ! -f "${APP_SCRIPT}" ]]; then
  echo "Could not find encryptopi.py in ${SCRIPT_DIR}"
  exit 1
fi

required_modules=(cryptography colorama tqdm)

verify_python_modules() {
  local python_bin="$1"
  "${python_bin}" - <<'PY'
import importlib
import sys

missing = []
for module in ("cryptography", "colorama", "tqdm"):
    try:
        importlib.import_module(module)
    except Exception as exc:
        missing.append(f"{module} ({exc})")

if missing:
    print("Missing Python modules: " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)
PY
}

install_system_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "Detected apt-get. Installing Debian-family packages..."
    export DEBIAN_FRONTEND=noninteractive
    if apt-get update -y && apt-get install -y python3 python3-pip python3-venv python3-cryptography python3-colorama python3-tqdm; then
      return 0
    fi
    echo "apt-get could not install all required packages. A local virtual environment will be tried next."
    return 1
  fi
  if command -v dnf >/dev/null 2>&1; then
    echo "Detected dnf. Installing Fedora-family packages..."
    dnf install -y python3 python3-pip python3-cryptography python3-colorama python3-tqdm && return 0
    return 1
  fi
  if command -v yum >/dev/null 2>&1; then
    echo "Detected yum. Installing RHEL-family packages..."
    yum install -y python3 python3-pip python3-cryptography python3-colorama python3-tqdm && return 0
    return 1
  fi
  if command -v pacman >/dev/null 2>&1; then
    echo "Detected pacman. Installing Arch-family packages..."
    pacman -Sy --noconfirm python python-pip python-cryptography python-colorama python-tqdm && return 0
    return 1
  fi
  if command -v zypper >/dev/null 2>&1; then
    echo "Detected zypper. Installing openSUSE packages..."
    zypper --non-interactive install python3 python3-pip python3-cryptography python3-colorama python3-tqdm && return 0
    return 1
  fi
  if command -v apk >/dev/null 2>&1; then
    echo "Detected apk. Installing Alpine packages..."
    apk add --no-cache python3 py3-pip py3-cryptography py3-colorama py3-tqdm && return 0
    return 1
  fi
  return 1
}

install_venv_dependencies() {
  if [[ ! -f "${REQUIREMENTS_FILE}" ]]; then
    echo "Dependency install failed: requirements.txt not found in ${SCRIPT_DIR}."
    return 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Dependency install failed: python3 is not available. Install Python 3 and rerun this installer."
    return 1
  fi

  echo "Installing Python dependencies in a local virtual environment: ${VENV_DIR}"
  if ! python3 -m venv "${VENV_DIR}"; then
    echo "Could not create a virtual environment. On Debian-family systems, install python3-venv and rerun this installer."
    return 1
  fi

  "${VENV_DIR}/bin/python" -m pip install --upgrade --no-input pip
  "${VENV_DIR}/bin/python" -m pip install --upgrade --no-input -r "${REQUIREMENTS_FILE}"
  verify_python_modules "${VENV_DIR}/bin/python"
  USE_VENV=1
}

create_launcher() {
  cat > "${LAUNCHER_SCRIPT}" <<EOF_LAUNCHER
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python" "${APP_SCRIPT}" "\$@"
EOF_LAUNCHER
  chmod +x "${LAUNCHER_SCRIPT}"
}

echo "[1/5] Installing dependencies..."
SYSTEM_PACKAGES_INSTALLED=0
if install_system_packages; then
  SYSTEM_PACKAGES_INSTALLED=1
else
  echo "No complete supported system package installation was detected."
fi

if [[ ${SYSTEM_PACKAGES_INSTALLED} -eq 1 ]] && verify_python_modules python3; then
  echo "Python dependencies verified from system packages."
  USE_VENV=0
else
  if [[ ${SYSTEM_PACKAGES_INSTALLED} -eq 1 ]]; then
    echo "System packages installed, but one or more Python modules could not be imported."
  fi
  echo "Falling back to pip inside a local virtual environment. System Python will not be modified."
  if ! install_venv_dependencies; then
    echo "Dependency install failed. EncryptoPI requires these Python modules: ${required_modules[*]}"
    echo "No system-wide pip install was attempted, and --break-system-packages was not used."
    exit 1
  fi
  echo "Python dependencies installed/verified in the local virtual environment."
fi

echo "[2/5] Ensuring executable permissions..."
chmod +x "${APP_SCRIPT}"
if [[ ${USE_VENV} -eq 1 ]]; then
  create_launcher
fi

echo "[3/5] Creating command shortcut: ${BIN_LINK}"
if [[ ${USE_VENV} -eq 1 ]]; then
  ln -sfn "${LAUNCHER_SCRIPT}" "${BIN_LINK}"
else
  ln -sfn "${APP_SCRIPT}" "${BIN_LINK}"
fi

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
  if encryptopi --help >/dev/null 2>&1; then
    echo "Install successful. Run: encryptopi"
  else
    echo "Install completed, but the encryptopi command did not start cleanly."
    echo "Check the dependency messages above, then try: encryptopi --help"
    exit 1
  fi
else
  echo "Install completed, but encryptopi not found in PATH yet. Open a new terminal and run: encryptopi"
fi
if [[ ${USE_VENV} -eq 1 ]]; then
  echo "Installer note: using local virtual environment at ${VENV_DIR}."
else
  echo "Installer note: using system Python packages from the OS package manager."
fi
echo "Installer note: existing project data (keys, backups, input, output, decrypted_output, logs) was not modified."
