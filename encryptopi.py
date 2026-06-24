#!/usr/bin/env python3

# =========================================================
# EncryptoPI
# Advanced Linux & Raspberry Pi encryption suite
#
# Fernet + AES-256-GCM encryption, integrity verification,
# key management, secure batch operations, and manifest tracking.
#
# Copyright (c) 2026 WastelandSYS
# Licensed under GPLv3
# =========================================================

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from pathlib import Path
from colorama import Fore, init
from tqdm import tqdm
import argparse
from argparse import RawDescriptionHelpFormatter
import tempfile
from getpass import getpass
from datetime import datetime, timezone
import json
import os
import base64
import hashlib
import zipfile
import logging
import contextlib
import io
import shutil
import struct
import textwrap
import unicodedata
from dataclasses import dataclass

# Initialize colorama
init(autoreset=True)

# Get the directory where the script is located
SCRIPT_DIR = Path(__file__).resolve().parent

# Paths relative to the script's directory
KEYS_DIR = SCRIPT_DIR / "keys"
INPUT_DIR = SCRIPT_DIR / "input"
OUTPUT_DIR = SCRIPT_DIR / "output"
DECRYPT_OUTPUT_DIR = SCRIPT_DIR / "decrypted_output"

@dataclass(frozen=True)
class AppState:
    script_dir: Path
    keys_dir: Path
    input_dir: Path
    output_dir: Path
    decrypt_output_dir: Path
    backup_dir: Path
    logs_dir: Path


STATE = AppState(
    script_dir=SCRIPT_DIR,
    keys_dir=KEYS_DIR,
    input_dir=INPUT_DIR,
    output_dir=OUTPUT_DIR,
    decrypt_output_dir=DECRYPT_OUTPUT_DIR,
    backup_dir=SCRIPT_DIR / "key_backups",
    logs_dir=SCRIPT_DIR / "logs",
)

MIN_PYTHON = (3, 8)
CHUNK_SIZE = 1024 * 1024  # 1 MiB
FERNET_LARGE_FILE_WARN_BYTES = 250 * 1024 * 1024
APP_VERSION = "1.0.1"


def env_int(name, default):
    try:
        value = int(os.environ.get(name, str(default)))
        return value if value > 0 else default
    except ValueError:
        return default


MAX_ZIP_ENTRIES = env_int("ENCRYPTOPI_MAX_ZIP_ENTRIES", 10000)
MAX_ZIP_FILE_BYTES = env_int("ENCRYPTOPI_MAX_ZIP_FILE_BYTES", 2 * 1024 * 1024 * 1024)
MAX_ZIP_TOTAL_BYTES = env_int("ENCRYPTOPI_MAX_ZIP_TOTAL_BYTES", 10 * 1024 * 1024 * 1024)
DEFAULT_OUTPUT_POLICY = os.environ.get("ENCRYPTOPI_OUTPUT_POLICY", "rename").strip().lower()
if DEFAULT_OUTPUT_POLICY not in ("rename", "skip", "overwrite"):
    DEFAULT_OUTPUT_POLICY = "rename"
SCRYPT_N = env_int("ENCRYPTOPI_SCRYPT_N", 2 ** 14)
SCRYPT_R = env_int("ENCRYPTOPI_SCRYPT_R", 8)
SCRYPT_P = env_int("ENCRYPTOPI_SCRYPT_P", 1)
ENCRYPTION_WARNING_SHOWN = False

def ensure_app_dirs():
    for directory in [STATE.keys_dir, STATE.input_dir, STATE.output_dir, STATE.decrypt_output_dir, STATE.backup_dir, STATE.logs_dir]:
        directory.mkdir(parents=True, exist_ok=True)


def secure_key_permissions(path):
    try:
        os.chmod(path, 0o600)
    except Exception:
        LOGGER.debug("Could not set restrictive permissions on %s", path, exc_info=True)


def get_metadata_path(key_filename):
    key_name = Path(key_filename).name
    if key_name.endswith(".key"):
        metadata_name = key_name[:-4] + "_metadata.json"
    else:
        metadata_name = key_name + "_metadata.json"
    return STATE.keys_dir / metadata_name


def relative_path_for(file_path, default_base, override_base=None):
    path = Path(file_path)
    for base in [override_base, default_base]:
        if base is None:
            continue
        try:
            return path.resolve().relative_to(Path(base).resolve())
        except ValueError:
            continue
    return Path(path.name)


def add_key_metadata_common(key_label):
    try:
        show_keys()
        key_filename = input(Fore.CYAN + f"Enter the {key_label} key filename to add metadata to (from above): ")
        key_file_path = resolve_key_path(key_filename)
        if key_file_path is None or not key_file_path.is_file():
            error("Key file not found.")
            return
        metadata = input(Fore.CYAN + "Enter metadata to add: ")
        metadata_path = get_metadata_path(key_file_path.name)
        with open(metadata_path, "w") as metadata_file:
            json.dump({"metadata": metadata}, metadata_file)
        success(f"Metadata added to {metadata_path.name}")
    except Exception:
        LOGGER.exception("add_key_metadata_common failed for %s", key_label)
        error(f"Error adding metadata to {key_label} key.")


def view_key_metadata_common(key_label):
    try:
        show_keys()
        key_filename = input(Fore.CYAN + f"Enter the {key_label} key filename to view metadata of (from above): ")
        key_file_path = resolve_key_path(key_filename)
        if key_file_path is None or not key_file_path.is_file():
            error("Key file not found.")
            return
        metadata_path = get_metadata_path(key_file_path.name)
        if not metadata_path.is_file():
            warning("No metadata found for the selected key")
            return
        with open(metadata_path, "r") as metadata_file:
            metadata_dict = json.load(metadata_file)
        info(f"Metadata for {key_file_path.name}: {metadata_dict.get('metadata', 'No metadata available')}")
    except Exception:
        LOGGER.exception("view_key_metadata_common failed for %s", key_label)
        error(f"Error viewing metadata of {key_label} key.")


def is_within(base: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except Exception:
        return False


def resolve_key_path(key_filename):
    key_filename = key_filename.strip()
    if not key_filename:
        error("Key filename cannot be empty.")
        return None
    key_path = (STATE.keys_dir / key_filename).resolve()
    if not is_within(STATE.keys_dir, key_path):
        error("Invalid key filename path.")
        return None
    return key_path



def setup_logger():
    logger = logging.getLogger("encryptopi")
    ensure_app_dirs()
    log_path = (STATE.logs_dir / "encryptopi.log").resolve()
    for handler in list(logger.handlers):
        if isinstance(handler, logging.FileHandler):
            if Path(handler.baseFilename).resolve() == log_path:
                return logger
            logger.removeHandler(handler)
            handler.close()
    if any(isinstance(handler, logging.FileHandler) for handler in logger.handlers):
        return logger
    logger.setLevel(logging.INFO)
    for handler in list(logger.handlers):
        if isinstance(handler, logging.NullHandler):
            logger.removeHandler(handler)
    fh = logging.FileHandler(log_path)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(fh)
    return logger

LOGGER = logging.getLogger("encryptopi")
LOGGER.setLevel(logging.INFO)
LOGGER.addHandler(logging.NullHandler())


def info(msg):
    print(Fore.CYAN + f"[INFO] {msg}")

def success(msg):
    print(Fore.GREEN + f"[OK] {msg}")

def warning(msg):
    print(Fore.YELLOW + f"[WARN] {msg}")

def error(msg):
    print(Fore.RED + f"[ERROR] {msg}")


THEME_ORANGE = Fore.YELLOW
THEME_ACCENT = Fore.CYAN
THEME_DIM = Fore.WHITE
THEME_OK = Fore.GREEN
MENU_WIDTH = 74
BANNER_OFFSET = 16


def strip_ansi(text):
    # Colorama constants are simple escape sequences; remove known values for width calculations.
    for code in (Fore.BLACK, Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN, Fore.WHITE, Fore.RESET):
        text = text.replace(code, "")
    return text


def visible_len(text):
    return len(strip_ansi(str(text)))


def ui_line(char="═", width=MENU_WIDTH):
    return THEME_ORANGE + (char * width)


def ui_text_line(text="", width=MENU_WIDTH, color=THEME_DIM):
    text = str(text)
    padding = max(0, width - 4 - visible_len(text))
    return THEME_ORANGE + "║ " + color + text + (" " * padding) + THEME_ORANGE + " ║"


def ui_center_line(text="", width=MENU_WIDTH, color=THEME_ACCENT):
    text = str(text)
    padding = max(0, width - 2 - visible_len(text))
    left = padding // 2
    right = padding - left
    return THEME_ORANGE + "║" + (" " * left) + color + text + (" " * right) + THEME_ORANGE + "║"


def ui_box(title, lines=None, subtitle=None, width=MENU_WIDTH):
    lines = lines or []
    print(THEME_ORANGE + "╔" + ("═" * (width - 2)) + "╗")
    print(ui_center_line(title, width, THEME_ORANGE))
    if subtitle:
        print(ui_center_line(subtitle, width, THEME_DIM))
    print(THEME_ORANGE + "╠" + ("═" * (width - 2)) + "╣")
    for line in lines:
        if visible_len(line) <= width - 4:
            print(ui_text_line(line, width, THEME_DIM))
        else:
            for wrapped in textwrap.wrap(strip_ansi(line), width=width - 4):
                print(ui_text_line(wrapped, width, THEME_DIM))
    print(THEME_ORANGE + "╚" + ("═" * (width - 2)) + "╝")


def menu_option(key, label, hint=""):
    left = f"{key:>2}. {label}" if key.isdigit() else f" {key}. {label}"
    if hint:
        return f"{left:<34} {Fore.CYAN}{hint}"
    return left


def render_menu(title, options, subtitle=None, footer="b. Back", width=MENU_WIDTH):
    lines = [menu_option(str(key), label, hint) for key, label, hint in options]
    if footer:
        lines.append("")
        lines.append(footer)
    ui_box(title, lines, subtitle=subtitle, width=width)


def prompt_choice():
    return input(THEME_ORANGE + "╰─" + THEME_ACCENT + " Select: ").strip().lower()


BANNER_LINES = [
    "╭━━━╮╱╱╱╱╱╱╱╱╱╱╱╱╱╱╭╮╱╱╱╭━━━┳━━╮",
    "┃╭━━╯╱╱╱╱╱╱╱╱╱╱╱╱╱╭╯╰╮╱╱┃╭━╮┣┫┣╯",
    "┃╰━━┳━╮╭━━┳━┳╮╱╭┳━┻╮╭╋━━┫╰━╯┃┃┃",
    "┃╭━━┫╭╮┫╭━┫╭┫┃╱┃┃╭╮┃┃┃╭╮┃╭━━╯┃┃",
    "┃╰━━┫┃┃┃╰━┫┃┃╰━╯┃╰╯┃╰┫╰╯┃┃╱╱╭┫┣╮",
    "╰━━━┻╯╰┻━━┻╯╰━╮╭┫╭━┻━┻━━┻╯╱╱╰━━╯",
    "╱╱╱╱╱╱╱╱╱╱╱╱╭━╯┃┃┃",
    "╱╱╱╱╱╱╱╱╱╱╱╱╰━━╯╰╯",
]


def render_banner(width=MENU_WIDTH):
    print()
    def banner_len(text):
        return sum(2 if unicodedata.east_asian_width(ch) in ("A", "F", "W") else 1 for ch in text)
    pad = max(0, (width - max(banner_len(line) for line in BANNER_LINES)) // 2) + BANNER_OFFSET
    for line in BANNER_LINES:
        print(THEME_ORANGE + (" " * pad) + line)
    print()


def safe_output_path(base_dir, rel_path, suffix):
    rel = Path(rel_path)
    target = base_dir / rel.parent / (rel.name + suffix)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        return target
    stem = rel.stem
    original_ext = rel.suffix
    i = 1
    while True:
        cand = base_dir / rel.parent / f"{stem}_{i}{original_ext}{suffix}"
        if not cand.exists():
            return cand
        i += 1


def choose_output_path(base_dir, rel_path, suffix, output_policy="rename"):
    rel = Path(rel_path)
    target = Path(base_dir) / rel.parent / (rel.name + suffix)
    target.parent.mkdir(parents=True, exist_ok=True)
    policy = (output_policy or DEFAULT_OUTPUT_POLICY).strip().lower()
    if policy not in ("rename", "skip", "overwrite"):
        policy = "rename"
    if not target.exists():
        return target
    if policy == "skip":
        warning(f"Output exists, skipping: {target}")
        return None
    if policy == "overwrite":
        warning(f"Output exists, overwriting: {target}")
        return target
    renamed = safe_output_path(base_dir, rel, suffix)
    info(f"Output exists, using: {renamed.name}")
    return renamed


def format_size(num_bytes):
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024.0


def maybe_warn_fernet_large_files(paths, interactive=False):
    large_files = []
    for p in paths:
        try:
            sz = p.stat().st_size
            if sz >= FERNET_LARGE_FILE_WARN_BYTES:
                large_files.append((p, sz))
        except Exception:
            continue
    if not large_files:
        return True
    warning("Fernet large-file warning: Fernet is best kept for small files because it loads full file data into memory.")
    warning("For large files, AES-GCM is recommended because it uses streamed chunked processing.")
    for p, sz in large_files[:10]:
        print(Fore.YELLOW + f" - {p} ({format_size(sz)})")
    if len(large_files) > 10:
        print(Fore.YELLOW + f" ... and {len(large_files)-10} more large file(s).")
    if interactive:
        cont = input(Fore.CYAN + "Continue Fernet operation anyway? (y/N): ").strip().lower() == "y"
        if not cont:
            warning("Operation cancelled by user.")
            return False
    return True

def key_metadata_value(key_filename):
    mp = get_metadata_path(key_filename)
    if not mp.exists():
        return "none"
    try:
        return json.loads(mp.read_text()).get("metadata", "none")
    except Exception:
        return "unreadable"

def manifest_output_candidates(entry):
    candidates = []
    raw_output = entry.get("output_path")
    if raw_output:
        candidates.append(Path(raw_output))
    rel_output = entry.get("output_relative_path")
    if rel_output:
        base = STATE.output_dir if entry.get("operation") == "encrypt" else STATE.decrypt_output_dir
        candidates.append(base / rel_output)
    # Preserve order while dropping duplicates.
    seen = set()
    unique = []
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            unique.append(candidate)
            seen.add(key)
    return unique


def manifest_entry_output_exists(entry):
    return any(candidate.exists() for candidate in manifest_output_candidates(entry))


def verify_manifest_integrity(manifest_path=None):
    manifest_path = Path(manifest_path) if manifest_path else (STATE.output_dir / "operations_manifest.jsonl")
    if not manifest_path.exists():
        error("No operations manifest found.")
        return False
    ok = True
    pass_count = 0
    fail_count = 0
    info("Manifest Verification: verifying output hashes from operations manifest...")
    for i, line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            candidates = manifest_output_candidates(entry)
            out = next((candidate for candidate in candidates if candidate.exists()), candidates[0] if candidates else Path(""))
            expected = entry.get("output_sha256")
            if not out.exists():
                error(f"FAIL [{i}] missing: {out}")
                LOGGER.error("Manifest verify fail [line %s]: missing output candidates %s", i, [str(c) for c in candidates])
                ok = False
                fail_count += 1
                continue
            actual = calculate_hash(out)
            if actual == expected:
                success(f"PASS [{i}] {out}")
                pass_count += 1
            else:
                error(f"FAIL [{i}] hash mismatch: {out}")
                LOGGER.error("Manifest verify fail [line %s]: hash mismatch for %s (expected=%s actual=%s)", i, out, expected, actual)
                ok = False
                fail_count += 1
        except Exception as e:
            warning(f"Skipping invalid manifest entry on line {i}.")
            LOGGER.exception("Manifest verify invalid entry [line %s]", i)
            ok = False
            fail_count += 1
    info(f"Manifest verification summary: PASS={pass_count} FAIL={fail_count}")
    success("Overall result: PASS") if ok else error("Overall result: FAIL")
    return ok

def detect_key_type(key_data):
    if len(key_data) == 44:
        try:
            Fernet(key_data)
            return "Fernet"
        except Exception:
            return "Unknown(44)"
    if len(key_data) == 32:
        return "AES-256"
    return f"Unknown({len(key_data)} bytes)"


def aes_file_prefix(file_path):
    try:
        with open(file_path, "rb") as file:
            return file.read(4)
    except Exception:
        return b""


def needs_legacy_cfb_opt_in(file_path):
    prefix = aes_file_prefix(file_path)
    return prefix not in (b"GCM1", b"GCM2")

def write_manifest(entry, manifest_path=None):
    manifest_path = Path(manifest_path) if manifest_path else (STATE.output_dir / "operations_manifest.jsonl")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "a", encoding="utf-8") as mf:
        mf.write(json.dumps(entry) + "\n")

def build_manifest_entry(operation, algorithm, input_path, output_path, key_name, input_sha256=None, output_sha256=None):
    input_path = Path(input_path)
    output_path = Path(output_path)
    output_base = STATE.output_dir if operation == "encrypt" else STATE.decrypt_output_dir
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "algorithm": algorithm,
        "input_path": str(input_path),
        "output_path": str(output_path),
        "input_relative_path": str(relative_path_for(input_path, STATE.input_dir if operation == "encrypt" else STATE.output_dir)),
        "output_relative_path": str(relative_path_for(output_path, output_base)),
        "input_sha256": input_sha256 if input_sha256 is not None else calculate_hash(input_path),
        "output_sha256": output_sha256 if output_sha256 is not None else calculate_hash(output_path),
        "key_name": key_name,
    }

# Function to clear terminal
def clear_terminal():
    if os.environ.get("ENCRYPTOPI_NO_CLEAR") == "1":
        return
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to generate a new encryption key
def generate_key():
    try:
        ensure_app_dirs()
        key = Fernet.generate_key()
        key_id = base64.urlsafe_b64encode(os.urandom(9)).decode("utf-8").rstrip("=")
        key_filename = STATE.keys_dir / (f"key_{key_id}.key")
        with open(key_filename, "wb") as key_file:
            key_file.write(key)
        secure_key_permissions(key_filename)
        success(f"Key generated and saved as {key_filename}")
    except Exception as e:
        LOGGER.exception("generate_key failed")
        error("Error generating key.")

# Function to show available keys
def show_keys():
    try:
        info("Available keys:")
        for key_file in sorted(STATE.keys_dir.iterdir()):
            if key_file.suffix == ".key":
                key_data = load_key(key_file.name)
                key_type = detect_key_type(key_data) if key_data else "Unreadable"
                meta = "yes" if get_metadata_path(key_file.name).exists() else "no"
                bkp = "yes" if (STATE.backup_dir / key_file.name).exists() else "no"
                mod = key_file.stat().st_mtime
                mstr = datetime.fromtimestamp(mod).strftime("%Y-%m-%d %H:%M")
                print(f" - {key_file.name:<32} [{key_type:<10}]  Metadata: {'Yes' if meta == 'yes' else 'No'}  Backup: {'Yes' if bkp == 'yes' else 'No'}  Modified: {mstr}")
    except Exception as e:
        LOGGER.exception("show_keys failed")
        error("Error showing keys.")

# Function to load a key
def load_key(key_filename):
    try:
        key_path = resolve_key_path(key_filename)
        if key_path is None or not key_path.is_file():
            error("Key file not found.")
            return None
        with open(key_path, "rb") as key_file:
            key_data = key_file.read()
        return key_data
    except Exception:
        LOGGER.exception("load_key failed for %s", key_filename)
        error("Error loading key.")
        return None


def select_key_by_length(expected_length=None, prompt="Enter the key filename to use (from above): "):
    show_keys()
    key_filename = input(Fore.CYAN + prompt).strip()
    key = load_key(key_filename)
    if key is None:
        return None
    if expected_length is not None and len(key) != expected_length:
        print(Fore.RED + f"Invalid key length for selected operation. Expected {expected_length} bytes.")
        return None
    return key

# Function to calculate file hash for integrity check
def calculate_hash(file_path):
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                hasher.update(block)
        return hasher.hexdigest()
    except Exception:
        LOGGER.exception("calculate_hash failed for %s", file_path)
        error(f"Error calculating hash for {file_path}.")
        return None

# Function to encrypt a file using Fernet
def encrypt_file_fernet(file_path, key, key_name="unknown", manifest_path=None, output_dir=None, relative_base=None, output_policy="rename"):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        rel = relative_path_for(file_path, STATE.input_dir, relative_base)
        target_output_dir = Path(output_dir) if output_dir else STATE.output_dir
        encrypted_file_path = choose_output_path(target_output_dir, rel, ".enc", output_policy=output_policy)
        if encrypted_file_path is None:
            return None
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)
        write_manifest(build_manifest_entry("encrypt", "Fernet", file_path, encrypted_file_path, key_name), manifest_path=manifest_path)
        success(f"Encrypted {file_path.name} to {encrypted_file_path.name}")
        return encrypted_file_path
    except Exception:
        LOGGER.exception("Fernet encrypt failed for %s", file_path)
        error(f"Error encrypting file {file_path}: operation failed (details written to logs/encryptopi.log).")
        return None

# Function to decrypt a file using Fernet
def decrypt_file_fernet(file_path, key, key_name="unknown", manifest_path=None, decrypt_output_dir=None, record_manifest=True, relative_base=None, output_policy="rename"):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        rel = relative_path_for(file_path, STATE.output_dir, relative_base)
        rel = rel.with_suffix("")
        target_decrypt_dir = Path(decrypt_output_dir) if decrypt_output_dir else STATE.decrypt_output_dir
        decrypted_file_path = choose_output_path(target_decrypt_dir, rel, "", output_policy=output_policy)
        if decrypted_file_path is None:
            return None
        with open(decrypted_file_path, "wb") as file:
            file.write(decrypted_data)
        if record_manifest:
            write_manifest(build_manifest_entry("decrypt", "Fernet", file_path, decrypted_file_path, key_name), manifest_path=manifest_path)
        success(f"Decrypted {file_path.name} to {target_decrypt_dir}")
        return decrypted_file_path
    except Exception as e:
        LOGGER.exception("Fernet decrypt failed for %s", file_path)
        error(f"Error decrypting file {file_path}: operation failed (details written to logs/encryptopi.log).")
        return None

# Function to handle encryption of multiple or all files
def encrypt_files():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the Fernet key filename to use (from above): ").strip()
        key = load_key(key_filename)
        if key is None or len(key) != 44:
            error("Wrong key type selected. Expected a Fernet key.")
            return
        if key is None:
            return
        
        files_to_encrypt = [p for p in STATE.input_dir.rglob("*") if p.is_file()]
        if not files_to_encrypt:
            warning("No files found to encrypt.")
            return
        if not maybe_warn_fernet_large_files(files_to_encrypt, interactive=True):
            return
        if not confirm_encryption_safety():
            return
        output_policy = prompt_output_policy()
        info("Encrypting files...")
        ok_count, fail_count = 0, 0
        for file_path in tqdm(files_to_encrypt, desc="Encrypting", unit="file"):
            original_hash = calculate_hash(file_path)
            encrypted_file_path = encrypt_file_fernet(file_path, key, key_filename, output_policy=output_policy)
            if not encrypted_file_path:
                fail_count += 1
                continue
            ok_count += 1
            rel = file_path.relative_to(STATE.input_dir) if STATE.input_dir in file_path.parents else Path(file_path.name)
            decrypted_file_path = decrypt_file_fernet(encrypted_file_path, key, key_filename, record_manifest=False)
            if decrypted_file_path is None:
                warning(f"Roundtrip verification skipped for {file_path.name} (decrypt failed).")
                continue
            decrypted_hash = calculate_hash(decrypted_file_path)
            if original_hash != decrypted_hash:
                warning(f"Integrity check failed for {file_path.name}")
            if decrypted_file_path.exists():
                os.remove(decrypted_file_path)
        info(f"Encryption summary: succeeded={ok_count} failed={fail_count}")
    except KeyboardInterrupt:
        LOGGER.info("encrypt_files interrupted by user")
        warning("Operation interrupted by user.")
    except Exception:
        LOGGER.exception("encrypt_files failed")
        error("Error encrypting files.")

# Function to handle decryption of multiple or all files
def decrypt_files():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the Fernet key filename to use (from above): ").strip()
        key = load_key(key_filename)
        if key is None or len(key) != 44:
            error("Wrong key type selected. Expected a Fernet key.")
            return
        if key is None:
            return
        encrypted_files = [p for p in STATE.output_dir.rglob("*.enc") if p.is_file()]
        if not encrypted_files:
            warning("No encrypted files found.")
            return
        if not maybe_warn_fernet_large_files(encrypted_files, interactive=True):
            return
        output_policy = prompt_output_policy()
        info("Decrypting files...")
        ok_count, fail_count = 0, 0
        for file_path in tqdm(encrypted_files, desc="Decrypting", unit="file"):
            result = decrypt_file_fernet(file_path, key, key_filename, output_policy=output_policy)
            if result is None: fail_count += 1
            else: ok_count += 1
        info(f"Decryption summary: succeeded={ok_count} failed={fail_count}")
    except KeyboardInterrupt:
        LOGGER.info("decrypt_files interrupted by user")
        warning("Operation interrupted by user.")
    except Exception:
        LOGGER.exception("decrypt_files failed")
        error("Error decrypting files.")

# Function to check file integrity
def check_file_integrity():
    try:
        info("Checking Manifest Integrity against operations manifest...")
        verify_manifest_integrity()
    except Exception:
        LOGGER.exception("integrity check failed")
        error("Error checking file integrity.")


def prompt_existing_file(prompt_text):
    p = Path(input(Fore.CYAN + prompt_text).strip())
    if not p.is_file():
        error(f"File not found: {p}")
        return None
    return p


def prompt_yes_no(prompt_text, default=False):
    suffix = "Y/n" if default else "y/N"
    raw = input(Fore.CYAN + f"{prompt_text} ({suffix}): ").strip().lower()
    if not raw:
        return default
    return raw == "y"


def confirm_encryption_safety():
    global ENCRYPTION_WARNING_SHOWN
    if ENCRYPTION_WARNING_SHOWN or os.environ.get("ENCRYPTOPI_SKIP_ENCRYPTION_WARNING") == "1":
        return True
    clear_terminal()
    ui_box(
        "Before You Encrypt",
        [
            "Back up your key before encrypting important files.",
            "If a key is lost, files encrypted with that key cannot be recovered.",
            "If using passphrase mode, the exact passphrase is required later.",
            "Use AES-GCM for large files.",
        ],
        subtitle="Encryption is only useful if you can decrypt later",
    )
    if not prompt_yes_no("I understand. Continue with encryption?", default=False):
        warning("Encryption cancelled.")
        return False
    ENCRYPTION_WARNING_SHOWN = True
    return True


def prompt_output_policy(default=DEFAULT_OUTPUT_POLICY):
    raw = input(Fore.CYAN + f"Output policy rename/skip/overwrite [{default}]: ").strip().lower()
    if not raw:
        raw = default
    if raw not in ("rename", "skip", "overwrite"):
        warning("Invalid output policy; using rename.")
        return "rename"
    return raw


def prompt_directory(prompt_text, default_path):
    raw = input(Fore.CYAN + f"{prompt_text} [{default_path}]: ").strip()
    path = Path(raw) if raw else Path(default_path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def prompt_passphrase(confirm=False):
    first = getpass(Fore.CYAN + "Passphrase: ")
    if not first:
        error("Passphrase cannot be empty.")
        return None
    if confirm:
        second = getpass(Fore.CYAN + "Confirm passphrase: ")
        if first != second:
            error("Passphrases do not match.")
            return None
    return first.encode("utf-8")


def derive_passphrase_key(passphrase, salt, n=None, r=None, p=None):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=n if n is not None else SCRYPT_N,
        r=r if r is not None else SCRYPT_R,
        p=p if p is not None else SCRYPT_P,
        backend=default_backend(),
    )
    return kdf.derive(passphrase)


def encode_passphrase_header(salt, iv):
    header = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "kdf": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(header_bytes)) + header_bytes


def read_passphrase_header(file_path):
    with open(file_path, "rb") as infile:
        prefix = infile.read(4)
        if prefix == b"PWD2":
            header_len_data = infile.read(4)
            if len(header_len_data) != 4:
                raise ValueError("Invalid passphrase AES file format.")
            header_len = struct.unpack(">I", header_len_data)[0]
            if header_len <= 0 or header_len > 4096:
                raise ValueError("Invalid passphrase AES header length.")
            header = json.loads(infile.read(header_len).decode("utf-8"))
            salt = base64.b64decode(header["salt"])
            iv = base64.b64decode(header["iv"])
            n = int(header["n"])
            r = int(header["r"])
            p = int(header["p"])
            data_offset = 4 + 4 + header_len
        elif prefix == b"PWD1":
            salt = infile.read(16)
            iv = infile.read(12)
            n, r, p = SCRYPT_N, SCRYPT_R, SCRYPT_P
            data_offset = 4 + 16 + 12
        else:
            raise ValueError("Unsupported passphrase AES file format.")
        infile.seek(0, os.SEEK_END)
        total_size = infile.tell()
        ciphertext_len = total_size - data_offset - 16
        if ciphertext_len < 0:
            raise ValueError("Invalid passphrase AES file format.")
        infile.seek(data_offset + ciphertext_len)
        tag = infile.read(16)
        if len(tag) != 16:
            raise ValueError("Invalid passphrase AES file format.")
    return salt, iv, n, r, p, data_offset, ciphertext_len, tag


def dry_run_preview(paths, label):
    info(f"[DRY-RUN] {label}: {len(paths)} file(s)")
    for p in paths[:20]:
        print(f" - {p}")
    if len(paths) > 20:
        print(f" ... and {len(paths) - 20} more")


def key_fingerprint(key_data):
    return hashlib.sha256(key_data).hexdigest()[:16]


def show_key_details():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter key filename to inspect: ").strip()
        key_path = resolve_key_path(key_filename)
        if key_path is None or not key_path.is_file():
            error("Key file not found.")
            return
        key_data = key_path.read_bytes()
        metadata_path = get_metadata_path(key_path.name)
        backup_path = STATE.backup_dir / key_path.name
        manifest_path = STATE.output_dir / "operations_manifest.jsonl"
        last_used = "never"
        if manifest_path.exists():
            for line in manifest_path.read_text(encoding="utf-8").splitlines():
                try:
                    entry = json.loads(line)
                except Exception:
                    continue
                if entry.get("key_name") == key_path.name:
                    last_used = f"{entry.get('timestamp_utc', 'unknown')} {entry.get('operation', '')} {entry.get('algorithm', '')}".strip()
        print(Fore.CYAN + "\nKey details")
        print(f"Name:        {key_path.name}")
        print(f"Type:        {detect_key_type(key_data)}")
        print(f"Size:        {len(key_data)} bytes")
        print(f"Fingerprint: {key_fingerprint(key_data)}")
        print(f"Modified:    {datetime.fromtimestamp(key_path.stat().st_mtime).isoformat(timespec='seconds')}")
        print(f"Metadata:    {key_metadata_value(key_path.name)}")
        print(f"Metadata file exists: {'yes' if metadata_path.exists() else 'no'}")
        print(f"Backup exists:        {'yes' if backup_path.exists() else 'no'}")
        print(f"Last manifest use:    {last_used}")
    except Exception:
        LOGGER.exception("show_key_details failed")
        error("Error showing key details.")


def import_key():
    try:
        src = prompt_existing_file("Enter source key file path: ")
        if src is None:
            return
        key_data = src.read_bytes()
        key_type = detect_key_type(key_data)
        if not key_type.startswith(("Fernet", "AES-256")):
            error(f"Unsupported key format: {key_type}")
            return
        default_name = src.name if src.name.endswith(".key") else src.name + ".key"
        dest_name = input(Fore.CYAN + f"Save as key filename [{default_name}]: ").strip() or default_name
        dest_path = resolve_key_path(dest_name)
        if dest_path is None:
            return
        if dest_path.exists() and not prompt_yes_no("Key already exists. Overwrite?", default=False):
            warning("Import cancelled.")
            return
        dest_path.write_bytes(key_data)
        secure_key_permissions(dest_path)
        success(f"Imported {key_type} key as {dest_path.name}")
    except Exception:
        LOGGER.exception("import_key failed")
        error("Error importing key.")


def import_key_bundle():
    try:
        bundle_raw = input(Fore.CYAN + "Enter recovery bundle folder path: ").strip()
        if not bundle_raw:
            error("Bundle folder path cannot be empty.")
            return
        bundle_dir = Path(bundle_raw).expanduser()
        if not bundle_dir.is_dir():
            error("Bundle folder not found.")
            return

        bundle_keys = sorted(bundle_dir.glob("*.key"))
        if not bundle_keys:
            error("No .key file found in bundle.")
            return
        if len(bundle_keys) > 1:
            error("Bundle has more than one .key file. Import one key file directly or clean the bundle first.")
            return

        src_key = bundle_keys[0]
        key_data = src_key.read_bytes()
        key_type = detect_key_type(key_data)
        if not key_type.startswith(("Fernet", "AES-256")):
            error(f"Unsupported key format: {key_type}")
            return

        fingerprint = key_fingerprint(key_data)
        fingerprint_path = bundle_dir / "KEY_FINGERPRINT.txt"
        if fingerprint_path.exists():
            fingerprint_text = fingerprint_path.read_text(encoding="utf-8", errors="replace")
            if fingerprint not in fingerprint_text:
                warning("Bundle fingerprint file does not match this key.")
                if not prompt_yes_no("Import anyway?", default=False):
                    warning("Bundle import cancelled.")
                    return

        print(Fore.CYAN + "\nRecovery bundle")
        print(f"Key file:    {src_key.name}")
        print(f"Key type:    {key_type}")
        print(f"Fingerprint: {fingerprint}")
        if (bundle_dir / "README_RECOVERY.txt").exists():
            print("Readme:      present")

        dest_name = input(Fore.CYAN + f"Save as key filename [{src_key.name}]: ").strip() or src_key.name
        dest_path = resolve_key_path(dest_name)
        if dest_path is None:
            return
        if dest_path.exists() and not prompt_yes_no("Key already exists. Overwrite?", default=False):
            warning("Bundle import cancelled.")
            return

        dest_path.write_bytes(key_data)
        secure_key_permissions(dest_path)

        metadata_src = bundle_dir / get_metadata_path(src_key.name).name
        if metadata_src.exists():
            metadata_dest = get_metadata_path(dest_path.name)
            if metadata_dest.exists() and not prompt_yes_no("Metadata already exists. Overwrite?", default=False):
                warning("Metadata import skipped.")
            else:
                shutil.copy2(metadata_src, metadata_dest)

        success(f"Imported recovery bundle key as {dest_path.name}")
    except Exception:
        LOGGER.exception("import_key_bundle failed")
        error("Error importing key bundle.")


def create_key_bundle(key_path, dest_dir):
    key_path = Path(key_path)
    dest_dir = Path(dest_dir).expanduser()
    if not key_path.is_file():
        error("Key file not found.")
        return False
    if dest_dir.exists() and not dest_dir.is_dir():
        error("Bundle destination must be a folder.")
        return False

    key_data = key_path.read_bytes()
    dest_key = dest_dir / key_path.name
    if dest_key.exists() and not prompt_yes_no("Bundle already contains this key. Overwrite?", default=False):
        warning("Bundle export cancelled.")
        return False

    warning("This bundle contains a decryption key. Anyone with the key can decrypt matching files.")
    dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(key_path, dest_key)
    secure_key_permissions(dest_key)

    metadata_path = get_metadata_path(key_path.name)
    if metadata_path.exists():
        shutil.copy2(metadata_path, dest_dir / metadata_path.name)

    fingerprint = key_fingerprint(key_data)
    key_type = detect_key_type(key_data)
    fingerprint_text = "\n".join([
        "EncryptoPI Key Fingerprint",
        f"Key file: {key_path.name}",
        f"Key type: {key_type}",
        f"Fingerprint: {fingerprint}",
        "",
    ])
    (dest_dir / "KEY_FINGERPRINT.txt").write_text(fingerprint_text, encoding="utf-8")

    readme_text = "\n".join([
        "EncryptoPI Recovery Bundle",
        "",
        "This folder contains a decryption key. Keep it private and store it somewhere safe.",
        "Anyone with this key can decrypt files that were encrypted with the matching key.",
        "",
        "To recover, copy the .key file back into EncryptoPI's keys folder, then decrypt as usual.",
        "Use KEY_FINGERPRINT.txt to confirm the restored key matches your records.",
        f"Created: {datetime.now().isoformat(timespec='seconds')}",
        "",
    ])
    (dest_dir / "README_RECOVERY.txt").write_text(readme_text, encoding="utf-8")
    return True


def export_key():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter key filename to export: ").strip()
        key_path = resolve_key_path(key_filename)
        if key_path is None or not key_path.is_file():
            error("Key file not found.")
            return
        dest_raw = input(Fore.CYAN + "Enter export destination file path: ").strip()
        if not dest_raw:
            error("Destination path cannot be empty.")
            return
        dest = Path(dest_raw).expanduser()
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and not prompt_yes_no("Destination exists. Overwrite?", default=False):
            warning("Export cancelled.")
            return
        shutil.copy2(key_path, dest)
        secure_key_permissions(dest)
        success(f"Exported key to {dest}")
    except Exception:
        LOGGER.exception("export_key failed")
        error("Error exporting key.")


def export_key_bundle():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter key filename to bundle export: ").strip()
        key_path = resolve_key_path(key_filename)
        if key_path is None or not key_path.is_file():
            error("Key file not found.")
            return

        default_dest = STATE.script_dir / f"{key_path.stem}_key_bundle"
        dest_raw = input(Fore.CYAN + f"Enter bundle destination folder [{default_dest}]: ").strip()
        dest_dir = Path(dest_raw).expanduser() if dest_raw else default_dest
        if create_key_bundle(key_path, dest_dir):
            success(f"Exported recovery bundle to {dest_dir}")
    except Exception:
        LOGGER.exception("export_key_bundle failed")
        error("Error exporting key bundle.")


def read_manifest_entries(manifest_path=None):
    path = Path(manifest_path) if manifest_path else STATE.output_dir / "operations_manifest.jsonl"
    entries = []
    if not path.exists():
        return entries
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            entry["_line"] = line_no
            entries.append(entry)
        except Exception:
            entries.append({"_line": line_no, "_invalid": line})
    return entries


def manifest_filter_view():
    try:
        entries = read_manifest_entries()
        if not entries:
            warning("No manifest entries found.")
            return
        operation = input(Fore.CYAN + "Filter operation encrypt/decrypt/all [all]: ").strip().lower() or "all"
        algorithm = input(Fore.CYAN + "Filter algorithm contains [all]: ").strip().lower()
        key_name = input(Fore.CYAN + "Filter key name contains [all]: ").strip().lower()
        status = input(Fore.CYAN + "Filter status all/missing/present [all]: ").strip().lower() or "all"
        limit_raw = input(Fore.CYAN + "Maximum rows [50]: ").strip()
        limit = int(limit_raw) if limit_raw.isdigit() else 50
        matches = []
        for entry in entries:
            if "_invalid" in entry:
                if status in ("all", "missing"):
                    matches.append(entry)
                continue
            if operation != "all" and entry.get("operation") != operation:
                continue
            if algorithm and algorithm not in entry.get("algorithm", "").lower():
                continue
            if key_name and key_name not in entry.get("key_name", "").lower():
                continue
            exists = manifest_entry_output_exists(entry)
            if status == "missing" and exists:
                continue
            if status == "present" and not exists:
                continue
            matches.append(entry)
        info(f"Manifest matches: {len(matches)}")
        for entry in matches[-limit:]:
            if "_invalid" in entry:
                print(f"line {entry['_line']}: invalid JSON")
                continue
            exists = "present" if manifest_entry_output_exists(entry) else "missing"
            print(f"line {entry['_line']}: {entry.get('timestamp_utc')} {entry.get('operation')} {entry.get('algorithm')} key={entry.get('key_name')} output={exists} {entry.get('output_path')}")
    except Exception:
        LOGGER.exception("manifest_filter_view failed")
        error("Error filtering manifest.")


def audit_report():
    try:
        key_files = list(STATE.keys_dir.glob("*.key")) if STATE.keys_dir.exists() else []
        input_files = [p for p in STATE.input_dir.rglob("*") if p.is_file()] if STATE.input_dir.exists() else []
        output_files = [p for p in STATE.output_dir.rglob("*") if p.is_file()] if STATE.output_dir.exists() else []
        decrypt_files_found = [p for p in STATE.decrypt_output_dir.rglob("*") if p.is_file()] if STATE.decrypt_output_dir.exists() else []
        entries = read_manifest_entries()
        invalid_entries = [e for e in entries if "_invalid" in e]
        missing_outputs = [e for e in entries if "_invalid" not in e and not manifest_entry_output_exists(e)]
        backed_up = sum(1 for k in key_files if (STATE.backup_dir / k.name).exists())
        print(Fore.CYAN + "\nAudit report")
        print(f"Version:                  {APP_VERSION}")
        print(f"Keys:                     {len(key_files)}")
        print(f"Keys with backups:        {backed_up}")
        print(f"Input files:              {len(input_files)}")
        print(f"Output files:             {len(output_files)}")
        print(f"Decrypted output files:   {len(decrypt_files_found)}")
        print(f"Manifest entries:         {len(entries)}")
        print(f"Manifest invalid lines:   {len(invalid_entries)}")
        print(f"Manifest missing outputs: {len(missing_outputs)}")
        print(f"ZIP limits:               entries={MAX_ZIP_ENTRIES}, file={format_size(MAX_ZIP_FILE_BYTES)}, total={format_size(MAX_ZIP_TOTAL_BYTES)}")
        print(f"Default output policy:    {DEFAULT_OUTPUT_POLICY}")
    except Exception:
        LOGGER.exception("audit_report failed")
        error("Error creating audit report.")


def doctor_check():
    ensure_app_dirs()
    setup_logger()
    ok = True
    print(Fore.CYAN + "\nEncryptoPI Doctor")
    print(f"Version: {APP_VERSION}")
    print(f"Python:  {os.sys.version.split()[0]}")
    for module_name in ("cryptography", "colorama", "tqdm"):
        try:
            __import__(module_name)
            success(f"Dependency available: {module_name}")
        except Exception:
            ok = False
            error(f"Dependency missing: {module_name}")
    for directory in [STATE.keys_dir, STATE.input_dir, STATE.output_dir, STATE.decrypt_output_dir, STATE.backup_dir, STATE.logs_dir]:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            probe = directory / ".encryptopi_write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            success(f"Writable directory: {directory}")
        except Exception:
            ok = False
            error(f"Directory not writable: {directory}")
    key_files = list(STATE.keys_dir.glob("*.key")) if STATE.keys_dir.exists() else []
    manifest_path = STATE.output_dir / "operations_manifest.jsonl"
    print(f"Keys found: {len(key_files)}")
    print(f"Manifest: {'present' if manifest_path.exists() else 'not found'}")
    if key_files:
        loose = []
        for key_file in key_files:
            try:
                if os.name != "nt" and (key_file.stat().st_mode & 0o077):
                    loose.append(key_file.name)
            except Exception:
                continue
        if loose:
            warning(f"{len(loose)} key file(s) are readable by group/others. Run backup/regenerate or chmod 600 keys/*.key.")
    success("Doctor result: PASS") if ok else error("Doctor result: FAIL")
    return ok


def settings_screen():
    print(Fore.CYAN + "\nCurrent settings")
    print(f"Script directory:          {STATE.script_dir}")
    print(f"Keys directory:            {STATE.keys_dir}")
    print(f"Input directory:           {STATE.input_dir}")
    print(f"Output directory:          {STATE.output_dir}")
    print(f"Decrypted output directory:{STATE.decrypt_output_dir}")
    print(f"Backup directory:          {STATE.backup_dir}")
    print(f"Logs directory:            {STATE.logs_dir}")
    print(f"Default output policy:     {DEFAULT_OUTPUT_POLICY}")
    print(f"Fernet large-file warning: {format_size(FERNET_LARGE_FILE_WARN_BYTES)}")
    print(f"ZIP max entries:           {MAX_ZIP_ENTRIES}")
    print(f"ZIP max file size:         {format_size(MAX_ZIP_FILE_BYTES)}")
    print(f"ZIP max total size:        {format_size(MAX_ZIP_TOTAL_BYTES)}")
    print(f"Scrypt parameters:         n={SCRYPT_N}, r={SCRYPT_R}, p={SCRYPT_P}")
    print("Set ENCRYPTOPI_* environment variables before launch to override these runtime values.")


def change_runtime_settings():
    global STATE, DEFAULT_OUTPUT_POLICY, MAX_ZIP_ENTRIES, MAX_ZIP_FILE_BYTES, MAX_ZIP_TOTAL_BYTES
    try:
        warning("Runtime setting changes apply only until this program exits.")
        if prompt_yes_no("Change working directories?", default=False):
            STATE = AppState(
                script_dir=STATE.script_dir,
                keys_dir=prompt_directory("Keys directory", STATE.keys_dir),
                input_dir=prompt_directory("Input directory", STATE.input_dir),
                output_dir=prompt_directory("Output directory", STATE.output_dir),
                decrypt_output_dir=prompt_directory("Decrypted output directory", STATE.decrypt_output_dir),
                backup_dir=prompt_directory("Backup directory", STATE.backup_dir),
                logs_dir=prompt_directory("Logs directory", STATE.logs_dir),
            )
            ensure_app_dirs()
            setup_logger()
            success("Runtime directories updated.")
        if prompt_yes_no("Change default output collision policy?", default=False):
            DEFAULT_OUTPUT_POLICY = prompt_output_policy(DEFAULT_OUTPUT_POLICY)
            success(f"Default output policy set to {DEFAULT_OUTPUT_POLICY}.")
        if prompt_yes_no("Change ZIP extraction limits?", default=False):
            entries = input(Fore.CYAN + f"Max ZIP entries [{MAX_ZIP_ENTRIES}]: ").strip()
            file_bytes = input(Fore.CYAN + f"Max ZIP file bytes [{MAX_ZIP_FILE_BYTES}]: ").strip()
            total_bytes = input(Fore.CYAN + f"Max ZIP total bytes [{MAX_ZIP_TOTAL_BYTES}]: ").strip()
            if entries:
                MAX_ZIP_ENTRIES = int(entries)
            if file_bytes:
                MAX_ZIP_FILE_BYTES = int(file_bytes)
            if total_bytes:
                MAX_ZIP_TOTAL_BYTES = int(total_bytes)
            success("ZIP extraction limits updated.")
    except ValueError:
        error("Invalid numeric setting.")
    except Exception:
        LOGGER.exception("change_runtime_settings failed")
        error("Error changing runtime settings.")


def single_file_operation():
    try:
        op = input(Fore.CYAN + "Operation (encrypt/decrypt): ").strip().lower()
        algo = input(Fore.CYAN + "Algorithm (fernet/aes): ").strip().lower()
        if op not in ("encrypt", "decrypt") or algo not in ("fernet", "aes"):
            error("Invalid operation or algorithm.")
            return
        src = prompt_existing_file("Enter full file path: ")
        if src is None:
            return
        dry_run = input(Fore.CYAN + "Dry run only? (y/N): ").strip().lower() == "y"
        if dry_run:
            dry_run_preview([src], f"{op} via {algo}")
            return
        if op == "encrypt" and not confirm_encryption_safety():
            return
        output_policy = prompt_output_policy()
        show_keys()
        key_filename = input(Fore.CYAN + "Enter key filename to use: ").strip()
        key = load_key(key_filename)
        if key is None:
            return
        if algo == "fernet":
            if not maybe_warn_fernet_large_files([src], interactive=True):
                return
            if len(key) != 44:
                error("Wrong key type selected. Expected a Fernet key.")
                return
            result = encrypt_file_fernet(src, key, key_filename, output_policy=output_policy) if op == "encrypt" else decrypt_file_fernet(src, key, key_filename, output_policy=output_policy)
        else:
            if len(key) != 32:
                error("Wrong key type selected. Expected a 32-byte AES key.")
                return
            allow_legacy_cfb = False
            if op == "decrypt" and needs_legacy_cfb_opt_in(src):
                warning("Legacy AES-CFB has no authentication; wrong keys or tampering may produce garbage output without cryptographic proof.")
                allow_legacy_cfb = input(Fore.CYAN + "File lacks an AES-GCM header. Try legacy AES-CFB recovery decrypt? (y/N): ").strip().lower() == "y"
            result = encrypt_files_aes_with_key(src, key, key_filename, output_policy=output_policy) if op == "encrypt" else decrypt_file_aes(src, key, key_filename, allow_legacy_cfb=allow_legacy_cfb, output_policy=output_policy)
        if result:
            success(f"Completed: {result}")
    except Exception:
        LOGGER.exception("single_file_operation failed")
        error("Single-file operation failed.")


def dry_run_batch_operation():
    try:
        op = input(Fore.CYAN + "Operation (encrypt/decrypt): ").strip().lower()
        algo = input(Fore.CYAN + "Algorithm (fernet/aes): ").strip().lower()
        if op not in ("encrypt", "decrypt") or algo not in ("fernet", "aes"):
            error("Invalid operation or algorithm.")
            return
        if op == "encrypt":
            files = [p for p in STATE.input_dir.rglob("*") if p.is_file()]
        else:
            files = [p for p in STATE.output_dir.rglob("*.enc" if algo == "fernet" else "*.aes") if p.is_file()]
        if not files:
            warning("No matching files found.")
            return
        dry_run_preview(files, f"batch {op} via {algo}")
    except Exception:
        LOGGER.exception("dry_run_batch_operation failed")
        error("Dry-run batch preview failed.")


def collect_folder_files(folder_path, recursive=True):
    pattern = "**/*" if recursive else "*"
    return [p for p in Path(folder_path).glob(pattern) if p.is_file()]


def custom_folder_operation():
    try:
        op = input(Fore.CYAN + "Operation (encrypt/decrypt): ").strip().lower()
        algo = input(Fore.CYAN + "Algorithm (fernet/aes/passphrase): ").strip().lower()
        if op not in ("encrypt", "decrypt") or algo not in ("fernet", "aes", "passphrase"):
            error("Invalid operation or algorithm.")
            return
        folder = Path(input(Fore.CYAN + "Enter folder path: ").strip())
        if not folder.is_dir():
            error(f"Folder not found: {folder}")
            return
        recursive = prompt_yes_no("Process recursively?", default=True)
        files = collect_folder_files(folder, recursive=recursive)
        if op == "decrypt":
            if algo == "fernet":
                files = [p for p in files if p.suffix == ".enc"]
            elif algo == "aes":
                files = [p for p in files if p.suffix == ".aes"]
            else:
                files = [p for p in files if p.suffix == ".pwaes"]
        if not files:
            warning("No matching files found.")
            return
        if prompt_yes_no("Dry run only?", default=False):
            dry_run_preview(files, f"custom folder {op} via {algo}")
            return
        if op == "encrypt" and not confirm_encryption_safety():
            return
        output_policy = prompt_output_policy()
        out_dir = prompt_directory("Output directory" if op == "encrypt" else "Decrypted output directory", STATE.output_dir if op == "encrypt" else STATE.decrypt_output_dir)
        ok_count, fail_count = 0, 0
        if algo == "passphrase":
            passphrase = prompt_passphrase(confirm=(op == "encrypt"))
            if passphrase is None:
                return
            for file_path in tqdm(files, desc=op.title(), unit="file"):
                if op == "encrypt":
                    result = encrypt_file_passphrase(file_path, passphrase, output_dir=out_dir, relative_base=folder, output_policy=output_policy)
                else:
                    result = decrypt_file_passphrase(file_path, passphrase, decrypt_output_dir=out_dir, relative_base=folder, output_policy=output_policy)
                ok_count += 1 if result else 0
                fail_count += 0 if result else 1
        else:
            show_keys()
            key_filename = input(Fore.CYAN + "Enter key filename to use: ").strip()
            key = load_key(key_filename)
            if key is None:
                return
            if algo == "fernet" and len(key) != 44:
                error("Wrong key type selected. Expected a Fernet key.")
                return
            if algo == "aes" and len(key) != 32:
                error("Wrong key type selected. Expected a 32-byte AES key.")
                return
            allow_legacy_cfb = False
            if op == "decrypt" and algo == "aes" and any(needs_legacy_cfb_opt_in(p) for p in files):
                warning("Legacy AES-CFB has no authentication; wrong keys or tampering may produce garbage output without cryptographic proof.")
                allow_legacy_cfb = prompt_yes_no("Some files lack a GCM header. Try legacy AES-CFB recovery decrypt?", default=False)
            for file_path in tqdm(files, desc=op.title(), unit="file"):
                if algo == "fernet":
                    result = encrypt_file_fernet(file_path, key, key_filename, output_dir=out_dir, relative_base=folder, output_policy=output_policy) if op == "encrypt" else decrypt_file_fernet(file_path, key, key_filename, decrypt_output_dir=out_dir, relative_base=folder, output_policy=output_policy)
                else:
                    result = encrypt_files_aes_with_key(file_path, key, key_filename, output_dir=out_dir, relative_base=folder, output_policy=output_policy) if op == "encrypt" else decrypt_file_aes(file_path, key, key_filename, decrypt_output_dir=out_dir, relative_base=folder, allow_legacy_cfb=allow_legacy_cfb, output_policy=output_policy)
                ok_count += 1 if result else 0
                fail_count += 0 if result else 1
        info(f"Custom folder summary: succeeded={ok_count} failed={fail_count}")
    except Exception:
        LOGGER.exception("custom_folder_operation failed")
        error("Custom folder operation failed.")


def passphrase_single_file_operation():
    try:
        op = input(Fore.CYAN + "Operation (encrypt/decrypt): ").strip().lower()
        if op not in ("encrypt", "decrypt"):
            error("Invalid operation.")
            return
        src = prompt_existing_file("Enter full file path: ")
        if src is None:
            return
        if prompt_yes_no("Dry run only?", default=False):
            dry_run_preview([src], f"{op} via passphrase")
            return
        if op == "encrypt" and not confirm_encryption_safety():
            return
        output_policy = prompt_output_policy()
        passphrase = prompt_passphrase(confirm=(op == "encrypt"))
        if passphrase is None:
            return
        result = encrypt_file_passphrase(src, passphrase, output_policy=output_policy) if op == "encrypt" else decrypt_file_passphrase(src, passphrase, output_policy=output_policy)
        if result:
            success(f"Completed: {result}")
    except Exception:
        LOGGER.exception("passphrase_single_file_operation failed")
        error("Passphrase operation failed.")


def manifest_tools_menu():
    manifest_path = STATE.output_dir / "operations_manifest.jsonl"
    while True:
        clear_terminal()
        render_menu(
            "Manifest & Integrity",
            [
                ("1", "Verify manifest", "check file hashes"),
                ("2", "Show recent entries", "last 20 records"),
                ("3", "Search entries", "filter records"),
                ("4", "Prune stale entries", "clean missing files"),
                ("5", "Audit report", "tool health summary"),
            ],
            subtitle="Check saved operation records",
        )
        c = prompt_choice()
        if c == "1":
            verify_manifest_integrity(manifest_path=manifest_path)
        elif c == "2":
            if not manifest_path.exists():
                warning("Manifest does not exist.")
                continue
            lines = manifest_path.read_text(encoding="utf-8").splitlines()[-20:]
            for line in lines:
                print(line)
        elif c == "3":
            manifest_filter_view()
        elif c == "4":
            if not manifest_path.exists():
                warning("Manifest does not exist.")
                continue
            kept = []
            removed = 0
            for line in manifest_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    if manifest_entry_output_exists(entry):
                        kept.append(line)
                    else:
                        removed += 1
                except Exception:
                    removed += 1
            manifest_path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
            success(f"Pruned manifest entries: removed={removed}, kept={len(kept)}")
        elif c == "5":
            audit_report()
        elif c in ("b", "q"):
            clear_terminal()
            break
        else:
            warning("Invalid choice.")

# Function to compress files
def compress_files():
    try:
        info("Compressing files...")
        files_to_compress = [p for p in STATE.input_dir.rglob('*') if p.is_file()]
        if not files_to_compress:
            warning("No files found to compress.")
            return
        zip_file_path = STATE.output_dir / "files.zip"
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in files_to_compress:
                zipf.write(file, file.relative_to(STATE.input_dir))
        success(f"Files compressed to {zip_file_path}")
    except Exception as e:
        LOGGER.exception("compress_files failed")
        error("Error compressing files.")


def decompress_files():
    try:
        default_zip = STATE.output_dir / "files.zip"
        raw = input(Fore.CYAN + f"Enter ZIP file path [{default_zip}]: ").strip()
        zip_path = Path(raw) if raw else default_zip
        if not zip_path.is_file():
            error(f"ZIP file not found: {zip_path}")
            return
        target_dir = STATE.script_dir / "decompressed_output"
        target_dir.mkdir(parents=True, exist_ok=True)
        extracted = 0
        skipped = 0
        total_uncompressed = 0
        with zipfile.ZipFile(zip_path, "r") as zf:
            members = zf.infolist()
            if len(members) > MAX_ZIP_ENTRIES:
                error(f"ZIP archive has too many entries ({len(members)} > {MAX_ZIP_ENTRIES}).")
                return
            declared_total = 0
            for member in members:
                if member.file_size > MAX_ZIP_FILE_BYTES:
                    error(f"ZIP member exceeds maximum size: {member.filename} ({format_size(member.file_size)} > {format_size(MAX_ZIP_FILE_BYTES)})")
                    return
                declared_total += member.file_size
                if declared_total > MAX_ZIP_TOTAL_BYTES:
                    error(f"ZIP archive exceeds maximum total extracted size ({format_size(declared_total)} > {format_size(MAX_ZIP_TOTAL_BYTES)}).")
                    return
            for member in members:
                member_path = Path(member.filename)
                if member_path.is_absolute() or ".." in member_path.parts:
                    warning(f"Skipping unsafe archive path: {member.filename}")
                    skipped += 1
                    continue
                dest = (target_dir / member.filename).resolve()
                if not is_within(target_dir, dest):
                    warning(f"Skipping unsafe extraction target: {member.filename}")
                    skipped += 1
                    continue
                if member.is_dir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member, "r") as src, open(dest, "wb") as out:
                    while True:
                        chunk = src.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        total_uncompressed += len(chunk)
                        if total_uncompressed > MAX_ZIP_TOTAL_BYTES:
                            raise ValueError(f"ZIP archive exceeded maximum total extracted size ({format_size(MAX_ZIP_TOTAL_BYTES)}).")
                        out.write(chunk)
                extracted += 1
        success(f"Decompression complete. Extracted={extracted}, Skipped={skipped}, Target={target_dir}")
    except zipfile.BadZipFile:
        LOGGER.exception("decompress_files invalid zip")
        error("Invalid ZIP archive.")
    except Exception:
        LOGGER.exception("decompress_files failed")
        error("Error decompressing files.")

# Function to add metadata to a Fernet key file
def add_key_metadata():
    add_key_metadata_common("Fernet")

# Function to view metadata of a Fernet key file
def view_key_metadata():
    view_key_metadata_common("Fernet")

# Function to delete a key
def delete_key():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to delete (from above): ")
        key_file_path = resolve_key_path(key_filename)
        if key_file_path is None or not key_file_path.is_file():
            error("Key file not found.")
            return
        key_data = load_key(key_filename)
        ktype = detect_key_type(key_data) if key_data else "Unknown"
        meta = key_metadata_value(key_filename)
        backup_path = STATE.backup_dir / key_filename
        warning(f"Selected key: {key_filename} | Type: {ktype} | Metadata: {meta}")
        if not backup_path.exists():
            warning("No backup copy exists for this key.")
            if prompt_yes_no("Create a backup before deletion?", default=True):
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                backup_path.write_bytes(key_file_path.read_bytes())
                success(f"Backup created: {backup_path}")
            elif not prompt_yes_no("Proceed without a backup?", default=False):
                warning("Deletion cancelled.")
                return
        confirm = input(Fore.CYAN + "Type the exact key filename to confirm deletion: ").strip()
        if confirm != key_filename:
            warning("Confirmation mismatch. Deletion cancelled.")
            return
        metadata_path = get_metadata_path(key_filename)
        remove_related = input(Fore.CYAN + "Also delete related metadata and backup copy? (y/N): ").strip().lower() == "y"
        secure_wipe = input(Fore.CYAN + "Best-effort secure overwrite before delete? (y/N): ").strip().lower() == "y"
        if secure_wipe:
            try:
                size = key_file_path.stat().st_size
                with open(key_file_path, "r+b") as kf:
                    kf.write(b"\x00" * size)
                    kf.flush()
                    os.fsync(kf.fileno())
                warning("Performed best-effort overwrite before delete (filesystem behavior may vary).")
            except Exception:
                LOGGER.exception("best-effort key overwrite failed for %s", key_file_path)
                warning("Best-effort overwrite failed; proceeding with normal delete.")
        os.remove(key_file_path)
        if remove_related:
            if metadata_path.exists():
                metadata_path.unlink()
            if backup_path.exists():
                backup_path.unlink()
        success(f"Key {key_filename} deleted.")
    except Exception as e:
        LOGGER.exception("delete_key failed")
        error("Error deleting key.")
        
# Function to back up keys
def backup_keys():
    try:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        snapshot_dir = STATE.backup_dir / timestamp
        suffix = 1
        while snapshot_dir.exists():
            snapshot_dir = STATE.backup_dir / f"{timestamp}_{suffix}"
            suffix += 1
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        copied = 0
        skipped_latest = 0
        for key_file in sorted(STATE.keys_dir.iterdir()):
            if key_file.suffix in [".key", ".json"] and (key_file.suffix == ".key" or key_file.name.endswith("_metadata.json")):
                snapshot_file = snapshot_dir / key_file.name
                snapshot_file.write_bytes(key_file.read_bytes())
                if snapshot_file.suffix == ".key":
                    secure_key_permissions(snapshot_file)
                latest_file = STATE.backup_dir / key_file.name
                if latest_file.exists():
                    skipped_latest += 1
                    warning(f"Latest backup already exists, not overwriting: {latest_file.name}")
                else:
                    latest_file.write_bytes(key_file.read_bytes())
                    if latest_file.suffix == ".key":
                        secure_key_permissions(latest_file)
                copied += 1
                success(f"Backed up: {key_file.name}")
        success(f"Backup operation completed. Snapshot: {snapshot_dir} Files: {copied} Latest-skipped: {skipped_latest}")
    except Exception as e:
        LOGGER.exception("backup_keys failed")
        error("Error backing up keys.")
        
def restore_keys():
    try:
        if not STATE.backup_dir.is_dir():
            error("Backup directory does not exist.")
            return

        snapshot_dirs = sorted([p for p in STATE.backup_dir.iterdir() if p.is_dir()])
        restore_dir = STATE.backup_dir
        if snapshot_dirs:
            latest_snapshot = snapshot_dirs[-1]
            if prompt_yes_no(f"Restore from latest timestamped snapshot {latest_snapshot.name}?", default=True):
                restore_dir = latest_snapshot

        candidates = [
            backup_file for backup_file in sorted(restore_dir.iterdir())
            if backup_file.is_file() and backup_file.suffix in [".key", ".json"] and (backup_file.suffix == ".key" or backup_file.name.endswith("_metadata.json"))
        ]
        if not candidates:
            warning("No key or metadata backup files found to restore.")
            return

        overwrites = [backup_file.name for backup_file in candidates if (STATE.keys_dir / backup_file.name).exists()]
        if overwrites:
            warning(f"Restore would overwrite {len(overwrites)} existing file(s): {', '.join(overwrites[:5])}{'...' if len(overwrites) > 5 else ''}")
            if not prompt_yes_no("Overwrite existing key/metadata files during restore?", default=False):
                warning("Restore cancelled.")
                return

        for backup_file in candidates:
            restored = STATE.keys_dir / backup_file.name
            restored.write_bytes(backup_file.read_bytes())
            if restored.suffix == ".key":
                secure_key_permissions(restored)
            success(f"Restored: {backup_file.name}")
        success(f"Restore operation completed from {restore_dir}.")
    except Exception as e:
        LOGGER.exception("restore_keys failed")
        error("Error restoring keys.")
        
def create_aes_key_file():
    ensure_app_dirs()
    key = os.urandom(32)  # AES-256 key size
    key_id = base64.urlsafe_b64encode(os.urandom(9)).decode("utf-8").rstrip("=")
    key_filename = STATE.keys_dir / (f"aes_key_{key_id}.key")
    with open(key_filename, "wb") as key_file:
        key_file.write(key)
    secure_key_permissions(key_filename)
    return key_filename


def generate_aes_key():
    try:
        key_filename = create_aes_key_file()
        success(f"AES Key generated and saved as {key_filename}")
    except Exception:
        LOGGER.exception("generate_aes_key failed")
        error("Error generating AES key.")        
        
def encrypt_files_aes_with_key(file_path, key, key_name="unknown", manifest_path=None, output_dir=None, relative_base=None, output_policy="rename"):
    try:
        if len(key) != 32:
            raise ValueError("Invalid AES key length. Must be 32 bytes for AES-256.")

        iv = os.urandom(12)  # Recommended IV size for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        rel = relative_path_for(file_path, STATE.input_dir, relative_base)
        target_output_dir = Path(output_dir) if output_dir else STATE.output_dir
        encrypted_file_path = choose_output_path(target_output_dir, rel, ".aes", output_policy=output_policy)
        if encrypted_file_path is None:
            return None

        # Stream file encryption to avoid loading large files fully into memory.
        with open(file_path, "rb") as infile, open(encrypted_file_path, "wb") as outfile:
            outfile.write(b"GCM2")
            outfile.write(iv)
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if not chunk:
                    break
                outfile.write(encryptor.update(chunk))
            outfile.write(encryptor.finalize())
            outfile.write(encryptor.tag)

        write_manifest(build_manifest_entry("encrypt", "AES-GCM-v2", file_path, encrypted_file_path, key_name), manifest_path=manifest_path)
        success(f"Encrypted {file_path.name} to {encrypted_file_path.name}")
        return encrypted_file_path
    except Exception:
        LOGGER.exception("AES encrypt failed for %s", file_path)
        error(f"Error encrypting file {file_path}: operation failed (details written to logs/encryptopi.log).")
        return None

def decrypt_file_aes(file_path, key, key_name="unknown", manifest_path=None, decrypt_output_dir=None, relative_base=None, allow_legacy_cfb=False, output_policy="rename"):
    try:
        if len(key) != 32:
            raise ValueError("Invalid AES key length. Must be 32 bytes for AES-256.")
        
        with open(file_path, "rb") as file:
            prefix = file.read(4)
            file.seek(0, os.SEEK_END)
            total_size = file.tell()
            file.seek(0)

        rel = relative_path_for(file_path, STATE.output_dir, relative_base)
        rel = rel.with_suffix("")
        target_decrypt_dir = Path(decrypt_output_dir) if decrypt_output_dir else STATE.decrypt_output_dir
        decrypted_file_path = choose_output_path(target_decrypt_dir, rel, "", output_policy=output_policy)
        if decrypted_file_path is None:
            return None

        if prefix == b"GCM2":
            # Layout: magic(4) + iv(12) + ciphertext(n) + tag(16)
            if total_size < 32:
                raise ValueError("Invalid AES-GCM file format.")
            tmp_path = None
            try:
                with open(file_path, "rb") as infile:
                    infile.read(4)
                    iv = infile.read(12)
                    ciphertext_len = total_size - 4 - 12 - 16
                    if ciphertext_len < 0:
                        raise ValueError("Invalid AES-GCM file format.")
                    tag_pos = 4 + 12 + ciphertext_len
                    infile.seek(tag_pos)
                    tag = infile.read(16)
                    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
                    decryptor = cipher.decryptor()
                    decrypted_file_path.parent.mkdir(parents=True, exist_ok=True)
                    with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(decrypted_file_path.parent), prefix=".decrypt_tmp_") as tf:
                        tmp_path = Path(tf.name)
                        infile.seek(4 + 12)
                        remaining = ciphertext_len
                        while remaining > 0:
                            chunk = infile.read(min(CHUNK_SIZE, remaining))
                            if not chunk:
                                break
                            tf.write(decryptor.update(chunk))
                            remaining -= len(chunk)
                        tf.write(decryptor.finalize())
                tmp_path.replace(decrypted_file_path)
            except Exception:
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink()
                raise
        elif prefix == b"GCM1":
            tmp_path = None
            try:
                with open(file_path, "rb") as file:
                    encrypted_data = file.read()
                iv = encrypted_data[4:16]
                tag = encrypted_data[16:32]
                ciphertext = encrypted_data[32:]
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                decrypted_file_path.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(decrypted_file_path.parent), prefix=".decrypt_tmp_") as tf:
                    tmp_path = Path(tf.name)
                    tf.write(decrypted_data)
                tmp_path.replace(decrypted_file_path)
            except Exception:
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink()
                raise
        else:
            if not allow_legacy_cfb:
                raise ValueError("Unsupported AES file format. Use AES-GCM files or explicitly allow legacy AES-CFB decrypt.")
            warning("Legacy AES-CFB decrypt is unauthenticated recovery mode; verify recovered file contents before trusting them.")
            tmp_path = None
            try:
                with open(file_path, "rb") as file:
                    encrypted_data = file.read()
                if len(encrypted_data) < 16:
                    raise ValueError("Invalid legacy AES-CFB file format.")
                # Backward-compatible decrypt path for legacy CFB-encrypted files
                iv = encrypted_data[:16]
                ciphertext = encrypted_data[16:]
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                decrypted_file_path.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(decrypted_file_path.parent), prefix=".decrypt_tmp_") as tf:
                    tmp_path = Path(tf.name)
                    tf.write(decrypted_data)
                tmp_path.replace(decrypted_file_path)
            except Exception:
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink()
                raise
        algo = "AES-GCM-v2" if prefix == b"GCM2" else ("AES-GCM-v1" if prefix == b"GCM1" else "AES-CFB-legacy")
        write_manifest(build_manifest_entry("decrypt", algo, file_path, decrypted_file_path, key_name), manifest_path=manifest_path)
        success(f"Decrypted {file_path.name} to {decrypted_file_path.name}")
        return decrypted_file_path
    except InvalidTag:
        LOGGER.exception("AES decrypt authentication failed for %s", file_path)
        error("Error decrypting file: authentication failed (data tampered or wrong key).")
        return None
    except Exception as e:
        LOGGER.exception("AES decrypt failed for %s", file_path)
        error(f"Error decrypting file {file_path}: operation failed (details written to logs/encryptopi.log).")
        return None


def encrypt_file_passphrase(file_path, passphrase, manifest_path=None, output_dir=None, relative_base=None, output_policy="rename"):
    try:
        salt = os.urandom(16)
        key = derive_passphrase_key(passphrase, salt)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        rel = relative_path_for(file_path, STATE.input_dir, relative_base)
        target_output_dir = Path(output_dir) if output_dir else STATE.output_dir
        encrypted_file_path = choose_output_path(target_output_dir, rel, ".pwaes", output_policy=output_policy)
        if encrypted_file_path is None:
            return None
        with open(file_path, "rb") as infile, open(encrypted_file_path, "wb") as outfile:
            outfile.write(b"PWD2")
            outfile.write(encode_passphrase_header(salt, iv))
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if not chunk:
                    break
                outfile.write(encryptor.update(chunk))
            outfile.write(encryptor.finalize())
            outfile.write(encryptor.tag)
        write_manifest(build_manifest_entry("encrypt", "AES-GCM-passphrase", file_path, encrypted_file_path, "passphrase"), manifest_path=manifest_path)
        success(f"Encrypted {file_path.name} to {encrypted_file_path.name}")
        return encrypted_file_path
    except Exception:
        LOGGER.exception("Passphrase encrypt failed for %s", file_path)
        error(f"Error encrypting file {file_path}: operation failed (details written to logs/encryptopi.log).")
        return None


def decrypt_file_passphrase(file_path, passphrase, manifest_path=None, decrypt_output_dir=None, relative_base=None, output_policy="rename"):
    try:
        salt, iv, n, r, p, data_offset, ciphertext_len, tag = read_passphrase_header(file_path)
        key = derive_passphrase_key(passphrase, salt, n=n, r=r, p=p)
        rel = relative_path_for(file_path, STATE.output_dir, relative_base).with_suffix("")
        target_decrypt_dir = Path(decrypt_output_dir) if decrypt_output_dir else STATE.decrypt_output_dir
        decrypted_file_path = choose_output_path(target_decrypt_dir, rel, "", output_policy=output_policy)
        if decrypted_file_path is None:
            return None
        tmp_path = None
        try:
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "rb") as infile, tempfile.NamedTemporaryFile("wb", delete=False, dir=str(decrypted_file_path.parent), prefix=".decrypt_tmp_") as tf:
                tmp_path = Path(tf.name)
                infile.seek(data_offset)
                remaining = ciphertext_len
                while remaining > 0:
                    chunk = infile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    tf.write(decryptor.update(chunk))
                    remaining -= len(chunk)
                tf.write(decryptor.finalize())
            tmp_path.replace(decrypted_file_path)
        except Exception:
            if tmp_path and tmp_path.exists():
                tmp_path.unlink()
            raise
        write_manifest(build_manifest_entry("decrypt", "AES-GCM-passphrase", file_path, decrypted_file_path, "passphrase"), manifest_path=manifest_path)
        success(f"Decrypted {file_path.name} to {decrypted_file_path.name}")
        return decrypted_file_path
    except InvalidTag:
        LOGGER.exception("Passphrase AES authentication failed for %s", file_path)
        error("Error decrypting file: authentication failed (wrong passphrase or tampered data).")
        return None
    except Exception:
        LOGGER.exception("Passphrase decrypt failed for %s", file_path)
        error(f"Error decrypting file {file_path}: operation failed (details written to logs/encryptopi.log).")
        return None


def aes_key_files():
    keys = []
    for key_file in sorted(STATE.keys_dir.glob("*.key")):
        try:
            key_data = key_file.read_bytes()
        except Exception:
            continue
        if len(key_data) == 32:
            keys.append(key_file)
    return keys


def guided_select_aes_key():
    keys = aes_key_files()
    if not keys:
        warning("No AES keys found. Guided Encrypt uses AES-GCM.")
        if not prompt_yes_no("Generate a new AES key now?", default=True):
            warning("Guided encryption cancelled.")
            return None, None, None
        key_path = create_aes_key_file()
        success(f"AES Key generated and saved as {key_path}")
        return key_path.name, key_path.read_bytes(), key_path

    print(Fore.CYAN + "\nAES keys")
    for key_file in keys:
        print(f" - {key_file.name}")
    action = input(Fore.CYAN + "Use existing AES key or generate new? (existing/generate) [existing]: ").strip().lower() or "existing"
    if action in ("g", "generate", "new"):
        key_path = create_aes_key_file()
        success(f"AES Key generated and saved as {key_path}")
        return key_path.name, key_path.read_bytes(), key_path

    default_name = keys[0].name
    key_name = input(Fore.CYAN + f"Enter AES key filename [{default_name}]: ").strip() or default_name
    key_path = resolve_key_path(key_name)
    if key_path is None or not key_path.is_file():
        error("Key file not found.")
        return None, None, None
    key_data = key_path.read_bytes()
    if len(key_data) != 32:
        error("Wrong key type selected. Expected a 32-byte AES key.")
        return None, None, None
    return key_path.name, key_data, key_path


def guided_encrypt():
    try:
        clear_terminal()
        ui_box(
            "Guided Encrypt",
            [
                "Recommended path: AES-GCM encryption.",
                "Pick a file or use the input folder.",
                "Choose or generate a key, then optionally export a recovery bundle.",
            ],
            subtitle="Simple, safer encryption workflow",
        )
        source_choice = input(Fore.CYAN + "Encrypt single file or input folder? (file/folder) [folder]: ").strip().lower() or "folder"
        if source_choice in ("f", "file", "single"):
            src = prompt_existing_file("Enter file path: ")
            if src is None:
                return
            files_to_encrypt = [src]
            relative_base = None
            source_label = str(src)
        elif source_choice in ("folder", "input", "i"):
            files_to_encrypt = [p for p in STATE.input_dir.rglob("*") if p.is_file()]
            relative_base = STATE.input_dir
            source_label = str(STATE.input_dir)
        else:
            error("Invalid source choice.")
            return

        if not files_to_encrypt:
            warning("No files found to encrypt.")
            return

        key_name, key, key_path = guided_select_aes_key()
        if key is None:
            return

        if prompt_yes_no("Export a recovery bundle for this key before encrypting?", default=True):
            default_bundle = STATE.script_dir / f"{key_path.stem}_key_bundle"
            bundle_raw = input(Fore.CYAN + f"Bundle destination folder [{default_bundle}]: ").strip()
            bundle_dir = Path(bundle_raw).expanduser() if bundle_raw else default_bundle
            if not create_key_bundle(key_path, bundle_dir):
                return
            success(f"Exported recovery bundle to {bundle_dir}")

        output_policy = prompt_output_policy()
        ui_box(
            "Guided Encrypt Summary",
            [
                f"Source: {source_label}",
                f"Files: {len(files_to_encrypt)}",
                "Algorithm: AES-GCM",
                f"Key: {key_name}",
                f"Output folder: {STATE.output_dir}",
                f"Output policy: {output_policy}",
            ],
            subtitle="Review before writing encrypted files",
        )
        if not prompt_yes_no("Start guided encryption now?", default=False):
            warning("Guided encryption cancelled.")
            return
        if not confirm_encryption_safety():
            return

        ok_count, fail_count = 0, 0
        info("Encrypting files with Guided Encrypt...")
        for file_path in tqdm(files_to_encrypt, desc="Guided encrypt", unit="file"):
            if encrypt_files_aes_with_key(file_path, key, key_name, relative_base=relative_base, output_policy=output_policy):
                ok_count += 1
            else:
                fail_count += 1
        info(f"Guided encryption summary: succeeded={ok_count} failed={fail_count}")
    except KeyboardInterrupt:
        LOGGER.info("guided_encrypt interrupted by user")
        warning("Operation interrupted by user.")
    except Exception:
        LOGGER.exception("guided_encrypt failed")
        error("Guided encryption failed.")


def encrypt_files_aes():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the AES key filename to use (from above): ").strip()
        key = load_key(key_filename)
        if key is None or len(key) != 32:
            error("Wrong key type selected. Expected a 32-byte AES key.")
            return
        
        files_to_encrypt = [p for p in STATE.input_dir.rglob("*") if p.is_file()]
        if not files_to_encrypt:
            warning("No files found to encrypt.")
            return
        if not confirm_encryption_safety():
            return
        output_policy = prompt_output_policy()
        info("Encrypting files...")
        ok_count, fail_count = 0, 0
        for file_path in tqdm(files_to_encrypt, desc="Encrypting", unit="file"):
            if encrypt_files_aes_with_key(file_path, key, key_filename, output_policy=output_policy): ok_count += 1
            else: fail_count += 1
        info(f"Encryption summary: succeeded={ok_count} failed={fail_count}")
    except KeyboardInterrupt:
        LOGGER.info("encrypt_files_aes interrupted by user")
        warning("Operation interrupted by user.")
    except Exception:
        LOGGER.exception("encrypt_files_aes failed")
        error("Error encrypting files.")

def decrypt_files_aes():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the AES key filename to use (from above): ").strip()
        key = load_key(key_filename)
        if key is None or len(key) != 32:
            error("Wrong key type selected. Expected a 32-byte AES key.")
            return
        encrypted_files = [p for p in STATE.output_dir.rglob("*.aes") if p.is_file()]
        if not encrypted_files:
            warning("No encrypted files found.")
            return
        legacy_candidates = [p for p in encrypted_files if needs_legacy_cfb_opt_in(p)]
        allow_legacy_cfb = False
        if legacy_candidates:
            warning(f"{len(legacy_candidates)} AES file(s) lack a GCM header and may be legacy AES-CFB.")
            warning("Legacy AES-CFB has no authentication; wrong keys or tampering may produce garbage output without cryptographic proof.")
            allow_legacy_cfb = input(Fore.CYAN + "Try legacy AES-CFB recovery decrypt for those files? (y/N): ").strip().lower() == "y"
        output_policy = prompt_output_policy()
        info("Decrypting files...")
        ok_count, fail_count = 0, 0
        for file_path in tqdm(encrypted_files, desc="Decrypting", unit="file"):
            result = decrypt_file_aes(file_path, key, key_filename, allow_legacy_cfb=allow_legacy_cfb, output_policy=output_policy)
            if result is None:
                fail_count += 1
            else:
                ok_count += 1
        info(f"Decryption summary: succeeded={ok_count} failed={fail_count}")
    except KeyboardInterrupt:
        LOGGER.info("decrypt_files_aes interrupted by user")
        warning("Operation interrupted by user.")
    except Exception:
        LOGGER.exception("decrypt_files_aes failed")
        error("Error decrypting files.")

def warn_cli_encryption_safety(args):
    if args.command != "encrypt" or getattr(args, "dry_run", False):
        return
    if getattr(args, "yes_i_understand_key_loss", False):
        return
    warning("CLI encryption will write encrypted files. Back up your key/passphrase first; lost secrets cannot be recovered.")
    warning("Pass --yes-i-understand-key-loss to acknowledge this warning in automation.")


def run_cli_operation(args):
    try:
        key = None
        passphrase = None
        if args.infile and args.folder:
            raise SystemExit("Error: use either --infile or --folder, not both.")
        if not args.infile and not args.folder:
            raise SystemExit("Error: provide exactly one of --infile or --folder.")
        if args.infile:
            infile_path = Path(args.infile)
            if not infile_path.is_file():
                raise SystemExit(f"Error: file does not exist: {infile_path}")
            targets = [infile_path]
            relative_base = None
        else:
            folder_path = Path(args.folder)
            if not folder_path.is_dir():
                raise SystemExit(f"Error: folder does not exist: {folder_path}")
            targets = collect_folder_files(folder_path, recursive=args.recursive)
            if args.command == "decrypt":
                suffix = ".enc" if args.algo == "fernet" else (".aes" if args.algo == "aes" else ".pwaes")
                targets = [p for p in targets if p.suffix == suffix]
            if not targets:
                raise SystemExit(f"Error: no files found in folder: {folder_path}")
            relative_base = folder_path
        if args.dry_run:
            dry_run_preview(targets, f"CLI {args.command} via {args.algo}")
            return
        warn_cli_encryption_safety(args)
        if args.algo == "passphrase":
            passphrase_value = os.environ.get(args.passphrase_env)
            if not passphrase_value:
                raise SystemExit(f"Error: passphrase mode requires environment variable {args.passphrase_env}.")
            passphrase = passphrase_value.encode("utf-8")
        else:
            if not args.key:
                raise SystemExit("Error: --key is required for fernet and aes operations.")
            key = load_key(args.key)
            if key is None:
                raise SystemExit(2)
        output_dir = Path(args.output_dir) if args.output_dir else None
        decrypt_output_dir = Path(args.decrypt_output_dir) if args.decrypt_output_dir else None
        manifest_path = Path(args.manifest_path) if args.manifest_path else None
        success_count = 0
        fail_count = 0
        if args.algo == "fernet":
            if len(key) != 44:
                raise SystemExit("Error: wrong key type. Fernet operations require a Fernet key (44-byte base64 key file).")
            maybe_warn_fernet_large_files(targets, interactive=False)
            for t in targets:
                if args.command == "encrypt":
                    result = encrypt_file_fernet(t, key, args.key, manifest_path=manifest_path, output_dir=output_dir, relative_base=relative_base, output_policy=args.output_policy)
                else:
                    result = decrypt_file_fernet(t, key, args.key, manifest_path=manifest_path, decrypt_output_dir=decrypt_output_dir, relative_base=relative_base, output_policy=args.output_policy)
                if result is None:
                    fail_count += 1
                else:
                    success_count += 1
        elif args.algo == "aes":
            if len(key) != 32:
                raise SystemExit("Error: wrong key type. AES operations require a 32-byte AES key file.")
            for t in targets:
                if args.command == "encrypt":
                    result = encrypt_files_aes_with_key(t, key, args.key, manifest_path=manifest_path, output_dir=output_dir, relative_base=relative_base, output_policy=args.output_policy)
                else:
                    result = decrypt_file_aes(t, key, args.key, manifest_path=manifest_path, decrypt_output_dir=decrypt_output_dir, relative_base=relative_base, allow_legacy_cfb=args.allow_legacy_cfb, output_policy=args.output_policy)
                if result is None:
                    fail_count += 1
                else:
                    success_count += 1
        else:
            for t in targets:
                if args.command == "encrypt":
                    result = encrypt_file_passphrase(t, passphrase, manifest_path=manifest_path, output_dir=output_dir, relative_base=relative_base, output_policy=args.output_policy)
                else:
                    result = decrypt_file_passphrase(t, passphrase, manifest_path=manifest_path, decrypt_output_dir=decrypt_output_dir, relative_base=relative_base, output_policy=args.output_policy)
                if result is None:
                    fail_count += 1
                else:
                    success_count += 1
        info("CLI operation completed.")
        success(f"Succeeded: {success_count}")
        if fail_count > 0:
            warning(f"Failed: {fail_count}")
            raise SystemExit(1)
        else:
            success("Failed: 0")
    except KeyboardInterrupt:
        LOGGER.info("CLI operation interrupted by user")
        warning("Operation interrupted by user.")
        raise SystemExit(130)

def run_extended_self_test():
    with tempfile.TemporaryDirectory() as td:
        manifest_path = Path(td) / "selftest_manifest.jsonl"
        test_output_dir = Path(td) / "output"
        test_decrypt_dir = Path(td) / "decrypted_output"
        test_output_dir.mkdir(parents=True, exist_ok=True)
        test_decrypt_dir.mkdir(parents=True, exist_ok=True)
        tpath = Path(td) / "sample.txt"
        tpath.write_text("encryptopi-self-test")
        fkey = Fernet.generate_key()
        akey = os.urandom(32)
        with contextlib.redirect_stdout(io.StringIO()):
            f_enc = encrypt_file_fernet(tpath, fkey, "selftest_fernet", manifest_path=manifest_path, output_dir=test_output_dir)
            f_dec = decrypt_file_fernet(f_enc, fkey, "selftest_fernet", manifest_path=manifest_path, decrypt_output_dir=test_decrypt_dir)
            a_enc = encrypt_files_aes_with_key(tpath, akey, "selftest_aes", manifest_path=manifest_path, output_dir=test_output_dir)
            a_dec = decrypt_file_aes(a_enc, akey, "selftest_aes", manifest_path=manifest_path, decrypt_output_dir=test_decrypt_dir)
            before_failed = list(test_decrypt_dir.glob("sample*"))
            wrong_key_result = decrypt_file_aes(a_enc, os.urandom(32), "selftest_aes_wrongkey", manifest_path=manifest_path, decrypt_output_dir=test_decrypt_dir)
            after_failed = list(test_decrypt_dir.glob("sample*"))
            tampered = test_output_dir / "sample_tampered.aes"
            tampered.write_bytes(a_enc.read_bytes())
            tampered_data = bytearray(tampered.read_bytes())
            tampered_data[20] ^= 0x01
            tampered.write_bytes(bytes(tampered_data))
            before_tamper = list(test_decrypt_dir.glob("sample*"))
            tamper_result = decrypt_file_aes(tampered, akey, "selftest_aes_tampered", manifest_path=manifest_path, decrypt_output_dir=test_decrypt_dir)
            after_tamper = list(test_decrypt_dir.glob("sample*"))
            manifest_ok = verify_manifest_integrity(manifest_path=manifest_path)
        if wrong_key_result is not None:
            raise RuntimeError("AES wrong-key decrypt unexpectedly succeeded")
        if len(after_failed) != len(before_failed):
            raise RuntimeError("Failed AES decrypt left an unexpected output file")
        if tamper_result is not None:
            raise RuntimeError("AES tampered decrypt unexpectedly succeeded")
        if len(after_tamper) != len(before_tamper):
            raise RuntimeError("Tampered AES decrypt left an unexpected output file")
        if list(test_decrypt_dir.glob(".decrypt_tmp_*")):
            raise RuntimeError("Temporary decrypt file cleanup failed")
        if calculate_hash(tpath) != calculate_hash(a_dec):
            raise RuntimeError("Roundtrip hash mismatch")
        if not manifest_ok:
            raise RuntimeError("Self-test manifest verification failed")
        for p in [f_enc, a_enc, f_dec, a_dec, tampered]:
            if p and Path(p).exists():
                Path(p).unlink()
        if manifest_path.exists():
            manifest_path.unlink()
        if any(test_output_dir.rglob("*")) or any(test_decrypt_dir.rglob("*")):
            raise RuntimeError("Self-test cleanup failed")
        
def add_aes_key_metadata():
    add_key_metadata_common("AES")

# Function to view metadata of an AES key file
def view_aes_key_metadata():
    view_key_metadata_common("AES")


def list_keys_cli(as_json=False):
    rows = []
    if not STATE.keys_dir.is_dir():
        if as_json:
            print(json.dumps(rows, indent=2))
        else:
            warning("No key files found.")
        return
    for key_file in sorted(STATE.keys_dir.iterdir()):
        if key_file.suffix != ".key":
            continue
        key_data = load_key(key_file.name)
        rows.append({
            "name": key_file.name,
            "type": detect_key_type(key_data) if key_data else "Unreadable",
            "has_metadata": get_metadata_path(key_file.name).exists(),
            "has_backup": (STATE.backup_dir / key_file.name).exists(),
            "modified": datetime.fromtimestamp(key_file.stat().st_mtime).isoformat(timespec="seconds"),
        })
    if as_json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        warning("No key files found.")
        return
    for row in rows:
        print(
            f"{row['name']:<32} [{row['type']:<12}] "
            f"metadata={'yes' if row['has_metadata'] else 'no'} "
            f"backup={'yes' if row['has_backup'] else 'no'} "
            f"modified={row['modified']}"
        )
        

def maybe_show_first_run_notice():
    if any(STATE.keys_dir.glob("*.key")):
        return
    if os.environ.get("ENCRYPTOPI_SKIP_FIRST_RUN_NOTICE") == "1":
        return
    clear_terminal()
    ui_box(
        "First Run Notice",
        [
            "No key files were found yet.",
            "Back up your keys after creating them.",
            "Losing a key means losing access to files encrypted with that key.",
            "Passphrase files require the exact passphrase used during encryption.",
            "AES-GCM is recommended for large files.",
        ],
        subtitle="Read this before encrypting important files",
    )
    pause()


# Function to display the help section
def display_help():
    clear_terminal()
    ui_box(
        "EncryptoPI Help",
        [
            "Main groups: Encrypt, Decrypt, Keys, Files & Archives, Manifest, Settings.",
            "Encrypt and decrypt support files, batches, custom folders, and dry-runs.",
            "AES-GCM is preferred for large files because it streams file data.",
            "Passphrase mode derives AES keys with scrypt and writes .pwaes outputs.",
            "Key tools include details, metadata, import/export, backup, restore, deletion.",
            "Manifest tools verify hashes, filter records, prune stale rows, and audit.",
            "Use the correct key type for key-file operations: Fernet or 32-byte AES.",
            "Back up keys regularly; encrypted data cannot be recovered without them.",
        ],
        subtitle="Workflow reference",
    )
    pause()


# Function to display the menu
def display_menu():
    clear_terminal()
    render_banner()
    render_menu(
        "EncryptoPI",
        [
            ("1", "Encrypt", "lock files and folders"),
            ("2", "Decrypt", "restore encrypted files"),
            ("3", "Keys", "create and manage keys"),
            ("4", "Files & Archives", "zip and unzip files"),
            ("5", "Manifest & Integrity", "check saved hashes"),
            ("6", "Settings & Audit", "view tool status"),
            ("7", "Help", "how to use EncryptoPI"),
            ("q", "Exit", "close the tool"),
        ],
        subtitle=f"v{APP_VERSION} | launch, use, close",
        footer=None,
    )


def pause():
    input(THEME_ORANGE + "╰─" + THEME_ACCENT + " Press Enter to continue...")


def encrypt_menu():
    while True:
        clear_terminal()
        render_menu(
            "Encrypt",
            [
                ("1", "Guided Encrypt", "recommended AES path"),
                ("2", "Single file with key", "choose Fernet or AES"),
                ("3", "Input folder with Fernet", "encrypt input/"),
                ("4", "Input folder with AES", "encrypt input/"),
                ("5", "Custom folder", "choose any folder"),
                ("6", "Single file with passphrase", "no key file needed"),
                ("7", "Preview batch", "show files only"),
            ],
            subtitle="Create encrypted files",
        )
        choice = prompt_choice()
        if choice == "1":
            guided_encrypt()
            pause()
        elif choice == "2":
            single_file_operation()
            pause()
        elif choice == "3":
            encrypt_files()
            pause()
        elif choice == "4":
            encrypt_files_aes()
            pause()
        elif choice == "5":
            custom_folder_operation()
            pause()
        elif choice == "6":
            passphrase_single_file_operation()
            pause()
        elif choice == "7":
            dry_run_batch_operation()
            pause()
        elif choice == "b":
            clear_terminal()
            break
        else:
            warning("Invalid choice.")


def decrypt_menu():
    while True:
        clear_terminal()
        render_menu(
            "Decrypt",
            [
                ("1", "Single file with key", "choose Fernet or AES"),
                ("2", "Output folder Fernet files", "decrypt *.enc"),
                ("3", "Output folder AES files", "decrypt *.aes"),
                ("4", "Custom folder", "choose any folder"),
                ("5", "Single file with passphrase", "decrypt *.pwaes"),
                ("6", "Preview batch", "show files only"),
            ],
            subtitle="Restore encrypted files",
        )
        choice = prompt_choice()
        if choice == "1":
            single_file_operation()
            pause()
        elif choice == "2":
            decrypt_files()
            pause()
        elif choice == "3":
            decrypt_files_aes()
            pause()
        elif choice == "4":
            custom_folder_operation()
            pause()
        elif choice == "5":
            passphrase_single_file_operation()
            pause()
        elif choice == "6":
            dry_run_batch_operation()
            pause()
        elif choice == "b":
            clear_terminal()
            break
        else:
            warning("Invalid choice.")


def keys_menu():
    while True:
        clear_terminal()
        render_menu(
            "Keys",
            [
                ("1", "List keys", "show saved keys"),
                ("2", "Key details", "fingerprint and status"),
                ("3", "Generate Fernet key", "new Fernet key"),
                ("4", "Generate AES key", "new AES key"),
                ("5", "Add Fernet metadata", "label a key"),
                ("6", "View Fernet metadata", "show label"),
                ("7", "Add AES metadata", "label a key"),
                ("8", "View AES metadata", "show label"),
                ("9", "Import key", "copy into keys/"),
                ("10", "Export key", "copy out"),
                ("11", "Export key bundle", "recovery folder"),
                ("12", "Import key bundle", "restore folder"),
                ("13", "Backup keys", "save copies"),
                ("14", "Restore keys", "recover copies"),
                ("15", "Delete key", "remove a key"),
            ],
            subtitle="Manage encryption keys",
        )
        choice = prompt_choice()
        if choice == "1":
            show_keys()
            pause()
        elif choice == "2":
            show_key_details()
            pause()
        elif choice == "3":
            generate_key()
            pause()
        elif choice == "4":
            generate_aes_key()
            pause()
        elif choice == "5":
            add_key_metadata()
            pause()
        elif choice == "6":
            view_key_metadata()
            pause()
        elif choice == "7":
            add_aes_key_metadata()
            pause()
        elif choice == "8":
            view_aes_key_metadata()
            pause()
        elif choice == "9":
            import_key()
            pause()
        elif choice == "10":
            export_key()
            pause()
        elif choice == "11":
            export_key_bundle()
            pause()
        elif choice == "12":
            import_key_bundle()
            pause()
        elif choice == "13":
            backup_keys()
            pause()
        elif choice == "14":
            restore_keys()
            pause()
        elif choice == "15":
            delete_key()
            pause()
        elif choice == "b":
            clear_terminal()
            break
        else:
            warning("Invalid choice.")


def files_archives_menu():
    while True:
        clear_terminal()
        render_menu(
            "Files & Archives",
            [
                ("1", "Compress input folder", "make files.zip"),
                ("2", "Decompress ZIP", "safe unzip"),
                ("3", "Preview batch", "show files only"),
            ],
            subtitle="Zip and unzip files",
        )
        choice = prompt_choice()
        if choice == "1":
            compress_files()
            pause()
        elif choice == "2":
            decompress_files()
            pause()
        elif choice == "3":
            dry_run_batch_operation()
            pause()
        elif choice == "b":
            clear_terminal()
            break
        else:
            warning("Invalid choice.")


def settings_audit_menu():
    while True:
        clear_terminal()
        render_menu(
            "Settings & Audit",
            [
                ("1", "Show settings", "paths and limits"),
                ("2", "Change settings", "this session only"),
                ("3", "Audit report", "tool health summary"),
                ("4", "Doctor check", "quick health check"),
            ],
            subtitle="View status and session settings",
        )
        choice = prompt_choice()
        if choice == "1":
            settings_screen()
            pause()
        elif choice == "2":
            change_runtime_settings()
            pause()
        elif choice == "3":
            audit_report()
            pause()
        elif choice == "4":
            doctor_check()
            pause()
        elif choice == "b":
            clear_terminal()
            break
        else:
            warning("Invalid choice.")


def main_menu():
    while True:
        try:
            display_menu()
            choice = prompt_choice()
            if choice == '1':
                encrypt_menu()
            elif choice == '2':
                decrypt_menu()
            elif choice == '3':
                keys_menu()
            elif choice == '4':
                files_archives_menu()
            elif choice == '5':
                manifest_tools_menu()
            elif choice == '6':
                settings_audit_menu()
            elif choice == '7':
                display_help()
            elif choice == 'q':
                success("Exiting...")
                break
            elif choice == 'h' or choice.lower() == 'help':
                display_help()
            else:
                error("Invalid choice. Please try again.")
        except KeyboardInterrupt:
            LOGGER.info("main_menu interrupted by user")
            warning("Operation interrupted by user.")
            break

if __name__ == "__main__":
    import sys
    if sys.version_info < MIN_PYTHON:
        error(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required.")
        raise SystemExit(1)

    top_examples = """
examples:
  encryptopi
  encryptopi --doctor
  encryptopi --self-test --no-clear
  encryptopi --list-keys
  encryptopi encrypt --algo aes --key aes_key_example.key --infile notes.txt
  encryptopi decrypt --algo aes --key aes_key_example.key --infile output/notes.txt.aes
  ENCRYPTOPI_PASSPHRASE='your passphrase' encryptopi encrypt --algo passphrase --infile notes.txt
"""
    parser = argparse.ArgumentParser(
        description="EncryptoPI encryption/decryption tool",
        epilog=top_examples,
        formatter_class=RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="Show EncryptoPI and Python version and exit")
    parser.add_argument("--self-test", action="store_true", help="Run a quick runtime self-test and exit")
    parser.add_argument("--verify-manifest", action="store_true", help="Verify output hashes in operations_manifest.jsonl and exit")
    parser.add_argument("--list-keys", action="store_true", help="List known keys and exit")
    parser.add_argument("--json", action="store_true", help="When used with --list-keys, print JSON output")
    parser.add_argument("--no-clear", action="store_true", help="Disable terminal clear operations")
    parser.add_argument("--doctor", action="store_true", help="Run an environment and project health check and exit")
    subparsers = parser.add_subparsers(dest="command")
    for cmd in ("encrypt", "decrypt"):
        if cmd == "encrypt":
            examples = """
examples:
  encryptopi encrypt --algo fernet --key key_example.key --infile notes.txt
  encryptopi encrypt --algo aes --key aes_key_example.key --folder input
  encryptopi encrypt --algo aes --key aes_key_example.key --folder input --dry-run
  encryptopi encrypt --algo aes --key aes_key_example.key --infile notes.txt --output-policy overwrite
  ENCRYPTOPI_PASSPHRASE='your passphrase' encryptopi encrypt --algo passphrase --infile notes.txt
"""
        else:
            examples = """
examples:
  encryptopi decrypt --algo fernet --key key_example.key --infile output/notes.txt.enc
  encryptopi decrypt --algo aes --key aes_key_example.key --folder output
  encryptopi decrypt --algo aes --key aes_key_example.key --folder output --dry-run
  encryptopi decrypt --algo aes --key aes_key_example.key --infile output/notes.txt.aes --decrypt-output-dir recovered
  ENCRYPTOPI_PASSPHRASE='your passphrase' encryptopi decrypt --algo passphrase --infile output/notes.txt.pwaes
"""
        cp = subparsers.add_parser(
            cmd,
            help=f"{cmd.title()} files non-interactively",
            description=f"{cmd.title()} one file or a folder without opening the menu.",
            epilog=examples,
            formatter_class=RawDescriptionHelpFormatter,
        )
        cp.add_argument("--algo", choices=["fernet", "aes", "passphrase"], required=True)
        cp.add_argument("--key", help="Key filename in keys/ (required for fernet and aes)")
        cp.add_argument("--infile", help="Input file path")
        cp.add_argument("--folder", help="Folder path for batch operation")
        cp.add_argument("--dry-run", action="store_true", help="Preview matching files without writing output")
        cp.add_argument("--output-dir", help="Directory for encrypted output")
        cp.add_argument("--decrypt-output-dir", help="Directory for decrypted output")
        cp.add_argument("--manifest-path", help="Manifest file path for operation records")
        cp.add_argument("--output-policy", choices=["rename", "skip", "overwrite"], default=DEFAULT_OUTPUT_POLICY, help="How to handle output collisions")
        cp.add_argument("--recursive", dest="recursive", action="store_true", default=True, help="Process folders recursively")
        cp.add_argument("--no-recursive", dest="recursive", action="store_false", help="Only process direct children when using --folder")
        cp.add_argument("--allow-legacy-cfb", action="store_true", help="Permit decrypting legacy AES-CFB files without a GCM header")
        cp.add_argument("--passphrase-env", default="ENCRYPTOPI_PASSPHRASE", help="Environment variable containing passphrase for passphrase mode")
        cp.add_argument("--yes-i-understand-key-loss", action="store_true", help="Acknowledge that lost keys/passphrases cannot recover encrypted files")
    args = parser.parse_args()

    if args.no_clear:
        os.environ["ENCRYPTOPI_NO_CLEAR"] = "1"

    if args.version:
        print(f"EncryptoPI v{APP_VERSION} | Python {sys.version_info.major}.{sys.version_info.minor}")
    elif args.list_keys:
        list_keys_cli(as_json=args.json)
    elif args.verify_manifest:
        ensure_app_dirs()
        LOGGER = setup_logger()
        raise SystemExit(0 if verify_manifest_integrity() else 1)
    elif args.doctor:
        raise SystemExit(0 if doctor_check() else 1)
    elif args.command in ("encrypt", "decrypt"):
        ensure_app_dirs()
        LOGGER = setup_logger()
        try:
            run_cli_operation(args)
        except KeyboardInterrupt:
            LOGGER.info("CLI mode interrupted by user")
            warning("Operation interrupted by user.")
            raise SystemExit(130)
        except SystemExit:
            raise
        except Exception:
            LOGGER.exception("CLI operation failed")
            error("Operation failed. Check logs/encryptopi.log for details.")
            raise SystemExit(1)
    elif args.self_test:
        ensure_app_dirs()
        LOGGER = setup_logger()
        try:
            print("Running self-test...")
            LOGGER.info("Self-test started")
            for directory in [STATE.keys_dir, STATE.input_dir, STATE.output_dir, STATE.decrypt_output_dir]:
                directory.mkdir(parents=True, exist_ok=True)
            _ = Fernet.generate_key()
            test_hash = calculate_hash(__file__)
            if not test_hash:
                raise RuntimeError("Failed to calculate script hash")
            run_extended_self_test()
            print("Self-test passed.")
            LOGGER.info("Self-test passed")
        except KeyboardInterrupt:
            LOGGER.info("self-test interrupted by user")
            warning("Operation interrupted by user.")
            raise SystemExit(130)
        except Exception:
            LOGGER.exception("self-test failed")
            error("Self-test failed.")
            raise SystemExit(1)
    else:
        ensure_app_dirs()
        LOGGER = setup_logger()
        maybe_show_first_run_notice()
        main_menu()
