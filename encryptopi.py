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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from pathlib import Path
from colorama import Fore, init
from tqdm import tqdm
import argparse
import tempfile
from datetime import datetime, timezone
import json
import os
import base64
import hashlib
import zipfile
import logging
import contextlib
import io
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
APP_VERSION = "1.0.0"

# Ensure directories exist
for directory in [STATE.keys_dir, STATE.input_dir, STATE.output_dir, STATE.decrypt_output_dir, STATE.backup_dir, STATE.logs_dir]:
    directory.mkdir(parents=True, exist_ok=True)


def get_metadata_path(key_filename):
    return STATE.keys_dir / key_filename.replace(".key", "_metadata.json")


def add_key_metadata_common(key_label):
    try:
        show_keys()
        key_filename = input(Fore.CYAN + f"Enter the {key_label} key filename to add metadata to (from above): ")
        key_file_path = resolve_key_path(key_filename)
        if key_file_path is None or not key_file_path.is_file():
            error("Key file not found.")
            return
        metadata = input(Fore.CYAN + "Enter metadata to add: ")
        metadata_path = get_metadata_path(key_filename)
        with open(metadata_path, "w") as metadata_file:
            json.dump({"metadata": metadata}, metadata_file)
        success(f"Metadata added to {key_filename.replace('.key', '_metadata.json')}")
    except Exception:
        LOGGER.exception("add_key_metadata_common failed for %s", key_label)
        error(f"Error adding metadata to {key_label} key.")


def view_key_metadata_common(key_label):
    try:
        show_keys()
        key_filename = input(Fore.CYAN + f"Enter the {key_label} key filename to view metadata of (from above): ")
        metadata_path = get_metadata_path(key_filename)
        if not metadata_path.is_file():
            warning("No metadata found for the selected key")
            return
        with open(metadata_path, "r") as metadata_file:
            metadata_dict = json.load(metadata_file)
        info(f"Metadata for {key_filename}: {metadata_dict.get('metadata', 'No metadata available')}")
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
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(STATE.logs_dir / "encryptopi.log")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(fh)
    return logger

LOGGER = setup_logger()


def info(msg):
    print(Fore.CYAN + f"[INFO] {msg}")

def success(msg):
    print(Fore.GREEN + f"[OK] {msg}")

def warning(msg):
    print(Fore.YELLOW + f"[WARN] {msg}")

def error(msg):
    print(Fore.RED + f"[ERROR] {msg}")


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
    warning("Fernet large-file warning: Fernet operations load full file data into memory.")
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
            out = Path(entry.get("output_path", ""))
            expected = entry.get("output_sha256")
            if not out.exists():
                error(f"FAIL [{i}] missing: {out}")
                LOGGER.error("Manifest verify fail [line %s]: missing output %s", i, out)
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

def write_manifest(entry, manifest_path=None):
    manifest_path = Path(manifest_path) if manifest_path else (STATE.output_dir / "operations_manifest.jsonl")
    with open(manifest_path, "a", encoding="utf-8") as mf:
        mf.write(json.dumps(entry) + "\n")

def build_manifest_entry(operation, algorithm, input_path, output_path, key_name, input_sha256=None, output_sha256=None):
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "algorithm": algorithm,
        "input_path": str(input_path),
        "output_path": str(output_path),
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
        key = Fernet.generate_key()
        key_filename = STATE.keys_dir / (f"key_{base64.urlsafe_b64encode(key).decode('utf-8')[:10]}.key")
        with open(key_filename, "wb") as key_file:
            key_file.write(key)
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
def encrypt_file_fernet(file_path, key, key_name="unknown", manifest_path=None, output_dir=None):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        rel = file_path.relative_to(STATE.input_dir) if STATE.input_dir in file_path.parents else Path(file_path.name)
        target_output_dir = Path(output_dir) if output_dir else STATE.output_dir
        preferred_encrypted_path = target_output_dir / rel.parent / (rel.name + ".enc")
        encrypted_file_path = safe_output_path(target_output_dir, rel, ".enc")
        if encrypted_file_path != preferred_encrypted_path:
            info(f"Output exists, using: {encrypted_file_path.name}")
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
def decrypt_file_fernet(file_path, key, key_name="unknown", manifest_path=None, decrypt_output_dir=None):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        rel = file_path.relative_to(STATE.output_dir) if STATE.output_dir in file_path.parents else Path(file_path.name)
        rel = rel.with_suffix("")
        target_decrypt_dir = Path(decrypt_output_dir) if decrypt_output_dir else STATE.decrypt_output_dir
        preferred_decrypt_path = target_decrypt_dir / rel
        decrypted_file_path = safe_output_path(target_decrypt_dir, rel, "")
        if decrypted_file_path != preferred_decrypt_path:
            warning(f"Output collision detected; writing decrypted file as {decrypted_file_path.name}")
        with open(decrypted_file_path, "wb") as file:
            file.write(decrypted_data)
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
        info("Encrypting files...")
        ok_count, fail_count = 0, 0
        for file_path in tqdm(files_to_encrypt, desc="Encrypting", unit="file"):
            original_hash = calculate_hash(file_path)
            encrypted_file_path = encrypt_file_fernet(file_path, key, key_filename)
            if not encrypted_file_path:
                fail_count += 1
                continue
            ok_count += 1
            rel = file_path.relative_to(STATE.input_dir) if STATE.input_dir in file_path.parents else Path(file_path.name)
            decrypted_file_path = decrypt_file_fernet(encrypted_file_path, key, key_filename)
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
        info("Decrypting files...")
        ok_count, fail_count = 0, 0
        for file_path in tqdm(encrypted_files, desc="Decrypting", unit="file"):
            result = decrypt_file_fernet(file_path, key, key_filename)
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


def dry_run_preview(paths, label):
    info(f"[DRY-RUN] {label}: {len(paths)} file(s)")
    for p in paths[:20]:
        print(f" - {p}")
    if len(paths) > 20:
        print(f" ... and {len(paths) - 20} more")


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
            result = encrypt_file_fernet(src, key, key_filename) if op == "encrypt" else decrypt_file_fernet(src, key, key_filename)
        else:
            if len(key) != 32:
                error("Wrong key type selected. Expected a 32-byte AES key.")
                return
            result = encrypt_files_aes_with_key(src, key, key_filename) if op == "encrypt" else decrypt_file_aes(src, key, key_filename)
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


def manifest_tools_menu():
    manifest_path = STATE.output_dir / "operations_manifest.jsonl"
    while True:
        print(Fore.CYAN + "\nManifest tools:\n 1. Verify manifest\n 2. Show last 20 entries\n 3. Prune invalid/missing entries\n 0. Back")
        c = input(Fore.CYAN + "Choice: ").strip()
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
                    out = Path(entry.get("output_path", ""))
                    if out.exists():
                        kept.append(line)
                    else:
                        removed += 1
                except Exception:
                    removed += 1
            manifest_path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
            success(f"Pruned manifest entries: removed={removed}, kept={len(kept)}")
        elif c == "0":
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
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.infolist():
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
        warning(f"Selected key: {key_filename} | Type: {ktype} | Metadata: {meta}")
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
            backup_path = STATE.backup_dir / key_filename
            if backup_path.exists():
                backup_path.unlink()
        success(f"Key {key_filename} deleted.")
    except Exception as e:
        LOGGER.exception("delete_key failed")
        error("Error deleting key.")
        
# Function to back up keys
def backup_keys():
    try:
        for key_file in sorted(STATE.keys_dir.iterdir()):
            if key_file.suffix in [".key", ".json"] and (key_file.suffix == ".key" or key_file.name.endswith("_metadata.json")):
                backup_file = STATE.backup_dir / key_file.name
                backup_file.write_bytes(key_file.read_bytes())
                success(f"Backed up: {key_file.name}")
        success("Backup operation completed.")
    except Exception as e:
        LOGGER.exception("backup_keys failed")
        error("Error backing up keys.")
        
# Function to restore keys from backup
def restore_keys():
    try:
        if not STATE.backup_dir.is_dir():
            error("Backup directory does not exist.")
            return
        
        for backup_file in sorted(STATE.backup_dir.iterdir()):
            if backup_file.suffix in [".key", ".json"] and (backup_file.suffix == ".key" or backup_file.name.endswith("_metadata.json")):
                restored = STATE.keys_dir / backup_file.name
                restored.write_bytes(backup_file.read_bytes())
                success(f"Restored: {backup_file.name}")
        success("Restore operation completed.")
    except Exception as e:
        LOGGER.exception("restore_keys failed")
        error("Error restoring keys.")
        
def generate_aes_key():
    try:
        key = os.urandom(32)  # AES-256 key size
        key_filename = STATE.keys_dir / (f"aes_key_{base64.urlsafe_b64encode(key).decode('utf-8')[:10]}.key")
        with open(key_filename, "wb") as key_file:
            key_file.write(key)
        success(f"AES Key generated and saved as {key_filename}")
    except Exception:
        LOGGER.exception("generate_aes_key failed")
        error("Error generating AES key.")        
        
def encrypt_files_aes_with_key(file_path, key, key_name="unknown", manifest_path=None, output_dir=None):
    try:
        if len(key) != 32:
            raise ValueError("Invalid AES key length. Must be 32 bytes for AES-256.")

        iv = os.urandom(12)  # Recommended IV size for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        rel = file_path.relative_to(STATE.input_dir) if STATE.input_dir in file_path.parents else Path(file_path.name)
        target_output_dir = Path(output_dir) if output_dir else STATE.output_dir
        preferred_encrypted_path = target_output_dir / rel.parent / (rel.name + ".aes")
        encrypted_file_path = safe_output_path(target_output_dir, rel, ".aes")
        if encrypted_file_path != preferred_encrypted_path:
            info(f"Output exists, using: {encrypted_file_path.name}")

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

def decrypt_file_aes(file_path, key, key_name="unknown", manifest_path=None, decrypt_output_dir=None):
    try:
        if len(key) != 32:
            raise ValueError("Invalid AES key length. Must be 32 bytes for AES-256.")
        
        with open(file_path, "rb") as file:
            prefix = file.read(4)
            file.seek(0, os.SEEK_END)
            total_size = file.tell()
            file.seek(0)

        rel = file_path.relative_to(STATE.output_dir) if STATE.output_dir in file_path.parents else Path(file_path.name)
        rel = rel.with_suffix("")
        target_decrypt_dir = Path(decrypt_output_dir) if decrypt_output_dir else STATE.decrypt_output_dir
        preferred_decrypt_path = target_decrypt_dir / rel
        decrypted_file_path = safe_output_path(target_decrypt_dir, rel, "")
        if decrypted_file_path != preferred_decrypt_path:
            warning(f"Output collision detected; writing decrypted file as {decrypted_file_path.name}")

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
            with open(file_path, "rb") as file:
                encrypted_data = file.read()
            iv = encrypted_data[4:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            with open(decrypted_file_path, "wb") as file:
                file.write(decrypted_data)
        else:
            with open(file_path, "rb") as file:
                encrypted_data = file.read()
            # Backward-compatible decrypt path for legacy CFB-encrypted files
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            with open(decrypted_file_path, "wb") as file:
                file.write(decrypted_data)
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
        info("Encrypting files...")
        ok_count, fail_count = 0, 0
        for file_path in tqdm(files_to_encrypt, desc="Encrypting", unit="file"):
            if encrypt_files_aes_with_key(file_path, key, key_filename): ok_count += 1
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
        info("Decrypting files...")
        ok_count, fail_count = 0, 0
        for file_path in tqdm(encrypted_files, desc="Decrypting", unit="file"):
            result = decrypt_file_aes(file_path, key, key_filename)
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

def run_cli_operation(args):
    try:
        key = load_key(args.key)
        if key is None:
            raise SystemExit(2)
        if args.infile and args.folder:
            raise SystemExit("Error: use either --infile or --folder, not both.")
        if not args.infile and not args.folder:
            raise SystemExit("Error: provide exactly one of --infile or --folder.")
        if args.infile:
            infile_path = Path(args.infile)
            if not infile_path.is_file():
                raise SystemExit(f"Error: file does not exist: {infile_path}")
            targets = [infile_path]
        else:
            folder_path = Path(args.folder)
            if not folder_path.is_dir():
                raise SystemExit(f"Error: folder does not exist: {folder_path}")
            targets = [p for p in folder_path.rglob("*") if p.is_file()]
            if not targets:
                raise SystemExit(f"Error: no files found in folder: {folder_path}")
        success_count = 0
        fail_count = 0
        if args.algo == "fernet":
            if len(key) != 44:
                raise SystemExit("Error: wrong key type. Fernet operations require a Fernet key (44-byte base64 key file).")
            maybe_warn_fernet_large_files(targets, interactive=False)
            for t in targets:
                if args.command == "encrypt":
                    result = encrypt_file_fernet(t, key, args.key)
                else:
                    result = decrypt_file_fernet(t, key, args.key)
                if result is None:
                    fail_count += 1
                else:
                    success_count += 1
        else:
            if len(key) != 32:
                raise SystemExit("Error: wrong key type. AES operations require a 32-byte AES key file.")
            for t in targets:
                if args.command == "encrypt":
                    result = encrypt_files_aes_with_key(t, key, args.key)
                else:
                    result = decrypt_file_aes(t, key, args.key)
                if result is None:
                    fail_count += 1
                else:
                    success_count += 1
        info("CLI operation completed.")
        success(f"Succeeded: {success_count}")
        if fail_count > 0:
            warning(f"Failed: {fail_count}")
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
        

# Function to display the help section
def display_help():
    clear_terminal()
    print(Fore.YELLOW + """
    
  *** Encryption/Decryption Help ***
    
    """)
    print(Fore.CYAN + """

Welcome to Encryptopi, a comprehensive encryption tool designed to provide you with 
powerful file and folder encryption capabilities using both Fernet and AES encryption. 
Below you will find detailed instructions on how to use each feature of the script.


1. Generate Fernet Key:
   - Create a new Fernet key for encrypting and decrypting files.
   - The generated key is saved in the 'keys' directory.

2. Generate AES Key:
   - Create a new AES-256 key for advanced encryption.
   - The generated key is stored in the 'keys' directory.

3. Show Available Keys:
   - List all encryption keys stored in the 'keys' directory.

4. Encrypt Files (Fernet):
   - Encrypt files using a Fernet key.
   - Files from the 'input' directory are encrypted and saved in the 'output' directory.
   - Includes integrity check after encryption.

5. Decrypt Files (Fernet):
   - Decrypt files previously encrypted with a Fernet key.
   - Encrypted files from the 'output' directory are decrypted and saved in the 'decrypted_output' directory.

6. Encrypt Files (AES):
   - Encrypt files using an AES key for enhanced security.
   - Files from the 'input' directory are encrypted and saved in the 'output' directory.

7. Decrypt Files (AES):
   - Decrypt files previously encrypted with an AES key.
   - Encrypted files from the 'output' directory are decrypted and saved in the 'decrypted_output' directory.

8. Check File Integrity:
   - Run Manifest Verification against operations_manifest.jsonl records.
   - Detect missing or modified encrypted/decrypted files by comparing stored and recalculated SHA256 hashes.

9. Compress Files:
   - Compress files in the 'input' directory into a ZIP archive.
   - The ZIP archive is saved in the 'output' directory.

10. Decompress Files:
   - Extract ZIP archives (default: output/files.zip) into 'decompressed_output'.
   - Includes safe path checks to block unsafe archive paths.

11. Add Key Metadata:
    - Add descriptive metadata to an encryption key file for easy identification.

12. View Key Metadata:
    - Display the metadata associated with a specific key file.

13. Backup Keys:
    - Create a backup of all keys stored in the 'keys' directory.

14. Restore Keys:
    - Restore keys from a backup, allowing for recovery of lost keys.

15. Delete Key:
    - Permanently remove an encryption key from the 'keys' directory.

16. Single File Operation:
    - Run encryption/decryption for one specific file path.
    - Supports Fernet and AES key validation.

17. Dry-Run Batch Preview:
    - Preview files that would be processed in batch mode without changing data.

18. Manifest Tools:
    - Verify manifest entries, view recent records, and prune stale or invalid lines.

0. Exit:
   - Exit the Encryptopi script.

ADDITIONAL NOTES:
- Ensure you use the correct key type (Fernet or AES) for encryption and decryption.
- For large files, prefer AES-GCM because Fernet operations load entire files into memory.
- All operations require selecting the appropriate key from the list of available keys.
- The script is designed to handle files in the 'input' directory and output results in the 'output' or 'decrypted_output' directory.
- Use the integrity check option to verify the correctness of encrypted or decrypted files.
- It's recommended to regularly back up your keys to prevent data loss.
    """)
    input(Fore.CYAN + "Press Enter to return to the main menu...")


# Function to display the menu
def display_menu():
    clear_terminal()
    print(Fore.YELLOW + """
    ╭━━━╮╱╱╱╱╱╱╱╱╱╱╱╱╱╱╭╮╱╱╱╭━━━┳━━╮
    ┃╭━━╯╱╱╱╱╱╱╱╱╱╱╱╱╱╭╯╰╮╱╱┃╭━╮┣┫┣╯
    ┃╰━━┳━╮╭━━┳━┳╮╱╭┳━┻╮╭╋━━┫╰━╯┃┃┃
    ┃╭━━┫╭╮┫╭━┫╭┫┃╱┃┃╭╮┃┃┃╭╮┃╭━━╯┃┃
    ┃╰━━┫┃┃┃╰━┫┃┃╰━╯┃╰╯┃╰┫╰╯┃┃╱╱╭┫┣╮
    ╰━━━┻╯╰┻━━┻╯╰━╮╭┫╭━┻━┻━━┻╯╱╱╰━━╯
    ╱╱╱╱╱╱╱╱╱╱╱╱╭━╯┃┃┃
    ╱╱╱╱╱╱╱╱╱╱╱╱╰━━╯╰╯
    """)
    print("    EncryptoPI - v1.0 - WastelandSYS ")
    print(Fore.CYAN + """
       1. Show Available Keys
       2. Generate Fernet Key
       3. Add Fernet Key Metadata
       4. View Fernet Key Metadata
       5. Generate AES Key
       6. Add AES Key Metadata
       7. View AES Key Metadata
       8. Encrypt Files (Fernet)
       9. Decrypt Files (Fernet)
      10. Encrypt Files (AES)
      11. Decrypt Files (AES)
      12. Check File Integrity
      13. Compress Files
      14. Decompress Files
      15. Backup Keys
      16. Restore Keys
      17. Delete Key
      18. Single File Operation
      19. Dry-Run Batch Preview
      20. Manifest Tools
       0. Exit
       h. Help
    """)

def main_menu():
    while True:
        try:
            display_menu()
            choice = input(Fore.CYAN + "  Enter your choice: ")
            if choice == '1':
                show_keys()
            elif choice == '2':
                generate_key()
            elif choice == '3':
                add_key_metadata()
            elif choice == '4':
                view_key_metadata()
            elif choice == '5':
                generate_aes_key()
            elif choice == '6':
                add_aes_key_metadata()
            elif choice == '7':
                view_aes_key_metadata()
            elif choice == '8':
                encrypt_files()
            elif choice == '9':
                decrypt_files()
            elif choice == '10':
                encrypt_files_aes()
            elif choice == '11':
                decrypt_files_aes()
            elif choice == '12':
                check_file_integrity()
            elif choice == '13':
                compress_files()
            elif choice == '14':
                decompress_files()
            elif choice == '15':
                backup_keys()
            elif choice == '16':
                restore_keys()
            elif choice == '17':
                delete_key()
            elif choice == '18':
                single_file_operation()
            elif choice == '19':
                dry_run_batch_operation()
            elif choice == '20':
                manifest_tools_menu()
            elif choice == '0':
                success("Exiting...")
                break
            elif choice == 'h' or choice.lower() == 'help':
                display_help()
            else:
                error("Invalid choice. Please try again.")
            input(Fore.CYAN + "Press Enter to return to the main menu...")
        except KeyboardInterrupt:
            LOGGER.info("main_menu interrupted by user")
            warning("Operation interrupted by user.")
            break

if __name__ == "__main__":
    import sys
    if sys.version_info < MIN_PYTHON:
        error(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required.")
        raise SystemExit(1)

    parser = argparse.ArgumentParser(description="EncryptoPI encryption/decryption tool")
    parser.add_argument("--version", action="store_true", help="Show EncryptoPI and Python version and exit")
    parser.add_argument("--self-test", action="store_true", help="Run a quick runtime self-test and exit")
    parser.add_argument("--verify-manifest", action="store_true", help="Verify output hashes in operations_manifest.jsonl and exit")
    parser.add_argument("--list-keys", action="store_true", help="List known keys and exit")
    parser.add_argument("--json", action="store_true", help="When used with --list-keys, print JSON output")
    parser.add_argument("--no-clear", action="store_true", help="Disable terminal clear operations")
    subparsers = parser.add_subparsers(dest="command")
    for cmd in ("encrypt", "decrypt"):
        cp = subparsers.add_parser(cmd, help=f"{cmd.title()} a single file non-interactively")
        cp.add_argument("--algo", choices=["fernet", "aes"], required=True)
        cp.add_argument("--key", required=True, help="Key filename in keys/")
        cp.add_argument("--infile", help="Input file path")
        cp.add_argument("--folder", help="Folder path for batch operation")
    args = parser.parse_args()

    if args.no_clear:
        os.environ["ENCRYPTOPI_NO_CLEAR"] = "1"

    if args.version:
        print(f"EncryptoPI v{APP_VERSION} | Python {sys.version_info.major}.{sys.version_info.minor}")
    elif args.list_keys:
        list_keys_cli(as_json=args.json)
    elif args.verify_manifest:
        raise SystemExit(0 if verify_manifest_integrity() else 1)
    elif args.command in ("encrypt", "decrypt"):
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
        main_menu()
