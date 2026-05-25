#!/usr/bin/env python3

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

# Ensure directories exist
for directory in [STATE.keys_dir, STATE.input_dir, STATE.output_dir, STATE.decrypt_output_dir, STATE.backup_dir, STATE.logs_dir]:
    directory.mkdir(parents=True, exist_ok=True)


def get_metadata_path(key_filename):
    return STATE.keys_dir / key_filename.replace(".key", "_metadata.json")



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
        print(Fore.RED + "No operations manifest found.")
        return False
    ok = True
    pass_count = 0
    fail_count = 0
    print(Fore.CYAN + "Verifying manifest outputs...")
    for i, line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            out = Path(entry.get("output_path", ""))
            expected = entry.get("output_sha256")
            if not out.exists():
                print(Fore.RED + f"FAIL [{i}] missing: {out}")
                LOGGER.error("Manifest verify fail [line %s]: missing output %s", i, out)
                ok = False
                fail_count += 1
                continue
            actual = calculate_hash(out)
            if actual == expected:
                print(Fore.GREEN + f"PASS [{i}] {out}")
                pass_count += 1
            else:
                print(Fore.RED + f"FAIL [{i}] hash mismatch: {out}")
                LOGGER.error("Manifest verify fail [line %s]: hash mismatch for %s (expected=%s actual=%s)", i, out, expected, actual)
                ok = False
                fail_count += 1
        except Exception as e:
            print(Fore.RED + f"FAIL [{i}] invalid manifest entry: {e}")
            LOGGER.exception("Manifest verify invalid entry [line %s]", i)
            ok = False
            fail_count += 1
    print(Fore.CYAN + f"Manifest verification summary: PASS={pass_count} FAIL={fail_count}")
    print(Fore.GREEN + "Overall result: PASS" if ok else Fore.RED + "Overall result: FAIL")
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

def build_manifest_entry(operation, algorithm, input_path, output_path, key_name):
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "algorithm": algorithm,
        "input_path": str(input_path),
        "output_path": str(output_path),
        "input_sha256": calculate_hash(input_path),
        "output_sha256": calculate_hash(output_path),
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
        print(Fore.GREEN + f"Key generated and saved as {key_filename}")
    except Exception as e:
        print(Fore.RED + f"Error generating key: {e}")

# Function to show available keys
def show_keys():
    try:
        print(Fore.CYAN + "Available keys:")
        for key_file in sorted(STATE.keys_dir.iterdir()):
            if key_file.suffix == ".key":
                key_data = load_key(key_file.name)
                key_type = detect_key_type(key_data) if key_data else "Unreadable"
                meta = "yes" if get_metadata_path(key_file.name).exists() else "no"
                bkp = "yes" if (STATE.backup_dir / key_file.name).exists() else "no"
                mod = key_file.stat().st_mtime
                from datetime import datetime
                mstr = datetime.fromtimestamp(mod).strftime("%Y-%m-%d %H:%M")
                print(f" - {key_file.name:<32} [{key_type:<10}]  Metadata: {'Yes' if meta == 'yes' else 'No'}  Backup: {'Yes' if bkp == 'yes' else 'No'}  Modified: {mstr}")
    except Exception as e:
        LOGGER.exception("show_keys failed")
        print(Fore.RED + f"Error showing keys: {e}")

# Function to load a key
def load_key(key_filename):
    try:
        key_path = STATE.keys_dir / key_filename
        if not key_path.is_file():
            print(Fore.RED + "Invalid key file")
            return None
        with open(key_path, "rb") as key_file:
            key_data = key_file.read()
        return key_data
    except Exception as e:
        print(Fore.RED + f"Error loading key: {e}")
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
    except Exception as e:
        print(Fore.RED + f"Error calculating hash for {file_path}: {e}")
        return None

# Function to encrypt a file using Fernet
def encrypt_file_fernet(file_path, key, key_name="unknown", manifest_path=None):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        rel = file_path.relative_to(STATE.input_dir) if STATE.input_dir in file_path.parents else Path(file_path.name)
        encrypted_file_path = safe_output_path(STATE.output_dir, rel, ".enc")
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)
        write_manifest(build_manifest_entry("encrypt", "Fernet", file_path, encrypted_file_path, key_name), manifest_path=manifest_path)
        print(Fore.GREEN + f"Encrypted {file_path.name} to {encrypted_file_path.name}")
        return encrypted_file_path
    except Exception as e:
        LOGGER.exception("Fernet encrypt failed for %s", file_path)
        print(Fore.RED + f"Error encrypting file {file_path}: {e}")
        return None

# Function to decrypt a file using Fernet
def decrypt_file_fernet(file_path, key, key_name="unknown", manifest_path=None):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        rel = file_path.relative_to(STATE.output_dir) if STATE.output_dir in file_path.parents else Path(file_path.name)
        rel = rel.with_suffix("")
        decrypted_file_path = STATE.decrypt_output_dir / rel
        decrypted_file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(decrypted_file_path, "wb") as file:
            file.write(decrypted_data)
        write_manifest(build_manifest_entry("decrypt", "Fernet", file_path, decrypted_file_path, key_name), manifest_path=manifest_path)
        print(Fore.GREEN + f"Decrypted {file_path.name} to {STATE.decrypt_output_dir}")
    except Exception as e:
        LOGGER.exception("Fernet decrypt failed for %s", file_path)
        print(Fore.RED + f"Error decrypting file {file_path}: {e}")

# Function to handle encryption of multiple or all files
def encrypt_files():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the Fernet key filename to use (from above): ").strip()
        key = load_key(key_filename)
        if key is None or len(key) != 44:
            print(Fore.RED + "Invalid Fernet key.")
            return
        if key is None:
            return
        
        files_to_encrypt = list(STATE.input_dir.rglob('*'))  # Use rglob for subdirectory traversal
        print(Fore.YELLOW + "Encrypting files...")
        for file_path in tqdm(files_to_encrypt, desc="Encrypting", unit="file"):
            if file_path.is_file():
                original_hash = calculate_hash(file_path)
                encrypted_file_path = encrypt_file_fernet(file_path, key, key_filename)
                if not encrypted_file_path:
                    continue
                rel = file_path.relative_to(STATE.input_dir) if STATE.input_dir in file_path.parents else Path(file_path.name)
                decrypt_file_fernet(encrypted_file_path, key, key_filename)  # Decrypt to verify integrity
                decrypted_file_path = STATE.decrypt_output_dir / rel
                decrypted_hash = calculate_hash(decrypted_file_path)
                if original_hash != decrypted_hash:
                    print(Fore.RED + f"Integrity check failed for {file_path.name}")
                if decrypted_file_path.exists():
                    os.remove(decrypted_file_path)  # Remove decrypted file after integrity check
    except Exception as e:
        LOGGER.exception("encrypt_files failed")
        print(Fore.RED + f"Error encrypting files: {e}")

# Function to handle decryption of multiple or all files
def decrypt_files():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the Fernet key filename to use (from above): ").strip()
        key = load_key(key_filename)
        if key is None or len(key) != 44:
            print(Fore.RED + "Invalid Fernet key.")
            return
        if key is None:
            return
        encrypted_files = list(STATE.output_dir.rglob('*.enc'))
        print(Fore.YELLOW + "Decrypting files...")
        for file_path in tqdm(encrypted_files, desc="Decrypting", unit="file"):
            if file_path.is_file():
                decrypt_file_fernet(file_path, key, key_filename)
    except Exception as e:
        LOGGER.exception("decrypt_files failed")
        print(Fore.RED + f"Error decrypting files: {e}")

# Function to check file integrity
def check_file_integrity():
    try:
        print(Fore.CYAN + "Checking file integrity against manifest...")
        verify_manifest_integrity()
    except Exception as e:
        LOGGER.exception("integrity check failed")
        print(Fore.RED + f"Error checking file integrity: {e}")

# Function to compress files
def compress_files():
    try:
        print(Fore.CYAN + "Compressing files...")
        zip_file_path = STATE.output_dir / "files.zip"  # Save ZIP file to OUTPUT_DIR
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in STATE.input_dir.rglob('*'):  # Use rglob to include all files in subdirectories
                if file.is_file():
                    zipf.write(file, file.relative_to(STATE.input_dir))
        print(Fore.GREEN + f"Files compressed to {zip_file_path}")
    except Exception as e:
        LOGGER.exception("compress_files failed")
        print(Fore.RED + f"Error compressing files: {e}")

# Function to add metadata to a Fernet key file
def add_key_metadata():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to add metadata to (from above): ")
        key_file_path = STATE.keys_dir / key_filename
        if not key_file_path.is_file():
            print(Fore.RED + "Invalid key file")
            return
        
        metadata = input(Fore.CYAN + "Enter metadata to add: ")

        # Store metadata separately in a JSON file
        metadata_filename = key_filename.replace('.key', '_metadata.json')
        metadata_path = get_metadata_path(key_filename)

        metadata_dict = {
            'metadata': metadata
        }

        with open(metadata_path, "w") as metadata_file:
            json.dump(metadata_dict, metadata_file)

        print(Fore.GREEN + f"Metadata added to {metadata_filename}")
    except Exception as e:
        LOGGER.exception("add_key_metadata failed")
        print(Fore.RED + f"Error adding metadata to Fernet key: {e}")

# Function to view metadata of a Fernet key file
def view_key_metadata():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to view metadata of (from above): ")
        metadata_filename = key_filename.replace('.key', '_metadata.json')
        metadata_path = get_metadata_path(key_filename)
        if not metadata_path.is_file():
            print(Fore.RED + "No metadata found for the selected key")
            return

        with open(metadata_path, "r") as metadata_file:
            metadata_dict = json.load(metadata_file)
        
        print(Fore.CYAN + f"Metadata for {key_filename}: {metadata_dict.get('metadata', 'No metadata available')}")
    except Exception as e:
        LOGGER.exception("view_key_metadata failed")
        print(Fore.RED + f"Error viewing metadata of Fernet key: {e}")

# Function to delete a key
def delete_key():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to delete (from above): ")
        key_file_path = STATE.keys_dir / key_filename
        if not key_file_path.is_file():
            print(Fore.RED + "Invalid key file")
            return
        key_data = load_key(key_filename)
        ktype = detect_key_type(key_data) if key_data else "Unknown"
        meta = key_metadata_value(key_filename)
        print(Fore.YELLOW + f"Selected key: {key_filename} | Type: {ktype} | Metadata: {meta}")
        confirm = input(Fore.CYAN + "Type the exact key filename to confirm deletion: ").strip()
        if confirm != key_filename:
            print(Fore.RED + "Confirmation mismatch. Deletion cancelled.")
            return
        metadata_path = get_metadata_path(key_filename)
        remove_related = input(Fore.CYAN + "Also delete related metadata and backup copy? (y/N): ").strip().lower() == "y"
        os.remove(key_file_path)
        if remove_related:
            if metadata_path.exists():
                metadata_path.unlink()
            backup_path = STATE.backup_dir / key_filename
            if backup_path.exists():
                backup_path.unlink()
        print(Fore.GREEN + f"Key {key_filename} deleted.")
    except Exception as e:
        LOGGER.exception("delete_key failed")
        print(Fore.RED + f"Error deleting key: {e}")
        
# Function to back up keys
def backup_keys():
    try:
        for key_file in sorted(STATE.keys_dir.iterdir()):
            if key_file.suffix in [".key", ".json"] and (key_file.suffix == ".key" or key_file.name.endswith("_metadata.json")):
                backup_file = STATE.backup_dir / key_file.name
                backup_file.write_bytes(key_file.read_bytes())
                print(Fore.GREEN + f"Backed up: {key_file.name}")
        print(Fore.GREEN + "Backup operation completed.")
    except Exception as e:
        LOGGER.exception("backup_keys failed")
        print(Fore.RED + f"Error backing up keys: {e}")
        
# Function to restore keys from backup
def restore_keys():
    try:
        if not STATE.backup_dir.is_dir():
            print(Fore.RED + "Backup directory does not exist.")
            return
        
        for backup_file in sorted(STATE.backup_dir.iterdir()):
            if backup_file.suffix in [".key", ".json"] and (backup_file.suffix == ".key" or backup_file.name.endswith("_metadata.json")):
                restored = STATE.keys_dir / backup_file.name
                restored.write_bytes(backup_file.read_bytes())
                print(Fore.GREEN + f"Restored: {backup_file.name}")
        print(Fore.GREEN + "Restore operation completed.")
    except Exception as e:
        LOGGER.exception("restore_keys failed")
        print(Fore.RED + f"Error restoring keys: {e}")
        
def generate_aes_key():
    try:
        key = os.urandom(32)  # AES-256 key size
        key_filename = STATE.keys_dir / (f"aes_key_{base64.urlsafe_b64encode(key).decode('utf-8')[:10]}.key")
        with open(key_filename, "wb") as key_file:
            key_file.write(key)
        print(Fore.GREEN + f"AES Key generated and saved as {key_filename}")
    except Exception as e:
        LOGGER.exception("generate_aes_key failed")
        print(Fore.RED + f"Error generating AES key: {e}")        
        
def encrypt_files_aes_with_key(file_path, key, key_name="unknown", manifest_path=None):
    try:
        if len(key) != 32:
            raise ValueError("Invalid AES key length. Must be 32 bytes for AES-256.")
        
        iv = os.urandom(12)  # Recommended IV size for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(file_path, "rb") as file:
            file_data = file.read()
        ciphertext = encryptor.update(file_data) + encryptor.finalize()
        encrypted_data = b"GCM1" + iv + encryptor.tag + ciphertext
        rel = file_path.relative_to(STATE.input_dir) if STATE.input_dir in file_path.parents else Path(file_path.name)
        encrypted_file_path = safe_output_path(STATE.output_dir, rel, ".aes")
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)
        write_manifest(build_manifest_entry("encrypt", "AES-GCM-v1", file_path, encrypted_file_path, key_name), manifest_path=manifest_path)
        print(Fore.GREEN + f"Encrypted {file_path.name} to {encrypted_file_path.name}")
        return encrypted_file_path
    except Exception as e:
        LOGGER.exception("AES encrypt failed for %s", file_path)
        print(Fore.RED + f"Error encrypting file {file_path}: {e}")
        return None

def decrypt_file_aes(file_path, key, key_name="unknown", manifest_path=None):
    try:
        if len(key) != 32:
            raise ValueError("Invalid AES key length. Must be 32 bytes for AES-256.")
        
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        if encrypted_data.startswith(b"GCM1"):
            iv = encrypted_data[4:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            # Backward-compatible decrypt path for legacy CFB-encrypted files
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        rel = file_path.relative_to(STATE.output_dir) if STATE.output_dir in file_path.parents else Path(file_path.name)
        rel = rel.with_suffix("")
        decrypted_file_path = STATE.decrypt_output_dir / rel
        decrypted_file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(decrypted_file_path, "wb") as file:
            file.write(decrypted_data)
        algo = "AES-GCM-v1" if encrypted_data.startswith(b"GCM1") else "AES-CFB-legacy"
        write_manifest(build_manifest_entry("decrypt", algo, file_path, decrypted_file_path, key_name), manifest_path=manifest_path)
        print(Fore.GREEN + f"Decrypted {file_path.name} to {decrypted_file_path.name}")
    except InvalidTag:
        LOGGER.exception("AES decrypt authentication failed for %s", file_path)
        print(Fore.RED + f"Error decrypting file {file_path}: authentication failed (data tampered or wrong key).")
    except Exception as e:
        LOGGER.exception("AES decrypt failed for %s", file_path)
        print(Fore.RED + f"Error decrypting file {file_path}: {e}")

def encrypt_files_aes():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the AES key filename to use (from above): ").strip()
        key = load_key(key_filename)
        if key is None or len(key) != 32:
            print(Fore.RED + "Invalid AES key.")
            return
        
        files_to_encrypt = list(STATE.input_dir.rglob('*'))
        print(Fore.YELLOW + "Encrypting files...")
        for file_path in tqdm(files_to_encrypt, desc="Encrypting", unit="file"):
            if file_path.is_file():
                encrypt_files_aes_with_key(file_path, key, key_filename)
    except Exception as e:
        LOGGER.exception("encrypt_files_aes failed")
        print(Fore.RED + f"Error encrypting files: {e}")

def decrypt_files_aes():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the AES key filename to use (from above): ").strip()
        key = load_key(key_filename)
        if key is None or len(key) != 32:
            print(Fore.RED + "Invalid AES key.")
            return
        encrypted_files = list(STATE.output_dir.rglob('*.aes'))
        print(Fore.YELLOW + "Decrypting files...")
        for file_path in tqdm(encrypted_files, desc="Decrypting", unit="file"):
            if file_path.is_file():
                decrypt_file_aes(file_path, key, key_filename)
    except Exception as e:
        LOGGER.exception("decrypt_files_aes failed")
        print(Fore.RED + f"Error decrypting files: {e}")

def run_cli_operation(args):
    key = load_key(args.key)
    if key is None:
        raise SystemExit(2)
    if not args.infile and not args.folder:
        raise SystemExit("Provide --infile or --folder")
    targets = [Path(args.infile)] if args.infile else [p for p in Path(args.folder).rglob("*") if p.is_file()]
    if args.algo == "fernet":
        if len(key) != 44:
            raise SystemExit("Fernet requires a 44-byte key.")
        for t in targets:
            if args.command == "encrypt":
                encrypt_file_fernet(t, key, args.key)
            else:
                decrypt_file_fernet(t, key, args.key)
    else:
        if len(key) != 32:
            raise SystemExit("AES requires a 32-byte key.")
        for t in targets:
            if args.command == "encrypt":
                encrypt_files_aes_with_key(t, key, args.key)
            else:
                decrypt_file_aes(t, key, args.key)

def run_extended_self_test():
    with tempfile.TemporaryDirectory() as td:
        manifest_path = Path(td) / "selftest_manifest.jsonl"
        tpath = Path(td) / "sample.txt"
        tpath.write_text("encryptopi-self-test")
        fkey = Fernet.generate_key()
        akey = os.urandom(32)
        f_enc = encrypt_file_fernet(tpath, fkey, "selftest_fernet", manifest_path=manifest_path)
        decrypt_file_fernet(f_enc, fkey, "selftest_fernet", manifest_path=manifest_path)
        a_enc = encrypt_files_aes_with_key(tpath, akey, "selftest_aes", manifest_path=manifest_path)
        decrypt_file_aes(a_enc, akey, "selftest_aes", manifest_path=manifest_path)
        if calculate_hash(tpath) != calculate_hash(STATE.decrypt_output_dir / tpath.name):
            raise RuntimeError("Roundtrip hash mismatch")
        if not verify_manifest_integrity(manifest_path=manifest_path):
            raise RuntimeError("Self-test manifest verification failed")
        for p in [f_enc, a_enc, STATE.decrypt_output_dir / tpath.name]:
            if p and Path(p).exists():
                Path(p).unlink()
        if manifest_path.exists():
            manifest_path.unlink()
        
def add_aes_key_metadata():
    try:
        show_keys()  # Show available keys
        key_filename = input(Fore.CYAN + "Enter the AES key filename to add metadata to (from above): ")
        key_file_path = STATE.keys_dir / key_filename
        if not key_file_path.is_file():
            print(Fore.RED + "Invalid key file")
            return
        
        metadata = input(Fore.CYAN + "Enter metadata to add: ")

        # Store metadata separately in a JSON file
        metadata_filename = key_filename.replace('.key', '_metadata.json')
        metadata_path = get_metadata_path(key_filename)

        metadata_dict = {
            'metadata': metadata
        }

        with open(metadata_path, "w") as metadata_file:
            json.dump(metadata_dict, metadata_file)

        print(Fore.GREEN + f"Metadata added to {metadata_filename}")
    except Exception as e:
        print(Fore.RED + f"Error adding metadata to AES key: {e}")

# Function to view metadata of an AES key file
def view_aes_key_metadata():
    try:
        show_keys()  # Show available keys
        key_filename = input(Fore.CYAN + "Enter the AES key filename to view metadata of (from above): ")
        metadata_filename = key_filename.replace('.key', '_metadata.json')
        metadata_path = get_metadata_path(key_filename)
        if not metadata_path.is_file():
            print(Fore.RED + "No metadata found for the selected key")
            return

        with open(metadata_path, "r") as metadata_file:
            metadata_dict = json.load(metadata_file)
        
        print(Fore.CYAN + f"Metadata for {key_filename}: {metadata_dict.get('metadata', 'No metadata available')}")
    except Exception as e:
        print(Fore.RED + f"Error viewing metadata of AES key: {e}")
        
# Function to load an AES key without reading metadata
def load_aes_key(key_filename):
    try:
        key_path = STATE.keys_dir / key_filename
        if not key_path.is_file():
            print(Fore.RED + "Invalid key file")
            return None
        with open(key_path, "rb") as key_file:
            key_data = key_file.read()
        # Ensure key length is correct
        if len(key_data) != 32:
            print(Fore.RED + "Loaded key length is incorrect")
            return None
        return key_data
    except Exception as e:
        print(Fore.RED + f"Error loading AES key: {e}")
        return None        



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
   - Verify integrity against operations_manifest.jsonl records.
   - Detect missing or modified encrypted/decrypted files by comparing stored and recalculated SHA256 hashes.

9. Compress Files:
   - Compress files in the 'input' directory into a ZIP archive.
   - The ZIP archive is saved in the 'output' directory.

10. Add Key Metadata:
    - Add descriptive metadata to an encryption key file for easy identification.

11. View Key Metadata:
    - Display the metadata associated with a specific key file.

12. Delete Key:
    - Permanently remove an encryption key from the 'keys' directory.

13. Backup Keys:
    - Create a backup of all keys stored in the 'keys' directory.

14. Restore Keys:
    - Restore keys from a backup, allowing for recovery of lost keys.

15. Help:
    - Display this help guide.

16. Exit:
    - Exit the Encryptopi script.

ADDITIONAL NOTES:
- Ensure you use the correct key type (Fernet or AES) for encryption and decryption.
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
    print("  EncryptoPI Encryptor - WastelandSYS ")
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
      14. Backup Keys
      15. Restore Keys
      16. Delete Key
       0. Exit
       h. Help
    """)

def main_menu():
    while True:
        display_menu()
        choice = input(Fore.CYAN + " Enter your choice: ")
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
            backup_keys()
        elif choice == '15':
            restore_keys()
        elif choice == '16':
            delete_key()
        elif choice == '0':
            print(Fore.GREEN + "Exiting...")
            break
        elif choice == 'h' or choice.lower() == 'help':
            display_help()
        else:
            print(Fore.RED + "Invalid choice. Please try again.")
        input(Fore.CYAN + "Press Enter to return to the main menu...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EncryptoPI encryption/decryption tool")
    parser.add_argument("--self-test", action="store_true", help="Run a quick runtime self-test and exit")
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

    if args.command in ("encrypt", "decrypt"):
        run_cli_operation(args)
    elif args.self_test:
        try:
            print(Fore.CYAN + "Running self-test...")
            LOGGER.info("Self-test started")
            for directory in [STATE.keys_dir, STATE.input_dir, STATE.output_dir, STATE.decrypt_output_dir]:
                directory.mkdir(parents=True, exist_ok=True)
            _ = Fernet.generate_key()
            test_hash = calculate_hash(__file__)
            if not test_hash:
                raise RuntimeError("Failed to calculate script hash")
            run_extended_self_test()
            print(Fore.GREEN + "Self-test passed.")
            LOGGER.info("Self-test passed")
        except Exception as e:
            LOGGER.exception("self-test failed")
            print(Fore.RED + f"Self-test failed: {e}")
            raise SystemExit(1)
    else:
        main_menu()
