#!/usr/bin/env python3

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pathlib import Path
from colorama import Fore, init
from tqdm import tqdm
import argparse
import json
import os
import base64
import hashlib
import zipfile

# Initialize colorama
init(autoreset=True)

# Get the directory where the script is located
SCRIPT_DIR = Path(__file__).resolve().parent

# Paths relative to the script's directory
KEYS_DIR = SCRIPT_DIR / "keys"
INPUT_DIR = SCRIPT_DIR / "input"
OUTPUT_DIR = SCRIPT_DIR / "output"
DECRYPT_OUTPUT_DIR = SCRIPT_DIR / "decrypted_output"

# Ensure directories exist
for directory in [KEYS_DIR, INPUT_DIR, OUTPUT_DIR, DECRYPT_OUTPUT_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Function to clear terminal
def clear_terminal():
    if os.environ.get("ENCRYPTOPI_NO_CLEAR") == "1":
        return
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to generate a new encryption key
def generate_key():
    try:
        key = Fernet.generate_key()
        key_filename = KEYS_DIR / (f"key_{base64.urlsafe_b64encode(key).decode('utf-8')[:10]}.key")
        with open(key_filename, "wb") as key_file:
            key_file.write(key)
        print(Fore.GREEN + f"Key generated and saved as {key_filename}")
    except Exception as e:
        print(Fore.RED + f"Error generating key: {e}")

# Function to show available keys
def show_keys():
    try:
        print(Fore.CYAN + "Available keys:")
        for key_file in KEYS_DIR.iterdir():
            if key_file.suffix == ".key":
                print(f" - {key_file.name}")
    except Exception as e:
        print(Fore.RED + f"Error showing keys: {e}")

# Function to load a key
def load_key(key_filename):
    try:
        key_path = KEYS_DIR / key_filename
        if not key_path.is_file():
            print(Fore.RED + "Invalid key file")
            return None
        with open(key_path, "rb") as key_file:
            key_data = key_file.read()
        return key_data
    except Exception as e:
        print(Fore.RED + f"Error loading key: {e}")
        return None

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
def encrypt_file_fernet(file_path, key):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        encrypted_file_path = OUTPUT_DIR / (file_path.name + ".enc")
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)
        print(Fore.GREEN + f"Encrypted {file_path.name} to {encrypted_file_path.name}")
    except Exception as e:
        print(Fore.RED + f"Error encrypting file {file_path}: {e}")

# Function to decrypt a file using Fernet
def decrypt_file_fernet(file_path, key):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        decrypted_file_path = DECRYPT_OUTPUT_DIR / file_path.name.replace(".enc", "")
        with open(decrypted_file_path, "wb") as file:
            file.write(decrypted_data)
        print(Fore.GREEN + f"Decrypted {file_path.name} to {DECRYPT_OUTPUT_DIR}")
    except Exception as e:
        print(Fore.RED + f"Error decrypting file {file_path}: {e}")

# Function to handle encryption of multiple or all files
def encrypt_files():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to use (from above): ")
        key = load_key(key_filename)
        if key is None:
            return
        
        files_to_encrypt = list(INPUT_DIR.rglob('*'))  # Use rglob for subdirectory traversal
        print(Fore.YELLOW + "Encrypting files...")
        for file_path in tqdm(files_to_encrypt, desc="Encrypting", unit="file"):
            if file_path.is_file():
                original_hash = calculate_hash(file_path)
                encrypt_file_fernet(file_path, key)
                encrypted_file_path = OUTPUT_DIR / (file_path.name + ".enc")
                decrypt_file_fernet(encrypted_file_path, key)  # Decrypt to verify integrity
                decrypted_file_path = DECRYPT_OUTPUT_DIR / file_path.name
                decrypted_hash = calculate_hash(decrypted_file_path)
                if original_hash != decrypted_hash:
                    print(Fore.RED + f"Integrity check failed for {file_path.name}")
                os.remove(decrypted_file_path)  # Remove decrypted file after integrity check
    except Exception as e:
        print(Fore.RED + f"Error encrypting files: {e}")

# Function to handle decryption of multiple or all files
def decrypt_files():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to use (from above): ")
        key = load_key(key_filename)
        if key is None:
            return
        encrypted_files = list(OUTPUT_DIR.rglob('*.enc'))
        print(Fore.YELLOW + "Decrypting files...")
        for file_path in tqdm(encrypted_files, desc="Decrypting", unit="file"):
            if file_path.is_file():
                decrypt_file_fernet(file_path, key)
    except Exception as e:
        print(Fore.RED + f"Error decrypting files: {e}")

# Function to check file integrity
def check_file_integrity():
    try:
        print(Fore.CYAN + "Checking file integrity...")
        files_to_check = list(OUTPUT_DIR.rglob('*.enc')) + list(DECRYPT_OUTPUT_DIR.rglob('*'))
        for file_path in tqdm(files_to_check, desc="Checking", unit="file"):
            if file_path.is_file():
                hash_value = calculate_hash(file_path)
                if hash_value:
                    print(Fore.GREEN + f"Integrity of {file_path.name} is intact.")
                else:
                    print(Fore.RED + f"Failed to calculate hash for {file_path.name}.")
    except Exception as e:
        print(Fore.RED + f"Error checking file integrity: {e}")

# Function to compress files
def compress_files():
    try:
        print(Fore.CYAN + "Compressing files...")
        zip_file_path = OUTPUT_DIR / "files.zip"  # Save ZIP file to OUTPUT_DIR
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in INPUT_DIR.rglob('*'):  # Use rglob to include all files in subdirectories
                if file.is_file():
                    zipf.write(file, file.relative_to(INPUT_DIR))
        print(Fore.GREEN + f"Files compressed to {zip_file_path}")
    except Exception as e:
        print(Fore.RED + f"Error compressing files: {e}")

# Function to add metadata to a Fernet key file
def add_key_metadata():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to add metadata to (from above): ")
        key_file_path = KEYS_DIR / key_filename
        if not key_file_path.is_file():
            print(Fore.RED + "Invalid key file")
            return
        
        metadata = input(Fore.CYAN + "Enter metadata to add: ")

        # Store metadata separately in a JSON file
        metadata_filename = key_filename.replace('.key', '_metadata.json')
        metadata_path = KEYS_DIR / metadata_filename

        metadata_dict = {
            'metadata': metadata
        }

        with open(metadata_path, "w") as metadata_file:
            json.dump(metadata_dict, metadata_file)

        print(Fore.GREEN + f"Metadata added to {metadata_filename}")
    except Exception as e:
        print(Fore.RED + f"Error adding metadata to Fernet key: {e}")

# Function to view metadata of a Fernet key file
def view_key_metadata():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to view metadata of (from above): ")
        metadata_filename = key_filename.replace('.key', '_metadata.json')
        metadata_path = KEYS_DIR / metadata_filename
        if not metadata_path.is_file():
            print(Fore.RED + "No metadata found for the selected key")
            return

        with open(metadata_path, "r") as metadata_file:
            metadata_dict = json.load(metadata_file)
        
        print(Fore.CYAN + f"Metadata for {key_filename}: {metadata_dict.get('metadata', 'No metadata available')}")
    except Exception as e:
        print(Fore.RED + f"Error viewing metadata of Fernet key: {e}")

# Function to delete a key
def delete_key():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to delete (from above): ")
        key_file_path = KEYS_DIR / key_filename
        if not key_file_path.is_file():
            print(Fore.RED + "Invalid key file")
            return
        os.remove(key_file_path)
        print(Fore.GREEN + f"Key {key_filename} deleted.")
    except Exception as e:
        print(Fore.RED + f"Error deleting key: {e}")
        
# Function to back up keys
def backup_keys():
    try:
        # Get the directory where the script is located
        SCRIPT_DIR = Path(__file__).resolve().parent
        backup_dir = SCRIPT_DIR / "key_backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        for key_file in KEYS_DIR.iterdir():
            if key_file.suffix == ".key":
                backup_file = backup_dir / key_file.name
                with open(key_file, "rb") as f:
                    key_data = f.read()
                with open(backup_file, "wb") as f:
                    f.write(key_data)
        print(Fore.GREEN + "Keys successfully backed up.")
    except Exception as e:
        print(Fore.RED + f"Error backing up keys: {e}")
        
# Function to restore keys from backup
def restore_keys():
    try:
        # Use the directory of the script for backup_dir
        script_dir = Path(__file__).resolve().parent
        backup_dir = script_dir / "key_backups"
        
        if not backup_dir.is_dir():
            print(Fore.RED + "Backup directory does not exist.")
            return
        
        for backup_file in backup_dir.iterdir():
            if backup_file.suffix == ".key":
                restored_key_file = KEYS_DIR / backup_file.name
                with open(backup_file, "rb") as f:
                    key_data = f.read()
                with open(restored_key_file, "wb") as f:
                    f.write(key_data)
        print(Fore.GREEN + "Keys successfully restored.")
    except Exception as e:
        print(Fore.RED + f"Error restoring keys: {e}")
        
def generate_aes_key():
    try:
        key = os.urandom(32)  # AES-256 key size
        key_filename = KEYS_DIR / (f"aes_key_{base64.urlsafe_b64encode(key).decode('utf-8')[:10]}.key")
        with open(key_filename, "wb") as key_file:
            key_file.write(key)
        print(Fore.GREEN + f"AES Key generated and saved as {key_filename}")
    except Exception as e:
        print(Fore.RED + f"Error generating AES key: {e}")        
        
def encrypt_files_aes(file_path, key):
    try:
        iv = os.urandom(16)  # Generate a new IV for each encryption
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = iv + encryptor.update(file_data) + encryptor.finalize()
        encrypted_file_path = OUTPUT_DIR / (file_path.name + ".aes")
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)
        print(Fore.GREEN + f"Encrypted {file_path.name} to {encrypted_file_path.name}")
    except Exception as e:
        print(Fore.RED + f"Error encrypting file {file_path}: {e}")

def encrypt_files_aes_with_key(file_path, key):
    try:
        if len(key) != 32:
            raise ValueError("Invalid AES key length. Must be 32 bytes for AES-256.")
        
        iv = os.urandom(16)  # Generate a new IV for each encryption
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = iv + encryptor.update(file_data) + encryptor.finalize()
        encrypted_file_path = OUTPUT_DIR / (file_path.name + ".aes")
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)
        print(Fore.GREEN + f"Encrypted {file_path.name} to {encrypted_file_path.name}")
    except Exception as e:
        print(Fore.RED + f"Error encrypting file {file_path}: {e}")

def decrypt_file_aes(file_path, key):
    try:
        if len(key) != 32:
            raise ValueError("Invalid AES key length. Must be 32 bytes for AES-256.")
        
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        iv = encrypted_data[:16]  # Extract the IV from the start of the encrypted data
        encrypted_data = encrypted_data[16:]  # Remaining data is the actual encrypted content
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_file_path = DECRYPT_OUTPUT_DIR / file_path.name.replace(".aes", "")
        with open(decrypted_file_path, "wb") as file:
            file.write(decrypted_data)
        print(Fore.GREEN + f"Decrypted {file_path.name} to {decrypted_file_path.name}")
    except Exception as e:
        print(Fore.RED + f"Error decrypting file {file_path}: {e}")

def encrypt_files_aes():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the AES key filename to use (from above): ")
        key = load_key(key_filename)
        if key is None or len(key) != 32:
            print(Fore.RED + "Invalid AES key.")
            return
        
        files_to_encrypt = list(INPUT_DIR.rglob('*'))
        print(Fore.YELLOW + "Encrypting files...")
        for file_path in tqdm(files_to_encrypt, desc="Encrypting", unit="file"):
            if file_path.is_file():
                encrypt_files_aes_with_key(file_path, key)
    except Exception as e:
        print(Fore.RED + f"Error encrypting files: {e}")

def decrypt_files_aes():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the AES key filename to use (from above): ")
        key = load_key(key_filename)
        if key is None or len(key) != 32:
            print(Fore.RED + "Invalid AES key.")
            return
        encrypted_files = list(OUTPUT_DIR.rglob('*.aes'))
        print(Fore.YELLOW + "Decrypting files...")
        for file_path in tqdm(encrypted_files, desc="Decrypting", unit="file"):
            if file_path.is_file():
                decrypt_file_aes(file_path, key)
    except Exception as e:
        print(Fore.RED + f"Error decrypting files: {e}")
        
def add_aes_key_metadata():
    try:
        show_keys()  # Show available keys
        key_filename = input(Fore.CYAN + "Enter the AES key filename to add metadata to (from above): ")
        key_file_path = KEYS_DIR / key_filename
        if not key_file_path.is_file():
            print(Fore.RED + "Invalid key file")
            return
        
        metadata = input(Fore.CYAN + "Enter metadata to add: ")

        # Store metadata separately in a JSON file
        metadata_filename = key_filename.replace('.key', '_metadata.json')
        metadata_path = KEYS_DIR / metadata_filename

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
        metadata_path = KEYS_DIR / metadata_filename
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
        key_path = KEYS_DIR / key_filename
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
   - Verify the integrity of files by checking their hash values.

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
    args = parser.parse_args()

    if args.no_clear:
        os.environ["ENCRYPTOPI_NO_CLEAR"] = "1"

    if args.self_test:
        try:
            print(Fore.CYAN + "Running self-test...")
            for directory in [KEYS_DIR, INPUT_DIR, OUTPUT_DIR, DECRYPT_OUTPUT_DIR]:
                directory.mkdir(parents=True, exist_ok=True)
            _ = Fernet.generate_key()
            test_hash = calculate_hash(__file__)
            if not test_hash:
                raise RuntimeError("Failed to calculate script hash")
            print(Fore.GREEN + "Self-test passed.")
        except Exception as e:
            print(Fore.RED + f"Self-test failed: {e}")
            raise SystemExit(1)
    else:
        main_menu()
