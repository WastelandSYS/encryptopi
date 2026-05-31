<img width="1536" height="1024" alt="encryptopiART" src="https://github.com/user-attachments/assets/06b2126c-c67a-4781-800e-78fec233b402" />

# encryptopi

Advanced terminal-based file and folder encryption suite for Linux featuring Fernet and AES-256-GCM encryption, key management, integrity verification, metadata handling, and secure batch workflows.

---

# FEATURES

- Dual encryption support using Fernet and AES-256-GCM
- Secure file and folder encryption/decryption workflows
- AES-GCM authenticated encryption with tamper detection
- Streamed AES-GCM processing for improved large-file reliability
- Fernet encryption with automatic integrity validation
- Batch encryption/decryption for entire folders
- Recursive folder traversal support
- SHA256 manifest-based integrity verification system
- Persistent operations manifest logging
- Key generation for both Fernet and AES encryption
- Key metadata management and labeling system
- Key backup and restore functionality
- Secure key deletion workflow with confirmation protection
- Compression support for input files and folders
- Built-in self-test runtime verification mode
- Interactive terminal menu system with colored output
- Progress bars for large encryption/decryption operations
- Desktop launcher integration for Raspberry Pi desktop environments
- Structured logging system with operation tracking

---

# ENCRYPTION MODES

| Mode | Purpose |
|------|----------|
| Fernet | Simple authenticated symmetric encryption |
| AES-256-GCM | Advanced authenticated encryption with tamper detection |

Both encryption systems support secure file handling, batch operations, and manifest-based integrity tracking.

---

## ENCRYPTOPI WORKFLOW

### Main Menu

Access encryption, decryption, key management, integrity verification, backup, and recovery tools from one terminal interface.

<p align="center">
  <img width="317" height="625" alt="encryptopiMAINMENU" src="https://github.com/user-attachments/assets/53325f54-89db-424f-bdd8-a36c10a85522" />
</p>

### Key Management & Metadata

Manage Fernet and AES keys, view metadata, monitor backup status, and track key history.

<p align="center">
  <img width="505" height="153" alt="encryptopikeymanipulation" src="https://github.com/user-attachments/assets/4c0a8249-7461-450e-beed-5b9d3d6a8437" />
</p>

### AES Encryption Workflow

Encrypt files using AES-256-GCM with progress tracking and operation summaries.

<p align="center">
  <img width="433" height="290" alt="encryptopiAESencryption" src="https://github.com/user-attachments/assets/5d9bb609-e3c6-45c1-bc93-f612ece63bae" />
</p>

### Integrity Verification

Verify encrypted output against manifest hashes and confirm file integrity.

<p align="center">
  <img width="425" height="294" alt="encryptopiCHECKINTEGRITY" src="https://github.com/user-attachments/assets/2d1dc73b-7d78-4ffa-97d6-0df04e20b554" />
</p>

### Backup & Recovery

Restore keys and metadata from backups to recover encryption access when needed.

<p align="center">
  <img width="354" height="86" alt="encryptopiKeyBackup" src="https://github.com/user-attachments/assets/7f93e4bf-5a18-4d88-9bdc-1ad62bc2e301" />
  <img width="347" height="87" alt="encryptopiKeyRestore" src="https://github.com/user-attachments/assets/82af9315-5e38-4456-80ba-f2eeda03dafa" />
</p>

---

# INSTALLATION

```bash
git clone https://github.com/WastelandSYS/encryptopi.git
cd encryptopi
chmod +x install.sh uninstall.sh
sudo ./install.sh
```

Installer compatibility notes:
- Supports apt, dnf, yum, pacman, zypper, and apk package managers.
- Falls back to pip-based install when distro package detection is unavailable.
- If your distro enforces externally managed Python environments, the installer will attempt a compatible pip fallback and provide a virtualenv recovery command.

Launch with:

```bash
encryptopi
```

---

# UNINSTALLATION

```bash
cd encryptopi
sudo ./uninstall.sh
```

The uninstaller removes:
- `/usr/local/bin/encryptopi`
- desktop launchers
- application shortcuts

Your project folders and encrypted data remain untouched.

---

# USAGE

Default launch:

```bash
encryptopi
```

Generate Fernet key:

```bash
encryptopi
```

Then select:

```text
2. Generate Fernet Key
```

Generate AES-256 key:

```bash
encryptopi
```

Then select:

```text
5. Generate AES Key
```

Run runtime self-test:

```bash
python3 encryptopi.py --self-test --no-clear
```

Show version:

```bash
python3 encryptopi.py --version
```

List keys in CLI mode:

```bash
python3 encryptopi.py --list-keys
python3 encryptopi.py --list-keys --json
```

Verify manifest integrity in CLI mode:

```bash
python3 encryptopi.py --verify-manifest
```

Encrypt a single file using Fernet (CLI mode):

```bash
python3 encryptopi.py encrypt --algo fernet --key mykey.key --infile example.txt
```

Decrypt a single file using Fernet:

```bash
python3 encryptopi.py decrypt --algo fernet --key mykey.key --infile example.txt.enc
```

Encrypt using AES-256-GCM:

```bash
python3 encryptopi.py encrypt --algo aes --key aeskey.key --infile example.txt
```

Decrypt AES-encrypted file:

```bash
python3 encryptopi.py decrypt --algo aes --key aeskey.key --infile example.txt.aes
```

Encrypt an entire folder recursively:

```bash
python3 encryptopi.py encrypt --algo aes --key aeskey.key --folder myfolder
```

Check manifest integrity:

```bash
encryptopi
```

Then select:

```text
12. Check File Integrity
```

New advanced menu options:
- Single-file interactive encrypt/decrypt operations.
- Dry-run preview for batch operations before execution.
- Manifest tools submenu for verification, tail view, and pruning stale entries.
- Decompression workflow to safely extract ZIP archives to `decompressed_output/`.

---

# DIRECTORY STRUCTURE

encryptopi automatically creates and manages:

```text
input/
output/
decrypted_output/
decompressed_output/
keys/
key_backups/
logs/
```

Workflow overview:

- Place files/folders into `input/`
- Encrypted outputs are written to `output/`
- Decrypted outputs are written to `decrypted_output/`
- Encryption keys are stored in `keys/`
- Key backups are stored in `key_backups/`
- Runtime logs are stored in `logs/`
- `output/` stores encrypted files and `operations_manifest.jsonl`

---

# IMPORTANT KEY WARNING

⚠️ WARNING: If encryption keys are lost, encrypted files cannot be recovered. Keep secure backups of your key files.

---

# SECURITY FEATURES

- AES-256-GCM authenticated encryption
- SHA256 integrity verification
- Manifest-based operation tracking
- Tamper detection during AES decryption
- Automatic encryption/decryption logging
- Key confirmation safety prompts
- Backup-aware key management
- Metadata tagging for key organization

---

# COMPATIBILITY

Designed primarily for Linux systems.

Tested on:

- Raspberry Pi OS
- Kali Linux ARM
- Raspberry Pi 4B
- Debian-based Linux systems

Notes:

- `install.sh` prefers system dependencies via `apt` on Debian/Raspberry Pi OS/Kali
- If `apt-get` is unavailable, installer prints guidance and falls back to pip when available
- Desktop launcher support is included for Raspberry Pi desktop environments
- The installer creates a global `encryptopi` command shortcut
- AES operations use the `cryptography` Python package backend

---

# DEPENDENCIES

Installed automatically by `install.sh`:

- `cryptography`
- `colorama`
- `tqdm`

---

# WHY ENCRYPTOPI?

encryptopi was built to provide a more organized, visual, and user-friendly encryption workflow for Linux and Raspberry Pi systems without sacrificing powerful functionality.

The tool focuses on:
- secure encryption workflows
- clean terminal experience
- organized key management
- integrity verification
- batch folder encryption
- practical day-to-day usability
- Raspberry Pi compatibility

---

# LICENSE

Encryptopi is released under the GNU General Public License v3.0. See [`LICENSE`](LICENSE) for the full license text.

---

# AUTHOR

[WastelandSYS](https://github.com/WastelandSYS)
