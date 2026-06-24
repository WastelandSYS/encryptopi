import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

import encryptopi


class TempStateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.old_state = encryptopi.STATE
        self.old_zip_total = encryptopi.MAX_ZIP_TOTAL_BYTES
        self.old_warning_shown = encryptopi.ENCRYPTION_WARNING_SHOWN
        self.state = encryptopi.AppState(
            script_dir=root,
            keys_dir=root / "keys",
            input_dir=root / "input",
            output_dir=root / "output",
            decrypt_output_dir=root / "decrypted_output",
            backup_dir=root / "key_backups",
            logs_dir=root / "logs",
        )
        encryptopi.STATE = self.state
        encryptopi.ensure_app_dirs()

    def tearDown(self):
        encryptopi.STATE = self.old_state
        encryptopi.MAX_ZIP_TOTAL_BYTES = self.old_zip_total
        encryptopi.ENCRYPTION_WARNING_SHOWN = self.old_warning_shown
        self.tmp.cleanup()

    def test_fernet_roundtrip(self):
        src = self.state.input_dir / "sample.txt"
        src.write_bytes(b"fernet roundtrip")
        key = Fernet.generate_key()
        with redirect_stdout(io.StringIO()):
            encrypted = encryptopi.encrypt_file_fernet(src, key, "test.key")
            decrypted = encryptopi.decrypt_file_fernet(encrypted, key, "test.key")
        self.assertEqual(src.read_bytes(), decrypted.read_bytes())

    def test_aes_roundtrip(self):
        src = self.state.input_dir / "sample.txt"
        src.write_bytes(b"aes roundtrip")
        key = os.urandom(32)
        with redirect_stdout(io.StringIO()):
            encrypted = encryptopi.encrypt_files_aes_with_key(src, key, "aes.key")
            decrypted = encryptopi.decrypt_file_aes(encrypted, key, "aes.key")
        self.assertEqual(src.read_bytes(), decrypted.read_bytes())

    def test_passphrase_roundtrip_with_changed_runtime_kdf(self):
        src = self.state.input_dir / "sample.txt"
        src.write_bytes(b"passphrase roundtrip")
        passphrase = b"correct horse battery staple"
        old_n = encryptopi.SCRYPT_N
        try:
            with redirect_stdout(io.StringIO()):
                encrypted = encryptopi.encrypt_file_passphrase(src, passphrase)
                encryptopi.SCRYPT_N = old_n * 2
                decrypted = encryptopi.decrypt_file_passphrase(encrypted, passphrase)
        finally:
            encryptopi.SCRYPT_N = old_n
        self.assertEqual(src.read_bytes(), decrypted.read_bytes())

    def test_metadata_strips_key_filename_input(self):
        key_path = self.state.keys_dir / "normal.key"
        key_path.write_bytes(os.urandom(32))
        with patch("builtins.input", side_effect=[" normal.key ", "metadata"]), redirect_stdout(io.StringIO()):
            encryptopi.add_key_metadata_common("AES")
        self.assertTrue((self.state.keys_dir / "normal_metadata.json").exists())
        self.assertFalse((self.state.keys_dir / " normal.key _metadata.json").exists())

    def test_export_key_bundle_includes_recovery_files(self):
        key_data = os.urandom(32)
        key_path = self.state.keys_dir / "bundle.key"
        key_path.write_bytes(key_data)
        metadata_path = self.state.keys_dir / "bundle_metadata.json"
        metadata_path.write_text('{"metadata": "backup key"}', encoding="utf-8")
        bundle_dir = self.state.script_dir / "bundle_export"

        with patch("builtins.input", side_effect=["bundle.key", str(bundle_dir)]), redirect_stdout(io.StringIO()) as out:
            encryptopi.export_key_bundle()

        self.assertEqual(key_data, (bundle_dir / "bundle.key").read_bytes())
        self.assertEqual(metadata_path.read_text(encoding="utf-8"), (bundle_dir / "bundle_metadata.json").read_text(encoding="utf-8"))
        self.assertIn(encryptopi.key_fingerprint(key_data), (bundle_dir / "KEY_FINGERPRINT.txt").read_text(encoding="utf-8"))
        self.assertIn("Anyone with this key can decrypt", (bundle_dir / "README_RECOVERY.txt").read_text(encoding="utf-8"))
        self.assertIn("Exported recovery bundle", out.getvalue())

    def test_import_key_bundle_restores_key_and_renames_metadata(self):
        key_data = os.urandom(32)
        bundle_dir = self.state.script_dir / "incoming_bundle"
        bundle_dir.mkdir()
        (bundle_dir / "bundle.key").write_bytes(key_data)
        (bundle_dir / "bundle_metadata.json").write_text('{"metadata": "restore me"}', encoding="utf-8")
        (bundle_dir / "KEY_FINGERPRINT.txt").write_text(
            f"Fingerprint: {encryptopi.key_fingerprint(key_data)}\n",
            encoding="utf-8",
        )

        with patch("builtins.input", side_effect=[str(bundle_dir), "restored.key"]), redirect_stdout(io.StringIO()) as out:
            encryptopi.import_key_bundle()

        self.assertEqual(key_data, (self.state.keys_dir / "restored.key").read_bytes())
        self.assertEqual(
            '{"metadata": "restore me"}',
            (self.state.keys_dir / "restored_metadata.json").read_text(encoding="utf-8"),
        )
        self.assertFalse((self.state.keys_dir / "bundle_metadata.json").exists())
        self.assertIn("Imported recovery bundle key as restored.key", out.getvalue())

    def test_guided_encrypt_uses_existing_aes_key_for_input_folder(self):
        key_data = os.urandom(32)
        (self.state.keys_dir / "aes_existing.key").write_bytes(key_data)
        src = self.state.input_dir / "guided.txt"
        src.write_text("guided content", encoding="utf-8")

        answers = ["", "existing", "", "n", "", "y", "y"]
        with patch.dict(os.environ, {"ENCRYPTOPI_NO_CLEAR": "1"}), patch("builtins.input", side_effect=answers), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
            encryptopi.guided_encrypt()

        encrypted = self.state.output_dir / "guided.txt.aes"
        self.assertTrue(encrypted.exists())
        self.assertIn("Guided encryption summary: succeeded=1 failed=0", out.getvalue())

    def test_cli_dry_run_does_not_require_secret(self):
        src = self.state.input_dir / "sample.txt"
        src.write_text("preview", encoding="utf-8")
        args = type("Args", (), {
            "algo": "passphrase",
            "passphrase_env": "ENCRYPTOPI_PASSPHRASE",
            "key": None,
            "infile": str(src),
            "folder": None,
            "command": "encrypt",
            "dry_run": True,
            "recursive": True,
            "output_dir": None,
            "decrypt_output_dir": None,
            "manifest_path": None,
            "output_policy": "rename",
            "allow_legacy_cfb": False,
        })()
        with redirect_stdout(io.StringIO()) as out:
            encryptopi.run_cli_operation(args)
        self.assertIn("DRY-RUN", out.getvalue())

    def test_zip_total_limit_blocks_archive(self):
        import zipfile

        zip_path = self.state.output_dir / "too_big.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", b"a" * 2048)
        encryptopi.MAX_ZIP_TOTAL_BYTES = 1024
        with patch("builtins.input", return_value=str(zip_path)), redirect_stdout(io.StringIO()) as out:
            encryptopi.decompress_files()
        self.assertIn("exceeds maximum total extracted size", out.getvalue())

    def test_first_run_notice_only_when_no_keys(self):
        with patch.dict(os.environ, {"ENCRYPTOPI_NO_CLEAR": "1"}), patch("builtins.input", return_value=""), redirect_stdout(io.StringIO()) as out:
            encryptopi.maybe_show_first_run_notice()
        self.assertIn("First Run Notice", out.getvalue())
        (self.state.keys_dir / "existing.key").write_bytes(os.urandom(32))
        with patch.dict(os.environ, {"ENCRYPTOPI_NO_CLEAR": "1"}), patch("builtins.input", return_value=""), redirect_stdout(io.StringIO()) as out:
            encryptopi.maybe_show_first_run_notice()
        self.assertEqual("", out.getvalue())

    def test_encryption_warning_confirms_once(self):
        encryptopi.ENCRYPTION_WARNING_SHOWN = False
        with patch.dict(os.environ, {"ENCRYPTOPI_NO_CLEAR": "1"}), patch("builtins.input", return_value="y"), redirect_stdout(io.StringIO()) as out:
            self.assertTrue(encryptopi.confirm_encryption_safety())
        self.assertIn("Before You Encrypt", out.getvalue())
        with patch.dict(os.environ, {"ENCRYPTOPI_NO_CLEAR": "1"}), patch("builtins.input", return_value="n"), redirect_stdout(io.StringIO()) as out:
            self.assertTrue(encryptopi.confirm_encryption_safety())
        self.assertEqual("", out.getvalue())


if __name__ == "__main__":
    unittest.main()
