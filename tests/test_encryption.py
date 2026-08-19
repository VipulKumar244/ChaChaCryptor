#!/usr/bin/env python3
"""Integration tests for the pfe command-line encryptor.

Run from the repository root with:
    python3 tests/test_encryption.py

Set PFE_BINARY to test a binary outside the default build/main location.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
INPUT_DIRECTORY = REPOSITORY_ROOT / "tests" / "input"
OUTPUT_DIRECTORY = REPOSITORY_ROOT / "tests" / "output"
DEFAULT_BINARY = REPOSITORY_ROOT / "build" / "main"
PASSWORD = "encryption-test-password"
HEADER_MAGIC = b"DOGE"
HEADER_SIZE = 29


class EncryptionIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.binary = Path(os.environ.get("PFE_BINARY", DEFAULT_BINARY))
        if not cls.binary.is_file():
            raise unittest.SkipTest(
                f"Encryptor binary not found at {cls.binary}. Build it first or set PFE_BINARY."
            )
        OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

        account_files = list((INPUT_DIRECTORY / "documents").rglob("account.csv"))
        if len(account_files) != 1:
            raise unittest.SkipTest("Expected exactly one account.csv below tests/input/documents.")
        cls.account_file = account_files[0]

    def run_encryptor(self, *arguments: Path | str) -> None:
        command = [str(self.binary), *(str(argument) for argument in arguments)]
        completed = subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(
            completed.returncode,
            0,
            "Command failed:\n"
            f"{' '.join(command)}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )

    def assert_encrypted_file(self, source: Path, encrypted: Path) -> None:
        self.assertTrue(encrypted.is_file(), f"Missing encrypted file: {encrypted}")
        encrypted_bytes = encrypted.read_bytes()
        self.assertEqual(encrypted_bytes[:4], HEADER_MAGIC)
        self.assertEqual(encrypted.stat().st_size, source.stat().st_size + HEADER_SIZE)
        self.assertNotEqual(encrypted_bytes[HEADER_SIZE:], source.read_bytes())

    def test_encrypt_single_account_csv(self) -> None:
        """Encrypt account.csv to a single artifact in tests/output."""
        encrypted_file = OUTPUT_DIRECTORY / "account.csv.pfe"
        encrypted_file.unlink(missing_ok=True)
        original_bytes = self.account_file.read_bytes()

        self.run_encryptor(
            "encrypt",
            self.account_file,
            "--output",
            encrypted_file,
            "--password",
            PASSWORD,
            "--chunk-size",
            "64",
        )

        self.assert_encrypted_file(self.account_file, encrypted_file)
        self.assertEqual(self.account_file.read_bytes(), original_bytes)

    def test_encrypt_entire_input_directory(self) -> None:
        """Encrypt every source file after staging tests/input beneath tests/output."""
        staged_directory = OUTPUT_DIRECTORY / "directory-encryption"
        shutil.rmtree(staged_directory, ignore_errors=True)
        shutil.copytree(INPUT_DIRECTORY, staged_directory)

        source_files = [
            path for path in staged_directory.rglob("*") if path.is_file() and path.suffix != ".pfe"
        ]
        self.assertGreater(len(source_files), 0, "tests/input must contain files to encrypt")

        self.run_encryptor(
            "encrypt-dir",
            staged_directory,
            "--password",
            PASSWORD,
            "--chunk-size",
            "64",
        )

        for source_file in source_files:
            encrypted_file = source_file.with_name(f"{source_file.name}.pfe")
            with self.subTest(source=source_file.relative_to(staged_directory)):
                self.assert_encrypted_file(source_file, encrypted_file)


if __name__ == "__main__":
    unittest.main(verbosity=2)
