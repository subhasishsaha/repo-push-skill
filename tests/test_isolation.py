"""
test_isolation.py — Adversarial Isolation Tests
Executable via both `python -m unittest tests/test_isolation.py` and `pytest tests/`.
"""

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "skills" / "repo-push" / "scripts" / "enforce_isolation.py"


def run_isolation(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + list(args),
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True
    )


class TestIsolation(unittest.TestCase):

    def setUp(self):
        run_isolation("unlock")
        trusted_dir = REPO_ROOT / ".audit" / ".trusted"
        if trusted_dir.exists():
            shutil.rmtree(trusted_dir)

    def tearDown(self):
        run_isolation("unlock")

    def test_missing_snapshot_fails_closed(self):
        """Missing snapshot must fail closed with exit code 1."""
        res = run_isolation("verify")
        self.assertNotEqual(res.returncode, 0)
        self.assertTrue("Verification failed" in res.stderr or "missing" in res.stderr.lower())

    def test_corrupted_snapshot_fails_closed(self):
        """Corrupted JSON snapshot must fail closed with exit code 1."""
        trusted_dir = REPO_ROOT / ".audit" / ".trusted"
        trusted_dir.mkdir(parents=True, exist_ok=True)
        manifest = trusted_dir / "reports_manifest.json"
        manifest.write_text("{ corrupt json: [", encoding="utf-8")

        res = run_isolation("verify")
        self.assertNotEqual(res.returncode, 0)
        self.assertTrue("Corrupted JSON" in res.stderr or "failed" in res.stderr.lower())

    def test_lock_and_pristine_verification(self):
        """Pristine reports after locking must pass verification."""
        reports_dir = REPO_ROOT / ".audit" / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        test_report = reports_dir / "test_report.md"
        test_report.write_text("# Initial Report Content", encoding="utf-8")

        res_lock = run_isolation("lock")
        self.assertEqual(res_lock.returncode, 0)

        res_verify = run_isolation("verify")
        self.assertEqual(res_verify.returncode, 0)
        self.assertIn("Audit reports integrity confirmed", res_verify.stdout)

        run_isolation("unlock")
        if test_report.exists():
            test_report.unlink()

    def test_unauthorized_file_creation_fails(self):
        """Adding an unauthorized report must fail verification."""
        res_lock = run_isolation("lock")
        self.assertEqual(res_lock.returncode, 0)

        reports_dir = REPO_ROOT / ".audit" / "reports"
        injected_file = reports_dir / "injected_tamper.md"
        injected_file.write_text("# Injected", encoding="utf-8")

        res_verify = run_isolation("verify")
        self.assertNotEqual(res_verify.returncode, 0)
        self.assertIn("UNAUTHORIZED FILE CREATION", res_verify.stderr)

        run_isolation("unlock")
        if injected_file.exists():
            injected_file.unlink()

    def test_verify_and_restore_rollback(self):
        """verify-and-restore must catch tampering and roll back to trusted backup."""
        reports_dir = REPO_ROOT / ".audit" / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        test_file = reports_dir / "auditor_report.md"
        test_file.write_text("# Original Auditor Findings", encoding="utf-8")

        res_lock = run_isolation("lock")
        self.assertEqual(res_lock.returncode, 0)

        # Inject unauthorized file
        injected = reports_dir / "malicious_file.md"
        injected.write_text("# Malicious Bypass", encoding="utf-8")

        res_restore = run_isolation("verify-and-restore")
        self.assertNotEqual(res_restore.returncode, 0)
        self.assertFalse(injected.exists())


if __name__ == "__main__":
    unittest.main()
