"""
test_isolation.py — Adversarial Isolation Tests (Fully Isolated in Temp Directories)
Executable via both `python -m unittest tests/test_isolation.py` and `pytest tests/`.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "skills" / "repo-push" / "scripts" / "enforce_isolation.py"


def run_isolation(cmd, reports_dir, trusted_dir):
    return subprocess.run(
        [
            sys.executable, str(SCRIPT), cmd,
            "--reports-dir", str(reports_dir),
            "--trusted-dir", str(trusted_dir)
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True
    )


class TestIsolation(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.reports_dir = self.base / "reports"
        self.trusted_dir = self.base / ".trusted"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.trusted_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        run_isolation("unlock", self.reports_dir, self.trusted_dir)
        try:
            self.tmp.cleanup()
        except Exception:
            pass

    def test_missing_snapshot_fails_closed(self):
        """Missing snapshot must fail closed with exit code 1."""
        res = run_isolation("verify", self.reports_dir, self.trusted_dir)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Verification failed", res.stderr)

    def test_corrupted_snapshot_fails_closed(self):
        """Corrupted JSON snapshot must fail closed with exit code 1."""
        manifest = self.trusted_dir / "reports_manifest.json"
        manifest.write_text("{ corrupt json: [", encoding="utf-8")

        res = run_isolation("verify", self.reports_dir, self.trusted_dir)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Verification failed", res.stderr)

    def test_forged_hmac_signature_fails_closed(self):
        """Forged or tampered HMAC signature in manifest must fail verification."""
        test_file = self.reports_dir / "report.md"
        test_file.write_text("# Report", encoding="utf-8")

        res_lock = run_isolation("lock", self.reports_dir, self.trusted_dir)
        self.assertEqual(res_lock.returncode, 0)

        # Tamper with the manifest file
        run_isolation("unlock", self.reports_dir, self.trusted_dir)
        manifest = self.trusted_dir / "reports_manifest.json"
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["hmac_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
        manifest.write_text(json.dumps(data), encoding="utf-8")

        res_verify = run_isolation("verify", self.reports_dir, self.trusted_dir)
        self.assertNotEqual(res_verify.returncode, 0)
        self.assertIn("signature verification FAILED", res_verify.stderr)

    def test_lock_and_pristine_verification(self):
        """Pristine reports after locking must pass verification."""
        test_report = self.reports_dir / "test_report.md"
        test_report.write_text("# Initial Report Content", encoding="utf-8")

        res_lock = run_isolation("lock", self.reports_dir, self.trusted_dir)
        self.assertEqual(res_lock.returncode, 0)

        res_verify = run_isolation("verify", self.reports_dir, self.trusted_dir)
        self.assertEqual(res_verify.returncode, 0)
        self.assertIn("Audit reports integrity confirmed", res_verify.stdout)

    def test_unauthorized_file_creation_fails(self):
        """Adding an unauthorized report must fail verification."""
        test_report = self.reports_dir / "test_report.md"
        test_report.write_text("# Initial", encoding="utf-8")

        res_lock = run_isolation("lock", self.reports_dir, self.trusted_dir)
        self.assertEqual(res_lock.returncode, 0)

        run_isolation("unlock", self.reports_dir, self.trusted_dir)
        injected = self.reports_dir / "injected.md"
        injected.write_text("# Injected", encoding="utf-8")

        res_verify = run_isolation("verify", self.reports_dir, self.trusted_dir)
        self.assertNotEqual(res_verify.returncode, 0)
        self.assertIn("UNAUTHORIZED FILE CREATION", res_verify.stderr)

    def test_verify_and_restore_rollback(self):
        """verify-and-restore must catch tampering and roll back to trusted backup."""
        test_file = self.reports_dir / "auditor_report.md"
        test_file.write_text("# Original Auditor Findings", encoding="utf-8")

        res_lock = run_isolation("lock", self.reports_dir, self.trusted_dir)
        self.assertEqual(res_lock.returncode, 0)

        # Inject an unauthorized file and edit original
        run_isolation("unlock", self.reports_dir, self.trusted_dir)
        injected = self.reports_dir / "fake_report.md"
        injected.write_text("# Malicious Report", encoding="utf-8")
        test_file.write_text("# Altered Content", encoding="utf-8")

        # Run verify-and-restore
        res_vr = run_isolation("verify-and-restore", self.reports_dir, self.trusted_dir)
        self.assertNotEqual(res_vr.returncode, 0)
        self.assertIn("Auto-restore enabled", res_vr.stderr)

        # Verify rollback restored the pristine original content and removed the injected file
        self.assertEqual(test_file.read_text(encoding="utf-8"), "# Original Auditor Findings")
        self.assertFalse(injected.exists())


if __name__ == "__main__":
    unittest.main()
