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


def run_isolation(cmd, reports_dir, trusted_dir, cwd=None):
    return subprocess.run(
        [
            sys.executable, str(SCRIPT), cmd,
            "--reports-dir", str(reports_dir),
            "--trusted-dir", str(trusted_dir)
        ],
        cwd=str(cwd) if cwd else str(REPO_ROOT),
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

    def test_tampered_backup_aborts_restoration(self):
        """If files inside the backup directory are tampered with, restoration must abort."""
        test_file = self.reports_dir / "auditor_report.md"
        test_file.write_text("# Original Auditor Findings", encoding="utf-8")

        res_lock = run_isolation("lock", self.reports_dir, self.trusted_dir)
        self.assertEqual(res_lock.returncode, 0)

        # Unlock and tamper with the backup directory
        run_isolation("unlock", self.reports_dir, self.trusted_dir)
        backup_file = self.trusted_dir / "reports_backup" / "auditor_report.md"
        backup_file.write_text("# Corrupted Backup Content", encoding="utf-8")

        # Now try to restore
        res_restore = run_isolation("restore", self.reports_dir, self.trusted_dir)
        self.assertNotEqual(res_restore.returncode, 0)
        self.assertIn("Backup verification failed", res_restore.stderr)

    def test_corrupted_key_fails_closed(self):
        """A key file containing fewer than 32 bytes (including zero bytes) must be rejected as corrupted."""
        import importlib.util
        import hashlib
        spec = importlib.util.spec_from_file_location("enforce_isolation", SCRIPT)
        iso_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(iso_mod)

        # Sub-test 1: 16-byte corrupted key
        with tempfile.TemporaryDirectory() as td:
            root_hash = hashlib.sha256(os.path.abspath(td).encode("utf-8")).hexdigest()[:16]
            key_dir = iso_mod.get_key_dir()
            key_file = key_dir / f".repo_push_key_{root_hash}.secret"
            key_file.write_bytes(b"0123456789abcdef")
            if os.name != "nt":
                try:
                    os.chmod(str(key_file), 0o600)
                except Exception:
                    pass
            try:
                with self.assertRaises(RuntimeError) as ctx:
                    iso_mod.get_session_hmac_key(repo_root=td)
                self.assertIn("Corrupted HMAC session key", str(ctx.exception))
            finally:
                if key_file.exists():
                    try:
                        key_file.unlink()
                    except Exception:
                        pass

        # Sub-test 2: 0-byte empty corrupted key
        with tempfile.TemporaryDirectory() as td:
            root_hash = hashlib.sha256(os.path.abspath(td).encode("utf-8")).hexdigest()[:16]
            key_dir = iso_mod.get_key_dir()
            key_file = key_dir / f".repo_push_key_{root_hash}.secret"
            key_file.write_bytes(b"")
            if os.name != "nt":
                try:
                    os.chmod(str(key_file), 0o600)
                except Exception:
                    pass
            try:
                with self.assertRaises(RuntimeError) as ctx:
                    iso_mod.get_session_hmac_key(repo_root=td)
                self.assertIn("Corrupted HMAC session key", str(ctx.exception))
            finally:
                if key_file.exists():
                    try:
                        key_file.unlink()
                    except Exception:
                        pass

    def test_atomic_key_persistence_and_readback(self):
        """Key generation must create exactly 32 bytes and return identical key on subsequent calls."""
        import importlib.util
        import hashlib
        spec = importlib.util.spec_from_file_location("enforce_isolation", SCRIPT)
        iso_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(iso_mod)

        with tempfile.TemporaryDirectory() as td:
            root_hash = hashlib.sha256(os.path.abspath(td).encode("utf-8")).hexdigest()[:16]
            key_dir = iso_mod.get_key_dir()
            key_file = key_dir / f".repo_push_key_{root_hash}.secret"
            try:
                key1 = iso_mod.get_session_hmac_key(repo_root=td)
                self.assertEqual(len(key1), 32)
                self.assertTrue(key_file.exists())
                self.assertEqual(len(key_file.read_bytes()), 32)

                # Subsequent call must read identical key
                key2 = iso_mod.get_session_hmac_key(repo_root=td)
                self.assertEqual(key1, key2)
            finally:
                if key_file.exists():
                    try:
                        key_file.unlink()
                    except Exception:
                        pass

    def test_refuse_to_adopt_symlink_key(self):
        """Pre-created symlink at key_file path must be rejected, and fallback key must persist across calls and processes."""
        import importlib.util
        import hashlib
        spec = importlib.util.spec_from_file_location("enforce_isolation", SCRIPT)
        iso_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(iso_mod)

        with tempfile.TemporaryDirectory() as td:
            repo_path = Path(td)
            root_hash = hashlib.sha256(os.path.abspath(td).encode("utf-8")).hexdigest()[:16]
            key_dir = iso_mod.get_key_dir()
            primary_key_file = key_dir / f".repo_push_key_{root_hash}.secret"
            target_decoy = key_dir / f".decoy_target_{root_hash}.txt"
            target_decoy.write_bytes(b"A" * 32)

            reports_dir = repo_path / "reports"
            trusted_dir = repo_path / ".trusted"
            reports_dir.mkdir(parents=True, exist_ok=True)
            trusted_dir.mkdir(parents=True, exist_ok=True)
            (reports_dir / "audit_report.md").write_text("# Report", encoding="utf-8")

            try:
                # Try to create symlink (may require admin on Windows; if os.symlink fails, skip symlink test)
                try:
                    os.symlink(str(target_decoy), str(primary_key_file))
                except OSError:
                    self.skipTest("Symlink creation not permitted in this environment")

                # 1. get_session_hmac_key must NOT adopt the symlinked file's key
                key1 = iso_mod.get_session_hmac_key(repo_root=td)
                self.assertEqual(len(key1), 32)
                self.assertNotEqual(key1, b"A" * 32)

                # 2. Second invocation must return the exact same persisted key
                key2 = iso_mod.get_session_hmac_key(repo_root=td)
                self.assertEqual(key1, key2)

                # 3. Snapshot creation and verification across separate process invocations must succeed
                res_lock = run_isolation("lock", reports_dir, trusted_dir, cwd=td)
                self.assertEqual(res_lock.returncode, 0, f"Lock failed: {res_lock.stderr}")

                res_verify = run_isolation("verify", reports_dir, trusted_dir, cwd=td)
                self.assertEqual(res_verify.returncode, 0, f"Verify failed: {res_verify.stderr}")
                self.assertIn("Audit reports integrity confirmed", res_verify.stdout)
            finally:
                if primary_key_file.exists() or primary_key_file.is_symlink():
                    try:
                        primary_key_file.unlink()
                    except Exception:
                        pass
                if target_decoy.exists():
                    try:
                        target_decoy.unlink()
                    except Exception:
                        pass
                alt_dir = key_dir / ".fallback_keys"
                alt_key = alt_dir / f".repo_push_key_{root_hash}.secret"
                if alt_key.exists():
                    try:
                        alt_key.unlink()
                    except Exception:
                        pass

    def test_strictly_enforce_key_dir_permissions(self):
        """Directories with permissive permissions (mode & 0o077 != 0) must be rejected on POSIX."""
        if os.name == "nt":
            self.skipTest("POSIX file permission bits not applicable on Windows")

        import importlib.util
        spec = importlib.util.spec_from_file_location("enforce_isolation", SCRIPT)
        iso_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(iso_mod)

        with tempfile.TemporaryDirectory() as td:
            permissive_dir = Path(td) / "permissive_keys"
            permissive_dir.mkdir(mode=0o777, exist_ok=True)
            os.chmod(str(permissive_dir), 0o777)
            # Simulate a filesystem or environment where chmod cannot enforce 0700
            orig_chmod = os.chmod
            try:
                def fake_chmod(path, mode):
                    if str(path) == str(permissive_dir):
                        return  # Ignore chmod to keep permissive
                    return orig_chmod(path, mode)
                os.chmod = fake_chmod
                self.assertFalse(iso_mod.verify_and_prepare_key_dir(permissive_dir))
            finally:
                os.chmod = orig_chmod

    def test_windows_dacl_enforcement(self):
        """Windows DACL verification must reject broad principals (Everyone, Users), arbitrary user SIDs, and accept restricted DACL."""
        if os.name != "nt":
            self.skipTest("Windows DACL enforcement test only runs on Windows (nt)")

        import importlib.util
        import subprocess
        spec = importlib.util.spec_from_file_location("enforce_isolation", SCRIPT)
        iso_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(iso_mod)

        # Verify current user SID resolution
        user_sid, context_sids = iso_mod._get_current_user_and_context_sids_windows()
        self.assertIsNotNone(user_sid)
        self.assertTrue(user_sid.startswith("S-1-"))
        self.assertIn(user_sid, context_sids)

        with tempfile.TemporaryDirectory() as td:
            test_dir = Path(td) / "sec_keys"
            test_dir.mkdir(parents=True, exist_ok=True)
            test_file = test_dir / "test.secret"
            test_file.write_bytes(b"A" * 32)

            try:
                # 1. Enforce strict DACL on directory and file
                self.assertTrue(iso_mod.enforce_windows_dacl(test_dir, is_dir=True))
                self.assertTrue(iso_mod.enforce_windows_dacl(test_file, is_dir=False))
                self.assertTrue(iso_mod.verify_windows_dacl(test_dir))
                self.assertTrue(iso_mod.verify_windows_dacl(test_file))

                # 2. Grant Everyone:(R) to test file - must be rejected by verify_windows_dacl
                res = subprocess.run(["icacls", str(test_file), "/grant", "Everyone:(R)"], capture_output=True, text=True)
                if res.returncode == 0:
                    self.assertFalse(iso_mod.verify_windows_dacl(test_file))

                # 3. Grant Users:(R) to test directory - must be rejected by verify_windows_dacl
                res = subprocess.run(["icacls", str(test_dir), "/grant", "Users:(R)"], capture_output=True, text=True)
                if res.returncode == 0:
                    self.assertFalse(iso_mod.verify_windows_dacl(test_dir))

                # 4. Granting another user-specific SID (e.g. docker-users with S-1-5-21-... SID) must be rejected
                res = subprocess.run(["icacls", str(test_file), "/grant", "docker-users:(R)"], capture_output=True, text=True)
                if res.returncode == 0:
                    self.assertFalse(iso_mod.verify_windows_dacl(test_file))

                # 5. Re-enforcing strict DACL must restore verified status
                self.assertTrue(iso_mod.enforce_windows_dacl(test_dir, is_dir=True))
                self.assertTrue(iso_mod.enforce_windows_dacl(test_file, is_dir=False))
                self.assertTrue(iso_mod.verify_windows_dacl(test_dir))
                self.assertTrue(iso_mod.verify_windows_dacl(test_file))
            finally:
                subprocess.run(["icacls", str(test_dir), "/reset", "/T"], capture_output=True)


if __name__ == "__main__":
    unittest.main()
