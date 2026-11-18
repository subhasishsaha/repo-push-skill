"""
test_git_publishing.py — Full Integration Tests for Isolated Worktree Publishing

Tests:
1. Rejection of unconfigured remotes and path traversal patterns.
2. Tag history leakage prevention in clean_snapshot mode.
3. Atomic concurrency locking (O_CREAT | O_EXCL).
4. End-to-end history-preserving publishing with exclusion verification against local bare remote.
5. End-to-end clean-snapshot publishing with orphan commit verification.
6. Guaranteed worktree cleanup on failure.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "skills" / "repo-push" / "scripts" / "git_publisher.py"


def run_cmd(args, cwd=None, check=True):
    res = subprocess.run(
        args,
        cwd=str(cwd) if cwd else str(REPO_ROOT),
        capture_output=True,
        text=True
    )
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {' '.join(args)}\nStderr: {res.stderr}")
    return res


class TestGitPublishingIntegration(unittest.TestCase):

    def test_invalid_remote_rejected(self):
        """Publishing to an unknown/unconfigured remote must fail."""
        res = run_cmd([sys.executable, str(SCRIPT), "--remote", "phantom_remote_xyz"], check=False)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("does not exist", res.stderr)

    def test_path_traversal_exclusion_rejected(self):
        """Exclusions with path traversal ('..') must be rejected upfront."""
        res = run_cmd([sys.executable, str(SCRIPT), "--remote", "origin", "--exclude", "../secret.txt"], check=False)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Dangerous exclusion pattern rejected", res.stderr)

    def test_clean_snapshot_forbids_tags(self):
        """Clean snapshot must reject --tags to prevent historical tag leakage."""
        res = run_cmd(
            [sys.executable, str(SCRIPT), "--remote", "origin", "--mode", "clean_snapshot", "--tags"],
            check=False
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("forbidden in 'clean_snapshot' mode", res.stderr)

    def test_atomic_concurrency_lock(self):
        """Second concurrent publisher must be rejected when lock is held."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("git_publisher", SCRIPT)
        pub_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pub_mod)
        PublishingLock = pub_mod.PublishingLock

        with tempfile.TemporaryDirectory() as td:
            lock_dir = Path(td) / ".audit" / ".trusted"
            lock_dir.mkdir(parents=True, exist_ok=True)
            lock_file = lock_dir / "publishing.lock"
            
            # Create active lock with current PID
            lock_file.write_text(f"{subprocess.os.getpid()}\n", encoding="utf-8")

            # Try to run publisher with this lock file
            with self.assertRaises(RuntimeError) as ctx:
                with PublishingLock(lock_file=str(lock_file)):
                    pass
            self.assertIn("Concurrent publishing operation detected", str(ctx.exception))

    def test_end_to_end_history_preserving_publishing(self):
        """Full integration test: publish to local bare remote with exclusions in history_preserving mode."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_repo = base / "src_repo"
            bare_remote = base / "bare_remote.git"
            clone_verify = base / "clone_verify"

            # 1. Initialize source repo
            src_repo.mkdir()
            run_cmd(["git", "init", "-b", "main"], cwd=src_repo)
            run_cmd(["git", "config", "user.name", "TestUser"], cwd=src_repo)
            run_cmd(["git", "config", "user.email", "test@example.com"], cwd=src_repo)

            (src_repo / "app.py").write_text("print('hello')", encoding="utf-8")
            (src_repo / "README.md").write_text("# Test Repo", encoding="utf-8")
            (src_repo / "internal_secrets.yaml").write_text("token: 123", encoding="utf-8")

            run_cmd(["git", "add", "."], cwd=src_repo)
            run_cmd(["git", "commit", "-m", "feat: initial commit"], cwd=src_repo)

            # 2. Initialize bare remote with default branch main
            run_cmd(["git", "init", "--bare", "-b", "main", str(bare_remote)])
            run_cmd(["git", "remote", "add", "origin", str(bare_remote)], cwd=src_repo)

            # 3. Execute publisher script in history_preserving mode with exclusion
            res_pub = run_cmd(
                [
                    sys.executable, str(SCRIPT),
                    "--remote", "origin",
                    "--branch", "main",
                    "--mode", "history_preserving",
                    "--exclude", "internal_secrets.yaml"
                ],
                cwd=src_repo
            )
            self.assertEqual(res_pub.returncode, 0)
            self.assertIn("Published to 'origin/main' successfully", res_pub.stdout)

            # 4. Clone from bare remote and verify published tree
            run_cmd(["git", "clone", "-b", "main", str(bare_remote), str(clone_verify)])
            self.assertTrue((clone_verify / "app.py").exists())
            self.assertTrue((clone_verify / "README.md").exists())
            self.assertFalse((clone_verify / "internal_secrets.yaml").exists(), "Excluded file must not exist in published tree!")

            # Verify commit count (initial commit + release commit = 2)
            rev_cnt = run_cmd(["git", "rev-list", "--count", "HEAD"], cwd=clone_verify).stdout.strip()
            self.assertEqual(rev_cnt, "2")

    def test_end_to_end_clean_snapshot_publishing(self):
        """Full integration test: publish single orphan snapshot commit with zero prior ancestry."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_repo = base / "src_repo"
            bare_remote = base / "bare_remote.git"
            clone_verify = base / "clone_verify"

            src_repo.mkdir()
            run_cmd(["git", "init", "-b", "main"], cwd=src_repo)
            run_cmd(["git", "config", "user.name", "TestUser"], cwd=src_repo)
            run_cmd(["git", "config", "user.email", "test@example.com"], cwd=src_repo)

            # Commit 1
            (src_repo / "file1.txt").write_text("v1", encoding="utf-8")
            run_cmd(["git", "add", "."], cwd=src_repo)
            run_cmd(["git", "commit", "-m", "commit 1"], cwd=src_repo)

            # Commit 2
            (src_repo / "file2.txt").write_text("v2", encoding="utf-8")
            (src_repo / "private_conf.json").write_text("{}", encoding="utf-8")
            run_cmd(["git", "add", "."], cwd=src_repo)
            run_cmd(["git", "commit", "-m", "commit 2"], cwd=src_repo)

            # Bare remote with default branch main
            run_cmd(["git", "init", "--bare", "-b", "main", str(bare_remote)])
            run_cmd(["git", "remote", "add", "origin", str(bare_remote)], cwd=src_repo)

            # Publish clean snapshot excluding private_conf.json
            res_pub = run_cmd(
                [
                    sys.executable, str(SCRIPT),
                    "--remote", "origin",
                    "--branch", "main",
                    "--mode", "clean_snapshot",
                    "--exclude", "private_conf.json"
                ],
                cwd=src_repo
            )
            self.assertEqual(res_pub.returncode, 0)

            # Clone and verify exactly 1 orphan commit
            run_cmd(["git", "clone", "-b", "main", str(bare_remote), str(clone_verify)])
            rev_cnt = run_cmd(["git", "rev-list", "--count", "HEAD"], cwd=clone_verify).stdout.strip()
            self.assertEqual(rev_cnt, "1", "clean_snapshot must publish exactly 1 orphan commit with no ancestry!")
            self.assertTrue((clone_verify / "file1.txt").exists())
            self.assertTrue((clone_verify / "file2.txt").exists())
            self.assertFalse((clone_verify / "private_conf.json").exists())

    def test_cleanup_after_ref_format_failure(self):
        """Invalid branch format must fail fast and leave zero dangling worktrees."""
        with tempfile.TemporaryDirectory() as td:
            src_repo = Path(td) / "src"
            src_repo.mkdir()
            run_cmd(["git", "init", "-b", "main"], cwd=src_repo)
            run_cmd(["git", "config", "user.name", "TestUser"], cwd=src_repo)
            run_cmd(["git", "config", "user.email", "test@example.com"], cwd=src_repo)
            (src_repo / "app.py").write_text("code", encoding="utf-8")
            run_cmd(["git", "add", "."], cwd=src_repo)
            run_cmd(["git", "commit", "-m", "init"], cwd=src_repo)

            # Attempt publish with invalid branch name '..'
            res = run_cmd(
                [sys.executable, str(SCRIPT), "--remote", "origin", "--branch", "..badref"],
                cwd=src_repo,
                check=False
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("violates ref-format rules", res.stderr)

            # Check that worktree list contains only the main worktree
            wt_list = run_cmd(["git", "worktree", "list"], cwd=src_repo).stdout.strip().splitlines()
            self.assertEqual(len(wt_list), 1)


if __name__ == "__main__":
    unittest.main()
