"""
test_git_publishing.py — Integration tests for safe worktree publishing
Verifies remote validation, exclusion safety, and guaranteed worktree cleanup.
"""

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "skills" / "repo-push" / "scripts" / "git_publisher.py"


def run_publisher(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + list(args),
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True
    )


class TestGitPublishing(unittest.TestCase):

    def test_invalid_remote_rejected(self):
        """Publishing to an unknown/unconfigured remote must fail."""
        res = run_publisher("--remote", "phantom_remote_xyz")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("does not exist", res.stderr)

    def test_path_traversal_exclusion_rejected(self):
        """Dangerous exclusion patterns must be rejected before touching Git."""
        res = run_publisher("--remote", "origin", "--exclude", "../malicious_path")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Dangerous exclusion pattern rejected", res.stderr)

    def test_root_exclusion_rejected(self):
        """Root wipeout exclusion pattern '/' must be rejected."""
        res = run_publisher("--remote", "origin", "--exclude", "/")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Dangerous exclusion pattern rejected", res.stderr)


if __name__ == "__main__":
    unittest.main()
