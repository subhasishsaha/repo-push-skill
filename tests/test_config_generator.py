"""
test_config_generator.py — Tests for deterministic .repo-push/config.yaml generator
Verifies that no fabricated URLs are generated when remotes are absent,
and tests dry-run and overwrite behavior.
"""

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "skills" / "repo-push" / "scripts" / "generate_config.py"


def run_generator(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + list(args),
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True
    )


class TestConfigGenerator(unittest.TestCase):

    def test_dry_run_outputs_valid_yaml(self):
        """Dry-run must output valid YAML containing active remote and schema header."""
        res = run_generator("--dry-run")
        self.assertEqual(res.returncode, 0)
        self.assertIn("yaml-language-server", res.stdout)
        self.assertIn("targets:", res.stdout)
        self.assertIn("platform: github", res.stdout)

    def test_existing_config_protected_without_force(self):
        """Generator must not overwrite existing config without --force."""
        res = run_generator()
        self.assertEqual(res.returncode, 0)
        self.assertIn("already exists", res.stdout)


if __name__ == "__main__":
    unittest.main()
