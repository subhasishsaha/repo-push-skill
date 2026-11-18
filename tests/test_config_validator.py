"""
test_config_validator.py — Adversarial Configuration Validator Tests
Tests JSON Schema compliance, cross-validation, and path traversal rejection.
"""

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "skills" / "repo-push" / "scripts" / "validate_config.py"


def run_validator(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + list(args),
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True
    )


class TestConfigValidator(unittest.TestCase):

    def test_canonical_repo_config_passes(self):
        """Current repository config must pass validation."""
        res = run_validator()
        self.assertEqual(res.returncode, 0)
        self.assertIn("[PASS]", res.stdout)

    def test_missing_config_fails(self):
        """Non-existent config path must fail."""
        res = run_validator("non_existent_config.yaml")
        self.assertNotEqual(res.returncode, 0)

    def test_duplicate_target_names_fail(self):
        """Duplicate target names must be rejected."""
        temp_cfg = REPO_ROOT / ".test_dup_targets.yaml"
        temp_cfg.write_text(
            'version: "1.0"\n'
            'targets:\n'
            '  - name: origin\n'
            '    platform: github\n'
            '    url: https://github.com/org/repo.git\n'
            '  - name: origin\n'
            '    platform: gitlab\n'
            '    url: https://gitlab.com/org/repo.git\n',
            encoding="utf-8"
        )
        try:
            res = run_validator(str(temp_cfg))
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Duplicate target name", res.stdout)
        finally:
            if temp_cfg.exists():
                temp_cfg.unlink()

    def test_path_traversal_in_exclusions_rejected(self):
        """Path traversal '..' in exclusions must be rejected."""
        temp_cfg = REPO_ROOT / ".test_traversal.yaml"
        temp_cfg.write_text(
            'version: "1.0"\n'
            'targets:\n'
            '  - name: origin\n'
            '    platform: github\n'
            '    url: https://github.com/org/repo.git\n'
            '    exclude:\n'
            '      - ../secret_file\n',
            encoding="utf-8"
        )
        try:
            res = run_validator(str(temp_cfg))
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Path traversal", res.stdout)
        finally:
            if temp_cfg.exists():
                temp_cfg.unlink()

    def test_invalid_git_url_rejected(self):
        """Malformed or non-Git URLs must be rejected."""
        temp_cfg = REPO_ROOT / ".test_bad_url.yaml"
        temp_cfg.write_text(
            'version: "1.0"\n'
            'targets:\n'
            '  - name: origin\n'
            '    platform: github\n'
            '    url: ftp://invalid-protocol.com/repo\n',
            encoding="utf-8"
        )
        try:
            res = run_validator(str(temp_cfg))
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("not a valid Git URL format", res.stdout)
        finally:
            if temp_cfg.exists():
                temp_cfg.unlink()


if __name__ == "__main__":
    unittest.main()
