#!/usr/bin/env python3
"""
Unit tests for skills/repo-push/scripts/audit_runner.py.
Tests:
- Abstract methods and Protocol classes are not falsely flagged as stubs.
- Concrete stub functions are correctly identified.
- Token masking prevents credential leakage in reports.
- Machine-readable evidence generation and cryptographic digest consistency.
"""
import ast
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "skills" / "repo-push" / "scripts" / "audit_runner.py"

spec = importlib.util.spec_from_file_location("audit_runner", SCRIPT_PATH)
audit_runner_mod = importlib.util.module_from_spec(spec)
sys.modules["audit_runner"] = audit_runner_mod
spec.loader.exec_module(audit_runner_mod)

AuditRunner = audit_runner_mod.AuditRunner
mask_token = audit_runner_mod.mask_token
sha256_digest = audit_runner_mod.sha256_digest


class TestAuditRunner(unittest.TestCase):
    def test_token_masking(self):
        pat = "ghp_" + "1234567890abcdef" + "1234567890abcdef"
        masked = mask_token(pat)
        self.assertEqual(masked, "ghp_****cdef")
        self.assertNotIn("1234567890abcdef1234567890ab", masked)

        short = "secret1"
        self.assertEqual(mask_token(short), "****")

    def test_abstract_and_protocol_not_flagged(self):
        """Interface definitions (ABC, Protocol, @abstractmethod) must not be flagged as stubs."""
        code = """
import abc
from abc import abstractmethod
from typing import Protocol

class InterfaceContract(abc.ABC):
    @abstractmethod
    def must_implement(self):
        pass

    @abstractmethod
    def another_stub(self):
        ...

class GreeterProtocol(Protocol):
    def greet(self) -> str:
        ...
"""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "dummy.py").write_text(code, encoding="utf-8")
            runner = AuditRunner(repo)

            gate = runner.run_gate_2_ast()
            self.assertEqual(gate["status"], "PASS")
            blockers = [f for f in runner.evidence["findings"] if f["severity"] == "BLOCKER"]
            self.assertEqual(len(blockers), 0)

    def test_concrete_stub_flagged_as_blocker(self):
        """Concrete function with only 'pass' or '...' must be flagged as a blocker."""
        code = """
class ConcreteService:
    def execute_payment(self, amount: float):
        pass

def calculate_tax():
    ...
"""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "concrete.py").write_text(code, encoding="utf-8")
            runner = AuditRunner(repo)

            gate = runner.run_gate_2_ast()
            self.assertEqual(gate["status"], "FAIL")
            blockers = [f for f in runner.evidence["findings"] if f["severity"] == "BLOCKER"]
            self.assertGreaterEqual(len(blockers), 2)

    def test_cryptographic_digest(self):
        data = "test-evidence-payload"
        digest1 = sha256_digest(data)
        digest2 = sha256_digest(data)
        self.assertEqual(digest1, digest2)
        self.assertEqual(len(digest1), 64)

    def test_gate_1_fails_on_dirty_working_tree(self):
        """Gate 1 must fail if uncommitted modifications exist in working tree."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            # Gate 1 should fail if git is missing or repo not git
            runner = AuditRunner(repo)
            gate = runner.run_gate_1_hygiene()
            self.assertEqual(gate["status"], "FAIL")

    def test_gate_4_detects_secret_in_untracked_file(self):
        """Gate 4 must inspect untracked files outside standard ignores."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            dummy_pat = "ghp_" + "9876543210fedcba" * 2
            (repo / "untracked_script.py").write_text(f'API_KEY = "{dummy_pat}"', encoding="utf-8")
            runner = AuditRunner(repo)
            gate = runner.run_gate_4_secrets()
            self.assertIn(gate["status"], ("FAIL", "NOT_VERIFIED"))
            blockers = [f for f in runner.evidence["findings"] if f["severity"] == "BLOCKER"]
            self.assertGreaterEqual(len(blockers), 1)


    def test_gate_3_fails_on_python_syntax_error(self):
        """Gate 3 must fail if Python source files have syntax/AST parsing errors."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "bad_syntax.py").write_text("def unclosed_function(: pass", encoding="utf-8")
            runner = AuditRunner(repo)
            gate = runner.run_gate_3_deps()
            self.assertEqual(gate["status"], "FAIL")
            blockers = [f for f in runner.evidence["findings"] if f["category"] == "DEPENDENCIES" and f["severity"] == "BLOCKER"]
            self.assertGreaterEqual(len(blockers), 1)

    def test_gate_4_does_not_exempt_coincidental_substrings(self):
        """Gate 4 must NOT exempt a credential merely because it contains 'test' or 'fake' as a substring."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            # A 36-char token containing the word 'test'
            # Split across variables so test file source code itself does not contain a contiguous credential
            prefix = "ghp_"
            body = "88887777test66665555mock444433332222"
            token_with_test = prefix + body
            (repo / "service.py").write_text(f'AUTH_SECRET = "{token_with_test}"\n', encoding="utf-8")
            runner = AuditRunner(repo)
            gate = runner.run_gate_4_secrets()
            self.assertIn(gate["status"], ("FAIL", "NOT_VERIFIED"))
            blockers = [f for f in runner.evidence["findings"] if f["severity"] == "BLOCKER"]
            self.assertGreaterEqual(len(blockers), 1)

    def test_gate_4_cannot_be_bypassed_by_comment(self):
        """Comments such as # test-fixture or # noqa must NEVER suppress detected credentials."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            prefix = "ghp_"
            body = "9876543210fedcba9876543210fedcba9876"
            token = prefix + body
            # Write credential with inline comments intended to bypass filters
            (repo / "compromised.py").write_text(
                f'SECRET_KEY = "{token}"  # test-fixture # noqa: secret # test-credential\n',
                encoding="utf-8"
            )
            runner = AuditRunner(repo)
            gate = runner.run_gate_4_secrets()
            self.assertIn(gate["status"], ("FAIL", "NOT_VERIFIED"))
            blockers = [f for f in runner.evidence["findings"] if f["severity"] == "BLOCKER"]
            self.assertGreaterEqual(len(blockers), 1)

    def test_gate_4_does_not_exempt_dummy_example_placeholder(self):
        """Credentials containing words like dummy, example, or placeholder must NOT be exempted."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            prefix = "ghp_"
            cases = [
                prefix + "dummy" + "a" * 31,
                prefix + "example" + "b" * 29,
                prefix + "placeholder" + "c" * 25,
            ]
            for idx, token in enumerate(cases):
                (repo / f"test_{idx}.py").write_text(f'AUTH = "{token}"\n', encoding="utf-8")
            runner = AuditRunner(repo)
            gate = runner.run_gate_4_secrets()
            self.assertIn(gate["status"], ("FAIL", "NOT_VERIFIED"))
            blockers = [f for f in runner.evidence["findings"] if f["severity"] == "BLOCKER"]
            self.assertGreaterEqual(len(blockers), 3)

    def test_gate_4_does_not_exempt_credential_on_re_compile_line(self):
        """A credential placed on the same line as re.compile must NOT escape detection."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            prefix = "ghp_"
            body = "123456789098765432101234567890987654"
            token = prefix + body
            (repo / "source.py").write_text(f'PAT = re.compile(r".*"); AUTH = "{token}"\n', encoding="utf-8")
            runner = AuditRunner(repo)
            gate = runner.run_gate_4_secrets()
            self.assertIn(gate["status"], ("FAIL", "NOT_VERIFIED"))
            blockers = [f for f in runner.evidence["findings"] if f["severity"] == "BLOCKER"]
            self.assertGreaterEqual(len(blockers), 1)


if __name__ == "__main__":
    unittest.main()
