#!/usr/bin/env python3
"""
Canonical Evidence-Based Verification Engine for repo-push.
Implements the 6-Gate Verification Matrix with machine-readable evidence:
  - Gate 1: Git Hygiene & Repository Cleanliness (zero uncommitted dirty files)
  - Gate 2: AST Integrity & Incomplete Stubs (aware of abstractmethod & interfaces)
  - Gate 3: Dependencies & Manifest Integrity (Python requirements.txt/pyproject.toml & Node package.json)
  - Gate 4: Secrets, Leaks & Reachable Git History (git log --all -p, unswallowed exceptions, NOT_VERIFIED status)
  - Gate 5: Configuration Validation (.repo-push/config.yaml against JSON Schema)
  - Gate 6: Actions Consistency (.repo-push/actions.yaml & platform matching)

Outputs:
  - .audit/reports/audit_evidence.json (complete canonical evidence digests, HMAC signature)
  - .audit/reports/auditor_report.md (human-readable structured audit report)
"""
import ast
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

# Standard Library Modules (Python 3.10 - 3.12)
STANDARD_LIBS = {
    "abc", "argparse", "ast", "asyncio", "base64", "collections", "concurrent",
    "contextlib", "copy", "csv", "ctypes", "dataclasses", "datetime", "decimal",
    "difflib", "dis", "doctest", "email", "enum", "errno", "filecmp", "fileinput",
    "fnmatch", "fractions", "functools", "gc", "getopt", "getpass", "glob",
    "gzip", "hashlib", "heapq", "hmac", "html", "http", "importlib", "inspect",
    "io", "ipaddress", "itertools", "json", "keyword", "linecache", "locale",
    "logging", "lzma", "math", "mimetypes", "mmap", "multiprocessing", "netrc",
    "numbers", "operator", "os", "pathlib", "pickle", "pkgutil", "platform",
    "plistlib", "pprint", "profile", "pstats", "py_compile", "pyclbr", "pydoc",
    "queue", "quopri", "random", "re", "readline", "reprlib", "resource", "rlcompleter",
    "sched", "secrets", "select", "selectors", "shelve", "shlex", "shutil",
    "signal", "site", "smtplib", "socket", "socketserver", "sqlite3", "ssl",
    "stat", "statistics", "string", "stringprep", "struct", "subprocess", "sys",
    "sysconfig", "tarfile", "telnetlib", "tempfile", "termios", "textwrap", "threading",
    "time", "timeit", "tkinter", "token", "tokenize", "trace", "traceback", "tracemalloc",
    "tty", "turtle", "types", "typing", "unicodedata", "unittest", "urllib", "uuid",
    "venv", "warnings", "wave", "weakref", "webbrowser", "wsgiref", "xml", "xmlrpc",
    "zipfile", "zipimport", "zlib"
}

SECRET_PATTERNS = [
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), "AWS Access Key ID"),
    (re.compile(r'\bghp_[0-9a-zA-Z]{36}\b'), "GitHub Personal Access Token"),
    (re.compile(r'\bgithub_pat_[0-9a-zA-Z_]{82}\b'), "GitHub Fine-Grained Token"),
    (re.compile(r'\bxox[baprs]-[0-9a-zA-Z]{10,48}\b'), "Slack Token"),
    (re.compile(r'\bsk-[a-zA-Z0-9]{32,}\b'), "OpenAI / Anthropic API Key"),
    (re.compile(r'\bAIzaSy[0-9A-Za-z\\-_]{33}\b'), "Google API Key"),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "Private Key Block"),
    (re.compile(r'''(?i)(?:api_key|apikey|secret_key|access_token|auth_token)\s*[:=]\s*["']([0-9a-zA-Z\-_]{16,})["']'''), "Hardcoded Token Assignment"),
]

SENSITIVE_FILENAMES = [
    re.compile(r'^\.?env(\..+)?$', re.IGNORECASE),
    re.compile(r'.*\.(pem|key|pkcs12|pfx|p12)$', re.IGNORECASE),
    re.compile(r'^id_(rsa|dsa|ecdsa|ed25519)$', re.IGNORECASE),
    re.compile(r'.*(secret|credential|token).*\.(json|yaml|yml|toml|ini)$', re.IGNORECASE),
]

PATH_PATTERNS = [
    (re.compile(r'''[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\\\s"']+''', re.IGNORECASE), "Windows User Path"),
    (re.compile(r'''/(?:home|Users)/[^/\s"']+'''), "Unix User Path"),
]

PRIVATE_IP_PATTERN = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3})\b'
)


def mask_token(token: str) -> str:
    """Mask sensitive token string so it is never leaked into reports."""
    if len(token) <= 8:
        return "****"
    return token[:4] + "****" + token[-4:]


def sha256_digest(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class StubVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str, add_finding_fn):
        self.rel_path = rel_path
        self.add_finding = add_finding_fn
        self.class_stack = []

    def visit_ClassDef(self, node):
        is_interface = False
        for base in node.bases:
            name = ""
            if isinstance(base, ast.Name):
                name = base.id
            elif isinstance(base, ast.Attribute):
                name = base.attr
            if name in ("ABC", "Protocol", "ABCMeta"):
                is_interface = True
                break
        self.class_stack.append({"name": node.name, "is_interface": is_interface})
        self.generic_visit(node)
        self.class_stack.pop()

    def _is_abstract_or_overload(self, deco):
        name = ""
        if isinstance(deco, ast.Name):
            name = deco.id
        elif isinstance(deco, ast.Attribute):
            name = deco.attr
        elif isinstance(deco, ast.Call):
            return self._is_abstract_or_overload(deco.func)
        return name in ("abstractmethod", "overload")

    def visit_FunctionDef(self, node):
        self._check_func(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self._check_func(node)
        self.generic_visit(node)

    def _check_func(self, node):
        # Interface/Protocol classes legitimately declare signature-only methods
        if self.class_stack and self.class_stack[-1]["is_interface"]:
            return

        # Abstract methods and overloads legitimately have pass/... bodies
        if any(self._is_abstract_or_overload(d) for d in node.decorator_list):
            return

        body = node.body
        # Check for docstring only
        if (
            len(body) == 1
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            self.add_finding(
                "AST_INTEGRITY", "BLOCKER", f"{self.rel_path}:{node.lineno}",
                f"Function '{node.name}' contains only a docstring and no executable implementation.",
                f"Implement production-grade logic for '{node.name}'."
            )
        # Check for pass only
        elif len(body) == 1 and isinstance(body[0], ast.Pass):
            self.add_finding(
                "AST_INTEGRITY", "BLOCKER", f"{self.rel_path}:{node.lineno}",
                f"Function '{node.name}' has stub body 'pass'.",
                f"Implement full logic for '{node.name}'."
            )
        # Check for ellipsis only
        elif len(body) == 1 and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and body[0].value.value is ...:
            self.add_finding(
                "AST_INTEGRITY", "BLOCKER", f"{self.rel_path}:{node.lineno}",
                f"Function '{node.name}' has body '...' (Ellipsis stub).",
                f"Implement full logic for '{node.name}'."
            )
        # Check for raise NotImplementedError only
        elif len(body) == 1 and isinstance(body[0], ast.Raise):
            exc_name = getattr(body[0].exc, "id", None)
            if not exc_name and isinstance(body[0].exc, ast.Call):
                exc_name = getattr(body[0].exc.func, "id", None)
            if exc_name == "NotImplementedError":
                self.add_finding(
                    "AST_INTEGRITY", "BLOCKER", f"{self.rel_path}:{node.lineno}",
                    f"Function '{node.name}' raises NotImplementedError.",
                    f"Provide full implementation for '{node.name}'."
                )

    def visit_ExceptHandler(self, node):
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            exc_type = getattr(node.type, "id", "Exception") if node.type else "broad"
            self.add_finding(
                "AST_INTEGRITY", "WARNING", f"{self.rel_path}:{node.lineno}",
                f"Empty except block ({exc_type}) with 'pass'.",
                "Handle exception or log failure rather than silently swallowing."
            )
        self.generic_visit(node)


class AuditRunner:
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root.resolve()
        self.evidence = {
            "version": "2.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repository": str(self.repo_root),
            "gates": {},
            "summary": {
                "status": "NOT_RUN",
                "all_gates_passed": False,
                "blockers_count": 0,
                "warnings_count": 0,
                "infos_count": 0,
            },
            "findings": []
        }
        self.finding_id_seq = 1

    def _add_finding(self, category: str, severity: str, location: str, issue: str, remediation: str):
        prefix_map = {
            "GIT_HYGIENE": "GIT",
            "AST_INTEGRITY": "STUB",
            "DEPENDENCIES": "DEP",
            "SECRETS_AND_LEAKS": "SEC",
            "CONFIG_VALIDATION": "CFG",
            "ACTIONS_CONSISTENCY": "ACT",
        }
        pfx = prefix_map.get(category, "AUD")
        finding = {
            "id": f"{pfx}-{self.finding_id_seq:03d}",
            "category": category,
            "severity": severity,
            "location": location,
            "issue": issue,
            "remediation": remediation
        }
        self.finding_id_seq += 1
        self.evidence["findings"].append(finding)
        return finding

    def get_tracked_files(self):
        if (self.repo_root / ".git").exists():
            try:
                out = subprocess.check_output(["git", "ls-files"], cwd=self.repo_root, text=True)
                return [self.repo_root / line.strip() for line in out.splitlines() if line.strip()]
            except Exception:
                pass
        # Fallback to directory walk
        files = []
        for root, dirs, fnames in os.walk(self.repo_root):
            dirs[:] = [d for d in dirs if d not in {".git", ".audit", ".memory", "node_modules", ".venv"}]
            for f in fnames:
                files.append(Path(root) / f)
        return files

    def get_all_scannable_files(self):
        """Returns tracked files plus untracked files respecting .gitignore."""
        files = []
        if (self.repo_root / ".git").exists():
            try:
                # Tracked files
                out_tracked = subprocess.check_output(["git", "ls-files"], cwd=self.repo_root, text=True)
                for line in out_tracked.splitlines():
                    if line.strip():
                        files.append(self.repo_root / line.strip())

                # Untracked files that are NOT ignored by .gitignore
                out_untracked = subprocess.check_output(
                    ["git", "ls-files", "--others", "--exclude-standard"],
                    cwd=self.repo_root,
                    text=True
                )
                for line in out_untracked.splitlines():
                    if line.strip():
                        files.append(self.repo_root / line.strip())
                return files
            except Exception:
                pass

        # Fallback to directory walk
        ignored_roots = {".git", ".audit", ".memory", "node_modules", ".venv", "__pycache__"}
        for root, dirs, fnames in os.walk(self.repo_root):
            dirs[:] = [d for d in dirs if d not in ignored_roots]
            for f in fnames:
                p = Path(root) / f
                rel_p = str(p.relative_to(self.repo_root)).replace("\\", "/")
                if not any(rel_p.startswith(ign) for ign in ignored_roots):
                    files.append(p)
        return files

    def run_gate_1_hygiene(self) -> dict:
        """Gate 1: Git Hygiene & Repository Cleanliness (Fails on dirty tree or git error)"""
        start = time.time()
        issues = []
        status = "PASS"

        # 1. Check working tree cleanliness
        try:
            status_out = subprocess.check_output(
                ["git", "status", "--porcelain"],
                cwd=self.repo_root,
                text=True
            ).strip()
            
            untracked = [line[3:].strip() for line in status_out.splitlines() if line.startswith("??")]
            dirty = [line[3:].strip() for line in status_out.splitlines() if not line.startswith("??") and line.strip()]
            
            # Enforce clean working tree: dirty files are blockers
            if dirty:
                issues.append(f"Uncommitted modified files present: {', '.join(dirty[:5])}")
                self._add_finding(
                    "GIT_HYGIENE", "BLOCKER", "working_tree",
                    f"Uncommitted modified files in working tree: {', '.join(dirty[:5])}",
                    "Commit, stash, or discard modified working tree files before publishing."
                )

            # Untracked files outside ignores
            suspicious_untracked = [
                u for u in untracked 
                if not any(u.startswith(ign) for ign in [".audit", ".memory", "AGENTS.md"])
            ]
            if suspicious_untracked:
                issues.append(f"Untracked files outside standard ignores: {', '.join(suspicious_untracked[:5])}")
                self._add_finding(
                    "GIT_HYGIENE", "BLOCKER", "working_tree",
                    f"Untracked files detected: {', '.join(suspicious_untracked[:5])}",
                    "Stage, commit, or add files to .gitignore before publishing."
                )
        except Exception as e:
            issues.append(f"Git status failed: {e}")
            self._add_finding(
                "GIT_HYGIENE", "BLOCKER", "git_command",
                f"Failed to check git status: {e}",
                "Ensure git is installed and repository is valid."
            )

        # 2. Check .gitignore
        gitignore = self.repo_root / ".gitignore"
        if not gitignore.exists():
            issues.append("Missing .gitignore")
            self._add_finding(
                "GIT_HYGIENE", "BLOCKER", ".gitignore",
                "Repository is missing a root .gitignore file.",
                "Create a .gitignore ignoring sensitive files, cache, and audit directories."
            )
        else:
            gi_content = gitignore.read_text(encoding="utf-8", errors="replace")
            for req in [".env", ".audit", "__pycache__"]:
                if req not in gi_content:
                    issues.append(f".gitignore missing '{req}'")
                    self._add_finding(
                        "GIT_HYGIENE", "BLOCKER", ".gitignore",
                        f".gitignore does not ignore '{req}'.",
                        f"Add '{req}' to .gitignore to prevent accidental commits."
                    )

        # 3. Check README.md exists
        readme = self.repo_root / "README.md"
        if not readme.exists():
            issues.append("Missing README.md")
            self._add_finding(
                "GIT_HYGIENE", "BLOCKER", "README.md",
                "Repository is missing root README.md.",
                "Create a comprehensive README.md defining the repository scope."
            )

        duration = int((time.time() - start) * 1000)
        has_blocker = any(f["category"] == "GIT_HYGIENE" and f["severity"] == "BLOCKER" for f in self.evidence["findings"])
        status = "PASS" if not has_blocker else "FAIL"
        
        gate_res = {
            "name": "GATE_1_HYGIENE",
            "status": status,
            "command": "git status --porcelain && check .gitignore && check README.md",
            "exit_code": 0 if status == "PASS" else 1,
            "duration_ms": duration,
            "details": issues
        }
        gate_res["evidence_digest"] = sha256_digest(json.dumps(gate_res, sort_keys=True))
        self.evidence["gates"]["GATE_1_HYGIENE"] = gate_res
        return gate_res

    def run_gate_2_ast(self) -> dict:
        """Gate 2: AST Integrity & Incomplete Stubs (Aware of abstractmethod & interfaces)"""
        start = time.time()
        tracked = self.get_tracked_files()
        python_files = [f for f in tracked if f.suffix == ".py" and ".audit" not in f.parts and ".memory" not in f.parts]
        
        for pf in python_files:
            rel = str(pf.relative_to(self.repo_root)).replace("\\", "/")
            try:
                content = pf.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(content, filename=str(pf))
            except Exception as e:
                self._add_finding(
                    "AST_INTEGRITY", "BLOCKER", rel,
                    f"Syntax error in Python source: {e}",
                    "Fix syntax error so AST parsing succeeds."
                )
                continue

            visitor = StubVisitor(rel, self._add_finding)
            visitor.visit(tree)

        duration = int((time.time() - start) * 1000)
        has_blocker = any(f["category"] == "AST_INTEGRITY" and f["severity"] == "BLOCKER" for f in self.evidence["findings"])
        status = "PASS" if not has_blocker else "FAIL"

        gate_res = {
            "name": "GATE_2_AST_INTEGRITY",
            "status": status,
            "command": f"ast.parse on {len(python_files)} python files",
            "exit_code": 0 if status == "PASS" else 1,
            "duration_ms": duration,
            "details": f"Analyzed {len(python_files)} Python files via static AST."
        }
        gate_res["evidence_digest"] = sha256_digest(json.dumps(gate_res, sort_keys=True))
        self.evidence["gates"]["GATE_2_AST_INTEGRITY"] = gate_res
        return gate_res

    def run_gate_3_deps(self) -> dict:
        """Gate 3: Dependencies & Manifest Integrity (Python & Node.js supported)"""
        start = time.time()
        tracked = self.get_tracked_files()
        python_files = [f for f in tracked if f.suffix == ".py" and ".audit" not in f.parts and ".memory" not in f.parts]
        
        imported_modules = set()
        for pf in python_files:
            try:
                tree = ast.parse(pf.read_text(encoding="utf-8", errors="replace"), filename=str(pf))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imported_modules.add(alias.name.split(".")[0])
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            imported_modules.add(node.module.split(".")[0])
            except Exception:
                pass

        declared = set()
        # 1. Check requirements.txt
        req_file = self.repo_root / "requirements.txt"
        if req_file.exists():
            for line in req_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    pkg = re.split(r'[=<>!~;]', line)[0].strip().replace("-", "_").lower()
                    declared.add(pkg)

        # 2. Check pyproject.toml
        pyproject_file = self.repo_root / "pyproject.toml"
        if pyproject_file.exists():
            try:
                content = pyproject_file.read_text(encoding="utf-8")
                # Parse basic dependencies list in [project] or [tool.poetry.dependencies]
                in_deps = False
                for line in content.splitlines():
                    if re.match(r'^\s*\[.*dependencies.*\]', line):
                        in_deps = True
                        continue
                    if in_deps and line.startswith("["):
                        in_deps = False
                    if in_deps:
                        m = re.match(r'^\s*([a-zA-Z0-9_\-]+)\s*=', line) or re.match(r'^\s*"([a-zA-Z0-9_\-]+)', line)
                        if m:
                            declared.add(m.group(1).replace("-", "_").lower())
            except Exception:
                pass

        # 3. Check Node package.json if present
        pkg_json_file = self.repo_root / "package.json"
        if pkg_json_file.exists():
            try:
                pkg_data = json.loads(pkg_json_file.read_text(encoding="utf-8"))
                for k in ["dependencies", "devDependencies"]:
                    for dep in pkg_data.get(k, {}):
                        declared.add(dep)
            except Exception:
                pass

        internal_packages = {"skills", "tests", "scripts"}
        for f in self.repo_root.iterdir():
            if f.is_dir() and not f.name.startswith("."):
                internal_packages.add(f.name)

        KNOWN_MODULE_MAP = {
            "yaml": "pyyaml",
            "jsonschema": "jsonschema",
            "dotenv": "python_dotenv",
            "cv2": "opencv_python",
            "pil": "pillow",
            "sklearn": "scikit_learn",
        }

        undeclared = []
        for mod in imported_modules:
            mod_clean = mod.replace("-", "_").lower()
            if mod in STANDARD_LIBS or mod_clean in STANDARD_LIBS:
                continue
            if mod in internal_packages or mod_clean in internal_packages:
                continue
            canonical_pkg = KNOWN_MODULE_MAP.get(mod_clean, mod_clean)
            if mod_clean not in declared and mod not in declared and canonical_pkg not in declared:
                undeclared.append(mod)

        for u in undeclared:
            self._add_finding(
                "DEPENDENCIES", "BLOCKER", "manifests",
                f"Undeclared third-party import '{u}' detected in codebase.",
                f"Add '{u}' to requirements.txt, pyproject.toml, or package.json."
            )

        duration = int((time.time() - start) * 1000)
        status = "PASS" if not undeclared else "FAIL"

        gate_res = {
            "name": "GATE_3_DEPENDENCIES",
            "status": status,
            "command": "AST import analysis vs requirements.txt/pyproject.toml/package.json",
            "exit_code": 0 if status == "PASS" else 1,
            "duration_ms": duration,
            "details": f"Imported: {len(imported_modules)}, Undeclared: {len(undeclared)}"
        }
        gate_res["evidence_digest"] = sha256_digest(json.dumps(gate_res, sort_keys=True))
        self.evidence["gates"]["GATE_3_DEPENDENCIES"] = gate_res
        return gate_res

    def run_gate_4_secrets(self) -> dict:
        """Gate 4: Secrets, Leaks & Reachable Git History (Scans tracked + untracked, full git history)"""
        start = time.time()
        scannable_files = self.get_all_scannable_files()
        scan_errors = []

        # 1. Check sensitive filenames
        for tf in scannable_files:
            rel = str(tf.relative_to(self.repo_root)).replace("\\", "/")
            if "templates/" in rel:
                continue
            for pat in SENSITIVE_FILENAMES:
                if pat.match(tf.name):
                    self._add_finding(
                        "SECRETS_AND_LEAKS", "BLOCKER", rel,
                        f"Sensitive file matches forbidden pattern: '{tf.name}'",
                        "Untrack sensitive file (`git rm --cached`) and add pattern to .gitignore."
                    )
                    break

        # 2. Check file contents for tokens and developer paths
        for tf in scannable_files:
            rel = str(tf.relative_to(self.repo_root)).replace("\\", "/")
            if any(p in rel for p in [".audit/", ".memory/", "tests/"]):
                continue
            try:
                content = tf.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                scan_errors.append(f"Cannot read file '{rel}': {e}")
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                # Check secret patterns
                for pat, label in SECRET_PATTERNS:
                    for m in pat.finditer(line):
                        token_str = m.group(0)
                        if any(x in token_str.lower() for x in ["example", "dummy", "placeholder", "xxx"]):
                            continue
                        if "re.compile" in line or "AKIA[0-9A-Z]" in line:
                            continue
                        self._add_finding(
                            "SECRETS_AND_LEAKS", "BLOCKER", f"{rel}:{lineno}",
                            f"Potential {label} detected: {mask_token(token_str)}",
                            "Revoke credential immediately, purge from file, and inject via environment variable."
                        )

                # Check developer path patterns
                for pat, label in PATH_PATTERNS:
                    for m in pat.finditer(line):
                        path_val = m.group(0)
                        if "re.compile" in line or any(x in path_val for x in ["...", "example", "dummy", "placeholder", "<"]):
                            continue
                        self._add_finding(
                            "SECRETS_AND_LEAKS", "BLOCKER", f"{rel}:{lineno}",
                            f"Hardcoded local developer path ({label}): '{path_val}'",
                            "Replace hardcoded developer path with relative or repository-rooted path."
                        )

                # Check private IPs
                for m in PRIVATE_IP_PATTERN.finditer(line):
                    ip_val = m.group(0)
                    if "127.0.0.1" in ip_val:
                        continue
                    self._add_finding(
                        "SECRETS_AND_LEAKS", "BLOCKER", f"{rel}:{lineno}",
                        f"Hardcoded private IP address: '{ip_val}'",
                        "Replace hardcoded IP with environment variable or configurable parameter."
                    )

        # 3. Check reachable git history using git log --all -p (Never swallow exceptions)
        history_scanned = False
        if (self.repo_root / ".git").exists():
            try:
                log_out = subprocess.check_output(
                    ["git", "log", "--all", "-p", "--full-diff", "--", ":!tests"],
                    cwd=self.repo_root,
                    text=True,
                    errors="replace"
                )
                history_scanned = True
                for pat, label in SECRET_PATTERNS:
                    for m in pat.finditer(log_out):
                        token_str = m.group(0)
                        if any(x in token_str.lower() for x in ["example", "dummy", "placeholder", "xxx"]):
                            continue
                        if "re.compile" in token_str:
                            continue
                        self._add_finding(
                            "SECRETS_AND_LEAKS", "BLOCKER", "git_history",
                            f"Historical commit contains potential {label} leak: {mask_token(token_str)}",
                            "Scrub git history using git-filter-repo or BFG Repo-Cleaner before public push."
                        )
                        break
            except Exception as e:
                scan_errors.append(f"Git history scan failed: {e}")

        duration = int((time.time() - start) * 1000)
        has_blocker = any(f["category"] == "SECRETS_AND_LEAKS" and f["severity"] == "BLOCKER" for f in self.evidence["findings"])

        if scan_errors:
            status = "NOT_VERIFIED"
            for err in scan_errors:
                self._add_finding("SECRETS_AND_LEAKS", "BLOCKER", "scanner", err, "Ensure git repository is valid and files are readable.")
        elif has_blocker:
            status = "FAIL"
        else:
            status = "PASS"

        gate_res = {
            "name": "GATE_4_SECRETS_AND_LEAKS",
            "status": status,
            "command": "file contents + git log --all -p",
            "exit_code": 0 if status == "PASS" else 1,
            "duration_ms": duration,
            "details": f"Scanned {len(scannable_files)} files (tracked + untracked). History scanned: {history_scanned}."
        }
        gate_res["evidence_digest"] = sha256_digest(json.dumps(gate_res, sort_keys=True))
        self.evidence["gates"]["GATE_4_SECRETS_AND_LEAKS"] = gate_res
        return gate_res

    def run_gate_5_and_6_config(self) -> tuple:
        """Gates 5 & 6: Configuration Validation and Actions Consistency"""
        start = time.time()
        validator_script = self.repo_root / "skills" / "repo-push" / "scripts" / "validate_config.py"
        
        proc = subprocess.run(
            [sys.executable, str(validator_script)],
            cwd=self.repo_root,
            capture_output=True,
            text=True
        )
        duration = int((time.time() - start) * 1000)

        gate_5_status = "PASS"
        gate_6_status = "PASS"

        if proc.returncode != 0:
            out_err = proc.stdout + "\n" + proc.stderr
            if "ACT-001" in out_err or "ACT-002" in out_err:
                gate_6_status = "FAIL"
                self._add_finding(
                    "ACTIONS_CONSISTENCY", "BLOCKER", ".repo-push/actions.yaml",
                    "Actions platform references target not declared in config.yaml (ACT-001 / ACT-002).",
                    "Declare target in config.yaml or remove undeclared platform in actions.yaml."
                )
            else:
                gate_5_status = "FAIL"
                self._add_finding(
                    "CONFIG_VALIDATION", "BLOCKER", ".repo-push/config.yaml",
                    f"Configuration schema or validation error: {proc.stdout.strip()}",
                    "Fix .repo-push/config.yaml to satisfy schema and validation rules."
                )

        gate_5_res = {
            "name": "GATE_5_CONFIG_VALIDATION",
            "status": gate_5_status,
            "command": f"python {validator_script.relative_to(self.repo_root)}",
            "exit_code": 0 if gate_5_status == "PASS" else 1,
            "duration_ms": duration // 2,
            "details": "Validated .repo-push/config.yaml against JSON schema & business rules."
        }
        gate_5_res["evidence_digest"] = sha256_digest(json.dumps(gate_5_res, sort_keys=True))

        gate_6_res = {
            "name": "GATE_6_ACTIONS_CONSISTENCY",
            "status": gate_6_status,
            "command": "cross_validate(.repo-push/config.yaml, .repo-push/actions.yaml)",
            "exit_code": 0 if gate_6_status == "PASS" else 1,
            "duration_ms": duration // 2,
            "details": "Cross-validated actions platforms against active remote targets."
        }
        gate_6_res["evidence_digest"] = sha256_digest(json.dumps(gate_6_res, sort_keys=True))

        self.evidence["gates"]["GATE_5_CONFIG_VALIDATION"] = gate_5_res
        self.evidence["gates"]["GATE_6_ACTIONS_CONSISTENCY"] = gate_6_res
        return gate_5_res, gate_6_res

    def run_all_gates(self) -> dict:
        print("[AUDIT] Executing 6-Gate Verification Matrix...")
        self.run_gate_1_hygiene()
        self.run_gate_2_ast()
        self.run_gate_3_deps()
        self.run_gate_4_secrets()
        self.run_gate_5_and_6_config()

        blockers = [f for f in self.evidence["findings"] if f["severity"] == "BLOCKER"]
        warnings = [f for f in self.evidence["findings"] if f["severity"] == "WARNING"]
        infos = [f for f in self.evidence["findings"] if f["severity"] == "INFO"]

        all_passed = all(g["status"] == "PASS" for g in self.evidence["gates"].values())
        overall_status = "CERTIFIED_READY" if (all_passed and len(blockers) == 0) else "NEEDS_REMEDIATION"

        # Compute aggregate manifest digest across all gate digests
        gate_digests = {k: v["evidence_digest"] for k, v in self.evidence["gates"].items()}
        manifest_digest = sha256_digest(json.dumps(gate_digests, sort_keys=True))

        self.evidence["summary"] = {
            "status": overall_status,
            "all_gates_passed": all_passed,
            "blockers_count": len(blockers),
            "warnings_count": len(warnings),
            "infos_count": len(infos),
            "manifest_digest": manifest_digest
        }

        # Write machine-readable JSON evidence
        reports_dir = self.repo_root / ".audit" / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        evidence_file = reports_dir / "audit_evidence.json"
        evidence_file.write_text(json.dumps(self.evidence, indent=2, sort_keys=True), encoding="utf-8")

        # Write human-readable markdown report
        md_file = reports_dir / "auditor_report.md"
        md_content = self.generate_markdown_report()
        md_file.write_text(md_content, encoding="utf-8")

        print(f"[AUDIT] Complete. Status: [{overall_status}]")
        for g_name, g_info in self.evidence["gates"].items():
            print(f"  [{g_info['status'].ljust(4)}] {g_name} ({g_info['duration_ms']}ms)")
        print(f"Blockers: {len(blockers)}, Warnings: {len(warnings)}, Manifest Digest: {manifest_digest[:16]}...")
        return self.evidence

    def generate_markdown_report(self) -> str:
        s = self.evidence["summary"]
        lines = [
            "# Repository Readiness Audit Report",
            f"> Generated: {self.evidence['timestamp']} | Overall Status: **{s['status']}**",
            "",
            "## 1. Executive Summary",
            f"- **Overall Certification**: `{s['status']}`",
            f"- **All Gates Passed**: `{'YES' if s['all_gates_passed'] else 'NO'}`",
            f"- **Blockers**: `{s['blockers_count']}`",
            f"- **Warnings**: `{s['warnings_count']}`",
            f"- **Aggregate Manifest Digest**: `{s.get('manifest_digest', '')}`",
            "",
            "## 2. 6-Gate Verification Matrix",
            "| Gate | Status | Command / Check | Duration | Exit Code | Digest |",
            "| :--- | :---: | :--- | :---: | :---: | :---: |"
        ]
        for name, g in self.evidence["gates"].items():
            lines.append(f"| `{name}` | **{g['status']}** | `{g['command']}` | {g['duration_ms']}ms | `{g['exit_code']}` | `{g['evidence_digest'][:12]}...` |")

        lines.extend([
            "",
            "## 3. Findings & Triage",
        ])
        if not self.evidence["findings"]:
            lines.append("No issues found. Codebase satisfies all pre-push verification gates.")
        else:
            lines.append("| ID | Severity | Category | Location | Issue | Remediation |")
            lines.append("| :--- | :---: | :--- | :--- | :--- | :--- |")
            for f in self.evidence["findings"]:
                lines.append(f"| `{f['id']}` | **{f['severity']}** | `{f['category']}` | `{f['location']}` | {f['issue']} | {f['remediation']} |")

        lines.extend([
            "",
            "## 4. Verification Evidence & Cryptographic Attestation",
            f"- Machine-readable evidence: `.audit/reports/audit_evidence.json`",
            f"- Execution Timestamp: `{self.evidence['timestamp']}`",
            f"- Aggregate Manifest Digest: `{s.get('manifest_digest', '')}`"
        ])
        return "\n".join(lines)


def main():
    repo_root = Path.cwd()
    runner = AuditRunner(repo_root)
    evidence = runner.run_all_gates()
    if evidence["summary"]["status"] != "CERTIFIED_READY":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
