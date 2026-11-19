#!/usr/bin/env python3
"""
enforce_isolation.py — Report Integrity & Tamper-Detection Engine

Enforces fail-closed cryptographic integrity verification, OS-level write restrictions,
HMAC-authenticated manifests, and automatic restoration for audit reports.

Security Architecture:
- Manifest is authenticated via HMAC-SHA256 using an isolated session key.
- Both REPORTS_DIR and TRUSTED_DIR are locked with OS read-only permissions during remediation.
- Verifies both SHA-256 hashes AND exact file sizes.
- Rejects symbolic links and path traversal attempts.
- Fails closed on any error (missing snapshot, forged signature, corrupted JSON, unreadable file -> exit code 1).
- Automatically backs up and restores pristine reports if tampering is detected.
"""

import argparse
import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

DEFAULT_REPORTS_DIR = os.path.abspath(os.path.join(".audit", "reports"))
DEFAULT_TRUSTED_DIR = os.path.abspath(os.path.join(".audit", ".trusted"))


def get_candidate_key_dirs() -> list[Path]:
    """
    Returns ordered list of candidate persistent key storage directories.
    Prioritizes secure runtime and per-user directories.
    """
    candidates = []
    if os.name != "nt":
        user_id = str(os.getuid()) if hasattr(os, "getuid") else "default"
        xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
        if xdg_runtime:
            candidates.append(Path(xdg_runtime) / "repo_push_keys")
        candidates.append(Path(tempfile.gettempdir()) / f".repo_push_{user_id}")
        try:
            candidates.append(Path.home() / ".repo_push" / "keys")
        except Exception:
            pass
    else:
        username = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            candidates.append(Path(local_app_data) / "repo_push" / "keys")
        candidates.append(Path(tempfile.gettempdir()) / f".repo_push_{username}")
        try:
            candidates.append(Path.home() / ".repo_push" / "keys")
        except Exception:
            pass
    return candidates


def verify_and_prepare_key_dir(d: Path) -> bool:
    """
    Verifies that directory d is safe for storing HMAC session keys:
    - Must exist or be cleanly created
    - Must NOT be a symbolic link
    - Must be a directory
    - On POSIX: must be owned by the current user and have strictly verified 0700 permissions.
    Returns True if fully verified; False otherwise.
    """
    try:
        if d.exists():
            if d.is_symlink() or os.path.islink(str(d)):
                return False
            if not d.is_dir():
                return False
            if os.name != "nt":
                if hasattr(os, "getuid"):
                    st = os.lstat(str(d))
                    if st.st_uid != os.getuid():
                        return False
                try:
                    os.chmod(str(d), 0o700)
                except OSError:
                    return False
                st = os.lstat(str(d))
                # Strictly verify group and other have zero permissions (0700)
                if (st.st_mode & 0o077) != 0:
                    return False
            return True
        else:
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.name != "nt":
                try:
                    os.chmod(str(d), 0o700)
                except OSError:
                    return False
                st = os.lstat(str(d))
                if hasattr(os, "getuid") and st.st_uid != os.getuid():
                    return False
                if (st.st_mode & 0o077) != 0:
                    return False
            return True
    except Exception:
        return False


def get_key_dir() -> Path:
    """
    Returns the primary verified private per-user directory for HMAC session keys.
    Enforces 0700 permissions and verifies directory ownership.
    Fails closed if no candidate directory can be securely established.
    """
    candidates = get_candidate_key_dirs()
    for cand in candidates:
        if verify_and_prepare_key_dir(cand):
            return cand

    raise RuntimeError(
        "Failed to establish secure persistent HMAC key storage. "
        "All candidate directories failed ownership, symlink, or restrictive permission (0700) checks."
    )


def get_candidate_key_files(root_hash: str) -> list[Path]:
    """
    Returns ordered list of stable, persistent file paths where the HMAC session key
    may be stored or retrieved.
    Each candidate directory provides a primary key file and a stable fallback key file.
    """
    key_files = []
    candidates = get_candidate_key_dirs()
    for cand in candidates:
        if verify_and_prepare_key_dir(cand):
            # Primary key file in this directory
            key_files.append(cand / f".repo_push_key_{root_hash}.secret")
            # Stable fallback key file in a verified subdirectory
            alt_dir = cand / ".fallback_keys"
            if verify_and_prepare_key_dir(alt_dir):
                key_files.append(alt_dir / f".repo_push_key_{root_hash}.secret")
    return key_files


def get_session_hmac_key(repo_root=None):
    """
    Retrieves or atomically creates an ephemeral HMAC secret key stored outside the repository
    in a private per-user directory (0700). Used for cryptographic tamper-detection of reports.
    Fails closed if persistent key storage is unavailable or corrupt.
    """
    env_key = os.environ.get("REPO_PUSH_HMAC_KEY")
    if env_key:
        key_bytes = env_key.encode("utf-8")
        if len(key_bytes) < 32:
            raise ValueError(f"Environment variable REPO_PUSH_HMAC_KEY must be at least 32 bytes (got {len(key_bytes)} bytes).")
        return key_bytes[:32]

    root = os.path.abspath(repo_root or ".")
    root_hash = hashlib.sha256(root.encode("utf-8")).hexdigest()[:16]

    candidate_files = get_candidate_key_files(root_hash)
    if not candidate_files:
        raise RuntimeError("Failed to establish secure persistent HMAC key storage across all candidate directories.")

    def validate_existing_key_file(path: Path) -> bytes | None:
        """
        Validates that path is a regular file, not a symlink, owned by the current user,
        and protected by restrictive permissions (0600 on POSIX).
        Returns 32-byte key if valid, None if untrusted/missing.
        Raises RuntimeError if regular file owned by user is corrupted in length.
        """
        if not path.exists():
            return None
        try:
            st = os.lstat(str(path))
        except Exception:
            return None

        # Reject symbolic links
        if stat.S_ISLNK(st.st_mode) or path.is_symlink():
            return None

        # Must be a regular file
        if not stat.S_ISREG(st.st_mode):
            return None

        # On POSIX: verify ownership
        if os.name != "nt" and hasattr(os, "getuid") and st.st_uid != os.getuid():
            return None

        try:
            data = path.read_bytes()
        except Exception as e:
            raise RuntimeError(f"Failed to read HMAC session key at '{path}': {e}")

        # Regular file owned by user with corrupted length must fail closed
        if len(data) > 0 and len(data) != 32:
            raise RuntimeError(f"Corrupted HMAC session key at '{path}': expected exactly 32 bytes, found {len(data)} bytes.")

        if len(data) != 32:
            return None

        # On POSIX: enforce restrictive permissions (0600)
        if os.name != "nt":
            if (st.st_mode & 0o077) != 0:
                try:
                    os.chmod(str(path), 0o600)
                    st = os.lstat(str(path))
                except OSError:
                    pass
            if (st.st_mode & 0o077) != 0:
                return None

        return data

    # Phase 1: Search for an EXISTING valid key in candidate files (in deterministic order)
    for kf in candidate_files:
        valid_key = validate_existing_key_file(kf)
        if valid_key is not None:
            return valid_key

    # Phase 2: If no existing key exists, atomically create and persist a new 32-byte key
    # at the first untainted candidate file location
    for kf in candidate_files:
        if kf.exists():
            # Exists but failed validation (e.g. pre-created symlink, wrong owner, bad permissions).
            # Refuse to touch, overwrite, or adopt. Skip to next candidate path.
            continue

        parent_dir = kf.parent
        new_key = os.urandom(32)
        temp_key_file = parent_dir / f".repo_push_key_{root_hash}_{os.getpid()}_{uuid.uuid4().hex}.tmp"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        try:
            temp_fd = os.open(str(temp_key_file), flags, 0o600)
            try:
                os.write(temp_fd, new_key)
                os.fsync(temp_fd)
            finally:
                os.close(temp_fd)
            if os.name != "nt":
                try:
                    os.chmod(str(temp_key_file), 0o600)
                except Exception:
                    pass
        except Exception:
            continue

        published = False
        try:
            if os.name == "nt":
                try:
                    os.rename(str(temp_key_file), str(kf))
                    published = True
                except FileExistsError:
                    published = False
            else:
                try:
                    os.link(str(temp_key_file), str(kf))
                    published = True
                except FileExistsError:
                    published = False
                except OSError:
                    if not kf.exists():
                        os.rename(str(temp_key_file), str(kf))
                        published = True
                    else:
                        published = False
        finally:
            if temp_key_file.exists():
                try:
                    os.unlink(str(temp_key_file))
                except Exception:
                    pass

        if published:
            persisted = validate_existing_key_file(kf)
            if persisted is not None and persisted == new_key:
                return new_key

        # If another concurrent process published kf first, wait and read back
        timeout = 2.0
        deadline = time.time() + timeout
        while time.time() < deadline:
            valid_key = validate_existing_key_file(kf)
            if valid_key is not None:
                return valid_key
            time.sleep(0.01)

    raise RuntimeError(
        "Failed to establish secure persistent HMAC key storage: "
        "all candidate key paths are unavailable, untrusted, or failed publication."
    )


def hash_file(filepath):
    """Computes SHA-256 hash of a regular file. Rejects symlinks."""
    if os.path.islink(filepath):
        raise ValueError(f"Security violation: Symbolic link detected at '{filepath}'. Symlinks are forbidden in audit reports.")
    if not os.path.isfile(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


class IsolationManager:
    def __init__(self, reports_dir=DEFAULT_REPORTS_DIR, trusted_dir=DEFAULT_TRUSTED_DIR, repo_root=None):
        self.reports_dir = os.path.abspath(reports_dir)
        self.trusted_dir = os.path.abspath(trusted_dir)
        self.snapshot_file = os.path.join(self.trusted_dir, "reports_manifest.json")
        self.backup_dir = os.path.join(self.trusted_dir, "reports_backup")
        self.hmac_key = get_session_hmac_key(repo_root)

    def snapshot_reports(self):
        """
        Takes a cryptographic SHA-256 snapshot of all files in reports_dir,
        authenticates the manifest with HMAC-SHA256, and creates a physical backup copy.
        Fails closed if anything cannot be read.
        """
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir, exist_ok=True)

        os.makedirs(self.trusted_dir, exist_ok=True)

        files_manifest = {}
        for root, dirs, files in os.walk(self.reports_dir, followlinks=False):
            for d in dirs:
                dir_path = os.path.join(root, d)
                if os.path.islink(dir_path):
                    raise ValueError(f"Security violation: Symbolic link directory detected at '{dir_path}'.")

            for file in sorted(files):
                full_path = os.path.join(root, file)
                if os.path.islink(full_path):
                    raise ValueError(f"Security violation: Symbolic link detected at '{full_path}'.")
                rel_path = os.path.relpath(full_path, self.reports_dir).replace("\\", "/")
                file_hash = hash_file(full_path)
                file_size = os.path.getsize(full_path)
                files_manifest[rel_path] = {
                    "sha256": file_hash,
                    "size": file_size
                }

        # Backup pristine reports to trusted directory
        if os.path.exists(self.backup_dir):
            shutil.rmtree(self.backup_dir)
        shutil.copytree(self.reports_dir, self.backup_dir)

        # Authenticate manifest with HMAC
        manifest_payload = json.dumps(files_manifest, sort_keys=True)
        sig = hmac.new(self.hmac_key, manifest_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        snapshot_data = {
            "version": "2.0",
            "files": files_manifest,
            "hmac_sha256": sig
        }

        # Write snapshot atomically
        temp_snapshot = self.snapshot_file + ".tmp"
        with open(temp_snapshot, "w", encoding="utf-8") as f:
            json.dump(snapshot_data, f, indent=2, sort_keys=True)
        if os.path.exists(self.snapshot_file):
            os.remove(self.snapshot_file)
        os.rename(temp_snapshot, self.snapshot_file)

        return snapshot_data

    def _apply_os_permissions(self, directory, readonly=True):
        """Applies OS-level read-only or read-write permissions across a directory tree."""
        if not os.path.exists(directory):
            return True

        if os.name == "nt":
            attr_flag = "+r" if readonly else "-r"
            res = subprocess.run(["attrib", attr_flag, os.path.join(directory, "*.*"), "/s"], shell=True, capture_output=True, text=True)
            if res.returncode != 0:
                print(f"[ISOLATION ERROR] Windows attrib {attr_flag} failed: {res.stderr.strip()}", file=sys.stderr)
                return False
        else:
            mode_dir = stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP if readonly else stat.S_IRWXU | stat.S_IRWXG
            mode_file = stat.S_IRUSR | stat.S_IRGRP if readonly else stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP

            os.chmod(directory, mode_dir)
            for root, dirs, files in os.walk(directory, followlinks=False):
                for d in dirs:
                    os.chmod(os.path.join(root, d), mode_dir)
                for f in files:
                    os.chmod(os.path.join(root, f), mode_file)
        return True

    def lock_reports(self):
        """
        Snapshots reports to trusted storage, then marks BOTH reports_dir
        AND trusted_dir read-only. Fails closed if OS permission changes fail.
        """
        try:
            self.snapshot_reports()
        except Exception as e:
            print(f"[ISOLATION ERROR] Failed to create trusted snapshot: {e}", file=sys.stderr)
            return 1

        # Lock reports directory
        if not self._apply_os_permissions(self.reports_dir, readonly=True):
            return 1

        # Lock trusted directory (protecting manifest and backup)
        if not self._apply_os_permissions(self.trusted_dir, readonly=True):
            return 1

        print(f"[ISOLATION] Reports and trusted backup locked read-only in '{self.reports_dir}' & '{self.trusted_dir}'.")
        return 0

    def unlock_reports(self):
        """Restores write permissions on reports_dir and trusted_dir."""
        err1 = not self._apply_os_permissions(self.reports_dir, readonly=False)
        err2 = not self._apply_os_permissions(self.trusted_dir, readonly=False)
        if err1 or err2:
            print("[ISOLATION ERROR] Failed to unlock directories.", file=sys.stderr)
            return 1

        print(f"[ISOLATION] Unlocked '{self.reports_dir}' and '{self.trusted_dir}' for execution.")
        return 0

    def verify_backup_integrity(self, expected_manifest):
        """Verifies that the backup directory matches the authenticated manifest before restoring."""
        if not os.path.exists(self.backup_dir):
            return False, f"Backup directory '{self.backup_dir}' not found."

        backup_files = set()
        for root, dirs, files in os.walk(self.backup_dir, followlinks=False):
            for d in dirs:
                dir_path = os.path.join(root, d)
                if os.path.islink(dir_path):
                    return False, f"Symlink directory in backup: {dir_path}"
            for file in files:
                full_path = os.path.join(root, file)
                if os.path.islink(full_path):
                    return False, f"Symlink file in backup: {full_path}"
                rel_path = os.path.relpath(full_path, self.backup_dir).replace("\\", "/")
                backup_files.add(rel_path)
                expected_entry = expected_manifest.get(rel_path)
                if not expected_entry:
                    return False, f"Unauthorized file in backup: {rel_path}"
                actual_hash = hash_file(full_path)
                actual_size = os.path.getsize(full_path)
                if actual_hash != expected_entry.get("sha256"):
                    return False, f"Hash mismatch in backup file '{rel_path}'"
                if expected_entry.get("size") is not None and actual_size != expected_entry.get("size"):
                    return False, f"Size mismatch in backup file '{rel_path}'"

        for expected_file in expected_manifest:
            if expected_file not in backup_files:
                return False, f"Missing file in backup: {expected_file}"

        return True, "Backup verified pristine against authenticated manifest."

    def restore_reports(self, authenticated_manifest=None):
        """
        Restores pristine reports from backup_dir after independently verifying
        that every backup file matches the HMAC-authenticated manifest.
        """
        if not os.path.exists(self.backup_dir):
            print(f"[ISOLATION ERROR] Cannot restore: Backup directory '{self.backup_dir}' not found.", file=sys.stderr)
            return False

        # Load and authenticate manifest if not passed in
        if authenticated_manifest is None:
            if not os.path.exists(self.snapshot_file):
                print(f"[ISOLATION ERROR] Cannot restore: Missing snapshot file '{self.snapshot_file}'.", file=sys.stderr)
                return False
            try:
                with open(self.snapshot_file, "r", encoding="utf-8") as f:
                    snapshot_data = json.load(f)
                files_manifest = snapshot_data.get("files")
                stored_sig = snapshot_data.get("hmac_sha256")
                manifest_payload = json.dumps(files_manifest, sort_keys=True)
                expected_sig = hmac.new(self.hmac_key, manifest_payload.encode("utf-8"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(stored_sig, expected_sig):
                    print("[SECURITY BREACH] Cannot restore: Manifest signature verification failed!", file=sys.stderr)
                    return False
                authenticated_manifest = files_manifest
            except Exception as e:
                print(f"[ISOLATION ERROR] Cannot restore: Error reading/authenticating manifest: {e}", file=sys.stderr)
                return False

        # Verify backup files match authenticated manifest
        is_valid, msg = self.verify_backup_integrity(authenticated_manifest)
        if not is_valid:
            print(f"[SECURITY BREACH] Cannot restore: Backup verification failed ({msg})! Restoration aborted.", file=sys.stderr)
            return False

        if self.unlock_reports() != 0:
            print("[ISOLATION ERROR] Cannot restore: Directory permissions could not be unlocked.", file=sys.stderr)
            return False

        if os.path.exists(self.reports_dir):
            shutil.rmtree(self.reports_dir)
        shutil.copytree(self.backup_dir, self.reports_dir)
        print(f"[ISOLATION RESTORED] Verified pristine audit reports restored from trusted backup '{self.backup_dir}'.")
        return True

    def verify_reports(self, auto_restore=False):
        """
        Verifies that reports_dir matches the trusted authenticated snapshot.
        Strict fail-closed: missing, corrupted, unreadable, or forged snapshot returns 1.
        Any modification, creation, deletion, or symlink returns 1.
        """
        # 1. Fail-closed check: snapshot must exist
        if not os.path.exists(self.snapshot_file):
            print(f"[ISOLATION FAIL-CLOSED] Verification failed: Trusted snapshot file '{self.snapshot_file}' is missing.", file=sys.stderr)
            return 1

        # 2. Fail-closed check: snapshot must be valid readable JSON
        try:
            with open(self.snapshot_file, "r", encoding="utf-8") as f:
                snapshot_data = json.load(f)
        except Exception as e:
            print(f"[ISOLATION FAIL-CLOSED] Verification failed: Unable to read snapshot '{self.snapshot_file}': {e}", file=sys.stderr)
            return 1

        if not isinstance(snapshot_data, dict):
            print(f"[ISOLATION FAIL-CLOSED] Verification failed: Snapshot manifest is invalid.", file=sys.stderr)
            return 1

        # 3. Authenticate HMAC signature
        files_manifest = snapshot_data.get("files")
        stored_sig = snapshot_data.get("hmac_sha256")

        if files_manifest is None or not stored_sig:
            print(f"[ISOLATION FAIL-CLOSED] Verification failed: Snapshot missing authenticated payload or signature.", file=sys.stderr)
            return 1

        manifest_payload = json.dumps(files_manifest, sort_keys=True)
        expected_sig = hmac.new(self.hmac_key, manifest_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(stored_sig, expected_sig):
            print("[SECURITY BREACH] Snapshot manifest signature verification FAILED! Manifest has been forged or tampered with.", file=sys.stderr)
            if auto_restore:
                self.restore_reports()
            return 1

        current_files = set()
        tampered = []

        if os.path.exists(self.reports_dir):
            for root, dirs, files in os.walk(self.reports_dir, followlinks=False):
                for d in dirs:
                    dir_path = os.path.join(root, d)
                    if os.path.islink(dir_path):
                        tampered.append(f"UNAUTHORIZED SYMLINK DIRECTORY: {os.path.relpath(dir_path, self.reports_dir)}")

                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.reports_dir).replace("\\", "/")
                    current_files.add(rel_path)

                    if os.path.islink(full_path):
                        tampered.append(f"UNAUTHORIZED SYMLINK DETECTED: {rel_path}")
                        continue

                    try:
                        current_hash = hash_file(full_path)
                        current_size = os.path.getsize(full_path)
                        expected_entry = files_manifest.get(rel_path)

                        if expected_entry is None:
                            tampered.append(f"UNAUTHORIZED FILE CREATION: {rel_path}")
                        else:
                            expected_hash = expected_entry.get("sha256")
                            expected_size = expected_entry.get("size")

                            if current_hash != expected_hash:
                                tampered.append(f"UNAUTHORIZED MODIFICATION (hash mismatch): {rel_path}")
                            if expected_size is not None and current_size != expected_size:
                                tampered.append(f"UNAUTHORIZED MODIFICATION (size mismatch): {rel_path} (got {current_size}, expected {expected_size})")
                    except Exception as e:
                        tampered.append(f"FILE ACCESS ERROR on {rel_path}: {e}")

        # Check for deleted files
        for original_file in files_manifest:
            if original_file not in current_files:
                tampered.append(f"UNAUTHORIZED DELETION: {original_file}")

        if tampered:
            print("[SECURITY BREACH] Audit report integrity check FAILED! Unauthorized alterations detected:", file=sys.stderr)
            for t in tampered:
                print(f"  - {t}", file=sys.stderr)

            if auto_restore:
                print("[ISOLATION] Auto-restore enabled: attempting rollback to trusted backup...", file=sys.stderr)
                if self.restore_reports(authenticated_manifest=files_manifest):
                    print("[ISOLATION] Rollback succeeded, but turn is marked as BREACH due to unauthorized edit attempt.", file=sys.stderr)
            return 1

        print("[ISOLATION VERIFIED] Audit reports integrity confirmed. Zero unauthorized modifications.")
        return 0


def main():
    parser = argparse.ArgumentParser(description="Enforce Isolation & Cryptographic Report Protection")
    parser.add_argument("command", choices=["lock", "unlock", "verify", "verify-and-restore", "snapshot", "restore"])
    parser.add_argument("--reports-dir", default=DEFAULT_REPORTS_DIR, help="Path to reports directory")
    parser.add_argument("--trusted-dir", default=DEFAULT_TRUSTED_DIR, help="Path to trusted evidence directory")

    args = parser.parse_args()
    mgr = IsolationManager(args.reports_dir, args.trusted_dir)

    cmd = args.command.lower()
    if cmd == "lock":
        return mgr.lock_reports()
    elif cmd == "unlock":
        return mgr.unlock_reports()
    elif cmd == "verify":
        return mgr.verify_reports(auto_restore=False)
    elif cmd == "verify-and-restore":
        return mgr.verify_reports(auto_restore=True)
    elif cmd == "snapshot":
        try:
            mgr.snapshot_reports()
            print(f"[ISOLATION] Cryptographic snapshot saved to '{mgr.snapshot_file}'.")
            return 0
        except Exception as e:
            print(f"[ISOLATION ERROR] Failed to snapshot: {e}", file=sys.stderr)
            return 1
    elif cmd == "restore":
        return 0 if mgr.restore_reports() else 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
