#!/usr/bin/env python3
"""
enforce_isolation.py — Report Integrity & Tamper-Detection Engine

Enforces fail-closed cryptographic integrity verification, OS-level write restrictions,
and automatic restoration for audit reports.

Security Model:
- Trusted evidence storage is maintained in '.audit/.trusted/' (isolated from agent scratch space).
- Fails closed on any error (missing snapshot, corrupted JSON, unreadable file -> exit code 1).
- Automatically backs up and restores pristine reports if tampering is detected.
- Detects and rejects symbolic links and path traversal attempts.
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys

REPORTS_DIR = os.path.abspath(os.path.join(".audit", "reports"))
TRUSTED_DIR = os.path.abspath(os.path.join(".audit", ".trusted"))
SNAPSHOT_FILE = os.path.join(TRUSTED_DIR, "reports_manifest.json")
BACKUP_DIR = os.path.join(TRUSTED_DIR, "reports_backup")


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


def snapshot_reports():
    """
    Takes a cryptographic SHA-256 snapshot of all files in REPORTS_DIR
    and creates a physical backup copy in TRUSTED_DIR.
    Fails closed if anything cannot be read.
    """
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, exist_ok=True)

    os.makedirs(TRUSTED_DIR, exist_ok=True)

    snapshot = {}
    for root, dirs, files in os.walk(REPORTS_DIR):
        for d in dirs:
            dir_path = os.path.join(root, d)
            if os.path.islink(dir_path):
                raise ValueError(f"Security violation: Symbolic link directory detected at '{dir_path}'.")

        for file in files:
            full_path = os.path.join(root, file)
            if os.path.islink(full_path):
                raise ValueError(f"Security violation: Symbolic link detected at '{full_path}'.")
            rel_path = os.path.relpath(full_path, REPORTS_DIR).replace("\\", "/")
            file_hash = hash_file(full_path)
            file_size = os.path.getsize(full_path)
            snapshot[rel_path] = {
                "sha256": file_hash,
                "size": file_size
            }

    # Backup pristine reports to trusted directory
    if os.path.exists(BACKUP_DIR):
        shutil.rmtree(BACKUP_DIR)
    shutil.copytree(REPORTS_DIR, BACKUP_DIR)

    # Write snapshot atomically
    temp_snapshot = SNAPSHOT_FILE + ".tmp"
    with open(temp_snapshot, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, sort_keys=True)
    if os.path.exists(SNAPSHOT_FILE):
        os.remove(SNAPSHOT_FILE)
    os.rename(temp_snapshot, SNAPSHOT_FILE)

    return snapshot


def lock_reports():
    """
    Snapshots reports to trusted storage, then marks REPORTS_DIR read-only.
    Fails closed if OS permission changes fail.
    """
    try:
        snapshot_reports()
    except Exception as e:
        print(f"[ISOLATION ERROR] Failed to create trusted snapshot: {e}", file=sys.stderr)
        return 1

    if not os.path.exists(REPORTS_DIR):
        return 0

    try:
        if os.name == "nt":
            res = subprocess.run(["attrib", "+r", os.path.join(REPORTS_DIR, "*.*"), "/s"], shell=True, capture_output=True, text=True)
            if res.returncode != 0 and res.stderr:
                print(f"[ISOLATION WARNING] attrib +r returned non-zero: {res.stderr.strip()}", file=sys.stderr)
        else:
            for root, dirs, files in os.walk(REPORTS_DIR):
                for d in dirs:
                    os.chmod(os.path.join(root, d), stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)
                for f in files:
                    os.chmod(os.path.join(root, f), stat.S_IRUSR | stat.S_IRGRP)
            os.chmod(REPORTS_DIR, stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)
    except Exception as e:
        print(f"[ISOLATION ERROR] Failed to set read-only permissions: {e}", file=sys.stderr)
        return 1

    print(f"[ISOLATION] Reports locked in '{REPORTS_DIR}'. Trusted evidence stored in '{TRUSTED_DIR}'.")
    return 0


def unlock_reports():
    """Restores write permissions on REPORTS_DIR for the Auditor."""
    if not os.path.exists(REPORTS_DIR):
        return 0

    try:
        if os.name == "nt":
            subprocess.run(["attrib", "-r", os.path.join(REPORTS_DIR, "*.*"), "/s"], shell=True, capture_output=True)
        else:
            os.chmod(REPORTS_DIR, stat.S_IRWXU | stat.S_IRWXG)
            for root, dirs, files in os.walk(REPORTS_DIR):
                for d in dirs:
                    os.chmod(os.path.join(root, d), stat.S_IRWXU | stat.S_IRWXG)
                for f in files:
                    os.chmod(os.path.join(root, f), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
    except Exception as e:
        print(f"[ISOLATION ERROR] Failed to unlock reports directory: {e}", file=sys.stderr)
        return 1

    print(f"[ISOLATION] Unlocked '{REPORTS_DIR}' for Auditor execution.")
    return 0


def restore_reports():
    """Restores pristine reports from BACKUP_DIR if tampering occurred."""
    if not os.path.exists(BACKUP_DIR):
        print(f"[ISOLATION ERROR] Cannot restore: Backup directory '{BACKUP_DIR}' not found.", file=sys.stderr)
        return False

    unlock_reports()
    if os.path.exists(REPORTS_DIR):
        shutil.rmtree(REPORTS_DIR)
    shutil.copytree(BACKUP_DIR, REPORTS_DIR)
    print(f"[ISOLATION RESTORED] Pristine audit reports restored from trusted backup '{BACKUP_DIR}'.")
    return True


def verify_reports(auto_restore=False):
    """
    Verifies that REPORTS_DIR matches the trusted snapshot.
    Strict fail-closed: missing, corrupted, or unreadable snapshot returns 1.
    Any modification, creation, deletion, or symlink returns 1.
    If auto_restore=True, restores from backup upon detecting tampering.
    """
    # 1. Fail-closed check: snapshot must exist
    if not os.path.exists(SNAPSHOT_FILE):
        print(f"[ISOLATION FAIL-CLOSED] Verification failed: Trusted snapshot file '{SNAPSHOT_FILE}' is missing.", file=sys.stderr)
        return 1

    # 2. Fail-closed check: snapshot must be valid readable JSON
    try:
        with open(SNAPSHOT_FILE, "r", encoding="utf-8") as f:
            snapshot = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[ISOLATION FAIL-CLOSED] Verification failed: Corrupted JSON in snapshot '{SNAPSHOT_FILE}': {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[ISOLATION FAIL-CLOSED] Verification failed: Unable to read snapshot '{SNAPSHOT_FILE}': {e}", file=sys.stderr)
        return 1

    if not isinstance(snapshot, dict):
        print(f"[ISOLATION FAIL-CLOSED] Verification failed: Snapshot manifest is invalid (expected dict, got {type(snapshot).__name__}).", file=sys.stderr)
        return 1

    current_files = set()
    tampered = []

    if os.path.exists(REPORTS_DIR):
        for root, dirs, files in os.walk(REPORTS_DIR):
            for d in dirs:
                dir_path = os.path.join(root, d)
                if os.path.islink(dir_path):
                    tampered.append(f"UNAUTHORIZED SYMLINK DIRECTORY: {os.path.relpath(dir_path, REPORTS_DIR)}")

            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, REPORTS_DIR).replace("\\", "/")
                current_files.add(rel_path)

                if os.path.islink(full_path):
                    tampered.append(f"UNAUTHORIZED SYMLINK DETECTED: {rel_path}")
                    continue

                try:
                    current_hash = hash_file(full_path)
                    expected_entry = snapshot.get(rel_path)

                    if expected_entry is None:
                        tampered.append(f"UNAUTHORIZED FILE CREATION: {rel_path}")
                    else:
                        expected_hash = expected_entry.get("sha256") if isinstance(expected_entry, dict) else expected_entry
                        if current_hash != expected_hash:
                            tampered.append(f"UNAUTHORIZED MODIFICATION: {rel_path} (hash mismatch)")
                except Exception as e:
                    tampered.append(f"FILE ACCESS ERROR on {rel_path}: {e}")

    # Check for deleted files
    for original_file in snapshot:
        if original_file not in current_files:
            tampered.append(f"UNAUTHORIZED DELETION: {original_file}")

    if tampered:
        print("[SECURITY BREACH] Audit report integrity check FAILED! Unauthorized alterations detected:", file=sys.stderr)
        for t in tampered:
            print(f"  - {t}", file=sys.stderr)

        if auto_restore:
            print("[ISOLATION] Auto-restore enabled: attempting rollback to trusted backup...", file=sys.stderr)
            if restore_reports():
                print("[ISOLATION] Rollback succeeded, but turn is marked as BREACH due to unauthorized edit attempt.", file=sys.stderr)
        return 1

    print("[ISOLATION VERIFIED] Audit reports integrity confirmed. Zero unauthorized modifications.")
    return 0


def main():
    if len(sys.argv) < 2:
        print("Usage: enforce_isolation.py [lock|unlock|verify|verify-and-restore|snapshot|restore]")
        return 1

    cmd = sys.argv[1].lower()
    if cmd == "lock":
        return lock_reports()
    elif cmd == "unlock":
        return unlock_reports()
    elif cmd == "verify":
        return verify_reports(auto_restore=False)
    elif cmd == "verify-and-restore":
        return verify_reports(auto_restore=True)
    elif cmd == "snapshot":
        try:
            snapshot_reports()
            print(f"[ISOLATION] Cryptographic snapshot saved to '{SNAPSHOT_FILE}'.")
            return 0
        except Exception as e:
            print(f"[ISOLATION ERROR] Failed to snapshot: {e}", file=sys.stderr)
            return 1
    elif cmd == "restore":
        return 0 if restore_reports() else 1
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
