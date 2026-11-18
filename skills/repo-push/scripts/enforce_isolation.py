#!/usr/bin/env python3
"""
enforce_isolation.py — Defense-in-Depth Behavioral Isolation Enforcer
Provides OS file-locking, cryptographic SHA-256 snapshotting, and post-execution diff verification
to ensure Remediators cannot tamper with Auditor reports even under prompt injection.
"""

import hashlib
import os
import stat
import subprocess
import sys

REPORTS_DIR = os.path.join(".audit", "reports")
SNAPSHOT_FILE = os.path.join(".audit", ".scratch", "reports_snapshot.json")


def hash_file(filepath):
    """Computes SHA-256 hash of a file."""
    if not os.path.isfile(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def snapshot_reports():
    """Takes a cryptographic snapshot of all files in .audit/reports/."""
    snapshot = {}
    if os.path.exists(REPORTS_DIR):
        for root, _, files in os.walk(REPORTS_DIR):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, REPORTS_DIR)
                snapshot[rel_path] = hash_file(full_path)

    os.makedirs(os.path.dirname(SNAPSHOT_FILE), exist_ok=True)
    import json
    with open(SNAPSHOT_FILE, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)
    return snapshot


def lock_reports():
    """Sets OS-level read-only permissions on .audit/reports/ and creates snapshot."""
    snapshot_reports()
    if not os.path.exists(REPORTS_DIR):
        return

    # Windows attrib +r or Unix chmod -R 555
    if os.name == "nt":
        subprocess.run(["attrib", "+r", os.path.join(REPORTS_DIR, "*.*"), "/s"], shell=True, capture_output=True)
    else:
        for root, dirs, files in os.walk(REPORTS_DIR):
            for d in dirs:
                os.chmod(os.path.join(root, d), stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)
            for f in files:
                os.chmod(os.path.join(root, f), stat.S_IRUSR | stat.S_IRGRP)
    print(f"[ISOLATION] Locked '{REPORTS_DIR}' with read-only permissions and recorded SHA-256 snapshot.")


def unlock_reports():
    """Restores write permissions on .audit/reports/ for the Auditor."""
    if not os.path.exists(REPORTS_DIR):
        return

    if os.name == "nt":
        subprocess.run(["attrib", "-r", os.path.join(REPORTS_DIR, "*.*"), "/s"], shell=True, capture_output=True)
    else:
        for root, dirs, files in os.walk(REPORTS_DIR):
            for d in dirs:
                os.chmod(os.path.join(root, d), stat.S_IRWXU | stat.S_IRWXG)
            for f in files:
                os.chmod(os.path.join(root, f), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
    print(f"[ISOLATION] Unlocked '{REPORTS_DIR}' for Auditor execution.")


def verify_reports():
    """
    Verifies that .audit/reports/ matches the pre-remediation snapshot.
    Returns 0 if pristine, 1 if tampering or modification detected.
    """
    if not os.path.exists(SNAPSHOT_FILE):
        print("[ISOLATION WARNING] No snapshot found to verify against.", file=sys.stderr)
        return 0

    import json
    with open(SNAPSHOT_FILE, "r", encoding="utf-8") as f:
        snapshot = json.load(f)

    current_files = set()
    tampered = []

    if os.path.exists(REPORTS_DIR):
        for root, _, files in os.walk(REPORTS_DIR):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, REPORTS_DIR)
                current_files.add(rel_path)
                current_hash = hash_file(full_path)
                original_hash = snapshot.get(rel_path)

                if original_hash is None:
                    tampered.append(f"UNAUTHORIZED FILE CREATED: {rel_path}")
                elif current_hash != original_hash:
                    tampered.append(f"UNAUTHORIZED MODIFICATION: {rel_path}")

    # Check for deleted files
    for original_file in snapshot:
        if original_file not in current_files:
            tampered.append(f"UNAUTHORIZED DELETION: {original_file}")

    if tampered:
        print("[SECURITY BREACH] Behavioral isolation contract violated!", file=sys.stderr)
        print("Unauthorized alterations detected in .audit/reports/:", file=sys.stderr)
        for t in tampered:
            print(f"  - {t}", file=sys.stderr)
        return 1

    print("[ISOLATION VERIFIED] .audit/reports/ integrity intact. Zero unauthorized modifications.")
    return 0


def main():
    if len(sys.argv) < 2:
        print("Usage: enforce_isolation.py [lock|unlock|verify|snapshot]")
        return 1

    cmd = sys.argv[1].lower()
    if cmd == "lock":
        lock_reports()
    elif cmd == "unlock":
        unlock_reports()
    elif cmd == "verify":
        return verify_reports()
    elif cmd == "snapshot":
        snapshot_reports()
        print(f"[ISOLATION] Cryptographic snapshot saved to '{SNAPSHOT_FILE}'.")
    else:
        print(f"Unknown command: {cmd}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
