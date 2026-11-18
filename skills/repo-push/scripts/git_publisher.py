#!/usr/bin/env python3
"""
git_publisher.py — Safe, Deterministic Multi-Platform Git Publishing Engine

Implements an isolated, worktree-based publishing pipeline that:
1. NEVER modifies the user's active branch, working tree, or index.
2. Supports two explicit publishing modes:
   - 'history_preserving' (default): Preserves full commit history, applying exclusions as a release commit.
   - 'clean_snapshot': Creates an isolated single-commit snapshot with zero past history.
3. Uses collision-resistant temporary references (UUID-based).
4. Enforces guaranteed cleanup via try/finally (even on failure, interrupt, or error).
5. Safe argument arrays (no shell string interpolation).
"""

import argparse
import os
import shutil
import subprocess
import sys
import uuid

LOCK_FILE = os.path.abspath(os.path.join(".audit", ".trusted", "publishing.lock"))


class PublishingLock:
    """Guarantees mutually exclusive publishing operations."""
    def __enter__(self):
        os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
        if os.path.exists(LOCK_FILE):
            try:
                with open(LOCK_FILE, "r", encoding="utf-8") as f:
                    pid = f.read().strip()
                raise RuntimeError(f"Concurrent publishing operation detected (Lock held by PID {pid}). Aborting.")
            except Exception:
                raise RuntimeError("Publishing lock file exists. Another publish operation may be active.")
        with open(LOCK_FILE, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if os.path.exists(LOCK_FILE):
            try:
                os.remove(LOCK_FILE)
            except Exception:
                pass


def git_cmd(args, cwd=None, check=True):
    """Executes a git command with argument arrays. Never uses shell=True."""
    res = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if check and res.returncode != 0:
        cmd_str = "git " + " ".join(args)
        raise RuntimeError(f"Command failed ({res.returncode}): {cmd_str}\nStderr: {res.stderr.strip()}")
    return res


def get_current_commit():
    """Returns current HEAD commit SHA, or raises if no commits exist."""
    res = git_cmd(["rev-parse", "HEAD"], check=False)
    if res.returncode != 0:
        raise RuntimeError("Repository has no commits. Create at least one commit before publishing.")
    return res.stdout.strip()


def validate_remote(remote_name):
    """Verifies that the remote exists in git remote -v."""
    res = git_cmd(["remote"], check=False)
    remotes = [r.strip() for r in res.stdout.splitlines() if r.strip()]
    if remote_name not in remotes:
        raise ValueError(f"Remote '{remote_name}' does not exist. Configured remotes: {remotes}")
    return True


def publish_target(
    remote_name,
    target_branch="main",
    mode="history_preserving",
    exclude_patterns=None,
    push_tags=False,
    dry_run=False
):
    """
    Publishes the repository to a target remote using an isolated Git worktree.
    Guarantees user working copy is NEVER switched or altered.
    """
    if exclude_patterns is None:
        exclude_patterns = []

    # Validate all exclusion patterns upfront before allocating any Git resources
    for pat in exclude_patterns:
        if pat in ("/", "\\", ".", "*") or ".." in pat:
            raise ValueError(f"Dangerous exclusion pattern rejected: '{pat}'")

    validate_remote(remote_name)
    head_commit = get_current_commit()

    run_id = uuid.uuid4().hex[:8]
    temp_branch = f"__repo_push_pub_{run_id}"
    worktree_dir = os.path.abspath(os.path.join(".audit", ".scratch", "worktrees", f"wt_{run_id}"))

    print(f"\n[GIT PUBLISHER] Target: '{remote_name}' (branch: '{target_branch}', mode: '{mode}')")
    if dry_run:
        print("[GIT PUBLISHER] DRY-RUN MODE: No network pushes will be executed.")

    os.makedirs(os.path.dirname(worktree_dir), exist_ok=True)

    try:
        # 1. Create isolated worktree on a unique temporary branch pointing to HEAD
        print(f"[WORKTREE] Creating isolated worktree at '{worktree_dir}' on ref '{temp_branch}'...")
        git_cmd(["worktree", "add", "-b", temp_branch, worktree_dir, head_commit])

        # 2. Execute publishing mode
        if mode == "history_preserving":
            # Apply exclusion filters to the worktree branch
            if exclude_patterns:
                print(f"[FILTER] Applying {len(exclude_patterns)} exclusion filter(s)...")
                for pat in exclude_patterns:
                    # Validate exclusion pattern against dangerous inputs
                    if pat in ("/", "\\", ".", "*") or ".." in pat:
                        raise ValueError(f"Dangerous exclusion pattern rejected: '{pat}'")
                    git_cmd(["rm", "-r", "--cached", "--ignore-unmatch", pat], cwd=worktree_dir, check=False)

                # Check if there are changes to commit after exclusions
                status_res = git_cmd(["status", "--porcelain"], cwd=worktree_dir)
                if status_res.stdout.strip():
                    commit_msg = f"publish: release to {remote_name} (platform filtered)"
                    git_cmd(["commit", "-m", commit_msg], cwd=worktree_dir)
                    print(f"[COMMIT] Created platform release commit on '{temp_branch}'.")
                else:
                    print(f"[INFO] No excluded files found in tree; publishing HEAD commit directly.")

        elif mode == "clean_snapshot":
            # Create a completely orphan branch with 0 historical commits
            print(f"[CLEAN SNAPSHOT] Creating orphan single-commit snapshot...")
            git_cmd(["checkout", "--orphan", f"{temp_branch}_orphan"], cwd=worktree_dir)
            if exclude_patterns:
                for pat in exclude_patterns:
                    if pat in ("/", "\\", ".", "*") or ".." in pat:
                        raise ValueError(f"Dangerous exclusion pattern rejected: '{pat}'")
                    git_cmd(["rm", "-r", "--cached", "--ignore-unmatch", pat], cwd=worktree_dir, check=False)
            git_cmd(["commit", "-m", f"publish: clean snapshot release to {remote_name}"], cwd=worktree_dir)
            temp_branch = f"{temp_branch}_orphan"
        else:
            raise ValueError(f"Unknown publishing mode: '{mode}'. Must be 'history_preserving' or 'clean_snapshot'.")

        # 3. Push to remote
        push_args = [remote_name, f"{temp_branch}:{target_branch}"]
        if push_tags:
            push_args.append("--tags")
        if dry_run:
            push_args.append("--dry-run")

        print(f"[PUSH] Executing: git push {' '.join(push_args)}")
        push_res = git_cmd(["push"] + push_args, cwd=worktree_dir)
        print(f"[SUCCESS] Published to '{remote_name}/{target_branch}' successfully.")
        return True

    finally:
        # GUARANTEED CLEANUP: executed regardless of errors, interrupts, or exceptions
        print(f"[CLEANUP] Cleaning up isolated worktree and temporary branch '{temp_branch}'...")
        if os.path.exists(worktree_dir):
            git_cmd(["worktree", "remove", "--force", worktree_dir], check=False)
            if os.path.exists(worktree_dir):
                shutil.rmtree(worktree_dir, ignore_errors=True)
        git_cmd(["worktree", "prune"], check=False)
        git_cmd(["branch", "-D", temp_branch], check=False)
        # Also clean up orphan branch if created
        git_cmd(["branch", "-D", f"{temp_branch}_orphan"], check=False)
        print("[CLEANUP] Workspace restored. Original user branch and index untouched.")


def main():
    parser = argparse.ArgumentParser(description="Deterministic Git Publisher with Worktree Isolation")
    parser.add_argument("--remote", "-r", required=True, help="Git remote name (e.g. origin, gitlab)")
    parser.add_argument("--branch", "-b", default="main", help="Target remote branch (default: main)")
    parser.add_argument("--mode", "-m", choices=["history_preserving", "clean_snapshot"], default="history_preserving",
                        help="Publishing mode (default: history_preserving)")
    parser.add_argument("--exclude", "-e", action="append", default=[], help="File pattern to exclude (repeatable)")
    parser.add_argument("--tags", action="store_true", help="Push tags")
    parser.add_argument("--dry-run", action="store_true", help="Execute dry-run without network changes")

    args = parser.parse_args()

    try:
        with PublishingLock():
            success = publish_target(
                remote_name=args.remote,
                target_branch=args.branch,
                mode=args.mode,
                exclude_patterns=args.exclude,
                push_tags=args.tags,
                dry_run=args.dry_run
            )
            return 0 if success else 1
    except Exception as e:
        print(f"[PUBLISHER ERROR] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
