#!/usr/bin/env python3
"""
git_publisher.py — Safe, Deterministic Multi-Platform Git Publishing Engine

Implements an isolated, worktree-based publishing pipeline that:
1. NEVER modifies the user's active branch, working tree, or index.
2. Uses atomic OS-level exclusive file locking (O_CREAT | O_EXCL) to prevent concurrency races.
3. Supports two explicit publishing modes:
   - 'history_preserving' (default): Preserves full commit history; filters release tree atop HEAD.
   - 'clean_snapshot': Creates an isolated single-commit snapshot with zero past history.
4. Forbids historical tags in 'clean_snapshot' mode to prevent history leakage through refs.
5. Verifies resulting tree against exclusion policy before executing push.
6. Enforces guaranteed worktree and branch cleanup with transparent error reporting.
"""

import argparse
import fnmatch
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

DEFAULT_LOCK_FILE = os.path.abspath(os.path.join(".audit", ".trusted", "publishing.lock"))


class PublishingLock:
    """
    OS-level kernel file lock for publishing operations.
    Uses msvcrt.locking on Windows and fcntl.flock on Unix.
    Provides true race-free concurrency: kernel automatically releases lock
    if the process terminates, crashes, or is killed.
    """
    def __init__(self, lock_file=DEFAULT_LOCK_FILE):
        self.lock_file = lock_file
        self.fd = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.lock_file), exist_ok=True)
        try:
            # Open or create lock file
            self.fd = os.open(self.lock_file, os.O_RDWR | os.O_CREAT, 0o600)
            if os.name == "nt":
                import msvcrt
                try:
                    msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                except OSError:
                    os.close(self.fd)
                    self.fd = None
                    raise RuntimeError(f"Concurrent publishing operation detected (Lock held at '{self.lock_file}'). Aborting.")
            else:
                import fcntl
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except (BlockingIOError, OSError):
                    os.close(self.fd)
                    self.fd = None
                    raise RuntimeError(f"Concurrent publishing operation detected (Lock held at '{self.lock_file}'). Aborting.")

            # Record active PID for diagnostic observability
            try:
                os.ftruncate(self.fd, 0)
                os.lseek(self.fd, 0, os.SEEK_SET)
                os.write(self.fd, f"{os.getpid()}\n".encode("utf-8"))
            except Exception:
                pass
            return self
        except RuntimeError:
            raise
        except Exception as e:
            if self.fd is not None:
                try:
                    os.close(self.fd)
                except Exception:
                    pass
                self.fd = None
            raise RuntimeError(f"Failed to acquire publishing lock at '{self.lock_file}': {e}")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd is not None:
            try:
                if os.name == "nt":
                    import msvcrt
                    try:
                        os.lseek(self.fd, 0, os.SEEK_SET)
                        msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
                else:
                    import fcntl
                    try:
                        fcntl.flock(self.fd, fcntl.LOCK_UN)
                    except Exception:
                        pass
                os.close(self.fd)
            except Exception:
                pass
            self.fd = None
        if os.path.exists(self.lock_file):
            try:
                os.remove(self.lock_file)
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


def get_current_commit(cwd=None):
    """Returns current HEAD commit SHA, or raises if no commits exist."""
    res = git_cmd(["rev-parse", "HEAD"], cwd=cwd, check=False)
    if res.returncode != 0:
        raise RuntimeError("Repository has no commits. Create at least one commit before publishing.")
    return res.stdout.strip()


def resolve_expected_url_from_config(remote_name, cwd=None):
    """Attempts to find the target's configured URL from .repo-push/config.yaml."""
    root = Path(cwd or ".").resolve()
    cfg_path = root / ".repo-push" / "config.yaml"
    if cfg_path.exists():
        try:
            import yaml
            data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "targets" in data:
                for t in data.get("targets", []):
                    if t.get("name") == remote_name:
                        return t.get("url")
        except Exception:
            pass
    return None


def validate_remote(remote_name, expected_url=None, cwd=None):
    """
    Verifies that the remote exists and checks that configured remote push URLs
    match the expected target URL declared in config or CLI.
    """
    res = git_cmd(["remote"], cwd=cwd, check=False)
    remotes = [r.strip() for r in res.stdout.splitlines() if r.strip()]
    if remote_name not in remotes:
        raise ValueError(f"Remote '{remote_name}' does not exist. Configured remotes: {remotes}")

    if not expected_url:
        expected_url = resolve_expected_url_from_config(remote_name, cwd=cwd)

    if expected_url:
        # Check all push URLs configured for this remote
        url_res = git_cmd(["remote", "get-url", "--push", "--all", remote_name], cwd=cwd, check=False)
        actual_urls = [u.strip() for u in url_res.stdout.splitlines() if u.strip()]
        if not actual_urls:
            # Fallback to standard get-url
            u_fallback = git_cmd(["remote", "get-url", remote_name], cwd=cwd, check=False)
            actual_urls = [u.strip() for u in u_fallback.stdout.splitlines() if u.strip()]

        for actual_url in actual_urls:
            if actual_url != expected_url:
                raise ValueError(
                    f"Remote push URL mismatch for '{remote_name}': expected target URL '{expected_url}', "
                    f"but git remote is configured with '{actual_url}'."
                )
    return True


def validate_target_branch(branch_name, cwd=None):
    """Validates target branch name using Git ref-format rules."""
    res = git_cmd(["check-ref-format", "--branch", branch_name], cwd=cwd, check=False)
    if res.returncode != 0:
        raise ValueError(f"Invalid Git branch name '{branch_name}': violates ref-format rules.")
    return True


def verify_tree_exclusions(worktree_dir, exclude_patterns):
    """Verifies that no excluded patterns remain in the published tree."""
    if not exclude_patterns:
        return
    res = git_cmd(["ls-files"], cwd=worktree_dir)
    tracked_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
    
    violated = []
    for pat in exclude_patterns:
        pat_clean = pat.rstrip("/\\")
        for f in tracked_files:
            if fnmatch.fnmatch(f, pat) or f == pat_clean or f.startswith(pat_clean + "/"):
                violated.append(f)
    if violated:
        raise RuntimeError(f"Exclusion verification FAILED! Excluded files still present in published tree: {violated}")


def publish_target(
    remote_name,
    target_branch="main",
    mode="history_preserving",
    exclude_patterns=None,
    push_tags=False,
    dry_run=False,
    expected_url=None,
    cwd=None
):
    """
    Publishes the repository to a target remote using an isolated Git worktree.
    Guarantees user working copy is NEVER switched or altered.
    """
    if exclude_patterns is None:
        exclude_patterns = []

    # 1. Input validations
    for pat in exclude_patterns:
        if pat in ("/", "\\", ".", "*") or ".." in pat:
            raise ValueError(f"Dangerous exclusion pattern rejected: '{pat}'")

    validate_target_branch(target_branch, cwd=cwd)
    validate_remote(remote_name, expected_url=expected_url, cwd=cwd)
    head_commit = get_current_commit(cwd=cwd)

    # 2. Tag leak defense: Clean snapshot must not push historical tags
    if mode == "clean_snapshot" and push_tags:
        raise ValueError(
            "Pushing global tags with '--tags' is forbidden in 'clean_snapshot' mode. "
            "Existing repository tags point to previous commits containing excluded history. "
            "To publish tags on a clean snapshot, tag the snapshot commit directly after publishing."
        )

    # 3. Print operational notices
    print(f"\n[GIT PUBLISHER] Target: '{remote_name}' (branch: '{target_branch}', mode: '{mode}')")
    if mode == "history_preserving":
        print("[NOTICE] Mode 'history_preserving': Exclusions are removed from the latest release commit only. Historical commits in ancestry still contain earlier revisions.")
    elif mode == "clean_snapshot":
        print("[NOTICE] Mode 'clean_snapshot': Publishing an isolated orphan commit with zero prior history.")

    if dry_run:
        print("[NOTICE] DRY-RUN MODE: Simulating push; remote refs will not be updated.")

    run_id = uuid.uuid4().hex[:8]
    temp_branch = f"__repo_push_pub_{run_id}"
    base_dir = cwd if cwd else os.path.abspath(".")
    worktree_dir = os.path.join(base_dir, ".audit", ".scratch", "worktrees", f"wt_{run_id}")

    # Ensure temp branch does not already exist
    check_branch = git_cmd(["rev-parse", "--verify", "--quiet", f"refs/heads/{temp_branch}"], cwd=cwd, check=False)
    if check_branch.returncode == 0:
        raise RuntimeError(f"Temporary reference '{temp_branch}' already exists. Aborting to avoid collision.")

    os.makedirs(os.path.dirname(worktree_dir), exist_ok=True)
    cleanup_warnings = []

    try:
        # Create isolated worktree
        print(f"[WORKTREE] Creating isolated worktree at '{worktree_dir}' on ref '{temp_branch}'...")
        git_cmd(["worktree", "add", "-b", temp_branch, worktree_dir, head_commit], cwd=cwd)

        if mode == "history_preserving":
            if exclude_patterns:
                print(f"[FILTER] Applying {len(exclude_patterns)} exclusion filter(s)...")
                for pat in exclude_patterns:
                    git_cmd(["rm", "-r", "--cached", "--ignore-unmatch", pat], cwd=worktree_dir, check=False)

                status_res = git_cmd(["status", "--porcelain"], cwd=worktree_dir)
                if status_res.stdout.strip():
                    commit_msg = f"publish: release to {remote_name} (platform filtered)"
                    git_cmd(["commit", "-m", commit_msg], cwd=worktree_dir)
                    print(f"[COMMIT] Created platform release commit on '{temp_branch}'.")
                else:
                    print(f"[INFO] No excluded files found in tree; publishing HEAD commit directly.")

        elif mode == "clean_snapshot":
            orphan_branch = f"{temp_branch}_orphan"
            print(f"[CLEAN SNAPSHOT] Creating orphan single-commit snapshot...")
            git_cmd(["checkout", "--orphan", orphan_branch], cwd=worktree_dir)
            if exclude_patterns:
                for pat in exclude_patterns:
                    git_cmd(["rm", "-r", "--cached", "--ignore-unmatch", pat], cwd=worktree_dir, check=False)
            git_cmd(["commit", "-m", f"publish: clean snapshot release to {remote_name}"], cwd=worktree_dir)
            temp_branch = orphan_branch
        else:
            raise ValueError(f"Unknown publishing mode: '{mode}'.")

        # Verify exclusion policy against resulting worktree tree
        verify_tree_exclusions(worktree_dir, exclude_patterns)

        # Push to remote
        push_args = [remote_name, f"{temp_branch}:{target_branch}"]
        if push_tags and mode != "clean_snapshot":
            push_args.append("--tags")
        if dry_run:
            push_args.append("--dry-run")

        print(f"[PUSH] Executing: git push {' '.join(push_args)}")
        git_cmd(["push"] + push_args, cwd=worktree_dir)
        print(f"[SUCCESS] Published to '{remote_name}/{target_branch}' successfully.")
        return True, cleanup_warnings

    finally:
        # Guaranteed cleanup with explicit error reporting
        if os.path.exists(worktree_dir):
            res = git_cmd(["worktree", "remove", "--force", worktree_dir], cwd=cwd, check=False)
            if res.returncode != 0:
                cleanup_warnings.append(f"worktree remove: {res.stderr.strip()}")
            if os.path.exists(worktree_dir):
                try:
                    shutil.rmtree(worktree_dir)
                except Exception as e:
                    cleanup_warnings.append(f"rmtree {worktree_dir}: {e}")

        res = git_cmd(["worktree", "prune"], cwd=cwd, check=False)
        if res.returncode != 0:
            cleanup_warnings.append(f"worktree prune: {res.stderr.strip()}")

        res = git_cmd(["branch", "-D", temp_branch], cwd=cwd, check=False)
        if res.returncode != 0:
            cleanup_warnings.append(f"branch -D {temp_branch}: {res.stderr.strip()}")

        orphan_branch = f"{temp_branch}_orphan"
        git_cmd(["branch", "-D", orphan_branch], cwd=cwd, check=False)

        if cleanup_warnings:
            print(f"[CLEANUP WARNING] Cleanup encountered issues: {'; '.join(cleanup_warnings)}", file=sys.stderr)
        else:
            print("[CLEANUP] Workspace restored cleanly. Original user branch and index untouched.")


def main():
    parser = argparse.ArgumentParser(description="Deterministic Git Publisher with Worktree Isolation")
    # Accept both --remote and --target
    parser.add_argument("--remote", "-r", "--target", "-t", dest="remote", required=True,
                        help="Git remote name (e.g. origin, gitlab)")
    parser.add_argument("--branch", "-b", default="main", help="Target remote branch (default: main)")
    parser.add_argument("--mode", "-m", choices=["history_preserving", "clean_snapshot"], default="history_preserving",
                        help="Publishing mode (default: history_preserving)")
    parser.add_argument("--exclude", "-e", action="append", default=[], help="File pattern to exclude (repeatable)")
    parser.add_argument("--tags", action="store_true", help="Push tags (forbidden in clean_snapshot mode)")
    parser.add_argument("--dry-run", action="store_true", help="Execute dry-run without network changes")
    parser.add_argument("--expected-url", default=None, help="Verify that remote URL matches this expected value")

    args = parser.parse_args()

    try:
        with PublishingLock():
            success, cleanup_warnings = publish_target(
                remote_name=args.remote,
                target_branch=args.branch,
                mode=args.mode,
                exclude_patterns=args.exclude,
                push_tags=args.tags,
                dry_run=args.dry_run,
                expected_url=args.expected_url
            )
            if not success:
                return 1
            if cleanup_warnings:
                print(f"[STATUS: PUBLISHED_WITH_CLEANUP_FAILURE] Push succeeded to '{args.remote}/{args.branch}', but cleanup warning(s) occurred: {'; '.join(cleanup_warnings)}", file=sys.stderr)
                return 2
            print(f"[STATUS: PUBLISHED] Published to '{args.remote}/{args.branch}' cleanly with zero warnings.")
            return 0
    except Exception as e:
        print(f"[PUBLISHER ERROR] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
