#!/usr/bin/env python3
"""
generate_config.py — Deterministic .repo-push.yaml Generator
Inspects git remotes and branch to deterministically generate a canonical .repo-push.yaml
with zero LLM hallucinations, zero token cost, and 100% schema compliance.
"""

import os
import re
import subprocess
import sys

SCHEMA_URL = "https://raw.githubusercontent.com/subhasishsaha/repo-push-skill/main/schemas/repo-push.schema.json"

EXCLUSIONS_MAP = {
    "github": [
        ".gitlab-ci.yml",
        "bitbucket-pipelines.yml",
    ],
    "gitlab": [
        ".github/",
        "bitbucket-pipelines.yml",
    ],
    "huggingface": [
        ".github/",
        ".gitlab-ci.yml",
        "bitbucket-pipelines.yml",
        "tests/",
    ],
    "bitbucket": [
        ".github/",
        ".gitlab-ci.yml",
    ],
    "generic": [],
}


def run_cmd(args):
    try:
        res = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return res.stdout.strip()
    except Exception:
        return ""


def detect_remotes():
    out = run_cmd(["git", "remote", "-v"])
    if not out:
        return {}

    remotes = {}
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            name = parts[0]
            url = parts[1]
            role = parts[2] if len(parts) > 2 else "(push)"
            # Prefer push URL
            if "(push)" in role or name not in remotes:
                remotes[name] = url
    return remotes


def detect_current_branch():
    branch = run_cmd(["git", "branch", "--show-current"])
    if not branch:
        branch = run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    return branch if branch and branch != "HEAD" else "main"


def infer_platform(url):
    url_lower = url.lower()
    if "github.com" in url_lower:
        return "github"
    if "gitlab." in url_lower:
        return "gitlab"
    if "huggingface.co" in url_lower:
        return "huggingface"
    if "bitbucket.org" in url_lower:
        return "bitbucket"
    return "generic"


def get_repo_title():
    cwd = os.path.basename(os.path.abspath(os.getcwd()))
    # Clean up dashes/underscores for human title
    title = re.sub(r"[-_]+", " ", cwd).title()
    return title or "My Application"


def build_yaml_content(targets, require_confirmation=True):
    lines = [
        f"# yaml-language-server: $schema={SCHEMA_URL}",
        'version: "1.0"',
        "",
        f"require_confirmation: {'true' if require_confirmation else 'false'}",
        "",
        "pre_push:",
        "  min_readiness_score: 100",
        "  dry_run: true",
        "",
        "targets:",
    ]

    for t in targets:
        lines.append(f"  - name: {t['name']}")
        lines.append(f"    platform: {t['platform']}")
        lines.append(f"    url: {t['url']}")
        lines.append(f"    branch: {t['branch']}")
        lines.append(f"    push_tags: {'true' if t.get('push_tags') else 'false'}")

        excludes = t.get("exclude", [])
        if excludes:
            lines.append("    exclude:")
            for exc in excludes:
                lines.append(f"      - {exc}")

        if t["platform"] == "huggingface":
            meta = t.get("metadata", {})
            lines.append("    metadata:")
            lines.append(f"      title: \"{meta.get('title', get_repo_title())}\"")
            lines.append(f"      emoji: \"{meta.get('emoji', '🚀')}\"")
            lines.append(f"      colorFrom: \"{meta.get('colorFrom', 'indigo')}\"")
            lines.append(f"      colorTo: \"{meta.get('colorTo', 'purple')}\"")
            lines.append(f"      sdk: \"{meta.get('sdk', 'gradio')}\"")
            lines.append(f"      app_file: \"{meta.get('app_file', 'app.py')}\"")
            lines.append("      pinned: false")
            lines.append("    lfs_patterns:")
            lines.append("      - \"*.safetensors\"")
            lines.append("      - \"*.bin\"")
            lines.append("      - \"*.onnx\"")

        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main():
    force = "--force" in sys.argv or "-f" in sys.argv
    dry_run = "--dry-run" in sys.argv
    output_path = ".repo-push.yaml"

    for i, arg in enumerate(sys.argv):
        if arg in ("--output", "-o") and i + 1 < len(sys.argv):
            output_path = sys.argv[i + 1]

    if not force and not dry_run:
        for candidate in [".repo-push.yaml", ".repo-push.yml"]:
            if os.path.exists(candidate):
                print(f"[INFO] '{candidate}' already exists. Use --force to overwrite.")
                return 0

    remotes = detect_remotes()
    branch = detect_current_branch()

    targets = []
    if remotes:
        for name, url in remotes.items():
            platform = infer_platform(url)
            excludes = EXCLUSIONS_MAP.get(platform, [])
            targets.append({
                "name": name,
                "platform": platform,
                "url": url,
                "branch": branch,
                "push_tags": (name in ("origin", "github")),
                "exclude": excludes,
                "metadata": {
                    "title": get_repo_title(),
                    "emoji": "🚀",
                    "sdk": "gradio",
                    "app_file": "app.py"
                }
            })
    else:
        # Fallback minimal target
        targets.append({
            "name": "origin",
            "platform": "github",
            "url": "https://github.com/username/repository.git",
            "branch": branch,
            "push_tags": True,
            "exclude": EXCLUSIONS_MAP["github"]
        })

    yaml_text = build_yaml_content(targets)

    if dry_run:
        print(yaml_text)
        return 0

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(yaml_text)
        target_summary = ", ".join(f"{t['name']} ({t['platform']})" for t in targets)
        print(f"[SUCCESS] Generated '{output_path}' with target(s): {target_summary}")
        return 0
    except Exception as e:
        print(f"[ERROR] Failed to write '{output_path}': {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
