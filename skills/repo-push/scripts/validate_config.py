#!/usr/bin/env python3
"""
validate_config.py — Zero-dependency Validator for .repo-push.yaml
Parses and mathematically validates .repo-push.yaml against the official schema specification.
"""

import os
import re
import sys

VALID_PLATFORMS = {"github", "gitlab", "huggingface", "bitbucket", "generic"}
VALID_URL_PREFIXES = ("https://", "http://", "git@", "ssh://")


def parse_simple_yaml(text):
    """
    Lightweight, zero-dependency YAML parser for standard .repo-push.yaml structures.
    Handles dictionaries, nested dictionaries, scalar lists, booleans, and integers.
    """
    data = {}
    current_target = None
    targets = []
    current_section = None
    current_list_field = None

    lines = text.splitlines()
    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip()
        # Strip trailing comments unless part of a string
        if "#" in line and not ("http://" in line or "https://" in line):
            line = re.sub(r"\s+#.*$", "", line)

        stripped = line.strip()
        if not stripped:
            continue

        indent = len(line) - len(line.lstrip())

        # Top-level keys (indent 0)
        if indent == 0:
            current_section = None
            current_list_field = None
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                k = k.strip()
                v = v.strip()
                if k == "targets":
                    data["targets"] = targets
                    current_section = "targets"
                elif k == "pre_push":
                    data["pre_push"] = {}
                    current_section = "pre_push"
                elif k == "version":
                    data["version"] = v.strip("\"'")
                elif k == "require_confirmation":
                    data["require_confirmation"] = (v.lower() == "true")
                else:
                    data[k] = v

        # Subsections under pre_push (indent 2)
        elif current_section == "pre_push" and indent >= 2:
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                k = k.strip()
                v = v.strip()
                if k == "min_readiness_score":
                    try:
                        data["pre_push"][k] = int(v)
                    except ValueError:
                        data["pre_push"][k] = v
                elif k == "dry_run":
                    data["pre_push"][k] = (v.lower() == "true")

        # Targets list items
        elif current_section == "targets":
            if indent == 2 and stripped.startswith("- "):
                current_target = {}
                targets.append(current_target)
                current_list_field = None
                rest = stripped[2:].strip()
                if ":" in rest:
                    k, v = rest.split(":", 1)
                    current_target[k.strip()] = v.strip().strip("\"'")
            elif current_target is not None:
                if stripped.startswith("- ") and current_list_field:
                    item = stripped[2:].strip().strip("\"'")
                    current_target.setdefault(current_list_field, []).append(item)
                elif ":" in stripped:
                    k, v = stripped.split(":", 1)
                    k = k.strip()
                    v = v.strip()
                    if v == "":
                        current_list_field = k
                    else:
                        current_list_field = None
                        if v.lower() in ("true", "false"):
                            current_target[k] = (v.lower() == "true")
                        else:
                            current_target[k] = v.strip("\"'")

    return data


def validate_config_data(data):
    errors = []

    # 1. Version check
    version = data.get("version")
    if not version:
        errors.append("Missing required top-level field 'version'.")
    elif version != "1.0":
        errors.append(f"Invalid 'version': expected '1.0', got '{version}'.")

    # 2. Targets check
    targets = data.get("targets")
    if targets is None:
        errors.append("Missing required field 'targets'.")
    elif not isinstance(targets, list) or len(targets) == 0:
        errors.append("'targets' must be a non-empty list of destination remotes.")
    else:
        for idx, t in enumerate(targets):
            prefix = f"targets[{idx}]"
            # Name
            name = t.get("name")
            if not name:
                errors.append(f"{prefix}: Missing required field 'name'.")
            elif not re.match(r"^[a-zA-Z0-9_-]+$", str(name)):
                errors.append(f"{prefix}.name: '{name}' contains invalid characters (use alphanum, hyphen, underscore).")

            # Platform
            platform = t.get("platform")
            if not platform:
                errors.append(f"{prefix}: Missing required field 'platform'.")
            elif platform not in VALID_PLATFORMS:
                errors.append(f"{prefix}.platform: '{platform}' is invalid. Allowed: {sorted(VALID_PLATFORMS)}.")

            # URL
            url = t.get("url")
            if not url:
                errors.append(f"{prefix}: Missing required field 'url'.")
            elif not any(str(url).startswith(p) for p in VALID_URL_PREFIXES):
                errors.append(f"{prefix}.url: '{url}' must start with https://, http://, git@, or ssh://.")

            # Excludes
            excludes = t.get("exclude", [])
            if isinstance(excludes, list):
                for exc in excludes:
                    if exc in ("/", "\\", ".", "*"):
                        errors.append(f"{prefix}.exclude: Dangerous root pattern '{exc}' is not allowed.")

    return errors


def main():
    target_path = None
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        target_path = sys.argv[1]
    else:
        for candidate in [".repo-push.yaml", ".repo-push.yml"]:
            if os.path.exists(candidate):
                target_path = candidate
                break

    if not target_path or not os.path.exists(target_path):
        print("[ERROR] No .repo-push.yaml or .repo-push.yml found to validate.", file=sys.stderr)
        return 1

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"[ERROR] Failed to read '{target_path}': {e}", file=sys.stderr)
        return 1

    data = parse_simple_yaml(content)
    errors = validate_config_data(data)

    if errors:
        print(f"[FAIL] '{target_path}' failed schema validation ({len(errors)} error(s)):")
        for err in errors:
            print(f"  - {err}")
        return 1

    targets_count = len(data.get("targets", []))
    print(f"[PASS] '{target_path}' is valid! ({targets_count} target(s) configured)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
