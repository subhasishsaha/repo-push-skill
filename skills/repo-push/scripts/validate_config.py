#!/usr/bin/env python3
"""
validate_config.py — Zero-dependency Validator for .repo-push/config.yaml & .repo-push/actions.yaml
Parses and validates configuration and enforces strict cross-referencing between actions and remotes.
"""

import os
import re
import sys

VALID_PLATFORMS = {"github", "gitlab", "huggingface", "bitbucket", "generic"}
VALID_URL_PREFIXES = ("https://", "http://", "git@", "ssh://")


def parse_simple_yaml(text):
    """
    Lightweight, zero-dependency YAML parser for standard .repo-push/config.yaml structures.
    """
    data = {}
    current_target = None
    targets = []
    current_section = None
    current_list_field = None

    lines = text.splitlines()
    for raw_line in lines:
        line = raw_line.rstrip()
        if "#" in line and not ("http://" in line or "https://" in line):
            line = re.sub(r"\s+#.*$", "", line)

        stripped = line.strip()
        if not stripped:
            continue

        indent = len(line) - len(line.lstrip())

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

        elif current_section == "pre_push" and indent >= 2:
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                k = k.strip()
                v = v.strip()
                if k == "require_all_gates":
                    data["pre_push"][k] = (v.lower() == "true")
                elif k == "min_readiness_score":
                    try:
                        data["pre_push"][k] = int(v)
                    except ValueError:
                        data["pre_push"][k] = v
                elif k == "dry_run":
                    data["pre_push"][k] = (v.lower() == "true")

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


def parse_simple_actions_yaml(text):
    """
    Lightweight YAML parser for .repo-push/actions.yaml structures.
    """
    data = {}
    actions = []
    current_action = None
    current_section = None

    lines = text.splitlines()
    for raw_line in lines:
        line = raw_line.rstrip()
        if "#" in line:
            line = re.sub(r"\s+#.*$", "", line)

        stripped = line.strip()
        if not stripped:
            continue

        indent = len(line) - len(line.lstrip())

        if indent == 0:
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                k = k.strip()
                v = v.strip()
                if k == "version":
                    data["version"] = v.strip("\"'")
                elif k == "actions":
                    data["actions"] = actions
                    current_section = "actions"

        elif current_section == "actions":
            if indent == 2 and stripped.startswith("- "):
                current_action = {}
                actions.append(current_action)
                rest = stripped[2:].strip()
                if ":" in rest:
                    k, v = rest.split(":", 1)
                    current_action[k.strip()] = v.strip().strip("\"'")
            elif current_action is not None and ":" in stripped:
                k, v = stripped.split(":", 1)
                k = k.strip()
                v = v.strip()
                if k == "platforms":
                    if v.startswith("[") and v.endswith("]"):
                        items = [p.strip().strip("\"'") for p in v[1:-1].split(",") if p.strip()]
                        current_action["platforms"] = items
                    else:
                        current_action["platforms"] = v.strip("\"'")
                else:
                    current_action[k] = v.strip("\"'")

    return data


def validate_config_data(data):
    errors = []

    version = data.get("version")
    if not version:
        errors.append("Missing required top-level field 'version'.")
    elif version != "1.0":
        errors.append(f"Invalid 'version': expected '1.0', got '{version}'.")

    targets = data.get("targets")
    seen_target_names = set()

    if targets is None:
        errors.append("Missing required field 'targets'.")
    elif not isinstance(targets, list) or len(targets) == 0:
        errors.append("'targets' must be a non-empty list of destination remotes.")
    else:
        for idx, t in enumerate(targets):
            prefix = f"targets[{idx}]"
            name = t.get("name")
            if not name:
                errors.append(f"{prefix}: Missing required field 'name'.")
            elif not re.match(r"^[a-zA-Z0-9_-]+$", str(name)):
                errors.append(f"{prefix}.name: '{name}' contains invalid characters (use alphanum, hyphen, underscore).")
            elif name in seen_target_names:
                errors.append(f"{prefix}.name: Duplicate target name '{name}' detected. Target names must be unique.")
            else:
                seen_target_names.add(name)

            platform = t.get("platform")
            if not platform:
                errors.append(f"{prefix}: Missing required field 'platform'.")
            elif platform not in VALID_PLATFORMS:
                errors.append(f"{prefix}.platform: '{platform}' is invalid. Allowed: {sorted(VALID_PLATFORMS)}.")

            url = t.get("url")
            if not url:
                errors.append(f"{prefix}: Missing required field 'url'.")
            elif not re.match(r"^((https?|ssh)://[a-zA-Z0-9_.-]+(:[0-9]+)?/.*|git@[a-zA-Z0-9_.-]+:.*)$", str(url)):
                errors.append(f"{prefix}.url: '{url}' is not a valid Git URL format (expected https://, ssh://, or git@).")

            excludes = t.get("exclude", [])
            if isinstance(excludes, list):
                for exc in excludes:
                    if exc in ("/", "\\", ".", "*"):
                        errors.append(f"{prefix}.exclude: Dangerous root pattern '{exc}' is not allowed.")
                    elif ".." in exc:
                        errors.append(f"{prefix}.exclude: Path traversal '..' in '{exc}' is not allowed.")

    return errors


def validate_actions_data(actions_data, configured_platforms):
    errors = []

    version = actions_data.get("version")
    if not version:
        errors.append("actions.yaml: Missing required field 'version'.")
    elif version != "1.0":
        errors.append(f"actions.yaml: Invalid 'version': expected '1.0', got '{version}'.")

    actions = actions_data.get("actions")
    seen_action_names = set()

    if actions is None:
        errors.append("actions.yaml: Missing required field 'actions'.")
    elif not isinstance(actions, list) or len(actions) == 0:
        errors.append("actions.yaml: 'actions' must be a non-empty list.")
    else:
        for idx, act in enumerate(actions):
            prefix = f"actions[{idx}]"
            name = act.get("name")
            if not name:
                errors.append(f"{prefix}: Missing required field 'name'.")
            elif not re.match(r"^[a-zA-Z0-9_-]+$", str(name)):
                errors.append(f"{prefix}.name: '{name}' contains invalid characters.")
            elif name in seen_action_names:
                errors.append(f"{prefix}.name: Duplicate workflow name '{name}' detected. Action names must be unique.")
            else:
                seen_action_names.add(name)

            desc = act.get("description")
            if not desc or len(str(desc).strip()) < 5:
                errors.append(f"{prefix}: 'description' is required and must be descriptive (at least 5 characters).")

            platforms = act.get("platforms", "all")
            if isinstance(platforms, list):
                if not platforms:
                    errors.append(f"{prefix}.platforms: List cannot be empty.")
                for p in platforms:
                    if p not in VALID_PLATFORMS and p != "all":
                        errors.append(f"{prefix}.platforms: Unknown platform '{p}'.")
                    elif p != "all" and p not in configured_platforms:
                        # STRICT CROSS-VALIDATION ERROR
                        errors.append(
                            f"[BLOCKER] ACT-001: Action '{name}' specifies platform '{p}', "
                            f"but '{p}' is not declared in targets of config.yaml! "
                            f"(Configured targets: {sorted(configured_platforms)})"
                        )
            elif isinstance(platforms, str):
                if platforms != "all" and platforms not in VALID_PLATFORMS:
                    errors.append(f"{prefix}.platforms: Unknown platform '{platforms}'.")
                elif platforms != "all" and platforms not in configured_platforms:
                    errors.append(
                        f"[BLOCKER] ACT-001: Action '{name}' specifies platform '{platforms}', "
                        f"but '{platforms}' is not declared in targets of config.yaml! "
                        f"(Configured targets: {sorted(configured_platforms)})"
                    )
                elif platforms == "all" and not configured_platforms:
                    errors.append(
                        f"[BLOCKER] ACT-002: Action '{name}' specifies 'platforms: all', "
                        f"but no target platforms are configured in config.yaml!"
                    )

    return errors


def main():
    target_path = None
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        target_path = sys.argv[1]
    else:
        for candidate in [
            os.path.join(".repo-push", "config.yaml"),
            os.path.join(".repo-push", "config.yml"),
            ".repo-push.yaml",
            ".repo-push.yml",
        ]:
            if os.path.exists(candidate):
                target_path = candidate
                break

    if not target_path or not os.path.exists(target_path):
        print("[ERROR] No .repo-push/config.yaml found to validate.", file=sys.stderr)
        return 1

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"[ERROR] Failed to read '{target_path}': {e}", file=sys.stderr)
        return 1

    data = parse_simple_yaml(content)
    config_errors = validate_config_data(data)

    if config_errors:
        print(f"[FAIL] '{target_path}' failed schema validation ({len(config_errors)} error(s)):")
        for err in config_errors:
            print(f"  - {err}")
        return 1

    targets = data.get("targets", [])
    configured_platforms = {t.get("platform") for t in targets if t.get("platform")}
    print(f"[PASS] '{target_path}' is valid! ({len(targets)} target(s) configured: {', '.join(sorted(configured_platforms))})")

    # Optional actions.yaml check
    actions_path = None
    for candidate in [
        os.path.join(".repo-push", "actions.yaml"),
        os.path.join(".repo-push", "actions.yml"),
    ]:
        if os.path.exists(candidate):
            actions_path = candidate
            break

    if actions_path:
        try:
            with open(actions_path, "r", encoding="utf-8") as f:
                act_content = f.read()
            actions_data = parse_simple_actions_yaml(act_content)
            actions_errors = validate_actions_data(actions_data, configured_platforms)

            if actions_errors:
                print(f"[FAIL] '{actions_path}' failed validation ({len(actions_errors)} error(s)):")
                for err in actions_errors:
                    print(f"  - {err}")
                return 1

            act_count = len(actions_data.get("actions", []))
            print(f"[PASS] '{actions_path}' is valid! ({act_count} action(s) defined, cross-referenced with config.yaml)")
        except Exception as e:
            print(f"[ERROR] Failed to validate '{actions_path}': {e}", file=sys.stderr)
            return 1
    else:
        print("[INFO] No .repo-push/actions.yaml found (optional; standard default templates active).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
