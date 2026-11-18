#!/usr/bin/env python3
"""
validate_config.py — Robust YAML and JSON Schema Validator for repo-push

Validates:
1. .repo-push/config.yaml against schemas/repo-push.schema.json
2. .repo-push/actions.yaml against schemas/repo-push-actions.schema.json (if present)
3. Enforces business-rule cross-validation:
   - Target name uniqueness
   - Action name uniqueness
   - Strict URL syntax (https://, git@, ssh://)
   - Path traversal prevention in exclusion patterns
   - Platform matching (ACT-001, ACT-002)
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Mandatory dependencies for schema-compliant configuration validation
try:
    import yaml
except ImportError:
    print("[FATAL ERROR] Mandatory dependency 'PyYAML' is not installed. Install via `pip install -r requirements.txt`.", file=sys.stderr)
    sys.exit(1)

try:
    import jsonschema
except ImportError:
    print("[FATAL ERROR] Mandatory dependency 'jsonschema' is not installed. Install via `pip install -r requirements.txt`.", file=sys.stderr)
    sys.exit(1)

VALID_PLATFORMS = {"github", "gitlab", "huggingface", "bitbucket", "generic"}
GIT_URL_REGEX = re.compile(r'^(https?://|git@|ssh://)[a-zA-Z0-9_\.\-]+([:/][a-zA-Z0-9_\.\-]+)+/?(\.git)?$')


def load_yaml(content: str):
    """Parses YAML strictly using PyYAML safe_load."""
    return yaml.safe_load(content)


def load_schema(schema_filename: str, repo_root: Path):
    """Loads schema from schemas/ or skills/repo-push/schemas/. Fails closed if missing."""
    candidates = [
        repo_root / "schemas" / schema_filename,
        repo_root / "skills" / "repo-push" / "schemas" / schema_filename,
    ]
    for c in candidates:
        if c.exists():
            try:
                return json.loads(c.read_text(encoding="utf-8"))
            except Exception as e:
                raise RuntimeError(f"Failed to parse schema '{c}': {e}")
    return None


class ConfigValidator:
    def __init__(self, repo_root: Path = None):
        self.repo_root = (repo_root or Path.cwd()).resolve()

    def validate_schema(self, data: dict, schema_filename: str, label: str):
        """Validates dict against JSON Schema strictly. Fails closed if schema missing or invalid."""
        schema = load_schema(schema_filename, self.repo_root)
        if not schema:
            print(f"[SCHEMA ERROR] Mandatory schema '{schema_filename}' not found in schemas/ or skills/repo-push/schemas/. Validation failed closed.", file=sys.stderr)
            return False

        try:
            jsonschema.validate(instance=data, schema=schema)
            return True
        except jsonschema.ValidationError as e:
            path_str = " -> ".join(str(p) for p in e.path) if e.path else "root"
            print(f"[SCHEMA ERROR] {label} schema violation at '{path_str}': {e.message}", file=sys.stderr)
            return False

    def validate_config_data(self, config_data: dict) -> tuple:
        """Validates config.yaml structure, business rules, and target constraints."""
        errors = []

        if not isinstance(config_data, dict):
            errors.append("Configuration root must be a YAML mapping.")
            return False, errors

        # Validate against schema
        if not self.validate_schema(config_data, "repo-push.schema.json", "config.yaml"):
            errors.append("config.yaml failed JSON Schema validation.")

        targets = config_data.get("targets")
        if targets is None:
            errors.append("Missing required field 'targets'.")
        elif not isinstance(targets, list):
            errors.append("'targets' must be a list of target objects.")
        elif len(targets) == 0:
            errors.append("'targets' list cannot be empty. At least one target remote must be configured.")
        else:
            seen_target_names = set()
            for idx, target in enumerate(targets):
                if not isinstance(target, dict):
                    errors.append(f"Target #{idx+1} must be an object.")
                    continue

                name = target.get("name")
                if not name:
                    errors.append(f"Target #{idx+1} is missing required field 'name'.")
                elif name in seen_target_names:
                    errors.append(f"Duplicate target name '{name}' detected. Every target remote must have a unique name.")
                else:
                    seen_target_names.add(name)

                platform = target.get("platform")
                if not platform:
                    errors.append(f"Target '{name or idx+1}' is missing required field 'platform'.")
                elif platform not in VALID_PLATFORMS:
                    errors.append(f"Target '{name}' has invalid platform '{platform}'. Supported: {sorted(VALID_PLATFORMS)}.")

                url = target.get("url")
                if not url:
                    errors.append(f"Target '{name or idx+1}' is missing required field 'url'.")
                elif not GIT_URL_REGEX.match(url):
                    errors.append(f"Target '{name}' has invalid Git URL '{url}': not a valid Git URL format. Must start with https://, git@, or ssh://.")

                # Exclusion pattern safety
                exclusions = target.get("exclude", [])
                if isinstance(exclusions, list):
                    for pat in exclusions:
                        if not isinstance(pat, str):
                            errors.append(f"Target '{name}' has non-string exclusion pattern: {pat}")
                        elif ".." in pat or pat in ("/", "\\", ".", "*"):
                            errors.append(f"Target '{name}' contains dangerous exclusion pattern '{pat}'. Path traversal '..' and root wildcards are forbidden.")

        return len(errors) == 0, errors

    def validate_actions_data(self, actions_data: dict, config_data: dict = None) -> tuple:
        """Validates actions.yaml structure and cross-validates platforms with config.yaml."""
        errors = []

        if not isinstance(actions_data, dict):
            errors.append("actions.yaml root must be a YAML mapping.")
            return False, errors

        # Validate against schema
        if not self.validate_schema(actions_data, "repo-push-actions.schema.json", "actions.yaml"):
            errors.append("actions.yaml failed JSON Schema validation.")

        actions = actions_data.get("actions", [])
        if not isinstance(actions, list):
            errors.append("'actions' must be a list of action recipes.")
            return False, errors

        active_platforms = set()
        if config_data and "targets" in config_data:
            for t in config_data["targets"]:
                if isinstance(t, dict) and "platform" in t:
                    active_platforms.add(t["platform"])

        seen_action_names = set()
        for idx, act in enumerate(actions):
            if not isinstance(act, dict):
                errors.append(f"Action #{idx+1} must be an object.")
                continue

            name = act.get("name")
            if not name:
                errors.append(f"Action #{idx+1} is missing required field 'name'.")
            elif name in seen_action_names:
                errors.append(f"Duplicate action name '{name}' detected. Every action recipe must have a unique name.")
            else:
                seen_action_names.add(name)

            platforms = act.get("platforms")
            if not platforms:
                errors.append(f"Action '{name or idx+1}' is missing required field 'platforms'.")
            elif isinstance(platforms, list):
                for p in platforms:
                    if p not in VALID_PLATFORMS:
                        errors.append(f"Action '{name}' references invalid platform '{p}'.")
                    elif config_data and p not in active_platforms:
                        errors.append(
                            f"[ACT-001] Action '{name}' specifies platform '{p}', but '{p}' is not declared as a target in config.yaml! "
                            f"Active targets: {list(active_platforms)}."
                        )
            elif platforms == "all":
                if config_data and len(active_platforms) == 0:
                    errors.append(f"[ACT-002] Action '{name}' specifies 'platforms: all', but no targets are defined in config.yaml.")
            else:
                errors.append(f"Action '{name}' has invalid 'platforms' field. Must be 'all' or list of platforms.")

        return len(errors) == 0, errors

    def validate_files(self, config_path: Path, actions_path: Path = None) -> bool:
        """Validates configuration files on disk."""
        if not config_path.exists():
            print(f"[ERROR] Config file '{config_path}' not found.")
            return False

        try:
            config_content = config_path.read_text(encoding="utf-8")
            config_data = load_yaml(config_content)
        except Exception as e:
            print(f"[ERROR] Failed to parse '{config_path}': {e}")
            return False

        cfg_valid, cfg_errors = self.validate_config_data(config_data)
        if not cfg_valid:
            print(f"\n[VALIDATION FAILED] {len(cfg_errors)} error(s) found in '{config_path}':")
            for err in cfg_errors:
                print(f"  - {err}")
            return False

        print(f"[PASS] [VALIDATION PASS] '{config_path}' is valid.")

        if actions_path and actions_path.exists():
            try:
                actions_content = actions_path.read_text(encoding="utf-8")
                actions_data = load_yaml(actions_content)
            except Exception as e:
                print(f"[ERROR] Failed to parse '{actions_path}': {e}")
                return False

            act_valid, act_errors = self.validate_actions_data(actions_data, config_data)
            if not act_valid:
                print(f"\n[VALIDATION FAILED] {len(act_errors)} error(s) found in '{actions_path}':")
                for err in act_errors:
                    print(f"  - {err}")
                return False

            print(f"[PASS] [VALIDATION PASS] '{actions_path}' is valid and matches declared targets.")

        return True


def main():
    parser = argparse.ArgumentParser(description="YAML & JSON Schema Validator for repo-push")
    parser.add_argument("config_pos", nargs="?", default=None, help="Positional path to config.yaml")
    parser.add_argument("--config", default=None, help="Path to config.yaml (default: .repo-push/config.yaml)")
    parser.add_argument("--actions", default=None, help="Path to actions.yaml (default: .repo-push/actions.yaml)")
    args = parser.parse_args()

    repo_root = Path.cwd()
    chosen_config = args.config_pos or args.config
    config_file = Path(chosen_config) if chosen_config else repo_root / ".repo-push" / "config.yaml"
    actions_file = Path(args.actions) if args.actions else repo_root / ".repo-push" / "actions.yaml"

    validator = ConfigValidator(repo_root)
    success = validator.validate_files(config_file, actions_file if actions_file.exists() else None)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
