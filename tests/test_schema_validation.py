"""
test_schema_validation.py — Validates JSON Schema syntax and draft compatibility.
"""

import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestSchemaValidation(unittest.TestCase):

    def test_config_schema_is_valid_json(self):
        """repo-push.schema.json must be valid JSON with required root fields."""
        schema_path = REPO_ROOT / "schemas" / "repo-push.schema.json"
        data = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(data.get("title"), "RepoPushConfig")
        self.assertIn("targets", data.get("required", []))
        self.assertFalse(data.get("additionalProperties", True))

    def test_actions_schema_is_valid_json(self):
        """repo-push-actions.schema.json must be valid JSON with required root fields."""
        schema_path = REPO_ROOT / "schemas" / "repo-push-actions.schema.json"
        data = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(data.get("title"), "RepoPushActionsConfig")
        self.assertIn("actions", data.get("required", []))
        self.assertFalse(data.get("additionalProperties", True))


if __name__ == "__main__":
    unittest.main()
