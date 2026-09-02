#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1406 synthetic metadata-drift analytic."""

import json
import pathlib
import unittest


WATCHED_OBJECT_TYPES = {"tool", "server"}
WATCHED_FIELDS = {
    "name",
    "title",
    "description",
    "inputSchema",
    "icons",
    "annotations.readOnlyHint",
    "annotations.destructiveHint",
    "annotations.idempotentHint",
    "annotations.openWorldHint",
}


def matches(event):
    """Implement the documented rule condition over one inert event mapping."""
    changed_fields = event.get("changed_fields")
    if not isinstance(changed_fields, list):
        return False
    return (
        event.get("event_type") == "mcp_metadata_snapshot"
        and event.get("object_type") in WATCHED_OBJECT_TYPES
        and event.get("metadata_changed") is True
        and bool(WATCHED_FIELDS.intersection(changed_fields))
        and event.get("approval_state") != "reapproved"
    )


class MetadataManipulationDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_path = pathlib.Path(__file__).with_name("test-events.json")
        cls.events = json.loads(fixture_path.read_text(encoding="utf-8"))

    def test_every_fixture_matches_expected_result(self):
        for event in self.events:
            with self.subTest(case=event["case"]):
                self.assertEqual(matches(event), event["expected_alert"])

    def test_fixture_suite_covers_required_classes(self):
        classes = {event["case_type"] for event in self.events}
        self.assertTrue({"positive", "negative", "boundary", "malformed", "false_positive_control"} <= classes)

    def test_hash_fields_are_present_for_well_formed_snapshots(self):
        for event in self.events:
            if event["case_type"] != "malformed":
                with self.subTest(case=event["case"]):
                    self.assertIn("metadata_hash", event)
                    self.assertIn("approved_metadata_hash", event)


if __name__ == "__main__":
    unittest.main(verbosity=2)
