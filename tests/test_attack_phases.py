import copy
import re
import tempfile
import unittest
from pathlib import Path

from uac_parser.enrich.attack_phases import (
    AttackPhaseRegistryError,
    enrich_attack_phases,
    load_attack_phase_registry,
    load_attack_phase_registry_file,
    phases_for_techniques,
    validate_attack_phase_registry,
)
from uac_parser.enrich.rule_registry import load_registry
from uac_parser.timeline.event import TimelineEvent


class AttackPhaseTests(unittest.TestCase):
    def test_registry_is_current_and_covers_detection_pack_techniques(self) -> None:
        phase_registry = load_attack_phase_registry()
        detection_registry = load_registry()
        referenced = {
            technique
            for section in (
                "tool_tags",
                "ttp_tags",
                "actor_similarity_profiles",
                "malware_payload_tags",
            )
            for rule in detection_registry[section].values()
            for field in ("mitre", "mitre_focus")
            for technique in rule.get(field, [])
        }
        parser_references = {
            technique
            for path in (Path(__file__).resolve().parents[1] / "uac_parser").rglob(
                "*.py"
            )
            for technique in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", path.read_text())
        }

        self.assertEqual(phase_registry["metadata"]["attack_version"], "19.1")
        self.assertEqual(len(phase_registry["phases"]), 15)
        self.assertEqual(
            (referenced | parser_references) - set(phase_registry["techniques"]),
            set(),
        )

    def test_behavior_and_state_evidence_keep_confirmed_phases_separate(self) -> None:
        behavior = TimelineEvent(mitre=["T1078"])
        contextual = TimelineEvent(
            event_category="persistence",
            tags=["persistence"],
            mitre=["T1053.003"],
        )
        state = TimelineEvent(
            evidence_role="state_observation",
            mitre_candidates=["T1556.003"],
        )

        enrich_attack_phases([behavior, contextual, state])

        self.assertEqual(
            behavior.attack_phase_candidates,
            ["initial_access", "persistence", "privilege_escalation", "stealth"],
        )
        self.assertEqual(behavior.attack_phases, [])
        self.assertEqual(contextual.attack_phases, ["persistence"])
        self.assertEqual(contextual.attack_phase_candidates, [])
        self.assertEqual(
            state.attack_phase_candidates,
            ["persistence", "defense_impairment", "credential_access"],
        )
        self.assertEqual(state.attack_phases, [])

    def test_unknown_techniques_are_not_guessed(self) -> None:
        self.assertEqual(phases_for_techniques(["T9999"]), [])

    def test_registry_validation_rejects_unknown_phases_and_duplicate_keys(
        self,
    ) -> None:
        registry = copy.deepcopy(load_attack_phase_registry())
        registry["techniques"]["T1059"] = ["execution", "not_a_phase"]
        with self.assertRaisesRegex(AttackPhaseRegistryError, "unknown phases"):
            validate_attack_phase_registry(registry)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.yml"
            path.write_text(
                "metadata:\n  schema_version: '1.0'\n  schema_version: '1.1'\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AttackPhaseRegistryError, "duplicate key"):
                load_attack_phase_registry_file(path)


if __name__ == "__main__":
    unittest.main()
