import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from write_pp5_phase_results import main


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


class PhaseResultsTest(unittest.TestCase):
    def run_writer(self, directory: Path, phase: str = "integrated") -> None:
        old_argv = sys.argv
        try:
            sys.argv = [
                "write_pp5_phase_results.py",
                str(directory),
                "--source-sha",
                "a" * 40,
                "--phase",
                phase,
            ]
            self.assertEqual(main(), 0)
        finally:
            sys.argv = old_argv

    def seed_s5(self, directory: Path) -> None:
        phases = [
            ("initial-scale-checkpoint", 5),
            ("pre-drain", 5),
            ("post-drain", 4),
            ("post-remove", 4),
            ("post-replacement", 5),
            ("post-reboot", 5),
        ]
        for phase, count in phases:
            write(directory / f"p15-7-scale-checkpoint-{phase}.json", {"phase": phase, "eligible_ready_count": count})

    def seed_boundary(self, directory: Path, tier: str, count: int) -> None:
        blocks = [
            {"block_id": f"00000000-0000-4000-8000-{index:012d}",
             "execution_identity": identity}
            for index, identity in enumerate(
                ["compute-agent", "block-a"][:count], start=1
            )
        ]
        write(directory / "p15-7-boundary-smoke-evidence.json", {
            "artifact_type": "o3k-pp5-boundary-smoke-evidence",
            "schema_version": 1,
            "phase": f"{tier.lower()}-boundary",
            "status": "passed",
            "tier": tier,
            "profile": "small-edge-cloud",
            "execution_environment": "nested-host-development",
            "tested_source_sha": "a" * 40,
            "eligible_ready_count": count,
            "eligible_blocks": blocks,
            "bootstrap_block_id": blocks[0]["block_id"],
            "additional_block_ids": [item["block_id"] for item in blocks[1:]],
            "guest_lifecycle": {"status": "passed", "created": True, "active": True, "deleted": True},
            "cleanup": {"status": "passed", "owned_domains_remaining": 0,
                        "owned_resources_remaining": 0, "foreign_state_unchanged": True},
            "multi_host_transition": tier == "S2",
            "redacted": True,
        })

    def test_boundary_smokes_are_separate_and_never_campaign_pass(self):
        for tier, count in (("S1", 1), ("S2", 2)):
            with self.subTest(tier=tier), tempfile.TemporaryDirectory() as directory:
                tmp_path = Path(directory)
                self.seed_boundary(tmp_path, tier, count)
                self.run_writer(tmp_path, f"{tier.lower()}-boundary")
                result = json.loads((tmp_path / f"pp5-{tier.lower()}-boundary-smoke-result.json").read_text())
                overall = json.loads((tmp_path / "pp5-overall-result.json").read_text())
                self.assertEqual(result["status"], "passed")
                self.assertEqual(result["tier"], tier)
                self.assertEqual(result["eligible_ready_count"], count)
                self.assertEqual(overall["overall"], "not_run")

    def test_boundary_smoke_wrong_cardinality_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            self.seed_boundary(tmp_path, "S2", 2)
            path = tmp_path / "p15-7-boundary-smoke-evidence.json"
            value = json.loads(path.read_text())
            value["eligible_ready_count"] = 1
            write(path, value)
            self.run_writer(tmp_path, "s2-boundary")
            result = json.loads((tmp_path / "pp5-s2-boundary-smoke-result.json").read_text())
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["eligible_ready_count"], 1)

    def test_boundary_smoke_rejects_unredacted_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            self.seed_boundary(tmp_path, "S1", 1)
            path = tmp_path / "p15-7-boundary-smoke-evidence.json"
            value = json.loads(path.read_text())
            value["redacted"] = False
            write(path, value)
            self.run_writer(tmp_path, "s1-boundary")
            result = json.loads((tmp_path / "pp5-s1-boundary-smoke-result.json").read_text())
            self.assertEqual(result["status"], "failed")

    def test_s5_pass_is_not_reclassified_when_crash_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            self.seed_s5(tmp_path)
            write(tmp_path / "p15-7-crash-injection-evidence.json", {"status": "failed", "phase": "orphan_discovered"})
            write(tmp_path / "p15-7-host-maintenance-evidence.json", {"status": "passed", "final_eligible_ready_count": 5})
            self.run_writer(tmp_path)
            s5 = json.loads((tmp_path / "pp5-s5-scale-result.json").read_text())
            crash = json.loads((tmp_path / "pp5-1035-crash-recovery-result.json").read_text())
            overall = json.loads((tmp_path / "pp5-overall-result.json").read_text())
            self.assertEqual(s5["status"], "passed")
            self.assertEqual(crash["status"], "failed")
            self.assertEqual(overall["s5_scale"], "passed")
            self.assertEqual(overall["crash_recovery"], "failed")
            self.assertEqual(overall["overall"], "failed")

    def test_focused_s5_ignores_later_phase_status(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            self.seed_s5(tmp_path)
            write(tmp_path / "p15-7-crash-injection-evidence.json", {"status": "failed", "phase": "orphan_discovered"})
            self.run_writer(tmp_path, "s5-scale")
            self.assertEqual(json.loads((tmp_path / "pp5-s5-scale-result.json").read_text())["status"], "passed")
            self.assertEqual(json.loads((tmp_path / "pp5-1035-crash-recovery-result.json").read_text())["status"], "not_run")
            self.assertEqual(json.loads((tmp_path / "pp5-host-maintenance-result.json").read_text())["status"], "not_run")
            self.assertEqual(json.loads((tmp_path / "pp5-overall-result.json").read_text())["overall"], "not_run")

    def test_focused_crash_and_maintenance_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            self.seed_s5(tmp_path)
            write(tmp_path / "p15-7-crash-injection-evidence.json", {"status": "passed", "phase": "completed"})
            self.run_writer(tmp_path, "1035-crash-recovery")
            crash = json.loads((tmp_path / "pp5-1035-crash-recovery-result.json").read_text())
            self.assertEqual(crash["status"], "passed")
            self.assertEqual(json.loads((tmp_path / "pp5-host-maintenance-result.json").read_text())["status"], "not_run")
            self.assertEqual(json.loads((tmp_path / "pp5-overall-result.json").read_text())["overall"], "not_run")

            write(tmp_path / "p15-7-host-maintenance-evidence.json", {"status": "passed", "final_eligible_ready_count": 5})
            self.run_writer(tmp_path, "host-maintenance")
            maintenance = json.loads((tmp_path / "pp5-host-maintenance-result.json").read_text())
            self.assertEqual(maintenance["status"], "passed")
            self.assertEqual(json.loads((tmp_path / "pp5-1035-crash-recovery-result.json").read_text())["status"], "not_run")
            self.assertEqual(json.loads((tmp_path / "pp5-overall-result.json").read_text())["overall"], "not_run")


if __name__ == "__main__":
    unittest.main()
