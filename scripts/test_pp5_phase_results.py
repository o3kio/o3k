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
