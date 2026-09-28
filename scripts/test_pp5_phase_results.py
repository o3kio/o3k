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
    def test_s5_pass_is_not_reclassified_when_crash_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            phases = [
                ("initial-scale-checkpoint", 5),
                ("pre-drain", 5),
                ("post-drain", 4),
                ("post-remove", 4),
                ("post-replacement", 5),
                ("post-reboot", 5),
            ]
            for phase, count in phases:
                write(tmp_path / f"p15-7-scale-checkpoint-{phase}.json", {"phase": phase, "eligible_ready_count": count})
            write(tmp_path / "p15-7-crash-injection-evidence.json", {"status": "failed", "phase": "orphan_discovered"})
            write(tmp_path / "p15-7-host-maintenance-evidence.json", {"status": "passed", "final_eligible_ready_count": 5})
            old_argv = sys.argv
            try:
                sys.argv = ["write_pp5_phase_results.py", str(tmp_path), "--source-sha", "a" * 40]
                self.assertEqual(main(), 0)
            finally:
                sys.argv = old_argv
            s5 = json.loads((tmp_path / "pp5-s5-scale-result.json").read_text())
            crash = json.loads((tmp_path / "pp5-1035-crash-recovery-result.json").read_text())
            overall = json.loads((tmp_path / "pp5-overall-result.json").read_text())
            self.assertEqual(s5["status"], "passed")
            self.assertEqual(crash["status"], "failed")
            self.assertEqual(overall["s5_scale"], "passed")
            self.assertEqual(overall["crash_recovery"], "failed")
            self.assertEqual(overall["overall"], "failed")


if __name__ == "__main__":
    unittest.main()
