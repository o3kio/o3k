#!/usr/bin/env python3
import json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).parent
GEN = ROOT / "generate_core_manifest.py"

def run(files, distro="ubuntu"):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        for name, value in files.items():
            (p / name).write_text(value, encoding="utf-8")
        out = subprocess.check_output([sys.executable, str(GEN), str(p), "v0.4.0-rc.22", "1" * 40, "2" * 40, distro], text=True)
        return json.loads(out)

def test_missing_mandatory_is_blocked():
    result = run({"installed-identity.txt": "ok\n"})
    assert result["verdict"] == "BLOCKED"
    assert result["gates"]["canonical_replay"] == "NOT PROVEN"

def test_optional_debian_horizon_does_not_upgrade_missing_core():
    result = run({"horizon-summary.txt": "RESULT: no repeat\n"}, "debian")
    assert result["gates"]["horizon"] == "NOT_APPLICABLE_OPTIONAL"
    assert result["verdict"] == "BLOCKED"

if __name__ == "__main__":
    test_missing_mandatory_is_blocked()
    test_optional_debian_horizon_does_not_upgrade_missing_core()
    print("core manifest tests: PASS")
