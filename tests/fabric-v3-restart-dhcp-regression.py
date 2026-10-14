#!/usr/bin/env python3
"""Execute the exact post-restart collector and validator with local fixtures."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).with_name("fabric-v3-retirement-microgate.sh").read_text()
VALIDATOR = SOURCE.split("import json,sys\nauthority=", 1)[1].split("\nPY\n", 1)[0]
VALIDATOR = "import json,sys\nauthority=" + VALIDATOR
COLLECTOR = SOURCE.split("<<'PYDHCPRESTART'", 1)[1].split("import json,pathlib,sys\nrun,realm=sys.argv[1:]; root=", 1)[1]
COLLECTOR = "import json,pathlib,sys\nrun,realm=sys.argv[1:]; root=" + COLLECTOR.split("\nPYDHCPRESTART", 1)[0]
MACS = ["02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"]
IPS = ["10.77.0.2", "10.77.0.3", "10.77.0.4"]


class RestartDhcpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.authority = {"root_is_symlink": False, "files": {
            "state.json": {"bindings": {"a": {}, "b": {}}},
            "fabric-dhcp-ownership.json": {},
            "dnsmasq.conf": {"text": "".join(
                f"dhcp-host={mac},{ip}\n" for mac, ip in zip(MACS[:2], IPS[:2]))},
            "dnsmasq.leases": None,
        }}
        self.departing = {"root_is_symlink": False, "files": {
            "state.json": {"bindings": {}, "config": None},
            "fabric-dhcp-ownership.json": {"withdrawn": True, "pending": False},
            "dnsmasq.conf": None, "dnsmasq.leases": None,
        }}

    def tearDown(self):
        self.temp.cleanup()

    def validate(self, authority=None, departing=None):
        a, c = self.root / "a.json", self.root / "c.json"
        a.write_text(json.dumps(authority if authority is not None else self.authority))
        c.write_text(json.dumps(departing if departing is not None else self.departing))
        return subprocess.run(
            ["python3", "-c", VALIDATOR, str(a), str(c), "a", "b", "c", *MACS, *IPS],
            capture_output=True, check=False,
        ).returncode

    def test_survivors_pass_without_dynamic_lease_file(self):
        self.assertEqual(self.validate(), 0)

    def test_departed_rendered_files_block_pass(self):
        for name in ("dnsmasq.conf", "dnsmasq.leases"):
            with self.subTest(name=name):
                value = copy.deepcopy(self.departing)
                value["files"][name] = {"text": "stale"}
                self.assertNotEqual(self.validate(departing=value), 0)

    def test_departed_authority_binding_blocks_pass(self):
        value = copy.deepcopy(self.authority)
        value["files"]["state.json"]["bindings"]["c"] = {}
        self.assertNotEqual(self.validate(authority=value), 0)

    def test_wrong_current_ip_mapping_blocks_pass(self):
        value = copy.deepcopy(self.authority)
        value["files"]["dnsmasq.conf"]["text"] = (
            f"dhcp-host={MACS[0]},{IPS[1]}\ndhcp-host={MACS[1]},{IPS[0]}\n")
        self.assertNotEqual(self.validate(authority=value), 0)

    def test_symlinked_state_file_blocks_pass(self):
        value = copy.deepcopy(self.departing)
        value["files"]["state.json"] = {"symlink": True}
        self.assertNotEqual(self.validate(departing=value), 0)

    def test_missing_observation_or_symlink_blocks_pass(self):
        for target in ("authority", "departing"):
            for mutation in ("missing", "symlink"):
                with self.subTest(target=target, mutation=mutation):
                    value = copy.deepcopy(getattr(self, target))
                    if mutation == "missing":
                        del value["files"]["dnsmasq.conf"]
                    else:
                        value["root_is_symlink"] = True
                    self.assertNotEqual(self.validate(**{target: value}), 0)

    def test_authority_collector_emits_required_root_observation(self):
        code = SOURCE.split("<<'PYDHCPRESTARTA'", 1)[1].split("import json,pathlib,sys\n", 1)[1]
        code = "import json,pathlib,sys\n" + code.split("\nPYDHCPRESTARTA", 1)[0]
        code = code.replace("/var/lib/o3k-fabric-v3", str(self.root))
        result = subprocess.run(["python3", "-c", code, "run", "realm"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIs(json.loads(result.stdout)["root_is_symlink"], False)

    def test_collector_rejects_nonregular_state_path(self):
        directory = self.root / "run/network/dhcp/fabric/realm"
        directory.mkdir(parents=True)
        (directory / "state.json").mkdir()
        code = COLLECTOR.replace("/var/lib/o3k-fabric-v3", str(self.root))
        result = subprocess.run(["python3", "-c", code, "run", "realm"],
                                capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_collector_observes_actual_departed_files(self):
        directory = self.root / "run/network/dhcp/fabric/realm"
        directory.mkdir(parents=True)
        (directory / "dnsmasq.conf").write_text("stale config")
        code = COLLECTOR.replace("/var/lib/o3k-fabric-v3", str(self.root))
        result = subprocess.run(["python3", "-c", code, "run", "realm"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["files"]["dnsmasq.conf"],
                         {"text": "stale config"})
        directory.rename(directory.with_name("foreign"))
        directory.symlink_to(directory.with_name("foreign"), target_is_directory=True)
        result = subprocess.run(["python3", "-c", code, "run", "realm"],
                                capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
