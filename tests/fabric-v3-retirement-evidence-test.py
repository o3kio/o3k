#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("fabric-v3-retirement-evidence.py")
SPEC = importlib.util.spec_from_file_location("fabric_v3_retirement_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class RetirementEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for directory in (
            "before-departure/plans",
            "environment",
            "survivor-convergence/plans",
            "survivor-convergence/host-a",
            "survivor-convergence/host-b",
            "c-delete/remove-command",
            "c-delete/retirement-obligation",
            "provider-absence/host-c/ownership",
        ):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self._write("before-departure/plans/host-a.json", {"directory_generation": 4})
        self._write("environment/fabric-identities.json", [
            {"host_id": f"host-{host}", "fabric_transport_ip": f"100.64.3.{index}"}
            for index, host in enumerate("abc", 1)
        ])
        prior = self._work("host-c", "Apply", "succeeded", 1, ["host-a", "host-b", "host-c"], ["host-a", "host-b"])
        remove = self._work("host-c", "Remove", "succeeded", 2, ["host-a", "host-b"], [])
        remove_command = {**remove, "local_host": "host-c"}
        apply_a = self._work("host-a", "Apply", "succeeded", 3, ["host-a", "host-b"], ["host-b"])
        apply_b = self._work("host-b", "Apply", "succeeded", 4, ["host-a", "host-b"], ["host-a"])
        self._write("c-delete/remove-command/c-remove-command.json", {
            "found": True, "matches": [remove_command], **remove_command
        })
        self._write("c-delete/retirement-obligation/c-prior-apply.json", {"c_prior_apply": prior})
        self._write("survivor-convergence/plans/durable-work.json", {
            "history": [prior, remove, apply_a, apply_b]
        })
        self._write("provider-absence/host-c/ownership/ownership.json", {"realms": {}})
        for host, peer, peer_ip, local_generation in (
            ("host-a", "host-b", "100.64.3.2", 2),
            ("host-b", "host-a", "100.64.3.1", 3),
        ):
            own_port = "port-a" if host == "host-a" else "port-b"
            peer_port = "port-b" if host == "host-a" else "port-a"
            self._write(f"survivor-convergence/{host}/ownership.json", {
                "realms": {"realm": {
                    "directory_generation": 5,
                    "local_fabric_generation": local_generation,
                    "vxlan": {"flood_peers": [peer_ip]},
                    "endpoint_taps": {own_port: {"interface": f"tap-{host}"}},
                    "pending_endpoint_taps": {},
                }}
            })
            self._write(f"survivor-convergence/{host}/plan.json", {
                "realm_id": "realm", "local_host": host, "directory_generation": 5,
                "local_fabric_generation": local_generation,
                "directory": {"entries": [
                    {"endpoint_id": own_port, "selected_host": host},
                    {"endpoint_id": peer_port, "selected_host": peer},
                ]},
                "peers": [{"host_id": peer}],
            })
            self._write(f"survivor-convergence/{host}/fdb.txt", f"00:00:00:00:00:00 dst {peer_ip} self permanent\n")
            self._write(f"survivor-convergence/{host}/command-journal.json", {"plans": [{
                "action": "Apply", "status": "Succeeded",
                "plan": {"fabric": {"realm_id": "realm"}},
                "target": {"agent_id": f"network-agent-{host[-1]}"},
            }]})

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value))

    @staticmethod
    def _work(host, action, state, insertion, participants, her):
        return {
            "target_host_id": host, "target_agent_id": f"network-agent-{host[-1]}",
            "target_agent_epoch": f"epoch-{host[-1]}",
            "action": action, "state": state, "insertion_order": insertion,
            "command_id": f"cmd-{host}-{insertion}", "participants": participants,
            "her_peers": her, "created_at": f"2026-10-12T00:00:0{insertion}Z",
            "updated_at": f"2026-10-12T00:00:0{insertion}Z", "outcome": "observed-absence",
        }

    def test_complete_durable_c_retirement_and_survivor_convergence_passes(self):
        result = evidence.validate(self.root, "realm", ["port-a", "port-b", "port-c"])
        self.assertTrue(result["removal_before_survivor_convergence"])
        self.assertFalse(result["stale_c_her"])

    def test_stale_c_her_is_rejected(self):
        plan = json.loads((self.root / "survivor-convergence/host-a/plan.json").read_text())
        plan["peers"].append({"host_id": "host-c"})
        self._write("survivor-convergence/host-a/plan.json", plan)
        with self.assertRaises(AssertionError):
            evidence.validate(self.root, "realm", ["port-a", "port-b", "port-c"])

    def test_c_apply_after_remove_is_rejected(self):
        history = json.loads((self.root / "survivor-convergence/plans/durable-work.json").read_text())
        history["history"].append(self._work("host-c", "Apply", "succeeded", 5, ["host-a", "host-b", "host-c"], ["host-a", "host-b"]))
        self._write("survivor-convergence/plans/durable-work.json", history)
        with self.assertRaises(AssertionError):
            evidence.validate(self.root, "realm", ["port-a", "port-b", "port-c"])

    def test_survivor_apply_before_remove_is_rejected(self):
        history = json.loads((self.root / "survivor-convergence/plans/durable-work.json").read_text())
        for row in history["history"]:
            if row["target_host_id"] == "host-a":
                row["insertion_order"] = 1
        self._write("survivor-convergence/plans/durable-work.json", history)
        with self.assertRaises(AssertionError):
            evidence.validate(self.root, "realm", ["port-a", "port-b", "port-c"])

    def test_durable_target_host_without_local_host_is_accepted(self):
        history = json.loads((self.root / "survivor-convergence/plans/durable-work.json").read_text())
        self.assertTrue(history["history"])
        self.assertTrue(all("local_host" not in row for row in history["history"]))
        result = evidence.validate(self.root, "realm", ["port-a", "port-b", "port-c"])
        self.assertEqual(result["c_remove_latest_history"]["target_host_id"], "host-c")

    def test_mismatched_durable_c_remove_target_is_rejected(self):
        history = json.loads((self.root / "survivor-convergence/plans/durable-work.json").read_text())
        next(row for row in history["history"] if row["action"] == "Remove")["target_host_id"] = "host-a"
        self._write("survivor-convergence/plans/durable-work.json", history)
        with self.assertRaises(AssertionError):
            evidence.validate(self.root, "realm", ["port-a", "port-b", "port-c"])


if __name__ == "__main__":
    unittest.main()
