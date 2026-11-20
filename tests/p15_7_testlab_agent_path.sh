#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$ROOT_DIR/scripts/p15-7-real-host-journey.sh" "$ROOT_DIR/bins/o3k/src/recovery_installation.rs" <<'PY'
from pathlib import Path
import re
import sys

journey = Path(sys.argv[1]).read_text(encoding="utf-8")
guard = Path(sys.argv[2]).read_text(encoding="utf-8")
install_agent = journey.split("install_agent() {", 1)[1].split("\n}\n\nregister_vm()", 1)[0]
maintenance = journey.split("# Restart the compute agent from its durable guest identity.", 1)[1].split(
    "# Bounded wait for the control plane to observe the reconnected agent.", 1
)[0]
compute_guard = guard.split("pub fn deny_compute_startup_access() -> Result<()> {", 1)[1].split(
    "pub fn deny_operational_access_for_backend(", 1
)[0]

assert "/usr/local/bin/o3k-compute" not in install_agent, "TestLab agent still uses C1 fixed executable path"
assert "/usr/local/bin/o3k-compute" not in maintenance, "maintenance restart still uses C1 fixed executable path"
assert "remote_agent_bin" in install_agent and "maintenance_agent_bin" in maintenance, \
    "initial and maintenance starts must share the run-scoped executable path helper"
assert 'remote_agent_bin="$(testlab_agent_bin_path "$RUN_ID" "$id")"' in install_agent, \
    "initial startup must derive its executable path from the run and agent identity"
assert 'maintenance_agent_bin="$(testlab_agent_bin_path "$RUN_ID" block-e)"' in maintenance, \
    "maintenance startup must derive the same path from the run and canonical agent identity"
assert "printf '/var/lib/o3k-testlab/%s/agents/%s/o3k-compute' \"$1\" \"$2\"" in journey, \
    "TestLab executable path must be scoped to this run and canonical agent id"
assert "install -d -o root -g root -m 0755" in install_agent, \
    "guest executable directory must be safely root-owned"
assert "install -o root -g root -m 0755" in install_agent, \
    "guest executable must be safely root-owned and executable"
assert "/etc/o3k/tls" in install_agent and "/var/lib/o3k-compute/agent-id" in install_agent, \
    "TLS files and canonical BuildingBlock identity storage must stay unchanged"
assert 'virsh -c qemu:///system undefine "$u" --nvram' in journey, \
    "the guest-owned executable must disappear with the run-owned child guest disk"
assert 'sudo -n rm -f -- "$p"' in journey and '"${OVERLAYS[@]}"' in journey, \
    "run cleanup must remove the run-owned child guest backing disks after domain removal"
assert "executable != Path::new(\"/usr/local/bin/o3k-compute\")" in guard, \
    "the production C1 compute startup guard must continue distinguishing the fixed path"
assert "!fixed_release_manifest_requires_selector()?" in compute_guard and "return Ok(());" in compute_guard, \
    "only a non-fixed executable with no installed selector may use the TestLab carveout"
assert compute_guard.rstrip().endswith("deny_operational_access(Path::new(\"/var/lib/o3k\"))\n}"), \
    "fixed-path or selector-bearing installed releases must use the C1 selector gate"
PY

echo "P15.7 TestLab agent path guards passed"
