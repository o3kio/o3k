#!/usr/bin/env python3
"""Owned, bounded packet-boundary capture for the frozen Fabric v3 campaign."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import re
import shlex
import subprocess
import sys
import time


def call(argv: list[str], *, input_text: str | None = None, check: bool = True) -> str:
    result = subprocess.run(argv, input=input_text, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv!r}: {result.stderr[-1000:]}")
    return result.stdout


def ssh(args: argparse.Namespace, host: str, command: str, *, input_text: str | None = None,
        check: bool = True) -> str:
    argv = ["ssh", "-i", args.key, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={args.known_hosts}",
            "-o", "ConnectTimeout=8", f"o3k@{args.addresses[host]}", command]
    return call(argv, input_text=input_text, check=check)


def read_remote_json(args: argparse.Namespace, host: str, path: str) -> dict:
    return json.loads(ssh(args, host, f"sudo cat {shlex.quote(path)}"))


def write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def remote_script(args: argparse.Namespace, host: str, script: str) -> str:
    return ssh(args, host, "sudo bash -s", input_text=script)


def topology(args: argparse.Namespace, ev: pathlib.Path) -> dict:
    root = f"/var/lib/o3k-fabric-v3/{args.run_id}/network/fabric"
    ownership: dict[str, dict] = {}
    plans: dict[str, dict] = {}
    maps: dict[str, dict] = {}
    realm_ids: set[str] = set()
    for h in "abc":
        ownership[h] = read_remote_json(args, h, f"{root}/ownership.json")
        endpoint = args.endpoints[h]
        matches = [(rid, realm) for rid, realm in ownership[h].get("realms", {}).items()
                   if endpoint in realm.get("endpoint_taps", {})]
        if len(matches) != 1:
            raise RuntimeError(f"host-{h}: expected one durable endpoint realm, got {len(matches)}")
        realm_id, realm = matches[0]
        realm_ids.add(realm_id)
        plan = read_remote_json(args, h, f"{root}/plans/{realm_id}.json")
        plans[h] = plan
        if plan.get("realm_id") != realm_id or plan.get("local_host") != f"host-{h}":
            raise RuntimeError(f"host-{h}: plan is not current for its stable host/realm")
        vxlan = realm.get("vxlan", {})
        tap = realm["endpoint_taps"][endpoint]
        if endpoint in realm.get("pending_endpoint_taps", {}):
            raise RuntimeError(f"host-{h}: endpoint TAP ownership is still pending")
        if (plan.get("directory_generation") != realm.get("directory_generation")
                or plan.get("local_fabric_generation") != realm.get("local_fabric_generation")
                or plan.get("encapsulation", {}).get("binding_generation") != vxlan.get("binding_generation")):
            raise RuntimeError(f"host-{h}: current plan and durable Fabric generations differ")
        if tap.get("mac", "").lower() == args.macs[h].lower():
            raise RuntimeError(f"host-{h}: provider TAP MAC unexpectedly equals canonical guest MAC")
        fabric = ownership[h].get("fabric", {})
        peers = {p["host_id"]: p for p in plan.get("peers", [])}
        maps[h] = {
            "host_id": f"host-{h}", "endpoint_id": endpoint,
            "guest_mac": args.macs[h], "tap": tap["interface"],
            "provider_tap_mac": tap["mac"], "realm_id": realm_id,
            "realm_bridge": realm["bridge"], "root_veth": vxlan["host_veth"],
            "fabric_veth": vxlan["fabric_veth"], "fabric_bridge": vxlan["bridge"],
            "vxlan": vxlan["interface"], "vni": vxlan["vni"],
            "namespace": fabric["namespace"], "wireguard": fabric["interface"],
            "fabric_transport_ip": plan["local_fabric_transport_ip"],
            "fabric_generation": plan.get("local_fabric_generation"),
            "peers": peers, "directory_generation": plan.get("directory_generation"),
            "binding_generation": plan.get("encapsulation", {}).get("binding_generation"),
        }
        write_json(ev / "topology" / "ownership" / f"host-{h}.json", ownership[h])
        write_json(ev / "topology" / "plans" / f"host-{h}.json", plan)
    if len(realm_ids) != 1:
        raise RuntimeError(f"endpoints do not share one current Realm: {sorted(realm_ids)}")
    realm_id = next(iter(realm_ids))
    expected_endpoints = {args.endpoints[h]: (args.macs[h].lower(), None, f"host-{h}") for h in "abc"}
    for h in "abc":
        directory = plans[h].get("directory", {}).get("entries", [])
        observed = {e.get("endpoint_id"): (e.get("mac", "").lower(), e.get("fixed_ip"), e.get("selected_host"))
                    for e in directory}
        for endpoint, (mac, _, selected) in expected_endpoints.items():
            if endpoint not in observed or observed[endpoint][0] != mac or observed[endpoint][2] != selected:
                raise RuntimeError(f"host-{h}: current plan does not bind all A/B/C canonical endpoints")
            expected_endpoints[endpoint] = (mac, observed[endpoint][1], selected)
    for h in "abc":
        dhcp_root = f"/var/lib/o3k-fabric-v3/{args.run_id}/network/dhcp/fabric/{realm_id}"
        owner_path = f"{dhcp_root}/fabric-dhcp-ownership.json"
        pids = ssh(args, h, f"sudo find {shlex.quote(dhcp_root)} -maxdepth 1 -type f -name 'dnsmasq-*.pid' -print")
        (ev / "dhcp" / f"host-{h}-owned-pids.txt").write_text(pids)
        pid_lines = [line for line in pids.splitlines() if line.strip()]
        if len(pid_lines) != (1 if h == "a" else 0):
            raise RuntimeError(f"host-{h}: expected exactly one authority dnsmasq process across A/B/C")
        owner = read_remote_json(args, h, owner_path)
        write_json(ev / "dhcp" / f"host-{h}-ownership.json", owner)
        if (owner.get("local_host") != f"host-{h}" or owner.get("authority_host") != "host-a"
                or not owner.get("dhcp_enabled") or owner.get("pending") or owner.get("withdrawn")
                or owner.get("directory_generation") != plans[h].get("directory_generation")
                or owner.get("local_fabric_generation") != plans[h].get("local_fabric_generation")):
            raise RuntimeError(f"host-{h} DHCP ownership is not committed to the current authority/plan")
        if h == "a":
            state = read_remote_json(args, h, f"{dhcp_root}/state.json")
            conf = ssh(args, h, f"sudo cat {shlex.quote(dhcp_root + '/dnsmasq.conf')}")
            write_json(ev / "dhcp" / f"host-{h}-state.json", state)
            (ev / "dhcp" / f"host-{h}-dnsmasq.conf").write_text(conf)
            bindings = state.get("bindings", {})
            if set(bindings) != set(expected_endpoints):
                raise RuntimeError("host-a DHCP binding state is missing canonical A/B/C endpoints")
            for endpoint, (mac, ip, _) in expected_endpoints.items():
                binding = bindings[endpoint]
                if binding.get("mac", "").lower() != mac or binding.get("address") != ip:
                    raise RuntimeError(f"host-a DHCP binding differs from canonical endpoint {endpoint}")
        if h == "a":
            config = state.get("config") or {}
            if config.get("interface") != maps[h]["realm_bridge"]:
                raise RuntimeError("authority dnsmasq is not bound to the A Realm bridge")
            if config.get("mtu") != 1390 or "dhcp-option=26,1390" not in conf:
                raise RuntimeError("authority DHCP state does not propagate tenant MTU 1390")
        else:
            state_path = f"{dhcp_root}/state.json"
            present = ssh(args, h, f"if sudo test -f {shlex.quote(state_path)}; then echo present; fi")
            state = (read_remote_json(args, h, state_path) if present.strip()
                     else {"config": None, "bindings": {}})
            write_json(ev / "dhcp" / f"host-{h}-state.json", state)
            if state.get("config") is not None or state.get("bindings"):
                raise RuntimeError(f"host-{h}: non-authority carries DHCP service configuration or bindings")
    (ev / "dhcp" / "preconditions.txt").write_text(
        "A/B/C canonical bindings present; host-a is the sole committed DHCP authority; "
        "A DHCP Realm bridge and MTU match are proved.\n")
    write_json(ev / "topology" / "topology-map.json", maps)
    return maps


def save_snapshot(args: argparse.Namespace, ev: pathlib.Path, h: str, topo: dict, phase: str) -> None:
    ns = shlex.quote(topo["namespace"])
    wg = shlex.quote(topo["wireguard"])
    d = f"{ev}/topology/{'nft-before' if phase == 'before' else 'nft-after'}/host-{h}"
    local = ev / "topology" / "links" / f"host-{h}-{phase}"
    local.mkdir(parents=True, exist_ok=True)
    commands = {
        "root-links.json": "ip -s -j link",
        "root-routes.json": "ip -j route show table all",
        "root-bridge-links.json": "bridge -j link",
        "root-bridge-fdb.json": "bridge -j fdb",
        "root-nftables.json": "nft -j list ruleset",
        "root-tap-detail.json": f"ip -j -d link show dev {shlex.quote(topo['tap'])}",
        "root-realm-bridge-detail.json": f"ip -j -d link show dev {shlex.quote(topo['realm_bridge'])}",
        "root-fabric-veth-detail.json": f"ip -j -d link show dev {shlex.quote(topo['root_veth'])}",
        "namespace-links.json": f"ip netns exec {ns} ip -s -j link",
        "namespace-routes.json": f"ip netns exec {ns} ip -j route show table all",
        "namespace-bridge-links.json": f"ip netns exec {ns} bridge -j link",
        "namespace-bridge-fdb.json": f"ip netns exec {ns} bridge -j fdb",
        "namespace-wireguard.txt": f"ip netns exec {ns} wg show {wg}",
        "namespace-wireguard-transfer.txt": f"ip netns exec {ns} wg show {wg} transfer",
        "namespace-nftables.json": f"ip netns exec {ns} nft -j list ruleset",
        "namespace-fabric-veth-detail.json": f"ip netns exec {ns} ip -j -d link show dev {shlex.quote(topo['fabric_veth'])}",
        "namespace-fabric-bridge-detail.json": f"ip netns exec {ns} ip -j -d link show dev {shlex.quote(topo['fabric_bridge'])}",
        "namespace-vxlan-detail.json": f"ip netns exec {ns} ip -j -d link show dev {shlex.quote(topo['vxlan'])}",
    }
    script = "set +e\n" + "\n".join(
        f"{{ {cmd}; }} >{shlex.quote(str(local / name))} 2>&1" for name, cmd in commands.items()
    ) + "\n"
    # The SSH user can write only to its home. Collect through a run-owned host path,
    # then copy the bounded text outputs back individually.
    remote = f"/var/lib/o3k-fabric-v3/{args.run_id}/network/dhcp-boundary/{h}/{phase}"
    script = script.replace(str(local), remote)
    remote_script(args, h, f"install -d -m 0700 {shlex.quote(remote)}\n" + script)
    for name in commands:
        content = ssh(args, h, f"sudo cat {shlex.quote(remote + '/' + name)}", check=False)
        (local / name).write_text(content)


def fdb_check(args: argparse.Namespace, ev: pathlib.Path, maps: dict) -> tuple[bool, str]:
    for h in "abc":
        t = maps[h]
        remote = f"sudo ip netns exec {shlex.quote(t['namespace'])} bridge fdb show dev {shlex.quote(t['vxlan'])}"
        out = ssh(args, h, remote)
        (ev / "topology" / "fdb" / f"host-{h}-vxlan.txt").write_text(out)
        expected = {p["fabric_transport_ip"] for peer, p in t["peers"].items()
                    if peer in {"host-a", "host-b", "host-c"}}
        lines = [line for line in out.splitlines()
                 if re.search(r"^00:00:00:00:00:00\s", line)]
        got = set()
        for line in lines:
            match = re.search(r"\bdst\s+(\S+)", line)
            if match:
                got.add(match.group(1))
        if len(lines) != len(expected) or got != expected:
            return False, f"host-{h} BUM FDB expected={sorted(expected)} observed={sorted(got)} lines={lines}"
    return True, "all three VXLAN devices contain exactly the two current participant BUM destinations"


def wireguard_identity_check(args: argparse.Namespace, ev: pathlib.Path, maps: dict) -> tuple[bool, str]:
    identity_path = ev / "environment" / "fabric-identities.json"
    try:
        identities = json.loads(identity_path.read_text())
        expected = {item["host_id"]: item["public_key"] for item in identities}
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        return False, f"registered Fabric identity evidence is malformed: {exc}"
    if set(expected) != {f"host-{h}" for h in "abc"} or len(set(expected.values())) != 3:
        return False, "registered Fabric host identities are missing or not unique"
    observed: dict[str, dict[str, str]] = {}
    for h in "abc":
        t = maps[h]
        command = (f"sudo ip netns exec {shlex.quote(t['namespace'])} "
                   f"wg show {shlex.quote(t['wireguard'])} public-key")
        live = ssh(args, h, command).strip()
        expected_key = expected[f"host-{h}"]
        observed[h] = {"registered_public_key": expected_key, "live_interface_public_key": live}
        if live != expected_key:
            write_json(ev / "topology" / "wireguard" / "runtime-identities.json", observed)
            return False, (f"host-{h} live Fabric interface key differs from the registered host identity; "
                           "provider key path/configuration is inconsistent")
    write_json(ev / "topology" / "wireguard" / "runtime-identities.json", observed)
    return True, "all live namespace WireGuard interface keys equal their registered canonical host identities"


def prime_wireguard_peers(args: argparse.Namespace, ev: pathlib.Path, maps: dict) -> None:
    """Send bounded transport probes so lazy WireGuard handshakes can start."""
    results = []
    for h in "abc":
        t = maps[h]
        for peer_host, peer in sorted(t["peers"].items()):
            if peer_host not in {f"host-{x}" for x in "abc"}:
                continue
            command = (f"sudo ip netns exec {shlex.quote(t['namespace'])} "
                       f"timeout 4s ping -n -c 1 -W 2 {shlex.quote(peer['fabric_transport_ip'])}")
            output = ssh(args, h, command, check=False)
            results.append({"source_host": f"host-{h}", "peer_host": peer_host,
                            "peer_transport_ip": peer["fabric_transport_ip"],
                            "probe_output": output[-1200:]})
    write_json(ev / "topology" / "wireguard" / "bounded-peer-probes.json", results)


def wg_check(args: argparse.Namespace, ev: pathlib.Path, maps: dict) -> tuple[bool, str]:
    for h in "abc":
        t = maps[h]
        out = ssh(args, h, f"sudo ip netns exec {shlex.quote(t['namespace'])} wg show {shlex.quote(t['wireguard'])}")
        (ev / "topology" / "wireguard" / f"host-{h}-wg-show.txt").write_text(out)
        for peer_host, peer in t["peers"].items():
            pub = peer["public_key"]
            block = re.search(r"(?ms)^peer:\s*" + re.escape(pub) + r"\s*$([\s\S]*?)(?=^peer:|\Z)", out)
            if not block:
                return False, f"host-{h} missing WireGuard peer for {peer_host}"
            body = block.group(1)
            allowed = re.search(r"(?m)^\s*allowed ips:\s*(\S+)", body)
            hs = re.search(r"(?m)^\s*latest handshake:\s*(.+)$", body)
            if not allowed or allowed.group(1) != peer["fabric_transport_ip"] + "/32":
                return False, f"host-{h} peer {peer_host} AllowedIPs mismatch"
            age = None
            if hs and hs.group(1).strip() != "never":
                m = re.search(r"(\d+)\s+seconds? ago", hs.group(1))
                if m:
                    age = int(m.group(1))
                else:
                    m = re.search(r"(\d+)\s+minutes? ago", hs.group(1))
                    if m:
                        age = int(m.group(1)) * 60
            if age is None or age > 180:
                return False, f"host-{h} peer {peer_host} handshake is absent or older than 180 seconds"
    return True, "all current participant peers have matching /32 AllowedIPs and handshakes no older than 180 seconds"


def capture_specs(maps: dict) -> list[dict]:
    result = []
    bmac = maps["b"]["guest_mac"]
    b_transport = maps["b"]["fabric_transport_ip"]
    for h in "ab":
        t = maps[h]
        route_peer = "host-a" if h == "b" else "host-b"
        peer = t["peers"].get(route_peer)
        if not peer:
            raise RuntimeError(f"host-{h} plan has no peer for {route_peer}")
        underlay = peer["underlay_endpoint"].rsplit(":", 1)[0]
        inner_filter = f"udp and (port 67 or port 68) and ether src {bmac}"
        wg_filter = f"udp port 4789 and src host {b_transport}"
        underlay_direction = "dst" if h == "b" else "src"
        underlay_filter = f"udp port 65001 and {underlay_direction} host {underlay}"
        result.extend([
            {"host": h, "label": "tap", "iface": t["tap"], "ns": None, "filter": inner_filter},
            {"host": h, "label": "realm-bridge", "iface": t["realm_bridge"], "ns": None, "filter": inner_filter},
            {"host": h, "label": "root-veth", "iface": t["root_veth"], "ns": None, "filter": inner_filter},
            {"host": h, "label": "fabric-veth", "iface": t["fabric_veth"], "ns": t["namespace"], "filter": inner_filter},
            {"host": h, "label": "fabric-bridge", "iface": t["fabric_bridge"], "ns": t["namespace"], "filter": inner_filter},
            {"host": h, "label": "vxlan", "iface": t["vxlan"], "ns": t["namespace"], "filter": inner_filter},
            {"host": h, "label": "wireguard", "iface": t["wireguard"], "ns": t["namespace"], "filter": wg_filter},
        ])
        # The physical device is resolved by the caller and saved into this spec.
        result.append({"host": h, "label": "underlay", "underlay_ip": underlay,
                       "iface": "", "ns": None, "filter": underlay_filter})
    return result


def action_prepare(args: argparse.Namespace) -> int:
    ev = pathlib.Path(args.evidence)
    specs: list[dict] = []
    try:
        maps = topology(args, ev)
        write_json(ev / "manifest.json", {
            "run_id": args.run_id, "product_sha": args.product_sha,
            "product_tree": args.product_tree, "harness_sha": args.harness_sha,
            "realm_id": maps["a"]["realm_id"], "authority": "host-a",
            "fabric_generations": {h: maps[h]["fabric_generation"] for h in "abc"},
            "directory_generations": {h: maps[h]["directory_generation"] for h in "abc"},
            "vni_binding_generations": {h: maps[h]["binding_generation"] for h in "abc"},
            "endpoints": {h: {"id": args.endpoints[h], "mac": args.macs[h]} for h in "abc"},
        })
        ok, detail = fdb_check(args, ev, maps)
        if not ok:
            write_json(ev / "result.json", {"result": "STOP", "classification": "HER_REALIZATION_DEFECT",
                                             "first_present_boundary": "current plans and endpoint ownership",
                                             "first_absent_boundary": "current BUM FDB destination", "detail": detail})
            print(json.dumps({"state": "stop", "classification": "HER_REALIZATION_DEFECT", "detail": detail}))
            return 20
        (ev / "topology" / "fdb" / "result.txt").write_text(detail + "\n")
        ok, detail = wireguard_identity_check(args, ev, maps)
        if not ok:
            write_json(ev / "result.json", {"result": "STOP", "classification": "WIREGUARD_PEER_DEFECT",
                                             "first_present_boundary": "current HER FDB",
                                             "first_absent_boundary": "live WireGuard identity matches registered host identity",
                                             "detail": detail})
            print(json.dumps({"state": "stop", "classification": "WIREGUARD_PEER_DEFECT", "detail": detail}))
            return 20
        (ev / "topology" / "wireguard" / "identity-result.txt").write_text(detail + "\n")
        prime_wireguard_peers(args, ev, maps)
        ok, detail = wg_check(args, ev, maps)
        if not ok:
            write_json(ev / "result.json", {"result": "STOP", "classification": "WIREGUARD_PEER_DEFECT",
                                             "first_present_boundary": "current HER FDB",
                                             "first_absent_boundary": "current WireGuard peer readiness", "detail": detail})
            print(json.dumps({"state": "stop", "classification": "WIREGUARD_PEER_DEFECT", "detail": detail}))
            return 20
        (ev / "topology" / "wireguard" / "result.txt").write_text(detail + "\n")
        # Baseline counters after bounded handshake probes, immediately before
        # the DHCP-only capture window begins.
        for h in "abc":
            save_snapshot(args, ev, h, maps[h], "before")
        specs = capture_specs(maps)
        for spec in specs:
            h = spec["host"]
            if spec["label"] == "underlay":
                route = ssh(args, h, f"ip -4 route get {shlex.quote(spec['underlay_ip'])}")
                m = re.search(r"\bdev\s+(\S+)", route)
                if not m:
                    raise RuntimeError(f"host-{h} has no physical route to {spec['underlay_ip']}")
                spec["iface"] = m.group(1)
                (ev / "topology" / "links" / f"host-{h}-underlay-route.txt").write_text(route)

        def start_capture(spec: dict) -> None:
            h = spec["host"]
            remote_dir = f"/var/lib/o3k-fabric-v3/{args.run_id}/network/dhcp-boundary/{h}/capture"
            base = f"{remote_dir}/{spec['label']}"
            pcap, log, pid = base + ".pcap", base + ".log", base + ".pid"
            iface_cmd = (f"ip netns exec {shlex.quote(spec['ns'])} " if spec["ns"] else "")
            # DHCP options, including Option 53 (DISCOVER/OFFER/REQUEST/ACK),
            # occur after the Ethernet/IP/UDP/BOOTP headers. 256 bytes can
            # truncate those options on valid 342-byte CirrOS DHCP frames and
            # make an actual DISCOVER indistinguishable from a generic BOOTP
            # request. Keep capture bounded while retaining the full DHCP frame.
            cmd = (f"{iface_cmd}timeout --signal=INT 45s tcpdump -c 20000 -i {shlex.quote(spec['iface'])} "
                   f"-nn -e -s 512 -U -w {shlex.quote(pcap)} {shlex.quote(spec['filter'])}")
            script = (f"install -d -m 0700 {shlex.quote(remote_dir)}\n"
                      f"nohup bash -c {shlex.quote(cmd + ' >' + shlex.quote(log) + ' 2>&1')} </dev/null >/dev/null 2>&1 &\n"
                      f"echo $! > {shlex.quote(pid)}\n"
                      f"ready=0\n"
                      f"for _ in $(seq 1 25); do\n"
                      f"  if test -s {shlex.quote(log)} && grep -Fq 'listening on ' {shlex.quote(log)}; then ready=1; break; fi\n"
                      f"  sleep 0.2\n"
                      f"done\n"
                      f"if test \"$ready\" != 1; then cat {shlex.quote(log)} 2>/dev/null || true; exit 42; fi\n")
            remote_script(args, h, script)
            spec.update({"pcap": pcap, "log": log, "pid": pid, "remote_dir": remote_dir})
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(specs)) as pool:
            futures = [pool.submit(start_capture, spec) for spec in specs]
            for future in concurrent.futures.as_completed(futures):
                future.result()
                write_json(ev / "topology" / "capture-manifest.json",
                           [spec for spec in specs if "pid" in spec])
        write_json(ev / "topology" / "capture-manifest.json", specs)
        time.sleep(2)
        print(json.dumps({"state": "ready", "captures": len(specs), "her": "PASS", "wireguard": "PASS"}))
        return 0
    except Exception as exc:
        for spec in specs:
            if not all(k in spec for k in ("pid", "pcap", "host")):
                continue
            script = (f"pid=$(cat {shlex.quote(spec['pid'])} 2>/dev/null || true); "
                      f"if test -n \"$pid\" && test -r /proc/$pid/cmdline && "
                      f"tr '\\0' ' ' </proc/$pid/cmdline | grep -Fq -- {shlex.quote(spec['pcap'])}; "
                      f"then kill -INT \"$pid\"; fi")
            try:
                remote_script(args, spec["host"], script)
            except Exception:
                pass
        write_json(ev / "result.json", {"result": "STOP", "classification": "HARNESS_GAP",
                                         "first_present_boundary": "unknown", "first_absent_boundary": "diagnostic setup",
                                         "detail": str(exc)})
        print(json.dumps({"state": "stop", "classification": "HARNESS_GAP", "detail": str(exc)}))
        return 20


def stop_and_copy(args: argparse.Namespace, ev: pathlib.Path, spec: dict) -> None:
    h = spec["host"]
    pid, pcap = spec["pid"], spec["pcap"]
    script = f"""set -e
pid=$(cat {shlex.quote(pid)})
case "$pid" in *[!0-9]*|'') exit 21;; esac
if test -r "/proc/$pid/cmdline" && tr '\\0' ' ' <"/proc/$pid/cmdline" | grep -Fq -- {shlex.quote(pcap)}; then kill -INT "$pid"; fi
sleep 1
test -f {shlex.quote(pcap)}
cp {shlex.quote(pcap)} {shlex.quote('/tmp/' + args.run_id + '-' + h + '-' + spec['label'] + '.pcap')}
chown o3k:o3k {shlex.quote('/tmp/' + args.run_id + '-' + h + '-' + spec['label'] + '.pcap')}
chmod 0600 {shlex.quote('/tmp/' + args.run_id + '-' + h + '-' + spec['label'] + '.pcap')}
"""
    remote_script(args, h, script)
    local = ev / h / f"{spec['label']}.pcap"
    call(["scp", "-i", args.key, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
          "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={args.known_hosts}",
          f"o3k@{args.addresses[h]}:/tmp/{args.run_id}-{h}-{spec['label']}.pcap", str(local)])
    ssh(args, h, f"sudo rm -f {shlex.quote('/tmp/' + args.run_id + '-' + h + '-' + spec['label'] + '.pcap')}", check=False)
    log = ssh(args, h, f"sudo cat {shlex.quote(spec['log'])}", check=False)
    (ev / h / f"{spec['label']}-tcpdump.log").write_text(log)


def packet_seen(path: pathlib.Path, mac: str, message: str = "Discover",
                xid: str | None = None) -> tuple[bool, str]:
    if not path.exists() or path.stat().st_size == 0:
        return False, "empty or missing pcap"
    text = call(["tcpdump", "-nn", "-e", "-tt", "-vvv", "-r", str(path)], check=False)
    decoded = path.with_suffix(".decoded.txt")
    decoded.write_text(text)
    valid = mac.lower() in text.lower() and re.search(r"DHCP-Message[^\n]*" + re.escape(message), text, re.I) is not None
    if xid:
        valid = valid and xid.lower() in text.lower()
    return bool(valid), text[:300]


def nft_drop_deltas(ev: pathlib.Path) -> dict:
    result = {}
    for h in "abc":
        for scope in ("root", "namespace"):
            before = ev / "topology" / "links" / f"host-{h}-before" / f"{scope}-nftables.json"
            after = ev / "topology" / "links" / f"host-{h}-after" / f"{scope}-nftables.json"
            try:
                old = json.loads(before.read_text()).get("nftables", [])
                new = json.loads(after.read_text()).get("nftables", [])
            except (OSError, json.JSONDecodeError):
                result[f"{h}:{scope}"] = {"available": False}
                continue
            def drops(items: list) -> dict:
                found = {}
                table = chain = "?"
                for item in items:
                    if "table" in item:
                        table = item["table"].get("name", "?")
                    elif "chain" in item:
                        chain = item["chain"].get("name", "?")
                    elif "rule" in item:
                        rule = item["rule"]
                        expr = rule.get("expr", [])
                        is_drop = any("drop" in atom for atom in expr if isinstance(atom, dict))
                        counters = [atom.get("counter", {}).get("packets") for atom in expr
                                    if isinstance(atom, dict) and "counter" in atom]
                        if is_drop and counters:
                            found[(rule.get("table", table), rule.get("chain", chain),
                                   rule.get("handle", 0))] = int(counters[-1] or 0)
                return found
            old_d, new_d = drops(old), drops(new)
            deltas = []
            for key, count in new_d.items():
                delta = count - old_d.get(key, 0)
                if delta:
                    deltas.append({"table": key[0], "chain": key[1], "handle": key[2], "packets": delta})
            result[f"{h}:{scope}"] = {"available": True, "drop_packet_deltas": deltas}
    return result


def link_packet_deltas(ev: pathlib.Path, maps: dict) -> dict:
    result = {}
    for h in "abc":
        old_path = ev / "topology" / "links" / f"host-{h}-before" / "root-links.json"
        new_path = ev / "topology" / "links" / f"host-{h}-after" / "root-links.json"
        try:
            old = {x["ifname"]: x for x in json.loads(old_path.read_text())}
            new = {x["ifname"]: x for x in json.loads(new_path.read_text())}
        except (OSError, json.JSONDecodeError, KeyError):
            result[h] = {"available": False}
            continue
        names = [maps[h]["tap"], maps[h]["realm_bridge"], maps[h]["root_veth"]]
        result[h] = {}
        for name in names:
            if name not in old or name not in new:
                result[h][name] = {"available": False}
                continue
            def stats(item: dict) -> dict:
                link = item.get("stats64", item.get("stats", {}))
                return {direction: {k: int(v) for k, v in fields.items()}
                        for direction, fields in link.items() if isinstance(fields, dict)}
            before_s, after_s = stats(old[name]), stats(new[name])
            delta = {}
            for direction in set(before_s) | set(after_s):
                delta[direction] = {k: after_s.get(direction, {}).get(k, 0) - before_s.get(direction, {}).get(k, 0)
                                    for k in set(before_s.get(direction, {})) | set(after_s.get(direction, {}))}
            result[h][name] = delta
    return result


def wg_transfer_deltas(ev: pathlib.Path, maps: dict) -> dict:
    result = {}
    for h in "ab":
        peer_host = "host-a" if h == "b" else "host-b"
        pub = maps[h]["peers"][peer_host]["public_key"]
        records = {}
        for phase in ("before", "after"):
            path = ev / "topology" / "links" / f"host-{h}-{phase}" / "namespace-wireguard-transfer.txt"
            try:
                lines = path.read_text().splitlines()
                fields = next(line.split() for line in lines if line.split() and line.split()[0] == pub)
                records[phase] = {"rx_bytes": int(fields[1]), "tx_bytes": int(fields[2])}
            except (OSError, StopIteration, ValueError, IndexError):
                records[phase] = None
        if records["before"] is None or records["after"] is None:
            result[f"host-{h}-to-{peer_host}"] = {"available": False}
        else:
            result[f"host-{h}-to-{peer_host}"] = {
                "rx_bytes": records["after"]["rx_bytes"] - records["before"]["rx_bytes"],
                "tx_bytes": records["after"]["tx_bytes"] - records["before"]["tx_bytes"],
            }
    return result


def action_finish(args: argparse.Namespace) -> int:
    ev = pathlib.Path(args.evidence)
    try:
        specs = json.loads((ev / "topology" / "capture-manifest.json").read_text())
        for spec in specs:
            stop_and_copy(args, ev, spec)
        maps = json.loads((ev / "topology" / "topology-map.json").read_text())
        for h in "abc":
            save_snapshot(args, ev, h, maps[h], "after")
        sequence = [
            ("b", "tap"), ("b", "realm-bridge"), ("b", "root-veth"),
            ("b", "fabric-veth"), ("b", "fabric-bridge"), ("b", "vxlan"),
            ("b", "wireguard"), ("b", "underlay"), ("a", "underlay"),
            ("a", "wireguard"), ("a", "vxlan"), ("a", "fabric-veth"),
            ("a", "root-veth"), ("a", "realm-bridge"),
        ]
        b_tap = ev / "b" / "tap.pcap"
        b_tap_text = call(["tcpdump", "-nn", "-e", "-tt", "-vvv", "-r", str(b_tap)], check=False)
        xid_matches = set(re.findall(r"\bxid\s+(0x[0-9a-f]+)", b_tap_text, re.I))
        if maps["b"]["guest_mac"].lower() not in b_tap_text.lower() or not xid_matches:
            raise RuntimeError("B TAP capture did not prove a canonical-MAC DHCPDISCOVER with a transaction ID")
        discover_lines = [line for line in b_tap_text.splitlines()
                          if maps["b"]["guest_mac"].lower() in line.lower()
                          and re.search(r"DHCP-Message[^\n]*Discover", line, re.I)]
        discover_xids = {m.group(1).lower() for line in discover_lines
                         if (m := re.search(r"\bxid\s+(0x[0-9a-f]+)", line, re.I))}
        if len(discover_xids) != 1:
            raise RuntimeError(f"bounded B window did not contain exactly one DHCP transaction ID: {sorted(discover_xids)}")
        xid = next(iter(discover_xids))
        (ev / "b" / "tap.decoded.txt").write_text(b_tap_text)
        observations = []
        first_missing = None
        for h, label in sequence:
            mac = maps["b"]["guest_mac"]
            transport = label in {"wireguard", "underlay"}
            seen, excerpt = packet_seen(ev / h / f"{label}.pcap", mac,
                                        "4789" if transport else "Discover", None if transport else xid)
            observations.append({"host": h, "boundary": label, "packet_seen": seen, "excerpt": excerpt})
            # Transport captures contain the outer UDP payload, so correlate by
            # transaction source MAC in the VXLAN layer is unavailable there.
            # Presence means bounded transport traffic appeared during the sole retry.
            if label in {"wireguard", "underlay"}:
                p = ev / h / f"{label}.decoded.txt"
                raw = p.read_text(errors="replace") if p.exists() else ""
                seen = "4789" in raw if label == "wireguard" else "65001" in raw
                observations[-1]["packet_seen"] = seen
            if not seen:
                first_missing = (h, label)
                break
        # Capture every side's packet observation even after identifying the first
        # missing boundary, for evidence review; decision remains at first absence.
        if first_missing:
            idx = len(observations)
            for h, label in sequence[idx:]:
                transport = label in {"wireguard", "underlay"}
                seen, excerpt = packet_seen(ev / h / f"{label}.pcap", maps["b"]["guest_mac"],
                                            "4789" if transport else "Discover", None if transport else xid)
                if label in {"wireguard", "underlay"}:
                    decoded = ev / h / f"{label}.decoded.txt"
                    raw = decoded.read_text(errors="replace") if decoded.exists() else ""
                    seen = ("4789" in raw) if label == "wireguard" else ("65001" in raw)
                observations.append({"host": h, "boundary": label, "packet_seen": seen, "excerpt": excerpt})
        present_index = next((i for i, item in enumerate(observations) if not item["packet_seen"]), len(observations))
        present = sequence[present_index - 1] if present_index > 0 else None
        absent = sequence[present_index] if present_index < len(sequence) else None
        drop_deltas = nft_drop_deltas(ev)
        link_deltas = link_packet_deltas(ev, maps)
        wireguard_deltas = wg_transfer_deltas(ev, maps)
        def named_drop_packets(key: str, predicate) -> int:
            return sum(d["packets"] for d in drop_deltas.get(key, {}).get("drop_packet_deltas", [])
                       if predicate(d["table"]))
        counter_summary = {
            "b_anti_spoof_drops": named_drop_packets("b:root", lambda table: table.startswith("o3k-as-")),
            "a_fabric_auth_drops": named_drop_packets("a:namespace", lambda table: table == "o3k-fabric-auth"),
            "a_vni_auth_drops": named_drop_packets("a:namespace", lambda table: table == "o3k-fabric-vni-auth"),
            "a_remote_anti_spoof_drops": named_drop_packets("a:root", lambda table: table.startswith("o3k-as-")),
        }
        classes = {
            ("b", "tap"): ("GUEST_ATTACHMENT_DEFECT", "guest B -> B TAP"),
            ("b", "root-veth"): ("REALM_BRIDGE_FLOOD_DEFECT", "B Realm bridge -> B root Fabric veth"),
            ("b", "fabric-veth"): ("FABRIC_VETH_DEFECT", "B root veth -> B fabric veth"),
            ("b", "fabric-bridge"): ("FABRIC_BRIDGE_BUM_DEFECT", "B fabric veth -> B fabric bridge"),
            ("b", "vxlan"): ("FABRIC_BRIDGE_BUM_DEFECT", "B fabric bridge -> B VXLAN"),
            ("b", "wireguard"): ("VXLAN_HER_DEFECT", "B VXLAN -> B WireGuard encapsulation"),
            ("b", "underlay"): ("WIREGUARD_ROUTE_DEFECT", "B WireGuard -> B physical underlay"),
            ("a", "underlay"): ("ENVIRONMENT_UNDERLAY_DEFECT", "B physical underlay -> A physical underlay"),
            ("a", "wireguard"): ("FABRIC_INGRESS_AUTH_DEFECT", "A physical underlay -> A WireGuard"),
            ("a", "vxlan"): ("VNI_ADMISSION_DEFECT", "A WireGuard -> A VXLAN decapsulation"),
            ("a", "fabric-veth"): ("REMOTE_REALM_BRIDGE_DEFECT", "A VXLAN -> A fabric veth"),
            ("a", "root-veth"): ("FABRIC_VETH_DEFECT", "A fabric veth -> A root Fabric veth"),
        }
        if absent == ("b", "realm-bridge"):
            classification, absent_name = (("ANTI_SPOOF_DHCP_DEFECT", "B TAP -> B Realm bridge (source anti-spoof drop counter increased)")
                                           if counter_summary["b_anti_spoof_drops"] else ("REALM_BRIDGE_FLOOD_DEFECT", "B TAP -> B Realm bridge (no source anti-spoof drop counter increase)"))
        elif absent == ("a", "realm-bridge"):
            classification, absent_name = (("REMOTE_DHCP_ANTI_SPOOF_DEFECT", "A root Fabric veth -> A Realm bridge (drop counter increased)")
                                           if counter_summary["a_remote_anti_spoof_drops"] else ("REMOTE_REALM_BRIDGE_DEFECT", "A root Fabric veth -> A Realm bridge (no drop counter increase)"))
        elif absent == ("a", "vxlan"):
            auth = bool(counter_summary["a_fabric_auth_drops"])
            classification, absent_name = (("FABRIC_INGRESS_AUTH_DEFECT", "A WireGuard -> A VXLAN (fabric-auth drop counter increased)")
                                           if auth else ("VXLAN_INGRESS_DEFECT", "A WireGuard -> A VXLAN (no fabric-auth drop counter increase)"))
        elif absent == ("a", "fabric-veth"):
            vni = bool(counter_summary["a_vni_auth_drops"])
            classification, absent_name = (("VNI_ADMISSION_DEFECT", "A VXLAN -> A fabric veth (VNI-auth drop counter increased)")
                                           if vni else ("REMOTE_REALM_BRIDGE_DEFECT", "A VXLAN -> A fabric veth (no VNI-auth drop counter increase)"))
        else:
            classification, absent_name = classes.get(absent, ("DHCP_INTERFACE_BINDING_DEFECT", "A Realm bridge -> dnsmasq"))
        result = {"result": "BOUNDARY_ESTABLISHED", "classification": classification,
                  "first_present_boundary": (f"{present[0]}:{present[1]}" if present else "guest B solicitation transcript"),
                  "first_absent_boundary": absent_name,
                  "observations": observations,
                  "link_counter_deltas": link_deltas, "nft_drop_counter_deltas": drop_deltas,
                  "counter_summary": counter_summary,
                  "wireguard_transfer_deltas": wireguard_deltas,
                  "dhcp_transaction_id": xid,
                  "transport_capture_correlation": "B peer IP/port filtered; same bounded DHCP retry window and WireGuard transfer-counter deltas",
                  "b_her_entry_for_a": True, "b_wireguard_peer_for_a": True,
                  "stop_at_first_failure": True}
        write_json(ev / "result.json", result)
        write_json(ev / "topology" / "boundary-observations.json", observations)
        print(json.dumps(result))
        return 0
    except Exception as exc:
        manifest = ev / "topology" / "capture-manifest.json"
        if manifest.exists():
            for spec in json.loads(manifest.read_text()):
                try:
                    script = (f"pid=$(cat {shlex.quote(spec['pid'])} 2>/dev/null || true); "
                              f"if test -n \"$pid\" && test -r /proc/$pid/cmdline && "
                              f"tr '\\0' ' ' </proc/$pid/cmdline | grep -Fq -- {shlex.quote(spec['pcap'])}; "
                              f"then kill -INT \"$pid\"; fi")
                    remote_script(args, spec["host"], script)
                except Exception:
                    pass
        write_json(ev / "result.json", {"result": "STOP", "classification": "HARNESS_GAP",
                                         "first_present_boundary": "unknown", "first_absent_boundary": "capture collection",
                                         "detail": str(exc)})
        print(json.dumps({"state": "stop", "classification": "HARNESS_GAP", "detail": str(exc)}))
        return 20


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=("prepare", "finish"))
    p.add_argument("--evidence", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--known-hosts", required=True)
    p.add_argument("--address-a", required=True)
    p.add_argument("--address-b", required=True)
    p.add_argument("--address-c", required=True)
    p.add_argument("--endpoint-a", required=True)
    p.add_argument("--endpoint-b", required=True)
    p.add_argument("--endpoint-c", required=True)
    p.add_argument("--mac-a", required=True)
    p.add_argument("--mac-b", required=True)
    p.add_argument("--mac-c", required=True)
    p.add_argument("--product-sha", required=True)
    p.add_argument("--product-tree", required=True)
    p.add_argument("--harness-sha", required=True)
    args = p.parse_args()
    args.addresses = {h: getattr(args, f"address_{h}") for h in "abc"}
    args.endpoints = {h: getattr(args, f"endpoint_{h}") for h in "abc"}
    args.macs = {h: getattr(args, f"mac_{h}") for h in "abc"}
    return action_prepare(args) if args.action == "prepare" else action_finish(args)


if __name__ == "__main__":
    sys.exit(main())
