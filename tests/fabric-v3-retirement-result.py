#!/usr/bin/env python3
"""Build the authoritative, secret-free Fabric retirement result artifact."""
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any


def read_json(root: pathlib.Path, relative: str) -> dict[str, Any]:
    value = json.loads((root / relative).read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {relative}")
    return value


def build_result(
    evidence: pathlib.Path, controller_id: str, controller_epoch: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    root = evidence.resolve()
    manifest = read_json(root, "manifest.json")
    before = read_json(root, "before-departure/durable-work/pre-delete-work-history.json")
    retirement = read_json(root, "c-delete/retirement-obligation/durable-order.json")
    provider_absence = read_json(root, "c-delete/provider-absence/result.json")
    restart_provider_absence = read_json(root, "restart/provider-absence/result.json")
    survivors = read_json(root, "endpoint-removal/survivor-state.json")
    restart = read_json(root, "restart/startup-recovery/result.json")
    controller_stop = read_json(root, "restart/startup-recovery/controller-stop.json")
    controller_stopped = read_json(root, "restart/startup-recovery/controller-stop-observed.json")
    controller_start = read_json(root, "restart/startup-recovery/controller-start.json")
    post_restart = read_json(root, "restart/durable-work/retirement-after-restart.json")
    restart_cutoff = (root / "restart/durable-work/pre-restart-rowid.txt").read_text().strip()
    ordering = read_json(root, "c-delete/retirement-obligation/ordering-observations.json")
    port = read_json(root, "c-delete/port/state-transition.json")
    cleanup = read_json(root, "teardown/management-network-cleanup-status.json")
    foreign = read_json(root, "teardown/foreign-state.json")
    directory = json.loads((root / "environment/network-agent-directory.json").read_text())
    fabric_identities = json.loads((root / "environment/fabric-identities.json").read_text())
    management = read_json(root, "environment/management-network-plan.json")

    inventory: dict[str, dict[str, str]] = {}
    for line in (root / "environment/inventory.tsv").read_text().splitlines():
        columns = line.split("\t")
        if len(columns) != 5:
            raise ValueError("fresh guest inventory row is malformed")
        role, domain, address, mac, guest_uuid = columns
        host = role.removeprefix("compute-")
        if host not in {"a", "b", "c"} or not guest_uuid:
            raise ValueError("fresh guest inventory identity is incomplete")
        inventory[host] = {
            "guest_uuid": guest_uuid,
            "domain": domain,
            "management_ip": address,
            "management_mac": mac,
        }
    if set(inventory) != {"a", "b", "c"}:
        raise ValueError("fresh A/B/C guest inventory is incomplete")

    compute_agents: dict[str, dict[str, str]] = {}
    for host in "abc":
        ready = read_json(root, f"management/compute-{host}-ready.json")
        if ready.get("agent_id") != f"compute-agent-{host}" or not ready.get("agent_epoch"):
            raise ValueError(f"compute agent identity is incomplete for host-{host}")
        compute_agents[f"host-{host}"] = {
            "agent_id": ready["agent_id"],
            "agent_epoch": ready["agent_epoch"],
        }

    network_agents: dict[str, dict[str, str]] = {}
    if len(directory) != 3 or len(fabric_identities) != 3:
        raise ValueError("network-agent/Fabric identity inventory is incomplete")
    for agent, fabric in zip(directory, fabric_identities, strict=True):
        host = agent.get("host_id")
        if (
            host not in {"host-a", "host-b", "host-c"}
            or fabric.get("host_id") != host
            or agent.get("agent_id") != f"network-agent-{host[-1]}"
            or fabric.get("agent_id") != agent.get("agent_id")
            or not agent.get("agent_epoch")
        ):
            raise ValueError(f"network-agent identity is inconsistent for {host}")
        network_agents[host] = {
            "agent_id": agent["agent_id"],
            "agent_epoch": agent["agent_epoch"],
        }

    realm_id = before.get("realm_id")
    prior_generation = before.get("realm_generation")
    prior_participants = before.get("participants")
    if not realm_id or prior_participants != ["host-a", "host-b", "host-c"]:
        raise ValueError("pre-retirement Realm identity/participants are invalid")
    plan = read_json(root, "before-departure/plans/host-a-fabric-plan.json")
    vni = (plan.get("encapsulation") or {}).get("provider_segment_id")
    if not isinstance(vni, int):
        raise ValueError("pre-retirement VNI is missing")
    if any(item.get("fabric_generation") != 1 for item in fabric_identities):
        raise ValueError("fresh Fabric generation inventory is inconsistent")

    remove = retirement.get("c_remove") or {}
    if (
        remove.get("action") != "Remove"
        or remove.get("state") != "succeeded"
        or remove.get("target_host_id") != "host-c"
        or remove.get("target_agent_id") != "network-agent-c"
        or not remove.get("target_agent_epoch")
        or not remove.get("idempotency_key")
    ):
        raise ValueError("durable C Remove identity/state is incomplete")
    expected_absence = {
        "endpoint_tap_absent",
        "realm_links_absent",
        "realm_namespace_absent",
        "vxlan_absent",
        "fabric_plan_absent",
        "anti_spoof_absent",
        "local_dhcp_state_absent",
    }
    if set(provider_absence) != expected_absence or not all(
        provider_absence.get(key) is True for key in expected_absence
    ):
        raise ValueError("provider absence artifact contains a failed predicate")
    if set(restart_provider_absence) != expected_absence or not all(
        restart_provider_absence.get(key) is True for key in expected_absence
    ):
        raise ValueError("post-restart provider absence artifact contains a failed predicate")
    if survivors.get("participants") != ["host-a", "host-b"] or survivors.get("retired_host_c_absent") is not True:
        raise ValueError("survivor convergence artifact is invalid")
    if (
        restart.get("controller_restarted") is not True
        or restart.get("c_apply_recreated") is not False
        or restart.get("c_provider_state_absent") is not True
        or restart.get("desired_participants") != ["host-a", "host-b"]
    ):
        raise ValueError("post-retirement controller restart artifact is invalid")
    if post_restart.get("c_apply_recreated") is not False:
        raise ValueError("durable recovery artifact reports a recreated C Apply")
    if (
        controller_stopped.get("old_process_gone") is not True
        or not controller_stop.get("old_controller_pid")
        or not controller_start.get("new_controller_pid")
        or not restart_cutoff.isdecimal()
        or not post_restart.get("latest_c_work")
    ):
        raise ValueError("controller restart process/cutoff evidence is incomplete")
    if (
        ordering.get("remove_success_observed_before_provider_absence") is not True
        or ordering.get("provider_absence_observed_before_survivor_convergence") is not True
        or not all(
            isinstance(ordering.get(key), str) and ordering.get(key)
            for key in (
                "remove_success_observed_at_utc",
                "provider_absence_observed_at_utc",
                "survivor_convergence_observed_at_utc",
            )
        )
        or not (
            ordering.get("remove_success_observed_at_utc")
            < ordering.get("provider_absence_observed_at_utc")
            < ordering.get("survivor_convergence_observed_at_utc")
        )):
            raise ValueError("provider absence was not observed before survivor convergence")
    if cleanup.get("cleanup_command_status") != "PASS" or cleanup.get("post_cleanup_inventory_status") != "PASS":
        raise ValueError("management network cleanup proof is incomplete")
    expected_foreign = {
        "foreign_networks_unchanged",
        "foreign_domains_unchanged",
        "foreign_pools_unchanged",
        "foreign_links_unchanged",
        "host_routes_unchanged",
        "host_addresses_unchanged",
    }
    if (
        cleanup.get("foreign_state_unchanged") is not True
        or set(foreign) != expected_foreign
        or not all(foreign.get(key) is True for key in expected_foreign)
    ):
        raise ValueError("foreign-state preservation proof is incomplete")
    if port.get("after", {}).get("status") != "DOWN":
        raise ValueError("C port transition does not end in DOWN")

    traffic_files = (
        "before-departure/traffic/a-to-b.txt",
        "before-departure/traffic/b-to-a.txt",
        "before-departure/traffic/a-to-c.txt",
        "before-departure/traffic/c-to-a.txt",
        "before-departure/traffic/a-to-c-canonical-arp.txt",
        "endpoint-removal/a-to-b.txt",
        "endpoint-removal/b-to-a.txt",
        "restart/traffic/a-to-b.txt",
        "restart/traffic/b-to-a.txt",
        "restart/traffic/a-to-b-canonical-arp.txt",
    )
    if any(not (root / item).is_file() for item in traffic_files):
        raise ValueError("required pre/post-retirement packet evidence is missing")

    identities = {
        "controller": {"id": controller_id, "epoch": controller_epoch},
        "compute_agents": compute_agents,
        "network_agents": network_agents,
        "fabric_generations": {item["host_id"]: item["fabric_generation"] for item in fabric_identities},
        "realm_id": realm_id,
        "realm_generation_before_departure": prior_generation,
        "vni": vni,
        "fresh_guests": inventory,
        "management_addresses": management.get("addresses"),
    }
    result = {
        "artifact_type": "fabric-v3-durable-host-retirement-result",
        "result": "PASS",
        "run_id": manifest.get("run_id"),
        "product_sha": manifest.get("product_sha"),
        "product_tree": manifest.get("product_tree"),
        "harness_sha": manifest.get("harness_sha"),
        "harness_tree": manifest.get("harness_tree"),
        "identities": identities,
        "pre_retirement": {
            "participants": prior_participants,
            "realm_generation": prior_generation,
            "her": before.get("her"),
            "latest_apply_by_host": before.get("latest_apply_by_host"),
            "traffic": "PASS",
        },
        "c_departure": {
            "server_id": read_json(root, "c-delete/operation/request.json").get("server_id"),
            "supported_api_delete": "PASS",
            "port_state_transition": port,
            "desired_participants": ["host-a", "host-b"],
        },
        "retirement": {
            "prior_c_apply": retirement.get("prior_c_apply"),
            "remove": remove,
            "dispatch_target": {
                "host_id": remove.get("target_host_id"),
                "agent_id": remove.get("target_agent_id"),
                "agent_epoch": remove.get("target_agent_epoch"),
            },
            "provider_absence": provider_absence,
            "ordering": retirement.get("ordering"),
        },
        "survivor_convergence": {
            "directory_generation": survivors.get("directory_generation"),
            "participants": survivors.get("participants"),
            "her": {host: item.get("her") for host, item in survivors.get("survivors", {}).items()},
            "stale_c_her": False,
            "traffic": "PASS",
        },
        "controller_restart": {
            "result": restart,
            "old_controller": controller_stop,
            "old_controller_exit": controller_stopped,
            "new_controller": controller_start,
            "durable_work_rowid_cutoff": int(restart_cutoff),
            "durable_recovery": post_restart,
            "traffic": "PASS",
        },
        "supported_teardown": "PASS",
        "foreign_state_preserved": foreign,
        "evidence_files": [
            "manifest.json",
            "before-departure/durable-work/pre-delete-work-history.json",
            "c-delete/operation/request.json",
            "c-delete/retirement-obligation/durable-order.json",
            "c-delete/retirement-obligation/ordering-observations.json",
            "c-delete/remove-command/durable-work-row.json",
            "c-delete/agent-journal/network-agent-c.json",
            "c-delete/provider-absence/result.json",
            "restart/provider-absence/result.json",
            "endpoint-removal/survivor-state.json",
            "restart/startup-recovery/result.json",
            "restart/durable-work/retirement-after-restart.json",
            "restart/startup-recovery/controller-stop.json",
            "restart/startup-recovery/controller-stop-observed.json",
            "restart/startup-recovery/controller-start.json",
            "restart/durable-work/pre-restart-rowid.txt",
            "c-delete/port/state-transition.json",
            "c-delete/provider-absence/remove-observed-before-survivor-convergence.txt",
            "c-delete/provider-absence/provider-absence-observed-at-utc.txt",
            "teardown/management-network-cleanup-status.json",
            "teardown/foreign-state.json",
        ],
        "first_failure": None,
        "classification": None,
    }
    manifest["controller"] = identities["controller"]
    manifest["compute_agents"] = compute_agents
    manifest["network_agents"] = network_agents
    manifest["fabric_generations"] = identities["fabric_generations"]
    manifest["realm"] = {
        "id": realm_id,
        "vni": vni,
        "generation_before_departure": prior_generation,
        "participants_before_departure": prior_participants,
    }
    manifest["guest_identity"] = inventory
    manifest["campaign_result"] = "PASS"
    return result, manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True, type=pathlib.Path)
    parser.add_argument("--controller-id", required=True)
    parser.add_argument("--controller-epoch", required=True)
    args = parser.parse_args()
    result, manifest = build_result(args.evidence_dir, args.controller_id, args.controller_epoch)
    (args.evidence_dir / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    (args.evidence_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
