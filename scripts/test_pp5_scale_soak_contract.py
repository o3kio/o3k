#!/usr/bin/env python3
"""Regression tests for the fail-closed PP.5 scale/soak evidence contract."""

from __future__ import annotations

import hashlib
import datetime as dt
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pp5_scale_soak_contract as contract


SOURCE = "0123456789abcdef0123456789abcdef01234567"
TREE = "1123456789abcdef0123456789abcdef01234567"
DIGEST = "a" * 64


def host_rows(count: int) -> list[dict]:
    return [{
        "stable_host_id": f"host-{index}", "ready": True, "compute_capable": True,
        "placement_eligible": True, "kernel": "6.8", "distro": "ubuntu 24.04",
        "architecture": "x86_64", "kvm_state": "enabled", "compute_agent_id": f"compute-{index}",
        "compute_agent_epoch": f"epoch-{index}", "network_agent_id": f"network-{index}",
        "network_agent_epoch": f"network-epoch-{index}", "fabric_generation": f"generation-{index}",
        "canonical_mac": f"02:00:00:00:00:{index + 1:02x}",
        "kernel_boot_id": f"00000000-0000-0000-0000-{index:012d}",
    } for index in range(count)]


def base(tier: str) -> dict:
    scale = tier if tier in contract.SCALE_HOSTS else contract.SOAKS[tier][0]
    count = contract.SCALE_HOSTS[scale]
    initial_hosts = host_rows(count)
    final_hosts = initial_hosts[:-1] + [dict(host_rows(1)[0], stable_host_id="host-replacement",
                                           compute_agent_id="compute-replacement",
                                           network_agent_id="network-replacement",
                                           canonical_mac="02:00:00:ff:ff:01",
                                           kernel_boot_id="00000000-0000-0000-0000-999999999999")]
    doc = {
        "schema": "o3k.pp5-scale-soak-run.v1", "artifact_type": "o3k-pp5-scale-soak-run",
        "status": "passed", "tier": tier,
        "source": {"sha": SOURCE, "tree": TREE},
        "release": {"version": "0.4.0-rc.25", "tag": "v0.4.0-rc.25", "tag_object_sha": TREE,
                    "source_sha": SOURCE, "source_tree": TREE, "archive_sha256": DIGEST,
                    "install_sha256": DIGEST, "manifest_sha256": DIGEST,
                    "sbom_sha256": DIGEST, "provenance_sha256": DIGEST,
                    "signature_bundle_sha256": DIGEST, "verification_report_sha256": DIGEST,
                    "signature_verified": True, "provenance_verified": True,
                    "workflow_identity_verified": True, "transparency_verified": True},
        "harness": {"sha": SOURCE, "tree": TREE, "workflow_sha": SOURCE},
        "run": {"id": f"123-{tier.lower().replace('-', '_')}", "workflow_run_id": "123", "workflow_ref": "o3kio/o3k/.github/workflows/real-host-validation.yml@refs/heads/main",
                 "workflow_sha": SOURCE, "runner_name": "protected-runner", "evidence_root": "."},
        "database": {"backend": "postgres", "identity": f"o3k_pp5_{tier.lower().replace('-', '_')}_123-{tier.lower().replace('-', '_')}", "server_version": "16.4",
                     "migrations_applied": 17},
        "timestamps": {"started_at": "2026-10-15T00:00:00Z", "finished_at": "2026-10-15T00:00:01Z",
                       "monotonic_elapsed_seconds": 0},
        "initial_eligible_hosts": initial_hosts,
        "eligible_hosts": final_hosts, "observed_eligible_host_count": count,
        "resource_budget": {"physical_host_cpus": 64, "physical_host_memory_bytes": 137438953472,
            "physical_disk_free_bytes": 1099511627776, "nested_vcpu_per_host": 2,
            "nested_memory_bytes_per_host": 2147483648, "nested_disk_bytes_per_host": 10737418240,
            "management_addresses_reserved": count, "kvm_available": True},
        "lifecycle": {key: {"status": "passed", "evidence": None} for key in contract.LIFECYCLE_GATES},
        "owned_leaks": 0, "foreign_mutations": 0,
    }
    doc["resource_baseline"] = {
        "schema": "o3k.pp5-resource-baseline.v1",
        "captured_at": "2026-10-15T00:00:00Z",
        "controller": {"rss_bytes": 1, "fd_count": 1, "process_count": 1, "thread_count": 1},
        "postgres": {"database_identity": doc["database"]["identity"],
                     "server_version": doc["database"]["server_version"],
                     "connections": 1, "database_size_bytes": 1},
        "hosts": [{
            "stable_host_id": host["stable_host_id"],
            "compute_agent": {"agent_id": host["compute_agent_id"], "pid": 100 + index,
                              "rss_bytes": 1, "fd_count": 1},
            "network_agent": {"agent_id": host["network_agent_id"], "pid": 200 + index,
                              "rss_bytes": 1, "fd_count": 1},
        } for index, host in enumerate(final_hosts)],
    }
    doc["lifecycle"]["placement_distribution"] = {"eligible_host_ids": ["host-0", "host-1"]}
    if tier in contract.SOAKS:
        elapsed = contract.SOAKS[tier][1]
        cycle_count = max(10, elapsed // 1800)
        completed_cycle_times = [elapsed * (index + 0.5) / cycle_count for index in range(cycle_count)]
        doc["timestamps"]["monotonic_elapsed_seconds"] = elapsed
        doc["timestamps"]["finished_at"] = (dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc)
                                                + dt.timedelta(seconds=elapsed)).isoformat().replace("+00:00", "Z")
        sample = {field: 0 for field in contract.SOAK_SAMPLE_FIELDS if field != "elapsed_seconds"}
        sample["eligible_hosts"] = count
        samples = []
        sample_count = int(elapsed / 600) + 1
        soak_started = dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc)
        for index in range(sample_count):
            item = dict(sample)
            item["elapsed_seconds"] = index * (elapsed / (sample_count - 1))
            item["timestamp"] = (soak_started + dt.timedelta(seconds=item["elapsed_seconds"])).isoformat().replace("+00:00", "Z")
            item["phase"] = "running"
            cycles_done = sum(value <= item["elapsed_seconds"] for value in completed_cycle_times)
            item["create_attempts"] = item["create_successes"] = cycles_done
            item["delete_attempts"] = item["delete_successes"] = cycles_done
            item["orphan_repair_duration_ms"] = index + 1
            item["deleted_server_history_size"] = index * 2
            item["compute_agents"] = [{
                "stable_host_id": host["stable_host_id"], "agent_id": host["compute_agent_id"],
                "pid": 100 + host_index, "epoch": host["compute_agent_epoch"],
                "rss_bytes": 1, "fd_count": 1,
            } for host_index, host in enumerate(final_hosts)]
            item["network_agents"] = [{
                "stable_host_id": host["stable_host_id"], "agent_id": host["network_agent_id"],
                "pid": 200 + host_index, "epoch": host["network_agent_epoch"],
                "rss_bytes": 1, "fd_count": 1,
            } for host_index, host in enumerate(final_hosts)]
            if index == sample_count - 1:
                item["phase"] = "post_cleanup"
                item.update({"quota_usage": 0, "allocation_count": 0, "server_count": 0,
                             "owned_endpoints": 0, "durable_work_pending": 0,
                             "durable_work_applying": 0, "durable_work_unknown": 0,
                             "durable_work_retryable": 0, "oldest_work_age_seconds": 0})
            samples.append(item)
        serialized = "".join(json.dumps(item, sort_keys=True) + "\n" for item in samples).encode()
        doc["_samples_bytes"] = serialized
        doc["soak"] = {
            "scale": scale, "required_duration_seconds": elapsed,
            "started_at": soak_started.isoformat().replace("+00:00", "Z"),
            "finished_at": (soak_started + dt.timedelta(seconds=elapsed)).isoformat().replace("+00:00", "Z"),
            "monotonic_elapsed_seconds": elapsed,
            "samples": {"path": "samples.jsonl", "sha256": hashlib.sha256(serialized).hexdigest()},
            "scale_baseline": {"tier": scale},
            "fault_events": [],
            "orphan_repair_sweeps": [{"elapsed_seconds": elapsed * (index + 0.5) / 5,
                "deleted_server_history_size": index * 2, "duration_ms": index + 1} for index in range(5)],
        }
        kinds = ["control_plane_restart", "control_plane_restart", "postgres_process_restart", "building_block_drain_recovery"] if tier == "K-min" else ["control_plane_restart", "postgres_process_restart", "building_block_drain_recovery"]
        offsets = [elapsed * fraction for fraction in ([0.15, 0.35, 0.65, 0.85] if tier == "K-min" else [0.2, 0.5, 0.8])]
        for kind, offset in zip(kinds, offsets):
            event = {"event_id": f"event-{len(doc['soak']['fault_events'])}", "kind": kind,
                     "elapsed_seconds": offset, "status": "passed"}
            if kind == "postgres_process_restart":
                event.update({"postgres_pid_before": 1, "postgres_pid_after": 2,
                              "postgres_start_time_before": "100", "postgres_start_time_after": "200",
                              "database_identity": doc["database"]["identity"],
                              "postgres_executable_before": "/usr/lib/postgresql/16/bin/postgres",
                              "postgres_executable_after": "/usr/lib/postgresql/16/bin/postgres",
                              "data_directory_identity_before": "data-dir-run-owned",
                              "data_directory_identity_after": "data-dir-run-owned",
                              "server_version_before": doc["database"]["server_version"],
                              "server_version_after": doc["database"]["server_version"]})
            elif kind == "control_plane_restart":
                event.update({"controller_pid_before": 10, "controller_pid_after": 11,
                              "controller_start_time_before": "100", "controller_start_time_after": "200",
                              "controller_executable_before": "/usr/bin/o3kd",
                              "controller_executable_after": "/usr/bin/o3kd",
                              "controller_epoch_before": 1, "controller_epoch_after": 2})
            else:
                event.update({"block_id": "host-0", "drain_observed": True,
                              "resident_blocker_observed": True, "recovery_state": "ready"})
            doc["soak"]["fault_events"].append(event)
        doc["churn"] = {
            "create_attempts": cycle_count, "create_successes": cycle_count, "delete_attempts": cycle_count,
            "delete_successes": cycle_count, "completed_cycles": cycle_count, "retries": 0, "failures": 0,
            "successful_cycle_elapsed_seconds": completed_cycle_times,
        }
        doc["resource_analysis"] = {
            "algorithm": "pp5-five-bucket-sustained-rise-v1", "decision": "bounded",
            "thresholds": contract.RESOURCE_LIMITS,
            "results": {key: contract.check_sustained_growth(samples, key, limits["absolute"], limits["fraction"])
                        for key, limits in contract.RESOURCE_LIMITS.items()
                        if key not in ("agent_rss_bytes", "agent_fd_count")},
        }
        samples = [json.loads(line) for line in serialized.decode().splitlines()]
        for metric, field in (("agent_rss_bytes", "rss_bytes"), ("agent_fd_count", "fd_count")):
            doc["resource_analysis"]["results"][metric] = {
                role: {
                    host["stable_host_id"]: contract.check_sustained_growth(
                        [{metric: agent[field]} for sample_item in samples
                         for agent in sample_item[f"{role}s"]
                         if agent["stable_host_id"] == host["stable_host_id"]],
                        metric, contract.RESOURCE_LIMITS[metric]["absolute"],
                        contract.RESOURCE_LIMITS[metric]["fraction"],
                    )
                    for host in final_hosts
                }
                for role in ("compute_agent", "network_agent")
            }
    return doc


def gate_observations(gate: str, doc: dict) -> dict:
    initial = [host["stable_host_id"] for host in doc["initial_eligible_hosts"]]
    final = [host["stable_host_id"] for host in doc["eligible_hosts"]]
    removed = initial[-1]
    values = {
        "release_install": {"release_tag": doc["release"]["tag"], "installed_version": doc["release"]["version"],
            "archive_sha256": doc["release"]["archive_sha256"], "install_sha256": doc["release"]["install_sha256"],
            "manifest_sha256": doc["release"]["manifest_sha256"], "sbom_sha256": doc["release"]["sbom_sha256"],
            "provenance_sha256": doc["release"]["provenance_sha256"],
            "signature_bundle_sha256": doc["release"]["signature_bundle_sha256"],
            "archive_round_trip_verified": True, "signature_verified": True},
        "control_plane_init": {"controller_identity": "o3kd-1", "api_ready": True, "postgres_backend": True},
        "authenticated_joins": {"authenticated_join_count": len(initial), "eligible_host_ids": initial},
        "canonical_topology": {"eligible_host_count": len(initial), "eligible_host_ids": initial,
            "duplicate_host_identities": 0},
        "placement": {"placed_host_ids": initial[:2], "real_workloads_created": True},
        "capacity_change": {"capacity_before": 2, "capacity_after": 3},
        "drain": {"drained_host_id": removed, "drain_state": "draining"},
        "placement_rejection": {"drained_host_id": removed, "placement_on_drained_host_rejected": True},
        "resident_blocker": {"resident_workload_blocker_observed": True, "blocker_count": 1},
        "remove": {"remove_operation_id": "operation-remove", "remove_succeeded": True, "removed_host_id": removed},
        "replacement": {"replacement_host_id": "host-replacement", "replacement_joined": True,
            "eligible_host_count_after_replacement": len(final), "eligible_host_ids_before_replacement": initial,
            "eligible_host_ids_after_replacement": final},
        "control_plane_restart": {"process_id_before": 1, "process_id_after": 2,
            "start_time_before": "100", "start_time_after": "200", "recovered_ready": True,
            "controller_epoch_before": 1, "controller_epoch_after": 2},
        "postgres_restart": {"process_id_before": 3, "process_id_after": 4,
            "start_time_before": "300", "start_time_after": "400", "recovered_ready": True,
            "restart_kind": "postgres_process", "database_identity": doc["database"]["identity"],
            "process_executable_before": "/usr/lib/postgresql/16/bin/postgres",
            "process_executable_after": "/usr/lib/postgresql/16/bin/postgres",
            "data_directory_identity_before": "data-dir-run-owned",
            "data_directory_identity_after": "data-dir-run-owned",
            "server_version_before": doc["database"]["server_version"],
            "server_version_after": doc["database"]["server_version"]},
        "identity_reconstruction": {"stable_host_ids_preserved": True, "duplicate_identities": 0},
        "projection_convergence": {"consecutive_consistent_observations": 2,
            "canonical_and_api_projections_equal": True},
        "fabric_networking": {"canonical_participant_ids": final, "dhcp_dora_pass": True,
            "canonical_arp_pass": True, "icmp_success_count": 6, "tcp_pass": True, "udp_pass": True},
        "tenant_isolation": {"cross_tenant_access_denied": True, "forged_source_mac_denied": True,
            "forged_source_ip_denied": True, "foreign_fdb_unchanged": True},
        "mtu": {"tested_mtu_bytes": 1500, "expected_mtu_bytes": 1500,
            "boundary_packet_passed": True, "oversize_packet_rejected": True},
        "endpoint_lifecycle": {"endpoint_id": "endpoint-1", "created": True, "attached": True,
            "recreated": True, "released_after_delete": True, "endpoint_count_after_teardown": 0},
        "agent_restart": {"agent_id": "compute-1", "process_id_before": 30, "process_id_after": 31,
            "process_kind": "compute_agent",
            "start_time_before": "before", "start_time_after": "after", "agent_epoch_before": 1,
            "agent_epoch_after": 2, "recovered_ready": True},
        "durable_work_recovery": {"interruption_injected": True, "work_persisted_before_restart": True,
            "work_converged_after_restart": True, "unresolved_work_after_recovery": 0},
        "quota_allocation": {"quota_accounting_consistent": True, "allocation_accounting_consistent": True,
            "quota_leak_count_after_teardown": 0, "allocation_leak_count_after_teardown": 0},
        "supported_teardown": {"supported_api_teardown": True, "owned_resources_remaining": 0},
        "owned_leaks_zero": {"supported_api_teardown": True, "owned_resources_remaining": 0},
        "foreign_state_unchanged": {"foreign_fingerprint_before": "abc", "foreign_fingerprint_after": "abc",
            "foreign_mutations": 0},
    }
    return values[gate]


def captured(payload: dict) -> dict:
    raw = json.dumps(payload, sort_keys=True)
    return {"captured_at": "2026-10-15T00:00:00Z", "command_class": "test_observation",
            "exit_code": 0, "raw_output": raw,
            "raw_output_sha256": hashlib.sha256(raw.encode()).hexdigest()}


def write_observation(root: pathlib.Path, prefix: str, name: str, payload: dict, doc: dict) -> dict:
    local_root = root if prefix == "." else root / prefix
    directory = local_root / "observations"
    directory.mkdir(parents=True, exist_ok=True)
    common = {"run_id": doc["run"]["id"], "source_sha": doc["source"]["sha"],
              "source_tree": doc["source"]["tree"], "harness_sha": doc["harness"]["sha"],
              "harness_tree": doc["harness"]["tree"], "tier": doc["tier"]}
    path = directory / f"{name}.json"
    raw = json.dumps({**common, **payload}, sort_keys=True).encode()
    path.write_bytes(raw)
    return {"path": path.relative_to(local_root).as_posix(), "sha256": hashlib.sha256(raw).hexdigest()}


def process_artifact(kind: str, doc: dict, before_pid: int, after_pid: int,
                     before_start: str, after_start: str, **extra) -> dict:
    executable = {"controller": "/usr/bin/o3kd", "postgres": "/usr/lib/postgresql/16/bin/postgres",
                  "compute_agent": "/opt/o3k/bin/o3k-compute",
                  "network_agent": "/opt/o3k/bin/o3k-network"}[kind]
    return {"schema": "o3k.pp5-process-restart-observation.v1", "process_kind": kind,
            "owner_type": "run-owned", "owner_run_id": doc["run"]["id"],
            "observer_type": "host_procfs_read_only", "before": {"pid": before_pid,
            "start_time": before_start, "executable": executable},
            "after": {"pid": after_pid, "start_time": after_start, "executable": executable},
            "recovery": {"ready": True, "consistent_observations": 2}, **captured({"kind": kind}), **extra}


def add_gate_observation_artifacts(gate: str, observations: dict, doc: dict,
                                   root: pathlib.Path, prefix: str) -> None:
    if gate in {"control_plane_restart", "postgres_restart", "agent_restart"}:
        if gate == "control_plane_restart":
            kind = "controller"
            extra = {"epochs": {"before": observations["controller_epoch_before"],
                                "after": observations["controller_epoch_after"]}}
            before, after = observations["process_id_before"], observations["process_id_after"]
            starts = (observations["start_time_before"], observations["start_time_after"])
        elif gate == "postgres_restart":
            kind = "postgres"
            extra = {"database_identity": doc["database"]["identity"],
                     "server_version": doc["database"]["server_version"],
                     "data_directory_identity": observations["data_directory_identity_before"]}
            before, after = observations["process_id_before"], observations["process_id_after"]
            starts = (observations["start_time_before"], observations["start_time_after"])
        else:
            kind = observations["process_kind"]
            extra = {"agent_id": observations["agent_id"],
                     "epochs": {"before": observations["agent_epoch_before"],
                                "after": observations["agent_epoch_after"]}}
            before, after = observations["process_id_before"], observations["process_id_after"]
            starts = (observations["start_time_before"], observations["start_time_after"])
        observations["process_observation_evidence"] = write_observation(
            root, prefix, f"{gate}-process", process_artifact(kind, doc, before, after, *starts, **extra), doc)
    elif gate == "fabric_networking":
        hosts = doc["eligible_hosts"]
        probes = []
        for host in hosts:
            probes.append({**captured({"probe": "dhcp"}), "probe_id": f"dhcp-{host['stable_host_id']}",
                           "kind": "dhcp_dora", "source_host_id": host["stable_host_id"],
                           "result": "passed", "lease_acquired": True})
        for source_index, destination_index in ((0, 1), (1, 0)):
            source, destination = hosts[source_index], hosts[destination_index]
            probes.append({**captured({"probe": "arp"}), "probe_id": f"arp-{source['stable_host_id']}",
                           "kind": "canonical_arp", "source_host_id": source["stable_host_id"],
                           "destination_host_id": destination["stable_host_id"],
                           "destination_canonical_mac": destination["canonical_mac"],
                           "resolved_mac": destination["canonical_mac"], "result": "passed"})
            probes.append({**captured({"probe": "icmp"}), "probe_id": f"icmp-{source['stable_host_id']}",
                           "kind": "icmp", "source_host_id": source["stable_host_id"],
                           "destination_host_id": destination["stable_host_id"],
                           "packets_sent": 3, "packets_received": 3, "result": "passed"})
        for kind in ("tcp", "udp"):
            probes.append({**captured({"probe": kind}), "probe_id": kind,
                           "kind": kind, "source_host_id": hosts[0]["stable_host_id"],
                           "destination_host_id": hosts[1]["stable_host_id"],
                           "connections_succeeded": 1, "result": "passed"})
        observations["packet_probe_evidence"] = write_observation(
            root, prefix, "network-probes", {"schema": "o3k.pp5-network-observation.v1", "probes": probes}, doc)
    elif gate == "tenant_isolation":
        checks = [{**captured({"check": name}), "kind": name, "result": "denied"}
                  for name in ("cross_tenant_access", "forged_source_mac", "forged_source_ip")]
        observations["isolation_probe_evidence"] = write_observation(
            root, prefix, "isolation-probes",
            {"schema": "o3k.pp5-isolation-observation.v1", "checks": checks,
             "foreign_fdb_fingerprint_before": "abc", "foreign_fdb_fingerprint_after": "abc"}, doc)
    elif gate == "mtu":
        probes = [
            {**captured({"probe": "mtu-boundary"}), "kind": "boundary", "result": "passed",
             "packet_size_bytes": observations["expected_mtu_bytes"]},
            {**captured({"probe": "mtu-oversize"}), "kind": "oversize", "result": "rejected",
             "packet_size_bytes": observations["expected_mtu_bytes"] + 1},
        ]
        observations["mtu_probe_evidence"] = write_observation(
            root, prefix, "mtu-probes", {"schema": "o3k.pp5-mtu-observation.v1",
                                          "tested_mtu_bytes": observations["tested_mtu_bytes"],
                                          "expected_mtu_bytes": observations["expected_mtu_bytes"],
                                          "probes": probes}, doc)


def write_gate_artifacts(doc: dict, root: pathlib.Path, prefix: str = ".") -> None:
    tier = doc["tier"]
    prefix_path = pathlib.Path() if prefix == "." else pathlib.Path(prefix)
    gate_dir = root / prefix_path / "gates" / tier
    gate_dir.mkdir(parents=True, exist_ok=True)
    common = {"run_id": doc["run"]["id"], "source_sha": doc["source"]["sha"],
              "source_tree": doc["source"]["tree"], "harness_sha": doc["harness"]["sha"],
              "harness_tree": doc["harness"]["tree"], "tier": tier}
    for gate in contract.LIFECYCLE_GATES:
        observations = gate_observations(gate, doc)
        add_gate_observation_artifacts(gate, observations, doc, root, prefix)
        payload = {"schema": "o3k.pp5-scale-soak-gate.v1", "gate": gate,
                   "status": "passed", **common, "observations": observations}
        raw = json.dumps(payload, sort_keys=True).encode()
        path = gate_dir / f"{gate}.json"
        path.write_bytes(raw)
        doc["lifecycle"][gate]["evidence"] = {
            "path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(raw).hexdigest(),
        }


def write_soak_observations(doc: dict, root: pathlib.Path) -> None:
    if doc["tier"] not in contract.SOAKS:
        return
    for event in doc["soak"]["fault_events"]:
        kind = event["kind"]
        if kind == "building_block_drain_recovery":
            payload = {"schema": "o3k.pp5-soak-drain-observation.v1", "event_id": event["event_id"],
                       "elapsed_seconds": event["elapsed_seconds"], "block_id": event["block_id"],
                       "drain_observed": True, "resident_blocker_observed": True,
                       "recovery_state": "ready", **captured({"kind": kind})}
        else:
            process_kind = {"control_plane_restart": "controller",
                            "postgres_process_restart": "postgres",
                            "compute_agent_restart": "compute_agent"}[kind]
            if process_kind == "controller":
                extra = {"epochs": {"before": event["controller_epoch_before"],
                                    "after": event["controller_epoch_after"]}}
                before, after = event["controller_pid_before"], event["controller_pid_after"]
                starts = event["controller_start_time_before"], event["controller_start_time_after"]
            elif process_kind == "postgres":
                extra = {"event_id": event["event_id"], "elapsed_seconds": event["elapsed_seconds"],
                         "database_identity": event["database_identity"],
                         "server_version": event["server_version_before"],
                         "data_directory_identity": event["data_directory_identity_before"]}
                before, after = event["postgres_pid_before"], event["postgres_pid_after"]
                starts = event["postgres_start_time_before"], event["postgres_start_time_after"]
            else:
                extra = {"agent_id": event["agent_id"],
                         "epochs": {"before": event["agent_epoch_before"], "after": event["agent_epoch_after"]}}
                before, after = event["agent_pid_before"], event["agent_pid_after"]
                starts = event["agent_start_time_before"], event["agent_start_time_after"]
            extra.setdefault("event_id", event["event_id"])
            extra.setdefault("elapsed_seconds", event["elapsed_seconds"])
            payload = process_artifact(process_kind, doc, before, after, *starts, **extra)
        event["observation_evidence"] = write_observation(
            root, ".", f"soak-event-{event['event_id']}", payload, doc)
    cleanup = {"schema": "o3k.pp5-soak-cleanup-observation.v1", "status": "passed",
               "supported_api_teardown": True,
               "elapsed_seconds": doc["soak"]["monotonic_elapsed_seconds"],
               "remaining_resources": {key: 0 for key in (
                   "servers", "ports", "domains", "quota_usage", "allocations", "owned_endpoints",
                   "orphan_endpoints", "durable_work_pending", "durable_work_applying",
                   "durable_work_unknown", "durable_work_retryable")},
               "foreign_fingerprint_before": "abc", "foreign_fingerprint_after": "abc",
               **captured({"cleanup": "supported_api"})}
    doc["soak"]["cleanup_evidence"] = write_observation(root, ".", "soak-cleanup", cleanup, doc)


def attach_scale_baseline(doc: dict, root: pathlib.Path) -> None:
    if doc["tier"] not in contract.SOAKS:
        return
    scale = contract.SOAKS[doc["tier"]][0]
    baseline = base(scale)
    baseline["run"]["id"] = f"124-{scale.lower()}-baseline"
    baseline["run"]["workflow_run_id"] = "124"
    baseline["run"]["evidence_root"] = "scale-baseline"
    baseline["database"]["identity"] = f"o3k_pp5_{scale.lower()}_{baseline['run']['id']}"
    baseline["resource_baseline"]["postgres"]["database_identity"] = baseline["database"]["identity"]
    write_gate_artifacts(baseline, root, "scale-baseline")
    for gate in contract.LIFECYCLE_GATES:
        evidence = baseline["lifecycle"][gate]["evidence"]
        evidence["path"] = str(pathlib.PurePosixPath(evidence["path"]).relative_to("scale-baseline"))
    baseline_raw = json.dumps(baseline, sort_keys=True).encode()
    baseline_path = root / "scale-baseline" / "run.json"
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_bytes(baseline_raw)
    snapshot_raw = json.dumps(baseline["resource_baseline"], sort_keys=True, separators=(",", ":")).encode()
    doc["soak"]["scale_baseline"].update({
        "run_id": baseline["run"]["id"],
        "database_identity": baseline["database"]["identity"],
        "evidence": {"path": "scale-baseline/run.json", "sha256": hashlib.sha256(baseline_raw).hexdigest()},
        "resource_baseline_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
    })


class ContractTests(unittest.TestCase):
    def validate(self, tier: str, mutate=None) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            doc = base(tier)
            doc["run"]["evidence_root"] = "."
            write_gate_artifacts(doc, root)
            if tier in contract.SOAKS:
                raw = doc.pop("_samples_bytes")
                (root / "samples.jsonl").write_bytes(raw)
                attach_scale_baseline(doc, root)
                write_soak_observations(doc, root)
            if mutate:
                mutate(doc)
            contract.validate_run(doc, tier, root, SOURCE, TREE, SOURCE, TREE, ".")

    def rejected(self, tier: str, mutate, expected: str) -> None:
        with self.assertRaisesRegex(contract.ContractError, expected):
            self.validate(tier, mutate)

    def test_scale_tiers_accept_exact_observed_eligibility(self) -> None:
        for tier in contract.SCALE_HOSTS:
            with self.subTest(tier=tier):
                self.validate(tier)

    def test_soak_artifacts_resolve_from_nested_run_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            tier = "K-min"
            document = base(tier)
            run_directory = pathlib.Path("runs") / document["run"]["id"]
            run_root = root / run_directory
            run_root.mkdir(parents=True)
            document["run"]["evidence_root"] = run_directory.as_posix()
            write_gate_artifacts(document, run_root)
            sample_bytes = document.pop("_samples_bytes")
            (run_root / "samples.jsonl").write_bytes(sample_bytes)
            attach_scale_baseline(document, root)
            write_soak_observations(document, run_root)

            contract.validate_run(
                document,
                tier,
                root,
                SOURCE,
                TREE,
                SOURCE,
                TREE,
                run_directory.as_posix(),
                "v0.4.0-rc.25",
                DIGEST,
                artifact_root=run_root,
            )

    def test_scale_cardinality_rejects_below_and_above(self) -> None:
        for tier, count in contract.SCALE_HOSTS.items():
            for wrong in (count - 1, count + 1):
                with self.subTest(tier=tier, wrong=wrong):
                    self.rejected(tier, lambda doc, n=wrong: doc.update(eligible_hosts=host_rows(n)), "observed eligible host count")

    def test_scale_rejects_noneligible_host(self) -> None:
        self.rejected("S3", lambda doc: doc["eligible_hosts"][0].update(placement_eligible=False), "placement_eligible")

    def test_nested_budget_reserves_every_eligible_host(self) -> None:
        self.rejected("S3", lambda doc: doc["resource_budget"].update(management_addresses_reserved=2),
                      "management address reservation")

    def test_malformed_identity_lists_fail_with_contract_error(self) -> None:
        with self.assertRaisesRegex(contract.ContractError, "list of non-empty strings"):
            contract.string_list(["host-a", []], "test.host_ids")

    def test_invalid_kernel_boot_uuid_rejected(self) -> None:
        self.rejected("S3", lambda doc: doc["eligible_hosts"][0].update(kernel_boot_id="z" * 36),
                      "kernel_boot_id must be a UUID")

    def test_wrong_source_digest_rejected(self) -> None:
        self.rejected("S3", lambda doc: doc["source"].update(sha="f" * 40), "expected candidate")

    def test_release_version_uses_unprefixed_tag_binding(self) -> None:
        self.validate("S3")
        self.rejected("S3", lambda doc: doc["release"].update(tag="0.4.0-rc.25"),
                      "v-prefixed")

    def test_workflow_identity_is_explicitly_bound_to_harness(self) -> None:
        self.rejected("S3", lambda doc: doc["run"].update(workflow_sha="f" * 40),
                      "explicitly bound workflow identity")

    def test_missing_database_identity_rejected(self) -> None:
        self.rejected("S3", lambda doc: doc["database"].update(identity="shared"), "unique to the tier and workflow run")

    def test_owned_leak_and_foreign_mutation_rejected(self) -> None:
        self.rejected("S3", lambda doc: doc.update(owned_leaks=1), "owned_leaks")
        self.rejected("S3", lambda doc: doc.update(foreign_mutations=1), "foreign_mutations")
        self.rejected("S3", lambda doc: doc.update(owned_leaks=False), "integer zero")
        self.rejected("S3", lambda doc: doc.update(foreign_mutations=False), "integer zero")

    def test_missing_lifecycle_event_rejected(self) -> None:
        self.rejected("S3", lambda doc: doc["lifecycle"].update(postgres_restart="not_run"), "lifecycle gate")

    def test_soaks_accept_minimum_duration_and_required_events(self) -> None:
        for tier in contract.SOAKS:
            with self.subTest(tier=tier):
                self.validate(tier)

    def test_short_soak_rejected(self) -> None:
        def shorten(doc):
            doc["soak"]["monotonic_elapsed_seconds"] = 7199
            doc["soak"]["finished_at"] = "2026-10-15T01:59:59Z"
        self.rejected("K-min", shorten, "actual monotonic duration")

    def test_wrong_soak_scale_rejected(self) -> None:
        self.rejected("K-full", lambda doc: doc["soak"].update(scale="S10"), "scale must be S20")

    def test_missing_samples_rejected(self) -> None:
        self.rejected("K-min", lambda doc: doc["soak"].update(samples=None), "artifact reference")

    def test_missing_postgres_restart_proof_rejected(self) -> None:
        self.rejected("K-min", lambda doc: doc["soak"]["fault_events"].__setitem__(2, {
            "event_id": "event-2", "kind": "postgres_process_restart", "status": "passed",
            "elapsed_seconds": 5000}), "PostgreSQL process restart must prove")

    def test_restart_pids_must_be_positive(self) -> None:
        self.rejected("K-min", lambda doc: doc["soak"]["fault_events"][2].update(postgres_pid_before=0),
                      "distinct positive PIDs")

    def test_postgres_restart_requires_nonempty_data_directory_identity(self) -> None:
        doc = base("S3")
        observations = gate_observations("postgres_restart", doc)
        observations["data_directory_identity_before"] = None
        with self.assertRaisesRegex(contract.ContractError, "data_directory_identity_before must be non-empty"):
            contract.validate_gate_observations(
                "postgres_restart", observations,
                {host["stable_host_id"] for host in doc["initial_eligible_hosts"]},
                {host["stable_host_id"] for host in doc["eligible_hosts"]},
                3, doc["release"], doc["database"]["identity"],
                pathlib.Path("."), doc, "S3",
            )

    def test_boolean_fault_elapsed_is_rejected(self) -> None:
        self.rejected("K-min", lambda doc: doc["soak"]["fault_events"][0].update(elapsed_seconds=True),
                      "must be finite")

    def test_nonfinite_orphan_sweep_elapsed_is_rejected(self) -> None:
        self.rejected("K-min", lambda doc: doc["soak"]["orphan_repair_sweeps"][0].update(
            elapsed_seconds=float("nan")), "must be finite")

    def test_early_soak_has_no_pass(self) -> None:
        def shorten(doc):
            doc["soak"]["monotonic_elapsed_seconds"] = 43199
            doc["soak"]["finished_at"] = (dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc)
                                             + dt.timedelta(seconds=43199)).isoformat().replace("+00:00", "Z")
        self.rejected("K-full", shorten, "actual monotonic duration")

    def test_foreign_state_and_missing_samples_cannot_be_masked(self) -> None:
        self.rejected("K-full", lambda doc: doc.update(foreign_mutations=1), "foreign_mutations")

    def test_soak_detects_sustained_resource_growth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            doc = base("K-min")
            doc["run"]["evidence_root"] = "."
            write_gate_artifacts(doc, root)
            samples = [json.loads(line) for line in doc.pop("_samples_bytes").decode().splitlines()]
            for index, sample in enumerate(samples):
                sample["o3kd_fd_count"] = 10 + index * 10
            raw = "".join(json.dumps(item, sort_keys=True) + "\n" for item in samples).encode()
            (root / "samples.jsonl").write_bytes(raw)
            doc["soak"]["samples"]["sha256"] = hashlib.sha256(raw).hexdigest()
            attach_scale_baseline(doc, root)
            write_soak_observations(doc, root)
            with self.assertRaisesRegex(contract.ContractError, "sustained resource growth o3kd_fd_count"):
                contract.validate_run(doc, "K-min", root, SOURCE)

    def test_resource_growth_accepts_a_stable_plateau_after_one_time_allocation(self) -> None:
        samples = [{"value": 10} for _ in range(10)]
        for sample in samples[2:]:
            sample["value"] = 100
        result = contract.check_sustained_growth(samples, "value", absolute=32, fraction=0.25)
        self.assertFalse(result["growth_exceeded"])
        self.assertEqual(result["positive_bucket_transitions"], 1)

    def test_resource_growth_ignores_a_transient_middle_spike(self) -> None:
        samples = [{"value": 10} for _ in range(10)]
        for sample in samples[4:6]:
            sample["value"] = 1000
        result = contract.check_sustained_growth(samples, "value", absolute=32, fraction=0.25)
        self.assertFalse(result["growth_exceeded"])

    def test_resource_growth_requires_ten_samples(self) -> None:
        with self.assertRaisesRegex(contract.ContractError, "at least ten samples"):
            contract.check_sustained_growth([{"value": 1}] * 9, "value", absolute=1, fraction=0.1)

    def test_resource_baseline_requires_matching_agent_identities(self) -> None:
        self.rejected("S3", lambda doc: doc["resource_baseline"]["hosts"][0]["compute_agent"].update(
            agent_id="foreign-agent"), "identity differs from eligible host evidence")

    def test_soak_requires_every_agent_in_each_sample(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            doc = base("K-min")
            doc["run"]["evidence_root"] = "."
            write_gate_artifacts(doc, root)
            samples = [json.loads(line) for line in doc.pop("_samples_bytes").decode().splitlines()]
            samples[0]["compute_agents"].pop()
            raw = "".join(json.dumps(item, sort_keys=True) + "\n" for item in samples).encode()
            (root / "samples.jsonl").write_bytes(raw)
            doc["soak"]["samples"]["sha256"] = hashlib.sha256(raw).hexdigest()
            attach_scale_baseline(doc, root)
            write_soak_observations(doc, root)
            with self.assertRaisesRegex(contract.ContractError, "must cover every eligible host"):
                contract.validate_run(doc, "K-min", root, SOURCE)

    def test_agent_resource_growth_is_checked_per_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            doc = base("K-min")
            doc["run"]["evidence_root"] = "."
            write_gate_artifacts(doc, root)
            samples = [json.loads(line) for line in doc.pop("_samples_bytes").decode().splitlines()]
            for index, sample in enumerate(samples):
                for agent in sample["compute_agents"]:
                    agent["rss_bytes"] = index * 32 * 1024 * 1024
            raw = "".join(json.dumps(item, sort_keys=True) + "\n" for item in samples).encode()
            (root / "samples.jsonl").write_bytes(raw)
            doc["soak"]["samples"]["sha256"] = hashlib.sha256(raw).hexdigest()
            attach_scale_baseline(doc, root)
            write_soak_observations(doc, root)
            with self.assertRaisesRegex(contract.ContractError, "sustained resource growth agent_rss_bytes"):
                contract.validate_run(doc, "K-min", root, SOURCE)

    def test_scale_baseline_run_id_must_match_bound_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            doc = base("K-min")
            doc["run"]["evidence_root"] = "."
            write_gate_artifacts(doc, root)
            (root / "samples.jsonl").write_bytes(doc.pop("_samples_bytes"))
            attach_scale_baseline(doc, root)
            write_soak_observations(doc, root)
            doc["soak"]["scale_baseline"]["run_id"] = "999-unrelated"
            with self.assertRaisesRegex(contract.ContractError, "run identity differs from the protected workflow input"):
                contract.validate_run(doc, "K-min", root, SOURCE)

    def test_artifact_path_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with self.assertRaisesRegex(contract.ContractError, "escapes evidence root"):
                contract.artifact_path(root, "../outside", DIGEST, "test")


if __name__ == "__main__":
    unittest.main()
