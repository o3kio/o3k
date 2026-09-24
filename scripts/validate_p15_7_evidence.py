#!/usr/bin/env python3
"""Validate the protected P15.7 scale/composition evidence contract.

This validator intentionally accepts only a completed real-host artifact.  A
missing, skipped, fake-provider, or fixture result is not evidence of P15.7.
The runner-specific journey is supplied by the protected host; this file only
validates its redacted, machine-readable result. Araf is an optional external
consumer and is recorded separately without becoming a mandatory gate.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any


SHA = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN_CLAIMS = re.compile(
    r"(?i)(?:datacenter[- ]scale|multi[- ]region|\bHA\b|high availability|"
    r"live migration|evacuation|production ready|production readiness)"
)
REQUIRED_STEPS = {
    "fresh_deployment",
    "init",
    "multiple_authenticated_joins",
    "topology",
    "capacity",
    "constrained_placement",
    "add_block_capacity_growth",
    "drain",
    "remove_rejoin_replace",
    "restart_recovery",
    "crash_injection_repair",
    "host_maintenance",
    "projections_convergent",
}
# Checkpoint phases the journey must record into
# scale_composition.checkpoints[] (identity sets per phase).
REQUIRED_CHECKPOINT_PHASES = (
    "initial-scale-checkpoint",
    "pre-drain",
    "post-drain",
    "post-remove",
    "post-replacement",
    "post-reboot",
    "post-crash-repair",
    "post-maintenance",
)
CLAIM_VALIDATION_SOURCES = {
    "README.md",
    "docs/ROADMAP.md",
    "docs/status/current-state.yaml",
    "compatibility/product-profiles.yaml",
    "docs/compatibility/matrix.yaml",
    "docs/architecture/p15-e2d-gap-register.md",
}


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def mapping(value: Any, name: str, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        fail(errors, f"{name} must be an object")
        return None
    return value


def passed(value: Any, name: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        value = value.get("status")
    if value is not True and value != "passed":
        fail(errors, f"{name} must be true or 'passed'")


def validate(
    document: Any,
    expected_sha: str | None = None,
    expected_profile: str | None = None,
) -> list[str]:
    errors: list[str] = []
    root = mapping(document, "evidence", errors)
    if root is None:
        return errors

    if root.get("artifact_type") != "o3k-p15-7-scale-composition-evidence":
        fail(errors, "invalid artifact_type")
    if root.get("schema_version") != 1:
        fail(errors, "schema_version must be 1")
    if root.get("phase") != "P15.7":
        fail(errors, "phase must be P15.7")
    if root.get("status") != "passed":
        fail(errors, "status must be passed; skipped/ready/not-executed is not evidence")
    if root.get("evidence_tier") != "protected-real-host":
        fail(errors, "evidence_tier must be protected-real-host")
    if root.get("profile") not in {"native-rust-testlab", "small-edge-cloud"}:
        fail(errors, "profile must be an accepted native-rust-testlab or small-edge-cloud profile")
    if expected_profile and root.get("profile") != expected_profile:
        fail(errors, f"profile does not match expected profile {expected_profile}")

    source_sha = root.get("tested_source_sha")
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
        fail(errors, "tested_source_sha must be a lowercase 40-character commit SHA")
    elif expected_sha and source_sha != expected_sha:
        fail(errors, f"tested_source_sha does not match expected source {expected_sha}")

    checkout_head = root.get("checkout_head")
    if not isinstance(checkout_head, str) or not SHA.fullmatch(checkout_head):
        fail(errors, "checkout_head must be a lowercase 40-character commit SHA")
    elif checkout_head != source_sha or (expected_sha and checkout_head != expected_sha):
        fail(errors, "checkout_head must match the tested and expected source SHA")
    if root.get("git_tree_clean") is not True:
        fail(errors, "git_tree_clean must be true for protected evidence")
    harness_digest = root.get("harness_inputs_sha256")
    if not isinstance(harness_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", harness_digest):
        fail(errors, "harness_inputs_sha256 must be a lowercase SHA-256 digest")

    execution = mapping(root.get("execution"), "execution", errors)
    if execution is not None:
        for key in ("real_o3kd", "real_auth", "real_execution_boundary", "multiple_real_hosts", "sqlite_parity"):
            passed(execution.get(key), f"execution.{key}", errors)
        if execution.get("provider") != "agent":
            fail(errors, "execution.provider must be agent (fake providers are forbidden)")
        if execution.get("hypervisor") != "libvirt":
            fail(errors, "execution.hypervisor must be libvirt (the real execution boundary)")
        if execution.get("database_backend") != "postgres":
            fail(errors, "execution.database_backend must be postgres for the production composition gate")
        if not isinstance(execution.get("block_count"), int) or execution["block_count"] < 2:
            fail(errors, "execution.block_count must be at least 2")

    scale = mapping(root.get("scale_composition"), "scale_composition", errors)
    if scale is not None:
        # The S5 composition contract (issues #974/#1037 decision): scale
        # cardinality is the ELIGIBLE set — canonical compute-capable (live
        # Placement ResourceProvider) + provider Enabled + Ready
        # BuildingBlocks with no recorded drain blockers — enumerated over
        # EVERY BuildingBlock, including the bootstrap block. Exactly five
        # eligible Ready blocks are required initially and finally; six
        # distinct compute identities (bootstrap + block-a..block-e) are
        # enrolled across the run; block-e is the replacement. Any evidence
        # that excludes the bootstrap block from the eligible set by label
        # filtering is rejected: the eligibility derivation must be recorded
        # per block in the checkpoints.
        if scale.get("counting_rule") != "eligible_ready":
            fail(errors, "scale_composition.counting_rule must be 'eligible_ready'")
        if not isinstance(scale.get("eligibility_rule"), str) or not scale["eligibility_rule"].strip():
            fail(errors, "scale_composition.eligibility_rule must record the per-block eligibility derivation")
        if scale.get("duplicate_identities") is not False:
            fail(errors, "scale_composition.duplicate_identities must be false")
        if not isinstance(scale.get("drained_agent"), str) or not scale["drained_agent"].strip():
            fail(errors, "scale_composition.drained_agent must be explicit")
        if scale.get("replacement_agent") != "block-e":
            fail(errors, "scale_composition.replacement_agent must be block-e")
        bootstrap = mapping(scale.get("bootstrap"), "scale_composition.bootstrap", errors)
        bootstrap_agent = ""
        bootstrap_block = ""
        if bootstrap is not None:
            for field in ("agent_id", "block_id"):
                if not isinstance(bootstrap.get(field), str) or not bootstrap[field].strip():
                    fail(errors, f"scale_composition.bootstrap.{field} must be a non-empty string")
                elif field == "agent_id":
                    bootstrap_agent = bootstrap[field]
                else:
                    bootstrap_block = bootstrap[field]
        enrolled = mapping(scale.get("enrolled_identities"), "scale_composition.enrolled_identities", errors)
        if enrolled is not None:
            if enrolled.get("distinct") is not True:
                fail(errors, "scale_composition.enrolled_identities.distinct must be true")
            count = enrolled.get("count")
            if not isinstance(count, int) or count < 6:
                fail(errors, "scale_composition.enrolled_identities.count must be at least 6 (bootstrap + block-a..block-e)")
            for field in ("agents", "block_ids"):
                values = enrolled.get(field)
                if not isinstance(values, list) or not values:
                    fail(errors, f"scale_composition.enrolled_identities.{field} must be a non-empty list")
                    continue
                if not all(isinstance(value, str) and value for value in values):
                    fail(errors, f"scale_composition.enrolled_identities.{field} must contain non-empty strings")
                elif len(set(values)) != len(values):
                    fail(errors, f"scale_composition.enrolled_identities.{field} must be distinct")
            enrolled_agents = enrolled.get("agents")
            enrolled_blocks = enrolled.get("block_ids")
            if bootstrap_agent and isinstance(enrolled_agents, list) and bootstrap_agent not in enrolled_agents:
                fail(errors, "scale_composition.enrolled_identities.agents must include the bootstrap agent (no label-filtered exclusion)")
            if bootstrap_block and isinstance(enrolled_blocks, list) and bootstrap_block not in enrolled_blocks:
                fail(errors, "scale_composition.enrolled_identities.block_ids must include the bootstrap block (no label-filtered exclusion)")
        drained_agent = scale.get("drained_agent")
        bootstrap_removed = isinstance(drained_agent, str) and drained_agent == bootstrap_agent
        for name, minimum in (
            ("initial_concurrent_ready", None),
            ("peak_concurrent_ready", 5),
            ("final_concurrent_ready", 5),
        ):
            section = mapping(scale.get(name), f"scale_composition.{name}", errors)
            if section is None:
                continue
            count = section.get("count")
            if not isinstance(count, int):
                fail(errors, f"scale_composition.{name}.count must be an integer")
            elif minimum is None and count != 5:
                fail(errors, f"scale_composition.{name}.count must be exactly 5")
            elif minimum is not None and count < minimum:
                fail(errors, f"scale_composition.{name}.count must be at least {minimum}")
            # Identity lists are mandatory for the observed initial/final
            # eligible sets; the peak section records the count only.
            if name == "peak_concurrent_ready":
                continue
            for field in ("agents", "block_ids"):
                values = section.get(field)
                if not isinstance(values, list):
                    fail(errors, f"scale_composition.{name}.{field} must be a list")
                    continue
                if not all(isinstance(value, str) and value for value in values):
                    fail(errors, f"scale_composition.{name}.{field} must contain non-empty strings")
                elif len(set(values)) != len(values):
                    fail(errors, f"scale_composition.{name}.{field} must be distinct")
            block_ids = section.get("block_ids")
            # The bootstrap block is always in the initial eligible set. It is
            # in the final eligible set too unless the drained agent IS the
            # bootstrap agent (a supported placement outcome that removes it);
            # absence in that case is recorded by the checkpoints, not
            # label-filtered away.
            if name == "final_concurrent_ready" and bootstrap_removed:
                continue
            if bootstrap_block and isinstance(block_ids, list) and bootstrap_block not in block_ids:
                fail(errors, f"scale_composition.{name}.block_ids must include the bootstrap block: label-filtered counting is not evidence")
        checkpoints = scale.get("checkpoints")
        if not isinstance(checkpoints, list) or not checkpoints:
            fail(errors, "scale_composition.checkpoints must be a non-empty list of per-phase identity sets")
        else:
            seen_phases = set()
            checkpoints_per_phase = {}
            for index, checkpoint in enumerate(checkpoints):
                cname = f"scale_composition.checkpoints[{index}]"
                checkpoint = mapping(checkpoint, cname, errors)
                if checkpoint is None:
                    continue
                phase = checkpoint.get("phase")
                if not isinstance(phase, str) or not phase.strip():
                    fail(errors, f"{cname}.phase must be a non-empty string")
                else:
                    seen_phases.add(phase)
                blocks = checkpoint.get("blocks")
                if not isinstance(blocks, list) or not blocks:
                    fail(errors, f"{cname}.blocks must be a non-empty list")
                    continue
                eligible = 0
                bootstrap_seen = 0
                for bindex, block in enumerate(blocks):
                    bname = f"{cname}.blocks[{bindex}]"
                    block = mapping(block, bname, errors)
                    if block is None:
                        continue
                    for field in ("block_id", "execution_identity", "state"):
                        if not isinstance(block.get(field), str) or not block[field]:
                            fail(errors, f"{bname}.{field} must be a non-empty string")
                    if not isinstance(block.get("resource_provider_ids"), list):
                        fail(errors, f"{bname}.resource_provider_ids must be a list")
                    for field in ("compute_capable", "placement_eligible"):
                        if not isinstance(block.get(field), bool):
                            fail(errors, f"{bname}.{field} must be a boolean")
                    if block.get("placement_eligible") is True:
                        eligible += 1
                    if block.get("is_bootstrap") is True or (
                        bootstrap_agent and block.get("execution_identity") == bootstrap_agent
                    ):
                        bootstrap_seen += 1
                checkpoints_per_phase[phase] = checkpoints_per_phase.get(phase, 0) + (1 if bootstrap_seen else 0)
                observed = checkpoint.get("eligible_ready_count")
                if not isinstance(observed, int) or observed != eligible:
                    fail(errors, f"{cname}.eligible_ready_count must equal the number of placement-eligible blocks")
                if phase == "initial-scale-checkpoint" and observed != 5:
                    fail(errors, f"{cname}.eligible_ready_count must be exactly 5")
                if phase == "post-replacement" and observed != 5:
                    fail(errors, f"{cname}.eligible_ready_count must be exactly 5")
            missing_phases = sorted(set(REQUIRED_CHECKPOINT_PHASES) - seen_phases)
            if missing_phases:
                fail(errors, "scale_composition.checkpoints missing required phase(s): " + ", ".join(missing_phases))
            # The bootstrap block must be enumerated whenever it exists. It is
            # enrolled from bootstrap time, so the initial and pre-drain
            # checkpoints must always contain it; after a remove it is absent
            # only when the drained agent IS the bootstrap agent (a supported
            # placement outcome), never because of label filtering.
            drained = scale.get("drained_agent")
            bootstrap_removed = isinstance(drained, str) and drained == bootstrap_agent
            for required_phase in ("initial-scale-checkpoint", "pre-drain"):
                if checkpoints_per_phase.get(required_phase, 0) == 0:
                    fail(errors, f"scale_composition.checkpoints[{required_phase}] must enumerate the bootstrap BuildingBlock")
            if not bootstrap_removed:
                for phase in REQUIRED_CHECKPOINT_PHASES:
                    if checkpoints_per_phase.get(phase, 0) == 0:
                        fail(errors, f"scale_composition.checkpoints[{phase}] excludes the bootstrap BuildingBlock from the enumeration")

    journey = mapping(root.get("journey"), "journey", errors)
    if journey is not None:
        missing = sorted(REQUIRED_STEPS - set(journey))
        for step in missing:
            fail(errors, f"journey.{step} is required")
        for step in sorted(REQUIRED_STEPS - {"drain", "multiple_authenticated_joins", "projections_convergent"}):
            if step in journey:
                passed(journey[step], f"journey.{step}", errors)
        joins = mapping(journey.get("multiple_authenticated_joins"), "journey.multiple_authenticated_joins", errors)
        if joins is not None:
            passed(joins.get("status"), "journey.multiple_authenticated_joins.status", errors)
            if not isinstance(joins.get("count"), int) or joins["count"] < 2:
                fail(errors, "journey.multiple_authenticated_joins.count must be at least 2")
            passed(joins.get("each_authenticated"), "journey.multiple_authenticated_joins.each_authenticated", errors)
        drain = mapping(journey.get("drain"), "journey.drain", errors)
        if drain is not None:
            passed(drain.get("status"), "journey.drain.status", errors)
            passed(drain.get("no_new_placement"), "journey.drain.no_new_placement", errors)
            passed(drain.get("blockers_observed"), "journey.drain.blockers_observed", errors)
            if drain.get("evacuation_claimed") is not False:
                fail(errors, "journey.drain.evacuation_claimed must be false")
            # #1042 empirical leg: after the workload's 404 is confirmed and
            # before the remove is issued, the deleted workload must be absent
            # from the drained block's durable blocker projection (a retained
            # terminal tombstone is audit state, not resident capacity).
            requery = mapping(drain.get("blocker_requery"), "journey.drain.blocker_requery", errors)
            if requery is not None:
                if requery.get("deleted_workload_absent_from_blockers") is not True:
                    fail(errors, "journey.drain.blocker_requery.deleted_workload_absent_from_blockers must be true")
                if not isinstance(requery.get("workload_id"), str) or not requery["workload_id"].strip():
                    fail(errors, "journey.drain.blocker_requery.workload_id must be explicit")
                blockers = requery.get("blockers_at_requery")
                if not isinstance(blockers, list):
                    fail(errors, "journey.drain.blocker_requery.blockers_at_requery must be a list")
                else:
                    stale = [b for b in blockers if isinstance(b, dict)
                             and b.get("kind") == "workload" and b.get("count", 0) > 0]
                    if stale:
                        fail(errors, "journey.drain.blocker_requery still reports the deleted workload as a resident blocker")
        crash = mapping(journey.get("crash_injection_repair"), "journey.crash_injection_repair", errors)
        if crash is not None:
            passed(crash.get("status"), "journey.crash_injection_repair.status", errors)
            hook = mapping(crash.get("fault_hook"), "journey.crash_injection_repair.fault_hook", errors)
            if hook is not None:
                if hook.get("env") != "O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS":
                    fail(errors, "journey.crash_injection_repair.fault_hook.env must be the endpoint-release pause hook")
                if not isinstance(hook.get("pause_ms"), int) or hook["pause_ms"] < 1:
                    fail(errors, "journey.crash_injection_repair.fault_hook.pause_ms must be a positive integer")
            endpoint = mapping(crash.get("endpoint_before_crash"), "journey.crash_injection_repair.endpoint_before_crash", errors)
            if endpoint is not None:
                if endpoint.get("existed") is not True:
                    fail(errors, "journey.crash_injection_repair.endpoint_before_crash.existed must be true")
                if endpoint.get("presence_asserted_while_pause_held") is not True:
                    fail(errors, "journey.crash_injection_repair.endpoint_before_crash.presence_asserted_while_pause_held must be true")
            kill = mapping(crash.get("kill"), "journey.crash_injection_repair.kill", errors)
            if kill is not None:
                if kill.get("signal") != "SIGKILL":
                    fail(errors, "journey.crash_injection_repair.kill.signal must be SIGKILL (true process death)")
                if kill.get("orderly_restart") is not False:
                    fail(errors, "journey.crash_injection_repair.kill.orderly_restart must be false")
                if kill.get("identity_verified") is not True:
                    fail(errors, "journey.crash_injection_repair.kill.identity_verified must be true")
            sweep = mapping(crash.get("sweep"), "journey.crash_injection_repair.sweep", errors)
            if sweep is not None:
                if not isinstance(sweep.get("passes_observed"), int) or sweep["passes_observed"] < 1:
                    fail(errors, "journey.crash_injection_repair.sweep.passes_observed must be at least 1")
                if not isinstance(sweep.get("time_to_repair_ms"), int) or sweep["time_to_repair_ms"] > 180000:
                    fail(errors, "journey.crash_injection_repair.sweep.time_to_repair_ms must be within the 180s bound")
                if sweep.get("endpoint_absent_after") is not True:
                    fail(errors, "journey.crash_injection_repair.sweep.endpoint_absent_after must be true")
            reuse = mapping(crash.get("fixed_ip_reuse"), "journey.crash_injection_repair.fixed_ip_reuse", errors)
            if reuse is not None and reuse.get("succeeded") is not True:
                fail(errors, "journey.crash_injection_repair.fixed_ip_reuse.succeeded must be true")
            quota = mapping(crash.get("quota"), "journey.crash_injection_repair.quota", errors)
            if quota is not None and quota.get("restored") is not True:
                fail(errors, "journey.crash_injection_repair.quota.restored must be true")
            allocation = mapping(crash.get("placement_allocation"), "journey.crash_injection_repair.placement_allocation", errors)
            if allocation is not None and allocation.get("leak") is not False:
                fail(errors, "journey.crash_injection_repair.placement_allocation.leak must be false")
            responsiveness = mapping(crash.get("responsiveness_during_backlog"), "journey.crash_injection_repair.responsiveness_during_backlog", errors)
            if responsiveness is not None:
                if responsiveness.get("orphan_present_at_create") is not True:
                    fail(errors, "journey.crash_injection_repair.responsiveness_during_backlog.orphan_present_at_create must be true")
                if responsiveness.get("server_active") is not True:
                    fail(errors, "journey.crash_injection_repair.responsiveness_during_backlog.server_active must be true")
                if not isinstance(responsiveness.get("create_call_latency_ms"), int) or responsiveness["create_call_latency_ms"] < 0:
                    fail(errors, "journey.crash_injection_repair.responsiveness_during_backlog.create_call_latency_ms must be recorded")
                probe = mapping(responsiveness.get("unrelated_db_backed_probe"), "journey.crash_injection_repair.responsiveness_during_backlog.unrelated_db_backed_probe", errors)
                if probe is not None:
                    if probe.get("path") != "/operator/diagnostics/providers?limit=1":
                        fail(errors, "unrelated DB-backed probe path is invalid")
                    if probe.get("succeeded") is not True:
                        fail(errors, "unrelated DB-backed probe must succeed while endpoint release is paused")
                    if not isinstance(probe.get("latency_ms"), int) or probe["latency_ms"] < 0:
                        fail(errors, "unrelated DB-backed probe latency must be recorded")
                    if probe.get("curl_exit") != 0:
                        fail(errors, "unrelated DB-backed probe curl_exit must be zero")
                    status_code = probe.get("status_code")
                    if not isinstance(status_code, int) or not 200 <= status_code < 300:
                        fail(errors, "unrelated DB-backed probe status_code must be 2xx")
            if crash.get("caller_supplied_endpoint_preserved") is not True:
                fail(errors, "journey.crash_injection_repair.caller_supplied_endpoint_preserved must be true")
            if crash.get("foreign_project_endpoint_preserved") is not True:
                fail(errors, "journey.crash_injection_repair.foreign_project_endpoint_preserved must be true")
        maintenance = mapping(journey.get("host_maintenance"), "journey.host_maintenance", errors)
        if maintenance is not None:
            passed(maintenance.get("status"), "journey.host_maintenance.status", errors)
            if not isinstance(maintenance.get("block_id"), str) or not maintenance["block_id"].strip():
                fail(errors, "journey.host_maintenance.block_id must be explicit")
            mdrain = mapping(maintenance.get("drain"), "journey.host_maintenance.drain", errors)
            if mdrain is not None and mdrain.get("blockers_empty") is not True:
                fail(errors, "journey.host_maintenance.drain.blockers_empty must be true on an empty block")
            if maintenance.get("placement_rejected_on_draining_block") is not True:
                fail(errors, "journey.host_maintenance.placement_rejected_on_draining_block must be true")
            identity = mapping(maintenance.get("identity_preserved"), "journey.host_maintenance.identity_preserved", errors)
            if identity is not None:
                for field in ("same_building_block_id", "same_execution_identity", "same_resource_provider_ids", "no_duplicate_block_or_provider"):
                    if identity.get(field) is not True:
                        fail(errors, f"journey.host_maintenance.identity_preserved.{field} must be true")
            ready = mapping(maintenance.get("returned_to_ready"), "journey.host_maintenance.returned_to_ready", errors)
            if ready is not None and ready.get("succeeded") is not True:
                fail(errors, "journey.host_maintenance.returned_to_ready.succeeded must be true (Draining->Ready is a canonical operator transition)")
            final_count = maintenance.get("final_eligible_ready_count")
            if not isinstance(final_count, int) or final_count != 5:
                fail(errors, "journey.host_maintenance.final_eligible_ready_count must be exactly 5 after the ready transition")
        transient = journey.get("transient_failures")
        if not isinstance(transient, list):
            fail(errors, "journey.transient_failures must be a list (empty when nothing was observed)")
        else:
            for index, event in enumerate(transient):
                ename = f"journey.transient_failures[{index}]"
                event = mapping(event, ename, errors)
                if event is None:
                    continue
                if event.get("type") not in {"bounded_retry", "http_5xx"}:
                    fail(errors, f"{ename}.type must be bounded_retry or http_5xx")
                if not isinstance(event.get("api"), str) or not event["api"].strip():
                    fail(errors, f"{ename}.api must be explicit")
                if not isinstance(event.get("at_unix_ms"), int):
                    fail(errors, f"{ename}.at_unix_ms must be recorded")
                if not isinstance(event.get("fault_injection_active"), bool):
                    fail(errors, f"{ename}.fault_injection_active must be a boolean")
                if event.get("type") == "http_5xx":
                    status = event.get("http_status")
                    if not isinstance(status, str) or not status.startswith("5"):
                        fail(errors, f"{ename}.http_status must carry the observed 5xx status")
        projections = mapping(journey.get("projections_convergent"), "journey.projections_convergent", errors)
        if projections is not None:
            # Native and OpenStack projections are mandatory P15.7 evidence.
            # Araf is an external, optional consumer and is deliberately not a
            # TestLab or P15 dependency.  Its state is recorded honestly, but
            # it must never be allowed to manufacture mandatory convergence.
            for name in ("native", "openstack"):
                passed(projections.get(name), f"journey.projections_convergent.{name}", errors)
            araf = mapping(projections.get("araf"), "journey.projections_convergent.araf", errors)
            if araf is not None:
                if araf.get("required") is not False:
                    fail(errors, "journey.projections_convergent.araf.required must be false")
                if araf.get("status") not in {"passed", "reachable", "not_configured", "not_applicable", "unavailable"}:
                    fail(errors, "journey.projections_convergent.araf.status is invalid")
                if not isinstance(araf.get("reason"), str) or not araf["reason"].strip():
                    fail(errors, "journey.projections_convergent.araf.reason must be explicit")

    network = mapping(root.get("network_observation"), "network_observation", errors)
    if network is not None:
        # Stale-DHCP resolver evidence: every child VM's lease selection is
        # recorded with candidates, freshness, the selection reason, and the
        # SSH liveness proof. The selection must never prefer a stale
        # same-MAC lease over a fresher valid one, never select a cross-MAC
        # address, and never select the gateway.
        child_vms = network.get("child_vms")
        if not isinstance(child_vms, list) or not child_vms:
            fail(errors, "network_observation.child_vms must be a non-empty list")
        else:
            for index, vm in enumerate(child_vms):
                vname = f"network_observation.child_vms[{index}]"
                vm = mapping(vm, vname, errors)
                if vm is None:
                    continue
                for field in ("domain", "uuid", "expected_mac", "selected_ip", "selection_reason"):
                    if not isinstance(vm.get(field), str) or not vm[field].strip():
                        fail(errors, f"{vname}.{field} must be a non-empty string")
                if not isinstance(vm.get("candidates"), list):
                    fail(errors, f"{vname}.candidates must be a list")
                if vm.get("ssh_proof") is not True:
                    fail(errors, f"{vname}.ssh_proof must be true (SSH is the liveness proof)")
                assertions = mapping(vm.get("assertions"), f"{vname}.assertions", errors)
                if assertions is not None:
                    if assertions.get("no_cross_mac") is not True:
                        fail(errors, f"{vname}.assertions.no_cross_mac must be true")
                    if assertions.get("not_gateway") is not True:
                        fail(errors, f"{vname}.assertions.not_gateway must be true")
                    stale = assertions.get("no_stale_over_fresh")
                    freshness = mapping(vm.get("freshness"), f"{vname}.freshness", errors)
                    freshness_available = freshness is not None and freshness.get("available") is True
                    if freshness_available and stale is not True:
                        fail(errors, f"{vname}.assertions.no_stale_over_fresh must be true when freshness data is available")
                    if stale is False:
                        fail(errors, f"{vname}.assertions.no_stale_over_fresh must never be false")

    security = mapping(root.get("security_negatives"), "security_negatives", errors)
    if security is not None:
        for name in (
            "unauthenticated_join_rejected",
            "replay_join_rejected",
            "cross_tenant_concealment",
            "foreign_state_preserved",
        ):
            passed(security.get(name), f"security_negatives.{name}", errors)

    recovery = mapping(root.get("restart_recovery"), "restart_recovery", errors)
    if recovery is not None:
        passed(recovery.get("status"), "restart_recovery.status", errors)
        passed(recovery.get("canonical_state_survived"), "restart_recovery.canonical_state_survived", errors)
        passed(recovery.get("postgres"), "restart_recovery.postgres", errors)
        passed(recovery.get("sqlite_parity"), "restart_recovery.sqlite_parity", errors)

    ownership = mapping(root.get("database_ownership"), "database_ownership", errors)
    if ownership is not None:
        # The production composition gate must prove which database backend the
        # real o3kd process actually consumed; a missing or sqlite effective
        # backend is not evidence of the postgres composition claim.
        if ownership.get("effective_backend") != "postgres":
            fail(errors, "database_ownership.effective_backend must be postgres")
        proof = mapping(ownership.get("backend_proof"), "database_ownership.backend_proof", errors)
        if proof is not None:
            if proof.get("status") != "passed":
                fail(errors, "database_ownership.backend_proof.status must be passed")
            if not isinstance(proof.get("method"), str) or not proof["method"].strip():
                fail(errors, "database_ownership.backend_proof.method must be explicit")

    timing = mapping(root.get("bootstrap_timing"), "bootstrap_timing", errors)
    if timing is not None:
        passed(timing.get("measured"), "bootstrap_timing.measured", errors)
        passed(timing.get("excludes_preprovisioned_external_work"), "bootstrap_timing.excludes_preprovisioned_external_work", errors)
        if not isinstance(timing.get("sample_count"), int) or timing["sample_count"] < 1:
            fail(errors, "bootstrap_timing.sample_count must be positive")
        if not isinstance(timing.get("boundary"), str) or not timing["boundary"].strip():
            fail(errors, "bootstrap_timing.boundary must be explicit")
        if timing.get("claim_scope") != "profile-specific-measurement-only":
            fail(errors, "bootstrap_timing.claim_scope must remain profile-specific")

    leaks = mapping(root.get("leak_check"), "leak_check", errors)
    if leaks is not None:
        if leaks.get("status") != "passed":
            fail(errors, "leak_check.status must be passed")
        for key in ("owned_leaks", "owned_inconsistencies", "foreign_state_changes"):
            if leaks.get(key) != 0:
                fail(errors, f"leak_check.{key} must be zero")

    defects = mapping(root.get("defect_ledger"), "defect_ledger", errors)
    if defects is not None:
        if defects.get("status") != "passed":
            fail(errors, "defect_ledger.status must be passed")
        for key in ("blockers", "high", "medium"):
            if defects.get(key) != 0:
                fail(errors, f"defect_ledger.{key} must be zero")

    claims = mapping(root.get("claim_validation"), "claim_validation", errors)
    if claims is not None:
        if claims.get("status") != "passed":
            fail(errors, "claim_validation.status must be passed")
        sources = claims.get("sources")
        if not isinstance(sources, list):
            fail(errors, "claim_validation.sources must be a list")
            sources = []
        elif not all(isinstance(source, str) for source in sources):
            fail(errors, "claim_validation.sources must contain strings")
        if len(sources) != len(CLAIM_VALIDATION_SOURCES) or (
            all(isinstance(source, str) for source in sources)
            and set(sources) != CLAIM_VALIDATION_SOURCES
        ):
            fail(errors, "claim_validation.sources must name the six public claim inputs")
        if claims.get("unsupported_claims_preserved") is not True:
            fail(errors, "claim_validation.unsupported_claims_preserved must be true")
        claim_list = claims.get("claims")
        if not isinstance(claim_list, list):
            fail(errors, "claim_validation.claims must be a list")
            claim_list = []
        for claim in claim_list:
            if not isinstance(claim, str):
                fail(errors, "claim_validation.claims must contain strings")
            elif FORBIDDEN_CLAIMS.search(claim):
                fail(errors, f"unsupported broad claim present: {claim!r}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=pathlib.Path)
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-profile")
    args = parser.parse_args()
    try:
        document = json.loads(args.evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"P15.7 evidence validation FAILED: {exc}", file=sys.stderr)
        return 1
    errors = validate(document, args.expected_source_sha, args.expected_profile)
    if errors:
        print("P15.7 evidence validation FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("P15.7 protected real-host scale/composition evidence validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
