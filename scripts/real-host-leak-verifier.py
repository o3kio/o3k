#!/usr/bin/env python3
"""Independent real-host resource-leak and foreign-state verifier.

This comparator never trusts O3K API output alone: it diffs two independent
host inventories (`scripts/real-host-owned-inventory.py` schema_version 2 or
3) and cross-checks durable state against host objects, then aggregates
per-scope verdicts into the protected `resource-leak-result` artifact
(schema_version 2, `artifact_type: "resource-leak-result"`, per ADR-0164 and
`docs/release-evidence-schema.md`).

Commands
--------

- ``compare --baseline B.json --after A.json --scope NAME
  --expect-state-root present|absent [--source-commit SHA --runner ID]
  --out OUT.json``

  Emits a per-scope verdict (``artifact_type: "resource-leak-scope-verdict"``,
  schema_version 1) with:

  - `owned_leaks`: after-only O3K-owned identities (domains, links, ports,
    allocations, non-terminal operations/commands/transfers, owned dnsmasq
    processes, active daemons, unmanaged processes, and managed-state entries
    classified `stale_owned` or `active_owned` that were not present in the
    baseline), each with its classification and contract reference;
  - `inconsistencies`: durable-vs-host contradictions present in the after
    snapshot (durable rows classified `inconsistent`, a host `o3k-*` domain
    with no live durable reference, an orphan TAP or bridge, stale DHCP
    bindings per the state.json cross-check);
  - `foreign_changes`: foreign-state digest mismatches and per-canary identity
    comparisons (redacted diagnostics naming only canary kind/name and what
    changed);
  - `expected_retained`: after-only retained state grouped by contract, for
    transparency;
  - `classification` summary; `status` in {passed, failed, blocked}.

  `failed` when owned_leaks, inconsistencies, or foreign_changes are
  non-empty. `blocked` (never passed) when either snapshot is unreadable,
  malformed, unavailable, or has an unsupported schema version; when the two
  snapshots have different schema versions or a section available in one is
  missing in the other; when `--expect-state-root present` is given but a
  snapshot does not record the state root as present (or `absent` is expected
  but a snapshot records it present); or when the after snapshot carries a
  canary configuration while the baseline does not. The after snapshot's
  `status: unavailable` fails closed carrying the collector's reason.

- ``negative-stale --baseline B --after A --out OUT.json``: the expected
  outcome is failure. Runs the same comparison and verifies (a) the verdict
  is failed, (b) at least one `stale_owned` O3K-owned object is identified,
  (c) no foreign canary was classified as that stale object. Emits
  ``{"expected": "failed", "observed": "failed", "stale_artifact_detected":
  true, ...}`` on success, ``{"expected": "failed", "observed": "passed",
  ...}`` when the verifier wrongly passed.

- ``negative-foreign --baseline B --after A --out OUT.json``: expected
  failure with `foreign_changes` non-empty; verifies the changed canary or
  digest is named and no owned leak is misattributed to it.

- ``aggregate --normal N.json --results R1.json [R2.json ...]
  --source-commit SHA --runner ID --started-at EPOCH --out OUT.json``

  Produces the protected artifact:
  ``{"artifact_type": "resource-leak-result", "schema_version": 2, ...}``.
  `status: passed` only when every input verdict passed, the negative tests
  detected their injections, all owned-leak/inconsistency/foreign-change
  counts are zero, every result file is valid, produced by `compare` with
  source identity matching the supplied commit, and none was blocked. A
  missing scope or negative result file makes the aggregate `blocked`.

Source identity: each `compare`/negative verdict records `source_commit` and
`runner` from the CLI flags; the aggregate requires all of them equal.

Fail-closed summary: any missing tool, unreadable snapshot, malformed JSON,
secret-shaped value in a snapshot (scrubbed by a redaction self-check), or
unknown classification token -> `blocked` with a named reason. Foreign
identities, protected-path raw values, environment contents, and anything
matching password/token/key/secret shapes never reach the output.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ARTIFACT_VERDICT = "resource-leak-scope-verdict"
ARTIFACT_NEGATIVE_STALE = "resource-leak-negative-stale"
ARTIFACT_NEGATIVE_FOREIGN = "resource-leak-negative-foreign"
ARTIFACT_AGGREGATE = "resource-leak-result"
SECRET_MARKERS = (
    "password",
    "secret",
    "private_key",
    "api_key",
    "access_key",
    "OS_PASSWORD",
    "BEGIN RSA",
    "BEGIN OPENSSH",
    "BEGIN PRIVATE",
)
VALID_CLASSIFICATIONS = (
    "active_owned",
    "expected_retained",
    "stale_owned",
    "inconsistent",
    # Canary records are foreign markers and carry their own token.
    "foreign",
)
EXTENDED_SECTIONS = (
    "managed_state",
    "durable",
    "dhcp",
    "processes",
    "canaries",
    "injection_root",
)


def redact_value(value):
    if isinstance(value, str):
        lowered = value.lower()
        if any(marker.lower() in lowered for marker in SECRET_MARKERS):
            return "<redacted>"
        return value
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    return value


def load_snapshot(path: str) -> tuple[dict | None, str | None]:
    try:
        with open(path, encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "snapshot_unreadable_or_malformed"
    if not isinstance(value, dict):
        return None, "snapshot_not_an_object"
    if value.get("redacted") is not True:
        return None, "snapshot_not_redacted"
    return value, None


def section_presence(snapshot: dict, name: str) -> tuple[str, str | None]:
    """Return (presence, reason) for an extended inventory section.

    presence is one of ``available``, ``absent``, ``not_checked``, or
    ``missing`` (key absent from the document).
    """
    if name not in snapshot:
        return "missing", None
    section = snapshot[name]
    if not isinstance(section, dict):
        return "missing", None
    status = section.get("status")
    if status == "available":
        return "available", None
    if status in ("absent", "not_checked"):
        return status, None
    return "missing", str(section.get("reason", "unknown"))


def check_classification_tokens(document: dict, path: str) -> str | None:
    """Fail closed on any unknown classification token in a snapshot."""
    if isinstance(document, dict):
        classification = document.get("classification")
        if (
            isinstance(classification, str)
            and classification not in VALID_CLASSIFICATIONS
        ):
            return f"unknown_classification:{classification}"
        for value in document.values():
            reason = check_classification_tokens(value, path)
            if reason:
                return reason
    elif isinstance(document, list):
        for value in document:
            reason = check_classification_tokens(value, path)
            if reason:
                return reason
    return None


def find_secret_shaped_value(document) -> str | None:
    """Fail closed on secret-shaped values inside a snapshot."""
    if isinstance(document, str):
        lowered = document.lower()
        if any(marker.lower() in lowered for marker in SECRET_MARKERS):
            return "secret_shaped_value"
        return None
    if isinstance(document, list):
        for value in document:
            reason = find_secret_shaped_value(value)
            if reason:
                return reason
        return None
    if isinstance(document, dict):
        for value in document.values():
            reason = find_secret_shaped_value(value)
            if reason:
                return reason
    return None


def after_only(identity: str, baseline_ids: set[str]) -> bool:
    return identity not in baseline_ids


def compare_snapshots(
    baseline: dict,
    after: dict,
    scope: str,
    expect_state_root: str,
    source_commit: str | None,
    runner: str | None,
) -> dict:
    verdict: dict = {
        "artifact_type": ARTIFACT_VERDICT,
        "schema_version": 1,
        "scope": scope,
        "expect_state_root": expect_state_root,
        "redacted": True,
        "finished_at": int(time.time()),
        "owned_leaks": [],
        "inconsistencies": [],
        "foreign_changes": [],
        "expected_retained": {"counts": {}, "contracts": {}},
        "classification": {},
        "pre_existing": [],
    }
    if source_commit is not None:
        verdict["source_commit"] = source_commit
    if runner is not None:
        verdict["runner"] = runner

    def blocked(reason: str) -> dict:
        verdict["status"] = "blocked"
        verdict["reason"] = reason
        return verdict

    baseline_version = baseline.get("schema_version")
    after_version = after.get("schema_version")
    if baseline_version not in (2, 3) or after_version not in (2, 3):
        return blocked("schema_version_unsupported")
    if baseline_version != after_version:
        return blocked("schema_version_mismatch")
    if baseline.get("status") != "available":
        return blocked("baseline_unavailable")
    if after.get("status") != "available":
        reason = after.get("reason", "unavailable")
        return blocked(f"after_unavailable:{reason}")

    for name in ("baseline", "after"):
        snapshot = baseline if name == "baseline" else after
        reason = check_classification_tokens(snapshot, name)
        if reason:
            return blocked(reason)
        reason = find_secret_shaped_value(snapshot)
        if reason:
            return blocked(f"{name}_{reason}")

    # Section symmetry: a category that is available in one snapshot must be
    # available in the other; a category silently disappearing is blocked.
    for section in EXTENDED_SECTIONS:
        baseline_presence, _ = section_presence(baseline, section)
        after_presence, after_reason = section_presence(after, section)
        if baseline_presence == "missing" or after_presence == "missing":
            if baseline_version == 3:
                return blocked(f"section_{section}_asymmetric")
            continue  # v2 snapshots legitimately carry no extended sections
        if baseline_presence == "available" and after_presence != "available":
            return blocked(f"section_{section}_disappeared")
        if after_presence == "available" and baseline_presence != "available":
            return blocked(f"section_{section}_appeared")
        if after_presence not in ("available", "absent", "not_checked"):
            return blocked(f"section_{section}_unavailable:{after_reason}")
        if baseline_presence not in ("available", "absent", "not_checked"):
            return blocked(f"section_{section}_unavailable_baseline")

    # Canary configuration present in the baseline must be present after.
    baseline_canaries = baseline.get("canaries")
    after_canaries = after.get("canaries")
    if isinstance(baseline_canaries, dict) and baseline_canaries.get("status") == "available":
        if not isinstance(after_canaries, dict) or after_canaries.get("status") != "available":
            return blocked("canary_config_disappeared")

    # --expect-state-root semantics.
    baseline_ms = baseline.get("managed_state")
    after_ms = after.get("managed_state")
    baseline_present = (
        isinstance(baseline_ms, dict) and baseline_ms.get("status") == "available"
    )
    after_present = isinstance(after_ms, dict) and after_ms.get("status") == "available"
    if expect_state_root == "present":
        if not baseline_present:
            return blocked("state_root_absent_in_baseline")
        if not after_present:
            return blocked("state_root_absent_in_after")
    else:
        if baseline_present:
            return blocked("state_root_present_in_baseline")
        if after_present:
            return blocked("state_root_present_in_after")

    leaks: list[dict] = []
    inconsistencies: list[dict] = []
    foreign_changes: list[dict] = []

    def classification_of(mapping, identity: str) -> dict:
        if isinstance(mapping, dict):
            record = mapping.get(identity)
            if isinstance(record, dict) and record.get("classification") in VALID_CLASSIFICATIONS:
                return record
        return {"classification": "stale_owned", "contract": "delta-after-baseline"}

    # Domains and links: after-only owned identities.
    baseline_domains = set(baseline.get("domains", []))
    after_domains = set(after.get("domains", []))
    for name in sorted(after_domains - baseline_domains):
        record = classification_of(after.get("domain_classifications"), name)
        leaks.append({
            "kind": "domain",
            "identity": name,
            "classification": record["classification"],
            "contract": record.get("contract", ""),
        })
    baseline_links = set(baseline.get("network_links", []))
    after_links = set(after.get("network_links", []))
    for name in sorted(after_links - baseline_links):
        record = classification_of(after.get("link_classifications"), name)
        leaks.append({
            "kind": "link",
            "identity": name,
            "classification": record["classification"],
            "contract": record.get("contract", ""),
        })

    # Durable rows (v3 pairs only).
    if baseline_version == 3:
        baseline_durable = baseline.get("durable", {})
        after_durable = after.get("durable", {})
        baseline_ids: dict[str, set[str]] = {}
        after_ids: dict[str, set[str]] = {}

        def durable_ids(section: dict, key: str, id_field: str) -> set[str]:
            return {
                str(entry[id_field])
                for entry in section.get(key, {}).get("entries", [])
                if isinstance(entry, dict) and id_field in entry
            }

        for key, id_field in (
            ("operations", "id"),
            ("agent_commands", "id"),
            ("artifact_transfers", "id"),
            ("network_ports", "id"),
            ("placement_allocations", "id"),
        ):
            baseline_ids[key] = durable_ids(baseline_durable, key, id_field)
            after_ids[key] = durable_ids(after_durable, key, id_field)
            # The collector's classification is authoritative: after-only rows
            # classified `expected_retained` (e.g. a non-terminal command row
            # whose owning operation reached a terminal state — journal
            # evidence of an UnknownOutcome boundary) are not leaks; anything
            # else that appears after the baseline is.
            after_classifications: dict[str, str] = {}
            for entry in after_durable.get(key, {}).get("entries", []):
                if isinstance(entry, dict) and id_field in entry:
                    after_classifications[str(entry[id_field])] = entry.get(
                        "classification", "active_owned"
                    )
            for identity in sorted(after_ids[key] - baseline_ids[key]):
                classification = after_classifications.get(
                    identity, "active_owned"
                )
                if classification == "expected_retained":
                    verdict["expected_retained"]["counts"][key] = (
                        verdict["expected_retained"]["counts"].get(key, 0) + 1
                    )
                    continue
                leaks.append({
                    "kind": key,
                    "identity": identity,
                    "classification": classification,
                    "contract": "after-only durable identity",
                })

        # Durable rows classified `inconsistent` are durable-vs-host
        # contradictions regardless of baseline.
        for key in (
            "operations",
            "agent_commands",
            "artifact_transfers",
            "network_ports",
            "placement_allocations",
            "image_overlay_ownership",
        ):
            for entry in after_durable.get(key, {}).get("entries", []):
                if isinstance(entry, dict) and entry.get("classification") == "inconsistent":
                    inconsistencies.append({
                        "kind": key,
                        "identity": entry.get("id", ""),
                        "classification": "inconsistent",
                        "contract": entry.get("contract", ""),
                    })

        # Managed-state entries (state root + test injection root): after-only
        # stale/active entries are leaks; after-only expected-retained entries
        # are listed for transparency; stale entries present in both snapshots
        # are pre-existing residue.
        def managed_entries(section: dict, kind: str) -> list[tuple[str, dict]]:
            entries = []
            for entry in section.get("entries", []):
                if isinstance(entry, dict) and entry.get("path") is not None:
                    tagged = dict(entry)
                    tagged["_kind"] = kind
                    entries.append((str(entry["path"]), tagged))
            return entries

        baseline_managed = baseline.get("managed_state", {})
        after_managed = after.get("managed_state", {})
        baseline_injection = baseline.get("injection_root", {})
        after_injection = after.get("injection_root", {})
        baseline_paths = {
            path
            for path, _entry in managed_entries(baseline_managed, "managed_state")
            + managed_entries(baseline_injection, "injection_root")
        }
        after_entries = {
            path: entry
            for path, entry in managed_entries(after_managed, "managed_state")
            + managed_entries(after_injection, "injection_root")
        }
        retained_counts: dict[str, int] = {}
        retained_contracts: dict[str, dict] = {}
        for path, entry in sorted(after_entries.items()):
            classification = entry.get("classification", "stale_owned")
            contract = str(entry.get("contract", ""))
            if path in baseline_paths:
                if classification == "stale_owned":
                    verdict["pre_existing"].append({
                        "kind": entry.get("_kind", "managed_state"),
                        "identity": path,
                        "classification": classification,
                        "contract": contract,
                    })
                continue
            if classification in ("stale_owned", "active_owned"):
                leaks.append({
                    "kind": entry.get("_kind", "managed_state"),
                    "identity": path,
                    "classification": classification,
                    "contract": contract,
                })
            elif classification == "expected_retained":
                retained_counts[contract] = retained_counts.get(contract, 0) + 1
                retained_contracts.setdefault(contract, []).append(path)
        verdict["expected_retained"]["counts"] = retained_counts
        verdict["expected_retained"]["contracts"] = retained_contracts

        # Stale host objects: `o3k-*` domain with no live durable reference,
        # orphan TAP or bridge, stale DHCP bindings.
        for name in sorted(after_domains):
            record = classification_of(after.get("domain_classifications"), name)
            if record["classification"] == "stale_owned":
                inconsistencies.append({
                    "kind": "domain",
                    "identity": name,
                    "classification": "stale_owned",
                    "contract": record.get("contract", ""),
                })
        for name in sorted(after_links):
            record = classification_of(after.get("link_classifications"), name)
            if record["classification"] == "stale_owned":
                inconsistencies.append({
                    "kind": "link",
                    "identity": name,
                    "classification": "stale_owned",
                    "contract": record.get("contract", ""),
                })
        for entry in after.get("dhcp", {}).get("bindings", []):
            if isinstance(entry, dict) and entry.get("classification") == "inconsistent":
                inconsistencies.append({
                    "kind": "dhcp_binding",
                    "identity": entry.get("port_id", ""),
                    "classification": "inconsistent",
                    "contract": entry.get("contract", ""),
                })

        # Owned dnsmasq processes and daemons: after-only identities. The
        # owned-dnsmasq identity is the redacted args digest (stable across a
        # process restart with the same configuration), never the pid: a
        # restart mid-scenario must not look like a new owned process.
        baseline_dhcp_procs = {
            str(entry.get("args_sha256") or entry.get("pid", ""))
            for entry in baseline.get("dhcp", {}).get("processes", {}).get("owned", [])
            if isinstance(entry, dict)
        }
        for entry in after.get("dhcp", {}).get("processes", {}).get("owned", []):
            if isinstance(entry, dict) and after_only(
                str(entry.get("args_sha256") or entry.get("pid", "")),
                baseline_dhcp_procs,
            ):
                leaks.append({
                    "kind": "dhcp_process",
                    "identity": entry.get("args_sha256") or entry.get("pid", ""),
                    "classification": entry.get("classification", "active_owned"),
                    "contract": entry.get("contract", ""),
                })
        baseline_daemons = {
            str(entry.get("daemon", ""))
            for entry in baseline.get("processes", {}).get("daemons", [])
            if isinstance(entry, dict) and entry.get("verified") is True
        }
        for entry in after.get("processes", {}).get("daemons", []):
            if isinstance(entry, dict) and entry.get("verified") is True and after_only(
                str(entry.get("daemon", "")), baseline_daemons
            ):
                leaks.append({
                    "kind": "daemon",
                    "identity": entry.get("daemon", ""),
                    "classification": "active_owned",
                    "contract": entry.get("contract", ""),
                })
        baseline_unmanaged = {
            f"{entry.get('binary', '')}:{entry.get('pid', '')}"
            for entry in baseline.get("processes", {}).get("unmanaged", [])
            if isinstance(entry, dict)
        }
        for entry in after.get("processes", {}).get("unmanaged", []):
            if isinstance(entry, dict) and after_only(
                f"{entry.get('binary', '')}:{entry.get('pid', '')}", baseline_unmanaged
            ):
                leaks.append({
                    "kind": "unmanaged_process",
                    "identity": entry.get("binary", ""),
                    "classification": entry.get("classification", "inconsistent"),
                    "contract": entry.get("contract", ""),
                })

    # Foreign state: digest comparison plus per-canary identity comparison.
    # Protected paths are run-scoped OWNED state (the TestLab's
    # inventory/protected dirs), not foreign host state: the pre-run baseline
    # snapshots them while the TestLab exists and the post-cleanup snapshot
    # runs after their legitimate removal, so their digests are recorded per
    # snapshot but excluded from the foreign-change comparison.
    baseline_foreign = {key: value for key, value in baseline.get("foreign_state", {}).items()
                        if key != "protected_paths_sha256"}
    after_foreign = {key: value for key, value in after.get("foreign_state", {}).items()
                     if key != "protected_paths_sha256"}
    for key in sorted(set(baseline_foreign) | set(after_foreign)):
        if baseline_foreign.get(key) != after_foreign.get(key):
            foreign_changes.append({
                "kind": "foreign_state",
                "identity": key,
                "change": "digest_changed",
                "baseline_sha256": baseline_foreign.get(key),
                "after_sha256": after_foreign.get(key),
            })
    baseline_canary_entries = []
    after_canary_entries = []
    if isinstance(baseline_canaries, dict):
        for kind in ("libvirt_domains", "network_links", "files"):
            for entry in baseline_canaries.get(kind, []):
                if isinstance(entry, dict):
                    baseline_canary_entries.append((kind, entry))
    if isinstance(after_canaries, dict):
        for kind in ("libvirt_domains", "network_links", "files"):
            for entry in after_canaries.get(kind, []):
                if isinstance(entry, dict):
                    after_canary_entries.append((kind, entry))
    baseline_canary_map = {
        (kind, str(entry.get("name") or entry.get("path", ""))): entry
        for kind, entry in baseline_canary_entries
    }
    after_canary_map = {
        (kind, str(entry.get("name") or entry.get("path", ""))): entry
        for kind, entry in after_canary_entries
    }
    for key, baseline_entry in sorted(baseline_canary_map.items()):
        kind, identity = key
        after_entry = after_canary_map.get(key)
        if after_entry is None:
            foreign_changes.append({
                "kind": f"canary:{kind}",
                "identity": identity,
                "change": "disappeared",
            })
            continue
        if baseline_entry.get("present") and not after_entry.get("present"):
            foreign_changes.append({
                "kind": f"canary:{kind}",
                "identity": identity,
                "change": "missing",
            })
            continue
        if not baseline_entry.get("present") and after_entry.get("present"):
            foreign_changes.append({
                "kind": f"canary:{kind}",
                "identity": identity,
                "change": "appeared",
            })
            continue
        if not baseline_entry.get("present"):
            continue
        for field in ("uuid", "xml_sha256", "addresses_sha256", "sha256", "kind"):
            if after_entry.get(field) != baseline_entry.get(field):
                change = "content_changed" if field in ("sha256", "xml_sha256") else "identity_changed"
                foreign_changes.append({
                    "kind": f"canary:{kind}",
                    "identity": identity,
                    "change": change,
                    "field": field,
                })
                break

    verdict["owned_leaks"] = leaks
    verdict["inconsistencies"] = inconsistencies
    verdict["foreign_changes"] = foreign_changes
    verdict["classification"] = after.get("classification", {})
    if leaks or inconsistencies or foreign_changes:
        verdict["status"] = "failed"
        verdict["reason"] = "resource_leak_or_foreign_change_detected"
    else:
        verdict["status"] = "passed"
        verdict["reason"] = "no_resource_leak_detected"
    return redact_value(verdict)


def load_verdict(path: str) -> tuple[dict | None, str | None]:
    try:
        with open(path, encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "verdict_unreadable_or_malformed"
    if not isinstance(value, dict):
        return None, "verdict_not_an_object"
    if value.get("artifact_type") != ARTIFACT_VERDICT or value.get("schema_version") != 1:
        return None, "verdict_wrong_artifact_type"
    if value.get("redacted") is not True:
        return None, "verdict_not_redacted"
    return value, None


def command_compare(args: argparse.Namespace) -> int:
    baseline, baseline_error = load_snapshot(args.baseline)
    if baseline_error:
        verdict = {
            "artifact_type": ARTIFACT_VERDICT,
            "schema_version": 1,
            "scope": args.scope,
            "expect_state_root": args.expect_state_root,
            "redacted": True,
            "finished_at": int(time.time()),
            "status": "blocked",
            "reason": baseline_error,
        }
    else:
        after, after_error = load_snapshot(args.after)
        if after_error:
            verdict = {
                "artifact_type": ARTIFACT_VERDICT,
                "schema_version": 1,
                "scope": args.scope,
                "expect_state_root": args.expect_state_root,
                "redacted": True,
                "finished_at": int(time.time()),
                "status": "blocked",
                "reason": after_error,
            }
        else:
            verdict = compare_snapshots(
                baseline,
                after,
                args.scope,
                args.expect_state_root,
                args.source_commit,
                args.runner,
            )
    write_json(args.out, verdict)
    return 0 if verdict["status"] == "passed" else 1


def command_negative(args: argparse.Namespace, expected: str) -> int:
    baseline, baseline_error = load_snapshot(args.baseline)
    after, after_error = load_snapshot(args.after)
    if baseline_error or after_error:
        result = {
            "artifact_type": (
                ARTIFACT_NEGATIVE_STALE if expected == "stale" else ARTIFACT_NEGATIVE_FOREIGN
            ),
            "schema_version": 1,
            "expected": "failed",
            "observed": "blocked",
            "status": "failed",
            "blocked_reason": baseline_error or after_error,
            "redacted": True,
            "finished_at": int(time.time()),
        }
        write_json(args.out, result)
        return 1
    verdict = compare_snapshots(
        baseline,
        after,
        f"negative-{expected}",
        args.expect_state_root,
        args.source_commit,
        args.runner,
    )
    stale_objects = []
    if expected == "stale":
        for entry in verdict.get("owned_leaks", []) + verdict.get("inconsistencies", []):
            if (
                entry.get("classification") == "stale_owned"
                and not str(entry.get("kind", "")).startswith("canary:")
            ):
                stale_objects.append(entry)
        detected = verdict["status"] == "failed" and bool(stale_objects)
    else:
        changed = [
            entry
            for entry in verdict.get("foreign_changes", [])
            if str(entry.get("kind", "")).startswith("canary:")
            or entry.get("kind") == "foreign_state"
        ]
        leaked_names = {
            str(entry.get("identity", "")) for entry in verdict.get("owned_leaks", [])
        }
        misattributed = any(
            str(entry.get("identity", "")) in leaked_names for entry in changed
        )
        detected = (
            verdict["status"] == "failed"
            and bool(changed)
            and not misattributed
        )
    observed = verdict.get("status", "blocked")
    result: dict = {
        "artifact_type": (
            ARTIFACT_NEGATIVE_STALE if expected == "stale" else ARTIFACT_NEGATIVE_FOREIGN
        ),
        "schema_version": 1,
        "expected": "failed",
        "observed": observed,
        "status": "passed" if detected else "failed",
        "redacted": True,
        "finished_at": int(time.time()),
    }
    if expected == "stale":
        result["stale_artifact_detected"] = detected
        result["stale_objects"] = [
            {"kind": entry.get("kind"), "identity": entry.get("identity")}
            for entry in stale_objects
        ]
    else:
        result["foreign_mutation_detected"] = detected
        result["foreign_changes"] = verdict.get("foreign_changes", [])
    if args.source_commit is not None:
        result["source_commit"] = args.source_commit
    if args.runner is not None:
        result["runner"] = args.runner
    write_json(args.out, result)
    return 0 if detected else 1


def command_aggregate(args: argparse.Namespace) -> int:
    now = int(time.time())
    aggregate: dict = {
        "artifact_type": ARTIFACT_AGGREGATE,
        "schema_version": 2,
        "profile": "libvirt",
        "source_commit": args.source_commit,
        "runner": args.runner,
        "started_at": args.started_at,
        "finished_at": now,
        "redacted": True,
        "normal_e2e": None,
        "failure_recovery": None,
        "negative_tests": {"stale_artifact_detected": False, "foreign_mutation_detected": False},
        "cleanup": None,
        "status": "blocked",
        "reason": "inputs_invalid",
        "per_scope": {},
    }

    def finalize(reason: str) -> int:
        aggregate["reason"] = reason
        write_json(args.out, redact_value(aggregate))
        return 1 if aggregate["status"] != "passed" else 0

    normal, normal_error = load_verdict(args.normal)
    if normal_error:
        return finalize(f"normal_verdict_invalid:{normal_error}")
    verdicts = []
    negative_results = []
    for path in args.results:
        value, error = load_verdict(path)
        if error:
            # Negative-test results are also accepted among the results.
            try:
                with open(path, encoding="utf-8") as stream:
                    candidate = json.load(stream)
            except (OSError, UnicodeError, json.JSONDecodeError):
                return finalize(f"result_invalid:{error}")
            if not isinstance(candidate, dict) or candidate.get("schema_version") != 1:
                return finalize(f"result_invalid:{error}")
            if candidate.get("artifact_type") in (
                ARTIFACT_NEGATIVE_STALE,
                ARTIFACT_NEGATIVE_FOREIGN,
            ):
                negative_results.append(candidate)
                continue
            return finalize(f"result_invalid:{error}")
        verdicts.append(value)

    for verdict in verdicts:
        if verdict.get("status") == "blocked":
            return finalize(f"scope_blocked:{verdict.get('scope')}:{verdict.get('reason')}")
        if verdict.get("source_commit") != args.source_commit:
            return finalize("source_commit_mismatch")
        if verdict.get("runner") != args.runner:
            return finalize("runner_mismatch")
    for negative in negative_results:
        if negative.get("source_commit") != args.source_commit:
            return finalize("source_commit_mismatch")
        if negative.get("runner") != args.runner:
            return finalize("runner_mismatch")

    if normal["status"] == "blocked":
        return finalize(f"normal_e2e_blocked:{normal.get('reason')}")
    if not verdicts:
        return finalize("missing_scope_results")

    stale_negative = next(
        (
            result
            for result in negative_results
            if result.get("artifact_type") == ARTIFACT_NEGATIVE_STALE
        ),
        None,
    )
    foreign_negative = next(
        (
            result
            for result in negative_results
            if result.get("artifact_type") == ARTIFACT_NEGATIVE_FOREIGN
        ),
        None,
    )
    if stale_negative is None or foreign_negative is None:
        return finalize("negative_evidence_missing")

    def totals(verdicts_to_sum):
        return {
            "owned_leaks": sum(len(v.get("owned_leaks", [])) for v in verdicts_to_sum),
            "inconsistencies": sum(
                len(v.get("inconsistencies", [])) for v in verdicts_to_sum
            ),
            "foreign_changes": sum(len(v.get("foreign_changes", [])) for v in verdicts_to_sum),
        }

    normal_counts = {
        "owned_leaks": len(normal.get("owned_leaks", [])),
        "inconsistencies": len(normal.get("inconsistencies", [])),
        "foreign_changes": len(normal.get("foreign_changes", [])),
    }
    scenario_counts = totals(verdicts)
    all_counts = totals([normal] + verdicts)

    aggregate["normal_e2e"] = {
        "executed": True,
        "cleanup_verified": normal["status"] == "passed",
        **normal_counts,
        "status": normal["status"],
    }
    aggregate["failure_recovery"] = {
        "scenario_count": len(verdicts),
        "scenario_pass_count": sum(1 for v in verdicts if v["status"] == "passed"),
        **scenario_counts,
        "status": "passed" if all(v["status"] == "passed" for v in verdicts) else "failed",
    }
    aggregate["negative_tests"] = {
        "stale_artifact_detected": (
            stale_negative.get("observed") == "failed"
            and stale_negative.get("stale_artifact_detected") is True
        ),
        "foreign_mutation_detected": (
            foreign_negative.get("observed") == "failed"
            and foreign_negative.get("foreign_mutation_detected") is True
        ),
    }
    aggregate["cleanup"] = {
        "status": "passed" if normal["status"] == "passed" else "failed",
        "resources": {},
    }
    aggregate["per_scope"] = {
        verdict.get("scope", "?"): {
            "status": verdict.get("status"),
            "owned_leaks": len(verdict.get("owned_leaks", [])),
            "inconsistencies": len(verdict.get("inconsistencies", [])),
            "foreign_changes": len(verdict.get("foreign_changes", [])),
        }
        for verdict in [normal] + verdicts
    }
    aggregate["totals"] = all_counts

    all_passed = (
        normal["status"] == "passed"
        and aggregate["failure_recovery"]["status"] == "passed"
        and all(value == 0 for value in all_counts.values())
        and aggregate["negative_tests"]["stale_artifact_detected"]
        and aggregate["negative_tests"]["foreign_mutation_detected"]
    )
    if all_passed:
        aggregate["status"] = "passed"
        aggregate["reason"] = "all_scopes_passed"
    else:
        aggregate["status"] = "failed"
        aggregate["reason"] = "scope_or_negative_failed"
    return finalize(aggregate["reason"])


def write_json(path: str, document: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as output:
        json.dump(document, output, indent=2, sort_keys=True)
        output.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    compare = subparsers.add_parser("compare")
    compare.add_argument("--baseline", required=True)
    compare.add_argument("--after", required=True)
    compare.add_argument("--scope", required=True)
    compare.add_argument(
        "--expect-state-root", choices=("present", "absent"), required=True
    )
    compare.add_argument("--source-commit", default=None)
    compare.add_argument("--runner", default=None)
    compare.add_argument("--out", required=True)
    compare.set_defaults(handler=command_compare)

    for name, expected in (("negative-stale", "stale"), ("negative-foreign", "foreign")):
        negative = subparsers.add_parser(name)
        negative.add_argument("--baseline", required=True)
        negative.add_argument("--after", required=True)
        negative.add_argument(
            "--expect-state-root", choices=("present", "absent"), default="present"
        )
        negative.add_argument("--source-commit", default=None)
        negative.add_argument("--runner", default=None)
        negative.add_argument("--out", required=True)
        negative.set_defaults(handler=lambda ns, expected=expected: command_negative(ns, expected))

    aggregate = subparsers.add_parser("aggregate")
    aggregate.add_argument("--normal", required=True)
    aggregate.add_argument("--results", nargs="+", required=True)
    aggregate.add_argument("--source-commit", required=True)
    aggregate.add_argument("--runner", required=True)
    aggregate.add_argument("--started-at", type=int, required=True)
    aggregate.add_argument("--out", required=True)
    aggregate.set_defaults(handler=command_aggregate)

    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
