#!/usr/bin/env python3
"""Assemble the PP.4 durable (redacted) evidence manifest.

Reads a campaign evidence directory and emits a JSON manifest containing only
immutable metadata: what was tested, on what host, against which exact
artifacts, which cases passed, which product-profile gaps were observed, and
SHA-256 values of every evidence file. No log content and no secrets are
embedded.

The manifest is fail-closed: every fact it reports must come from numbered
evidence produced by the campaign itself (never from a caller-supplied
fallback), the expected acceptance-case set of all three phases must be present
and PASS, and the classified-gap ledger (35-classified-gaps.txt) must exist and
carry the gaps that are known facts of this profile. When any of that is not
true, the manifest is still written (as evidence) but the process exits
non-zero.

Usage: make-manifest.py <distro> <evidence-final-dir> <o3k-version> <source-sha>
"""
import datetime
import hashlib
import json
import os
import re
import sys

# Every acceptance case the campaign is required to produce, per phase. Phase
# identity matters: scenario C (phase1b) and the cleanup matrix (phase2) share
# the C1..C6 labels, so the requirement is per-phase, not a union.
EXPECTED_CASES = {
    "phase1a": ["I1", "I2", "I3", "I4", "I5", "I6", "I7", "I8", "I9", "I10",
                "I11", "I12", "I13", "I14", "I15", "I16", "I17"],
    "phase1b": ["X0", "A-gap", "B1", "B2", "B3", "C1", "C2", "C3", "D1", "D2",
                "D3", "G1", "S1", "T1", "T2", "SEC1"],
    "phase2": ["R1", "R2", "R3", "F1", "F2", "F3", "F4", "C1", "C2", "C3", "C4",
               "C5", "C6", "C7", "C8"],
}

# Classified gaps that are KNOWN FACTS of the demo profile: the manifest must
# report them, because a campaign that did not observe them did not actually
# exercise the profile. (Other observed gaps are reported but not required.)
# A trailing "*" makes the requirement a prefix match: the console create error
# class itself is observed at run time (`console-create-schema-dialect=<class>`).
REQUIRED_GAPS = {
    "native-vm-create=network-provider-inactive",
    "console-create-schema-dialect=*",
    "compat-created-resource-not-canonical",
}


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_pairs(path: str) -> dict:
    """Parse KEY=VALUE and KEY: VALUE lines.

    The evidence mixes both notations: /etc/os-release (in the host inventory)
    and the phase ledgers are KEY=VALUE, while the inventory's own header lines
    are "KEY: VALUE". Values are unquoted and stripped.
    """
    values = {}
    if not os.path.isfile(path):
        return values
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line and (": " not in line or line.index("=") < line.index(": ")):
            key, _, value = line.partition("=")
        elif ": " in line:
            key, _, value = line.partition(": ")
        else:
            continue
        values[key.strip()] = value.strip().strip('"')
    return values


def read_cases(path: str) -> list:
    cases = []
    if not os.path.isfile(path):
        return cases
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if line:
            cases.append(json.loads(line))
    return cases


def log_text(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    return open(path, encoding="utf-8", errors="replace").read()


def main() -> int:
    distro, evidence_dir, campaign_version, campaign_sha = sys.argv[1:5]
    failures = []

    files = {}
    for name in sorted(os.listdir(evidence_dir)):
        path = os.path.join(evidence_dir, name)
        if os.path.isfile(path) and not name.endswith("-done"):
            files[name] = sha256_file(path)

    def evidence(name: str) -> str:
        return os.path.join(evidence_dir, name)

    # ---- host inventory (KEY=VALUE os-release block + header KEY: VALUE) ----
    inventory = read_pairs(evidence("00-host-inventory.txt"))
    kernel = inventory.get("kernel", "")
    if not kernel:
        kernel = next(
            (l.split(" ", 2)[2] for l in
             log_text(evidence("00-host-inventory.txt")).splitlines()
             if l.startswith("Linux ")), "")

    # ---- release identity: numbered evidence only, never an argv fallback ----
    release = read_pairs(evidence("06-release-identity.txt"))
    o3k_version = release.get("installed_version", "")
    o3k_sha = release.get("installed_source_commit", "")
    if not o3k_version:
        failures.append("06-release-identity.txt carries no installed_version")
    if not o3k_sha:
        failures.append("06-release-identity.txt carries no installed_source_commit")
    if o3k_version and o3k_version.lstrip("v") != campaign_version.lstrip("v"):
        failures.append(
            f"installed version {o3k_version} does not match the campaign version {campaign_version}")
    if o3k_sha and o3k_sha != campaign_sha:
        failures.append(
            f"installed source_commit {o3k_sha} does not match the campaign source SHA {campaign_sha}")

    # ---- Araf production tuple: numbered evidence only, never hardcoded ----
    araf = read_pairs(evidence("10-araf-production-tuple.txt"))
    for key in ("ARAF_VERSION", "ARAF_SOURCE_SHA", "ARAF_UPSTREAM_ADAPTER",
                "ARAF_RUNTIME_PROFILE"):
        if not araf.get(key):
            failures.append(f"10-araf-production-tuple.txt carries no {key}")
    if araf.get("ARAF_UPSTREAM_ADAPTER") not in (None, "", "o3k"):
        failures.append(
            f"deployed Araf upstream adapter is {araf.get('ARAF_UPSTREAM_ADAPTER')!r}, not o3k")
    if araf.get("ARAF_RUNTIME_PROFILE") not in (None, "", "production"):
        failures.append(
            f"deployed Araf runtime profile is {araf.get('ARAF_RUNTIME_PROFILE')!r}, not production")

    # ---- timestamps ---------------------------------------------------------
    stamps = read_pairs(evidence("03-timestamps.env"))
    stamps = {k: int(v) for k, v in stamps.items() if v.isdigit()}
    timing = {}
    for label, key in (("T0_oneline_invoked", "T0"),
                       ("T1_o3k_canonical_ready", "T1"),
                       ("T2_buildingblock_ready", "T2"),
                       ("T3_araf_ready", "T3"),
                       ("T4_browser_login_usable", "T4"),
                       ("T5_first_vm_active_boot", "T5")):
        if key in stamps:
            timing[label] = stamps[key]
    if "T0" in stamps and "T5" in stamps:
        timing["T0_to_T5_seconds"] = stamps["T5"] - stamps["T0"]
    for required in ("T0", "T1", "T2", "T3", "T4", "T5"):
        if required not in stamps:
            failures.append(f"timestamp {required} missing from 03-timestamps.env")

    # ---- browser journeys (markers + the console-deleted resource id) ------
    browser_log = log_text(evidence("05-browser-e2e.log"))
    for marker in ("PP4-TENANT-OK", "PP4-OPERATOR-OK"):
        if marker not in browser_log:
            failures.append(f"05-browser-e2e.log is missing {marker}")
    if "PP4-UI-FALLBACK" in browser_log:
        failures.append("05-browser-e2e.log records a PP4-UI-FALLBACK: the browser journey did not perform the mutation")
    # The console mutation is a DELETE of the CLI-created server the harness
    # owns: the pinned Araf SPA cannot submit any create form (JSON Schema
    # 2020-12 create schemas vs draft-07 Ajv), so no console-created resource id
    # is expected (and would have to be explained).
    if not re.search(r"PP4-UI-DELETE id=[0-9a-f-]{36}", browser_log):
        failures.append("05-browser-e2e.log is missing the PP4-UI-DELETE id line (console-deleted server)")
    for gap_line in (
        "PP4-GAP native-vm-create=network-provider-inactive",
        "PP4-GAP console-create-schema-dialect=",
    ):
        if gap_line not in browser_log:
            failures.append(f"05-browser-e2e.log is missing the classified gap line: {gap_line}")
    if "PP4-RELOGIN-OK" not in log_text(evidence("23-browser-relogin.log")):
        failures.append("23-browser-relogin.log is missing PP4-RELOGIN-OK")
    browser_ids = read_pairs(evidence("05-browser-ids.env"))
    if not browser_ids.get("PP4_UI_DELETE_ID"):
        failures.append(
            "05-browser-ids.env carries no PP4_UI_DELETE_ID (console-deleted server)")

    # ---- classified gaps (known profile facts, evidence, never failures) ---
    gaps = []
    gap_path = evidence("35-classified-gaps.txt")
    if not os.path.isfile(gap_path):
        failures.append("35-classified-gaps.txt is missing (the classified-gap ledger was not written)")
    else:
        for line in open(gap_path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 2)
            if parts[0] != "GAP" or len(parts) < 2 or not parts[1]:
                failures.append(f"35-classified-gaps.txt carries a malformed line: {line}")
                continue
            gaps.append({
                "id": parts[1],
                "detail": parts[2] if len(parts) > 2 else "",
            })
    observed_gaps = {gap["id"] for gap in gaps}
    missing_gaps = {
        requirement for requirement in REQUIRED_GAPS
        if not any(
            observed.startswith(requirement[:-1]) if requirement.endswith("*") else observed == requirement
            for observed in observed_gaps
        )
    }
    if missing_gaps:
        failures.append(
            "35-classified-gaps.txt is missing known profile gaps: " + ", ".join(sorted(missing_gaps)))

    # ---- canonical resource identity ---------------------------------------
    identity = {}
    identity_path = evidence("14-scenarioA-identity.txt")
    if os.path.isfile(identity_path):
        for line in open(identity_path):
            parts = line.split()
            if len(parts) == 2:
                identity[parts[0]] = parts[1]
    if not identity:
        failures.append("14-scenarioA-identity.txt is missing or empty")

    boot_after = ""
    boot_after_path = evidence("boot-id-after.txt")
    if os.path.isfile(boot_after_path):
        boot_after = open(boot_after_path).read().strip()
    if not boot_after:
        failures.append("boot-id-after.txt is missing (post-reboot gate did not run)")

    # ---- acceptance cases: required set per phase, all PASS ----------------
    cases = read_cases(evidence("cases.jsonl"))
    by_phase = {}
    for case in cases:
        by_phase.setdefault(case.get("phase", "unknown"), {})[case.get("id")] = case.get("status")
    missing_cases = []
    for phase, expected in EXPECTED_CASES.items():
        observed = by_phase.get(phase, {})
        if not observed:
            failures.append(f"no acceptance cases recorded for {phase} (cases.jsonl lacks the phase label)")
            continue
        for case_id in expected:
            if case_id not in observed:
                missing_cases.append(f"{phase}/{case_id}")
    if missing_cases:
        failures.append("missing acceptance cases: " + ", ".join(missing_cases))
    failed_cases = [f"{c.get('phase', '?')}/{c.get('id')}" for c in cases if c.get("status") != "PASS"]
    if failed_cases:
        failures.append("non-PASS acceptance cases: " + ", ".join(sorted(set(failed_cases))))

    manifest = {
        "campaign": f"pp4-{distro}",
        "tracking_issue": "o3kio/o3k#973",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {
            "distro": distro,
            "os_pretty": inventory.get("PRETTY_NAME", ""),
            "kernel": kernel,
            "cpu": inventory.get("cpu", ""),
            "kvm_device": inventory.get("kvm device", ""),
            "svm_vmx_flag": inventory.get("svm/vmx flag", "").strip(),
            "boot_id_before": inventory.get("boot_id", ""),
            "boot_id_after_reboot": boot_after,
        },
        "o3k": {
            "version": o3k_version,
            "source_sha": o3k_sha,
            "campaign_version": campaign_version,
            "campaign_source_sha": campaign_sha,
            "release_identity_evidence": "06-release-identity.txt",
        },
        "araf": {
            "version": araf.get("ARAF_VERSION", ""),
            "source_sha": araf.get("ARAF_SOURCE_SHA", ""),
            "upstream_adapter": araf.get("ARAF_UPSTREAM_ADAPTER", ""),
            "runtime_profile": araf.get("ARAF_RUNTIME_PROFILE", ""),
            "image_digests": {
                "bff": araf.get("ARAF_BFF_IMAGE_DIGEST", ""),
                "tenant_console": araf.get("ARAF_TENANT_CONSOLE_IMAGE_DIGEST", ""),
                "operator_console": araf.get("ARAF_OPERATOR_CONSOLE_IMAGE_DIGEST", ""),
            },
            "compose_services": [s for s in araf.get("ARAF_COMPOSE_SERVICES", "").split(",") if s],
            "tuple_evidence": "10-araf-production-tuple.txt",
        },
        "canonical_resources": identity,
        "browser_console_deleted_resource": {
            "resource_type": "compute.server",
            "id": browser_ids.get("PP4_UI_DELETE_ID", ""),
            "created_through_the_unmodified_openstack_cli": True,
            "deleted_through_the_console_ui": True,
        },
        "classified_gaps": gaps,
        "timestamps_unix": timing,
        "test_cases": cases,
        "result": "PASS" if not failures else "FAIL",
        "failures": failures,
        "evidence_file_sha256": files,
        "known_limitations": [
            "single-node demo profile (o3k-demo-v1); not HA, not multi-node",
            "the pinned Araf console SPA sends no x-csrf-token, so the campaign bridges that one header at the network layer; any UI fallback fails this campaign",
            "NO console create can succeed on the pinned Araf tuple: the create schemas O3K serves declare JSON Schema 2020-12 while the pinned schema-runtime compiles with draft-07 Ajv, so the form fails client-side before any request is sent; the upstream fix (Araf PR #118) is not in this release tuple, and the observed error class is recorded as the classified gap console-create-schema-dialect=client-schema-compile. No campaign evidence claims a console create of a VM OR of a network",
            "the native compute.server create is NOT supported on this profile (the o3k-network execution agent is inactive by contract): the console attempt is performed and its truthful failure is recorded as the classified gap native-vm-create=network-provider-inactive",
            "native image and flavor inventories are compatibility-backed only: image.image has no canonical row and compute.flavor has no collection, so the console create form can only be fed the ids the compatibility APIs report",
            "compat-created networks and images are not canonical resources: testlab-network and the demo image exist only through the compatibility (Neutron/Glance) APIs (classified gap compat-created-resource-not-canonical)",
            "the native list projection carries no spec name for compute.server, so console rows are identified by canonical id (see 13b-native-name-projection.txt)",
            "the canonical ledger keeps a DELETED tombstone after a delete; the native show view conceals it (404) while the collection may still list it with a non-live status",
            "the operator console's dedicated global operations route (/api/v1/operator/operations) is not implemented by upstream O3K on this profile; the canonical /api/v1/operations list the same surface serves is what ties the operator view to tenant work",
            "demo IdP (Keycloak start-dev) is not a production identity claim",
            "native demo tokens are 1-hour HMAC without renewal (accepted Araf deviation)",
            "Horizon is an optional external compatibility witness, not the O3K dashboard",
        ],
    }
    json.dump(manifest, sys.stdout, indent=2)
    print()
    if failures:
        for failure in failures:
            print(f"[make-manifest] FAIL: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
