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
import uuid

# Every acceptance case the campaign is required to produce, per phase. Phase
# identity matters: scenario C (phase1b) and the cleanup matrix (phase2) share
# the C1..C6 labels, so the requirement is per-phase, not a union.
EXPECTED_CASES = {
    "phase1a": ["I1", "I2", "I3", "I4", "I5", "I6", "I7", "I8", "I9", "I10",
                "I11", "I12", "I13", "I14", "I15", "I16", "I17"],
    "phase1b": ["X0", "UI_CREATE_5", "UI_CREATE_6", "UI_CREATE_7", "B1", "B2", "B3",
                "C1", "C2", "C3", "D1", "D2", "D3", "G1", "S1", "T1", "T2", "SEC1", "A1"],
    "phase2": ["R1", "R2", "R3", "F1", "F2", "F3", "F4", "C1", "C2", "C3", "C4",
               "C5", "C6", "C7", "C8"],
}

# Classified gaps that are KNOWN FACTS of the demo profile: the manifest must
# report them, because a campaign that did not observe them did not actually
# exercise the profile. (Other observed gaps are reported but not required.)
# A trailing "*" makes the requirement a prefix match: the console create error
# class itself is observed at run time (`console-create-schema-dialect=<class>`).
REQUIRED_GAPS = {
    "compat-created-resource-not-canonical",
    "compat-action-operation-not-canonical",
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


def pinned_araf_image_digests() -> dict:
    """Read the published tuple's index/config digest pair from the source.

    Docker reports either the image index digest or the image config digest
    depending on the host image store.  Keeping both pinned values in the
    manifest makes that representation difference explicit while still
    proving that each observed value belongs to the exact tuple.
    """
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "packaging", "o3k-araf-demo.sh"))
    text = open(path, encoding="utf-8", errors="replace").read()
    values = {}
    for name in ("BFF", "TENANT_CONSOLE", "OPERATOR_CONSOLE"):
        for suffix in ("DIGEST", "CONFIG_DIGEST"):
            match = re.search(rf'^ARAF_{name}_{suffix}="([^"]+)"$', text, re.MULTILINE)
            if match:
                values[f"{name}_{suffix}"] = match.group(1)
    return values


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
    for forbidden in (".horizon-login.secrets", ".horizon-login.form"):
        if os.path.exists(os.path.join(evidence_dir, forbidden)):
            failures.append(f"secret-bearing Horizon temporary file was transferred: {forbidden}")

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

    base_image = read_pairs(evidence("00-base-image.txt"))
    for key in ("distro", "url", "digest_algorithm", "digest"):
        if not base_image.get(key):
            failures.append(f"00-base-image.txt carries no {key}")
    if base_image.get("distro") and base_image["distro"] != distro:
        failures.append(
            f"base image distro {base_image['distro']} does not match campaign distro {distro}")
    if base_image.get("digest_algorithm") not in (None, "", "sha256", "sha512"):
        failures.append(f"unsupported base image digest algorithm {base_image['digest_algorithm']!r}")
    if base_image.get("digest") and not re.fullmatch(r"[0-9a-f]{64,128}", base_image["digest"]):
        failures.append("00-base-image.txt carries a malformed digest")

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
    pinned_images = pinned_araf_image_digests()
    image_identity = {}
    for output_name, tuple_name in (("bff", "BFF"),
                                    ("tenant_console", "TENANT_CONSOLE"),
                                    ("operator_console", "OPERATOR_CONSOLE")):
        observed = araf.get(f"ARAF_{tuple_name}_IMAGE_DIGEST", "")
        index_digest = pinned_images.get(f"{tuple_name}_DIGEST", "")
        config_digest = pinned_images.get(f"{tuple_name}_CONFIG_DIGEST", "")
        revision = araf.get(f"ARAF_{tuple_name}_IMAGE_REVISION", "")
        source_sha = araf.get("ARAF_SOURCE_SHA", "")
        if observed not in (index_digest, config_digest) and revision != source_sha:
            failures.append(
                f"{output_name} observed digest {observed!r} is not a pinned index/config "
                f"digest and revision {revision!r} does not match source {source_sha!r}")
            digest_kind = "unknown"
        elif observed == index_digest:
            digest_kind = "index"
        elif observed == config_digest:
            digest_kind = "config"
        else:
            digest_kind = "source-revision"
        image_identity[output_name] = {
            "observed": observed,
            "digest_kind": digest_kind,
            "revision": revision,
            "pinned_index_digest": index_digest,
            "pinned_config_digest": config_digest,
        }

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
    # The published installer intentionally stamps the canonical join (T2)
    # before control-plane readiness (T1), and the first TestLab VM boot (T5)
    # before the external Araf demo is ready (T3).  Validate the real execution
    # contract rather than imposing a lexicographic label order.
    ordered = [stamps.get(key) for key in ("T0", "T2", "T1", "T5", "T3", "T4")]
    if all(value is not None for value in ordered):
        if ordered != sorted(ordered):
            failures.append("timestamps are not monotonic T0<=T2<=T1<=T5<=T3<=T4")
        if timing.get("T0_to_T5_seconds", -1) < 0:
            failures.append("T0_to_T5_seconds is negative")
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
    if "PP4-UI-CSRF-BRIDGE" in browser_log:
        failures.append("05-browser-e2e.log records a PP4-UI-CSRF-BRIDGE: request mutation is forbidden")
    for marker in ("UI_CREATE_1 schema-form-rendered", "UI_CREATE_2 browser-submit",
                   "UI_CREATE_3 operation-succeeded", "UI_CREATE_4 resource-ready"):
        if marker not in browser_log:
            failures.append(f"05-browser-e2e.log is missing {marker}")
    # The browser mutation is a native create followed by a later delete of the
    # same canonical resource. A CLI-created resource is never accepted as proof.
    create_match = re.search(r"PP4-UI-CREATE id=([0-9a-f-]{36}) operation=([0-9a-f-]{36})", browser_log)
    delete_match = re.search(r"PP4-UI-DELETE id=([0-9a-f-]{36})", browser_log)
    if not create_match:
        failures.append("05-browser-e2e.log is missing PP4-UI-CREATE id/operation")
    if not delete_match:
        failures.append("05-browser-e2e.log is missing PP4-UI-DELETE id")
    if create_match and delete_match and create_match.group(1) != delete_match.group(1):
        failures.append("browser delete id differs from browser-created canonical id")
    if "PP4-RELOGIN-OK" not in log_text(evidence("23-browser-relogin.log")):
        failures.append("23-browser-relogin.log is missing PP4-RELOGIN-OK")
    browser_ids = read_pairs(evidence("05-browser-ids.env"))
    if not browser_ids.get("PP4_UI_CREATE_ID") or not browser_ids.get("PP4_UI_DELETE_ID"):
        failures.append("05-browser-ids.env lacks browser create/delete canonical ids")
    if browser_ids.get("PP4_UI_CREATE_ID") != browser_ids.get("PP4_UI_DELETE_ID"):
        failures.append("05-browser-ids.env create/delete ids differ")
    for required_evidence in (
        "14-browser-native-identity.txt",
        "14-browser-native-openstack-show.txt",
        "14-browser-native-console.log",
    ):
        if not os.path.isfile(evidence(required_evidence)):
            failures.append(f"{required_evidence} is missing: native browser workload proof incomplete")

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
            gap = {"id": parts[1], "detail": parts[2] if len(parts) > 2 else ""}
            existing = next((item for item in gaps if item["id"] == gap["id"]), None)
            if existing is None:
                gaps.append(gap)
            elif gap["detail"] and gap["detail"] not in existing["detail"]:
                existing["detail"] = f"{existing['detail']}; {gap['detail']}"
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
    for required_id in ("test-vm", "pp4-openstack", "pp4-ui-target"):
        value = identity.get(required_id, "")
        try:
            uuid.UUID(value)
        except (ValueError, AttributeError):
            failures.append(f"canonical resource {required_id} is missing or not a UUID")
    if len({identity.get(key) for key in ("test-vm", "pp4-openstack", "pp4-ui-target")}) != 3:
        failures.append("canonical resource IDs are not distinct")

    boot_after = ""
    boot_after_path = evidence("boot-id-after.txt")
    if os.path.isfile(boot_after_path):
        boot_after = open(boot_after_path).read().strip()
    if not boot_after:
        failures.append("boot-id-after.txt is missing (post-reboot gate did not run)")
    if boot_after and inventory.get("boot_id") == boot_after:
        failures.append("boot_id_after_reboot did not change from boot_id_before")

    ui_delete_id = browser_ids.get("PP4_UI_DELETE_ID", "")
    if ui_delete_id and identity.get("pp4-ui-target") != ui_delete_id:
        failures.append("browser UI delete id does not match canonical pp4-ui-target id")

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
        "base_image": {
            "url": base_image.get("url", ""),
            "digest_algorithm": base_image.get("digest_algorithm", ""),
            "digest": base_image.get("digest", ""),
            "evidence": "00-base-image.txt",
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
            "image_identity": image_identity,
            "compose_services": [s for s in araf.get("ARAF_COMPOSE_SERVICES", "").split(",") if s],
            "tuple_evidence": "10-araf-production-tuple.txt",
        },
        "canonical_resources": identity,
        "browser_console_deleted_resource": {
            "resource_type": "compute.server",
            "id": browser_ids.get("PP4_UI_DELETE_ID", ""),
            "created_through_the_unmodified_openstack_cli": False,
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
            "native compute.server creation is required through the schema-driven browser form; the canonical Operation, resource, provider execution, libvirt guest boot, and cross-interface identity are independently checked",
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
