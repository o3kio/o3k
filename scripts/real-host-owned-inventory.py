#!/usr/bin/env python3
"""Collect a redacted, stable host inventory for the real-host guard.

The collector deliberately records only O3K-owned identities. Foreign host
state is represented by hashes so the verifier can detect mutation without
publishing unrelated domain, interface, or provider identities.

Schema versions
---------------

- schema_version 2: the bounded libvirt/OpenStack inventory. Its fields
  (`domains`, `pools`, `network_links`, `openstack`, `foreign_state`) are
  stable and consumed verbatim by `scripts/real-host-pre-run-guard.sh` and
  `scripts/real-host-post-run-guard.sh`. `pools` records each `o3k-p15-7-`
  owned-name libvirt dir pool with its libvirt state/autostart/target path,
  ownership-marker presence and digest, and an `active_owned` / `ambiguous`
  classification (the stale-pool sweep reaps proven stale pools before the
  guard runs, so pools have no `stale_owned` class; anything with broken or
  missing ownership evidence is `ambiguous`); foreign pool names are counted
  only in `foreign_state.pools_count`.
- schema_version 3: adds the independent verifier sections. The v2 fields are
  preserved byte-identically; the new sections are gated by environment
  variables so a configuration that never sets them produces an unchanged v2
  artifact:

  - ``O3K_REAL_HOST_STATE_ROOT`` enables `managed_state`, `dhcp`, and
    `durable`. When set, every configured source must be inspectable or the
    whole snapshot fails closed (``status: unavailable`` with a named reason).
    A root that does not exist records ``managed_state.status: "absent"``
    (valid clean state) while the remaining sections still fail closed when
    their sources are missing. Managed state lives under ``<root>/data`` in
    the disposable-testlab layout and directly under ``<root>`` in the
    installed layout (the installer passes the state root itself as
    ``--data-dir``); the collector probes ``data/`` when present and walks
    the root otherwise, and `collect_durable` finds the ledger in both
    places.
  - ``O3K_REAL_HOST_PID_ROOT`` enables `processes` (pidfile verification and
    unmanaged-daemon detection under the state root).
  - ``O3K_REAL_HOST_CANARIES`` enables `canaries` (path to a small JSON
    config; see below).
  - ``O3K_REAL_HOST_MANAGED_INJECTION_ROOT`` enables `injection_root`: a
    bounded, explicitly O3K-owned test sink used only by the stale-artifact
    negative test. Every entry inside it is classified ``stale_owned`` (no
    durable reference exists by construction); an absent configured root is
    valid state, an unreadable or symlink-containing root fails closed.
    Normal runs never set this env.

Non-terminal durable predicates (derived from the code, not guessed)
--------------------------------------------------------------------

- operations: terminal states are ``succeeded`` and ``failed``
  (`crates/o3k-reconciler/src/lib.rs` treats
  ``OperationState::Succeeded | OperationState::Failed`` as terminal in
  `apply_agent_observation`, `reconcile_operation`, and the re-inspect paths;
  `unknown_outcome` is non-terminal and recovered by re-inspection per
  ADR-0094). Non-terminal: ``pending``, ``running``, ``retryable``,
  ``unknown_outcome``.
- agent_commands: terminal ``succeeded``/``failed`` (the reconciler treats a
  terminal command record as authoritative in the presence-inspection paths,
  `crates/o3k-reconciler/src/lib.rs`); ``unknown_outcome`` is recovered by
  re-dispatch. Non-terminal: ``pending``, ``accepted``, ``running``,
  ``retryable``, ``unknown_outcome``. A non-terminal command row whose owning
  operation reached a terminal state is classified ``expected_retained``
  (journal evidence of the UnknownOutcome boundary; operation state is
  authoritative), not active residue.
- artifact_transfers: terminal ``committed``/``rejected``/``expired``
  (`ArtifactTransferState::is_terminal`,
  `crates/o3k-store/src/artifact_transfer.rs`). Non-terminal: ``offered``,
  ``receiving``.
- resources: a resource is deleted only when its ``observed_state`` decodes
  to ``ServerState::Deleted`` (case-insensitive; canonical storage spelling
  ``DELETED`` per `crates/o3k-store/src/server_state.rs`,
  `server_state_from_storage`). Non-deleted = ``upper(observed_state) !=
  'DELETED'``. Rows persist as tombstones after deletion; the tombstone itself
  is expected historical state, never a leak.
- network_ports: rows are hard-deleted by
  ``DELETE FROM network_ports WHERE id = ? AND project_id = ?``
  (`crates/o3k-store/src/lib.rs`), so every existing row is a non-deleted
  port. Ports are intentionally reusable after a terminal delete
  (`crates/o3k-compute/src/lib.rs`, `project_terminal_binding_outcome`).
- image_overlay_ownership: ``deleted`` is the only terminal state
  (`ImageOverlayState::is_terminal`, `crates/o3k-store/src/lib.rs`);
  ``failed`` overlays are recovered on restart (ADR-0135).
- placement_allocations: all rows are recorded; release-on-delete is the
  contract (`crates/o3k-compute/src/lib.rs` `release_placement_allocation`).

Classification contract (deliverable of issue #88, ADR-0164)
------------------------------------------------------------

Every O3K-owned object the inventory records carries exactly one of
``active_owned``, ``expected_retained``, ``stale_owned``, ``inconsistent``.
The rules below are derived from the code as it exists today and each
`expected_retained` entry cites its contract; the `contract` field names a
file or function. If the live host disagrees with the contract, the object is
recorded as `stale_owned` — that is exactly what the verifier exists for.

- libvirt domains (`o3k-*`, names matching `provider_refs`):
  - referenced by a live (non-deleted) resource -> `active_owned`;
  - referenced by a terminally-deleted resource -> `stale_owned` (the agent
    delete reaps domains: `undefine`/`force_stop` in
    `bins/o3k-compute/src/main.rs` `execute_command` Delete arm);
  - present with no durable `provider_refs` entry -> `stale_owned` (orphan).
- network links:
  - `o3ktap-*` TAPs (naming: `HostNetworkManager::tap_name`,
    `crates/o3k-network/src/lib.rs`, sha256(port_id)[:8]): recorded in
    `data/network/ownership.json` and owned by a live instance ->
    `active_owned`; recorded but instance terminally deleted -> `stale_owned`
    (reaped by `cleanup_instance_network` -> `delete_taps_for_instance` and
    `reap_stale_instance_networks`, `bins/o3k-compute/src/main.rs`);
    present on the host with no ownership.json record -> `stale_owned`
    (orphan). Note: the v2 collector previously classified `o3ktap-*` links
    as foreign because it only recognized the `o3k-` prefix; that defect is
    fixed here so leaked TAPs are visible to the owned-link delta.
  - `o3ktmp-*` provisional TAPs and `o3kbm-*` provisional bridges (create
    residue before the ownership record becomes durable, issues #602/#608):
    always `stale_owned` — no manifest record or live domain ever references
    a provisional name.
  - `o3k-br0` (the managed bridge): `active_owned` while a live network or
    instance exists or the ownership manifest records it; otherwise
    `stale_owned` (`cleanup_if_unused` removes the unused bridge,
    `bins/o3k-compute/src/main.rs`).
- managed-state files (relative to the walked data root — the state root's
  ``data/`` in the testlab layout, the state root itself in the installed
  layout):
  - `config-drive/<uuid>.iso`, `<uuid>/` directory, and
    `<uuid>.iso.o3k-iso-ownership.json` for a live instance ->
    `active_owned`; for a terminally-deleted instance -> `stale_owned`:
    `ConfigDriveStore::cleanup` (`crates/o3k-config-drive/src/lib.rs`) is the
    intended reaper but no delete path invokes it (the agent reaps only the
    agent-side artifact copies via
    `ArtifactStore::cleanup_config_drive_for_resource`,
    `crates/o3k-compute-agent/src/artifact.rs`). This is an observed contract
    gap, not an intentional cache.
  - `image-cache/base/<sha>.<format>` -> `expected_retained` (content-
    addressed cache revalidated by `resolve_base`,
    `crates/o3k-image/src/lib.rs`; ADR-0062, ADR-0147).
  - `image-cache/overlays/<uuid>.qcow2` and
    `image-cache/ownership/<uuid>.json` -> `active_owned` for live instances,
    `stale_owned` after terminal delete (`ImageMaterializer::delete_instance`
    and `Cache::delete_overlay`, `crates/o3k-image/src/lib.rs`; wired at
    `bins/o3k-compute/src/main.rs`).
  - `images/content/<uuid>` -> `expected_retained` while an `image_metadata`
    row exists (committed content; `ImageContentStore::delete` reaps on image
    delete, `crates/o3k-image/src/lib.rs`); `stale_owned` without a row.
  - `agent-id.artifacts/.{id}.manifest`: committed config-drive manifests of
    a terminally-deleted instance -> `stale_owned`
    (`cleanup_config_drive_for_resource` reaps them); image-base manifests
    and manifests of live resources -> `expected_retained` (committed
    manifest history; issue #88 expected historical/durable state).
  - `agent-id.artifacts/{sha256}.{format}` final content -> `expected_retained`
    (shared content-addressed store; removed only when the last manifest
    reference is removed, `crates/o3k-compute-agent/src/artifact.rs`).
  - `agent-id`, `agent-id.commands`, `agent-id.state` -> `expected_retained`
    (identity and durable command journal; the journal is bounded and
    single-writer, `crates/o3k-compute-agent/src/lib.rs`).
  - `network/ownership.json` -> `expected_retained` (durable ownership
    manifest, `crates/o3k-network/src/lib.rs`).
  - `dhcp/dnsmasq.conf`, `dhcp/state.json`, `dhcp/dnsmasq.leases`,
    `dhcp/dnsmasq-*.pid` -> `expected_retained` (durable DHCP configuration
    and runtime files, `crates/o3k-dhcp/src/lib.rs`; ADR-0025, ADR-0030).
    Lease rows are runtime records with natural expiry, not leaks; stale
    *bindings* (state.json entries whose port has no live instance) are
    `inconsistent` because `DhcpRuntime::remove_ports` must remove them on
    delete (`bins/o3k-compute/src/main.rs`).
  - `placement/` journal files (`placement.json*`, `allocation-intents.json*`)
    -> `expected_retained` (`crates/o3k-placement/src/lib.rs`); any other
    placement file -> `stale_owned`.
  - `console/<uuid>.log` -> `active_owned` for live instances, `stale_owned`
    after terminal delete (console cleanup runs in
    `crates/o3k-api/src/compute.rs` `delete_server`).
  - incomplete-transfer temporaries are recognized by the exact names the
    code uses (see `collect_managed_state`): `.{id}.part` and
    `.{id}.manifest.tmp` (`crates/o3k-compute-agent/src/artifact.rs`),
    `.{instance}-tmp-*`/`.{instance}-old-*` and
    `.{instance}.iso-{tmp,manifest-tmp,old,manifest-old}-*`
    (`crates/o3k-config-drive/src/lib.rs`), `base-<sha>.tmp-<uuid>`
    (`crates/o3k-image/src/lib.rs`), `.<instance>.tmp-<uuid>` overlay
    temporaries, `ownership/<id>.json.tmp-*` (ADR-0135), `<uuid>.upload-<uuid>`
    content-store temporaries, and `<identity>.commands.tmp`/`<identity>.state.tmp`
    journal temporaries. A `.part` whose manifest exists and whose transfer
    row is non-terminal is `expected_retained` (in-flight transfer); every
    other temp present at rest is `stale_owned` (crash residue recovered on
    restart per ADR-0135).
- dhcp processes: an owned dnsmasq (cmdline references the state root's dhcp
  directory) with live bindings -> `active_owned`; with zero bindings ->
  `stale_owned` (the supervisor stops dnsmasq when the last binding is
  removed, `bins/o3k-compute/src/main.rs` `DhcpRuntime::remove_ports`).
  Foreign dnsmasq processes are recorded only as count + digest.
- processes: a pidfile-verified daemon -> `active_owned`; a pidfile whose
  process does not match /proc -> `stale_owned`; an O3K daemon binary running
  under the state root's ``bin/`` without a matching pidfile -> `inconsistent`
  (owned state that contradicts the declared pidfile registry; potential
  leak).
- durable rows: non-terminal operations/commands/transfers and overlay rows
  whose resource is live -> `active_owned`; the same rows pointing at a
  terminally-deleted resource -> `inconsistent` (durable state for a provably
  absent host object). Non-deleted resources and bound ports -> `active_owned`;
  unbound ports under an existing network -> `expected_retained` (reusable);
  a bound port whose instance is absent -> `inconsistent`. Allocation rows ->
  `active_owned` for live consumers, `inconsistent` after terminal delete.
  `provider_refs` and `operation_retry_state` are recorded as counts only.

Canaries (``O3K_REAL_HOST_CANARIES``) are operator-configured foreign-state
markers: exactly ``{"libvirt_domains": ["NAME", ...], "network_links":
["NAME", ...], "files": [{"path": "/abs/path", "sha256": "..."}, ...]}``.
Their names are operator-chosen and publishable; raw content is never
published (files are hashed, libvirt XML is hashed raw — `virsh dumpxml` is
deterministic for a defined domain — and link JSON is digested). A missing
canary is recorded as ``present: false`` and the verifier treats its
disappearance as foreign-state change.

Redaction
---------

The final document passes a self-check that scrubs any value containing a
known secret marker (``password``, ``secret``, ``private_key``, ``api_key``,
``access_key``, ``OS_PASSWORD``, PEM headers). Protected-path raw values,
foreign identities, and environment contents are never written.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat as stat_module
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import uuid as uuid_module
from pathlib import Path

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
RESOURCES = ("server", "image", "network", "subnet", "flavor")
MAX_PROTECTED_FILE_BYTES = 64 * 1024 * 1024
MAX_PROTECTED_ENTRIES = 10_000
MAX_PROTECTED_TOTAL_BYTES = 256 * 1024 * 1024
MAX_MANAGED_FILE_BYTES = 64 * 1024 * 1024
MAX_MANAGED_ENTRIES = 20_000
MAX_MANAGED_TOTAL_BYTES = 512 * 1024 * 1024
MAX_CANARY_FILE_BYTES = 64 * 1024 * 1024
RESOURCE_COMMANDS = {
    # Name lookups make server inventory depend on optional flavor/image
    # collection compatibility.  The guard needs only server IDs and names.
    "server": ("server", "list", "-n", "-f", "json"),
    "image": ("image", "list", "-f", "json"),
    "network": ("network", "list", "-f", "json"),
    "subnet": ("subnet", "list", "-f", "json"),
    "flavor": ("flavor", "list", "-f", "json"),
}
RESOURCE_NAMES = {
    "server": "o3k-testlab-server",
    "image": "o3k-testlab-image",
    "network": "o3k-testlab-network",
    "subnet": "o3k-testlab-subnet",
    "flavor": "o3k-testlab-flavor",
}
DIRECT_COLLECTIONS = {
    "server": ("compute", "servers", "servers"),
    "image": ("image", "v2/images", "images"),
}
DAEMON_BINARIES = ("o3kd", "o3k-compute")
EXTENDED_ENVS = (
    "O3K_REAL_HOST_STATE_ROOT",
    "O3K_REAL_HOST_PID_ROOT",
    "O3K_REAL_HOST_CANARIES",
    "O3K_REAL_HOST_MANAGED_INJECTION_ROOT",
)
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
TEMP_NAME_PATTERNS = (
    # crates/o3k-compute-agent/src/artifact.rs: `.part` (incomplete transfer
    # content) and `.manifest.tmp` (atomic manifest publication temporary).
    re.compile(r"^\.[A-Za-z0-9._:-]+\.part$"),
    re.compile(r"^\.[A-Za-z0-9._:-]+\.manifest\.tmp$"),
    # crates/o3k-config-drive/src/lib.rs: directory and ISO publication
    # temporaries and backups.
    re.compile(r"^\.[A-Za-z0-9._:-]+-tmp-[0-9a-f-]+$"),
    re.compile(r"^\.[A-Za-z0-9._:-]+-old-[0-9a-f-]+$"),
    re.compile(r"^\.[A-Za-z0-9._:-]+\.iso-(tmp|manifest-tmp|old|manifest-old)-[0-9a-f-]+$"),
    # crates/o3k-image/src/lib.rs: base publication temporary, overlay
    # publication temporary, ownership-manifest temporary (ADR-0135 recovery),
    # and content-store upload temporary.
    re.compile(r"^base-[0-9a-f]{64}\.tmp-[0-9a-f-]+$"),
    re.compile(r"^\.[A-Za-z0-9._:-]+\.tmp-[0-9a-f-]+$"),
    re.compile(r"^[A-Za-z0-9._:-]+\.json\.tmp-[0-9a-f-]+$"),
    re.compile(r"^[0-9a-f-]{36}\.upload-[0-9a-f-]+$"),
    # crates/o3k-compute-agent/src/lib.rs: command-journal and administrative
    # state publication temporaries.
    re.compile(r"^[A-Za-z0-9._:-]+\.commands\.tmp$"),
    re.compile(r"^[A-Za-z0-9._:-]+\.state\.tmp$"),
)
LAST_FAILURE_REASON = "inventory_collection_failed"

POOL_PREFIX = "o3k-p15-7-"
POOL_MARKER_MAGIC = "o3k-p15-7-pool-owned-v1"
POOL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def failure_class(stderr: str) -> str:
    """Classify CLI failure without publishing provider diagnostics."""
    value = stderr.lower()
    if any(marker in value for marker in ("401", "403", "unauthorized", "forbidden", "authentication")):
        return "auth"
    if any(marker in value for marker in ("404", "not found", "no route", "endpoint")):
        return "route"
    if any(marker in value for marker in ("timed out", "timeout", "timedout")):
        return "timeout"
    if any(marker in value for marker in ("unrecognized arguments", "no such command", "invalid choice")):
        return "client"
    if any(marker in value for marker in ("json", "parse", "decode", "schema")):
        return "response_schema"
    return "unknown"


def failure_detail(stderr: str) -> str:
    """Return a bounded diagnostic category, never provider-supplied text."""
    value = stderr.lower()
    categories = (
        ("endpoint_not_found", ("endpointnotfound", "endpoint not found")),
        ("bad_request", ("badrequest", "bad request")),
        ("not_found", ("notfound", "not found")),
        ("unauthorized", ("unauthorized", "unauthenticated")),
        ("forbidden", ("forbidden",)),
        ("missing_configuration", ("missing value", "required option")),
        ("client_error", ("clientexception", "command error")),
    )
    for name, markers in categories:
        if any(marker in value for marker in markers):
            return name
    exception = re.search(r"\b([a-z][a-z0-9_]*(?:error|exception))\b", value)
    if exception:
        return "exception_" + re.sub(r"[^a-z0-9_]+", "_", exception.group(1))[:48]
    return "unspecified"


def command(args: tuple[str, ...], *, scrub_provider_config: bool = False) -> str | None:
    global LAST_FAILURE_REASON
    environment = os.environ.copy()
    if scrub_provider_config:
        environment.pop("OS_CLOUD", None)
        environment.pop("OS_CLIENT_CONFIG_FILE", None)
    try:
        result = subprocess.run(
            args,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=10,
            text=True,
        )
    except FileNotFoundError:
        LAST_FAILURE_REASON = "command_unavailable:" + ":".join(args[:3])
        return None
    except subprocess.TimeoutExpired:
        LAST_FAILURE_REASON = "command_timeout:" + ":".join(args[:3])
        return None
    except subprocess.CalledProcessError as error:
        stderr = error.stderr if isinstance(error.stderr, str) else ""
        category = failure_class(stderr)
        LAST_FAILURE_REASON = (
            "command_failed:" + ":".join(args[:3]) + ":" + category
        )
        print(
            "real-host inventory command failed: "
            f"family={':'.join(args[:3])} class={category} detail={failure_detail(stderr)}",
            file=sys.stderr,
        )
        return None
    except (OSError, UnicodeError, subprocess.SubprocessError):
        LAST_FAILURE_REASON = "command_error:" + ":".join(args[:3])
        return None
    return result.stdout


def named_resource_ids(resource: str, output: str) -> list[str] | None:
    """Parse JSON resource output and retain only the exact owned name.

    Server-side name filters are not part of the bounded compatibility surface;
    filtering locally also keeps the baseline collector independent of CLI
    query syntax while preserving fail-closed parsing and ownership checks.
    """
    try:
        records = json.loads(output)
    except json.JSONDecodeError:
        global LAST_FAILURE_REASON
        LAST_FAILURE_REASON = "response_schema:openstack:" + resource + ":json"
        return None
    if not isinstance(records, list):
        LAST_FAILURE_REASON = "response_schema:openstack:" + resource + ":list"
        return None
    expected_name = RESOURCE_NAMES[resource]
    values: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            LAST_FAILURE_REASON = "response_schema:openstack:" + resource + ":record"
            return None
        name = record.get("Name", record.get("name"))
        identifier = record.get("ID", record.get("id"))
        if name == expected_name:
            if not isinstance(identifier, str) or SAFE_ID.fullmatch(identifier) is None:
                LAST_FAILURE_REASON = "response_schema:openstack:" + resource + ":identity"
                return None
            values.append(identifier)
    return sorted(set(values))


def direct_collection(resource: str) -> str | None:
    """Read a bounded collection when CLI service discovery is incompatible."""
    global LAST_FAILURE_REASON
    service, suffix, collection_key = DIRECT_COLLECTIONS[resource]
    token_output = command(("openstack", "token", "issue", "-f", "json"), scrub_provider_config=True)
    catalog_output = command(("openstack", "catalog", "show", service, "-f", "json"), scrub_provider_config=True)
    if token_output is None or catalog_output is None:
        return None
    try:
        token = json.loads(token_output)
        catalog = json.loads(catalog_output)
        token_id = token["id"]
        project_id = token["project_id"]
        endpoints = catalog["endpoints"]
        endpoint = next(
            item["url"] for item in endpoints
            if item.get("interface") == os.environ.get("OS_INTERFACE", "public")
            and item.get("region") == os.environ.get("OS_REGION_NAME", "RegionOne")
        )
        if not isinstance(token_id, str) or not isinstance(project_id, str) or not isinstance(endpoint, str):
            raise ValueError
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        LAST_FAILURE_REASON = "response_schema:openstack:" + resource + ":catalog"
        return None
    url = endpoint.rstrip("/") + "/" + suffix
    if resource == "server" and project_id not in url:
        url += "/" + project_id
    request = urllib.request.Request(
        url,
        headers={"X-Auth-Token": token_id, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        status = error.code
        LAST_FAILURE_REASON = f"command_failed:openstack:{resource}:route" if status in (404, 405) else f"command_failed:openstack:{resource}:http{status}"
        return None
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        LAST_FAILURE_REASON = "command_error:openstack:" + resource + ":direct"
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get(collection_key), list):
        LAST_FAILURE_REASON = "response_schema:openstack:" + resource + ":collection"
        return None
    records = []
    for item in payload[collection_key]:
        if not isinstance(item, dict):
            LAST_FAILURE_REASON = "response_schema:openstack:" + resource + ":record"
            return None
        records.append({"ID": item.get("id"), "Name": item.get("name")})
    return json.dumps(records)


def digest(values: list[str]) -> str:
    payload = "\n".join(sorted(values)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str | None:
    """Hash a regular file's content; fails closed on any read error."""
    global LAST_FAILURE_REASON
    try:
        hasher = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, UnicodeError):
        LAST_FAILURE_REASON = "managed_state_unreadable:" + path.name[:64]
        return None


def protected_paths_digest() -> str | None:
    """Hash an explicit, redacted allowlist of host paths and their contents."""
    global LAST_FAILURE_REASON
    raw_allowlist = os.environ.get("O3K_REAL_HOST_PROTECTED_PATHS")
    if raw_allowlist is None:
        return None
    paths = []
    for raw in raw_allowlist.splitlines():
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        path = Path(value)
        if (not path.is_absolute() or "\x00" in value
                or ".." in path.parts):
            LAST_FAILURE_REASON = "protected_path_allowlist_invalid"
            return None
        paths.append(Path(os.path.abspath(path)))

    records: list[str] = []
    total_bytes = 0
    for root in sorted(set(paths), key=str):
        try:
            candidates = [root]
            if root.is_dir():
                for candidate in root.rglob("*"):
                    candidates.append(candidate)
                    if len(candidates) > MAX_PROTECTED_ENTRIES:
                        LAST_FAILURE_REASON = "protected_path_too_many_entries"
                        return None
            for candidate in candidates:
                stat = candidate.lstat()
                kind = ("dir" if stat_module.S_ISDIR(stat.st_mode)
                        else "file" if stat_module.S_ISREG(stat.st_mode)
                        else "symlink" if stat_module.S_ISLNK(stat.st_mode) else "other")
                content = ""
                if kind == "file":
                    if stat.st_size > MAX_PROTECTED_FILE_BYTES:
                        LAST_FAILURE_REASON = "protected_path_file_too_large"
                        return None
                    total_bytes += stat.st_size
                    if total_bytes > MAX_PROTECTED_TOTAL_BYTES:
                        LAST_FAILURE_REASON = "protected_path_total_too_large"
                        return None
                    hasher = hashlib.sha256()
                    with candidate.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            hasher.update(chunk)
                    content = hasher.hexdigest()
                elif kind == "symlink":
                    content = hashlib.sha256(os.readlink(candidate).encode("utf-8")).hexdigest()
                relative = "." if candidate == root else str(candidate.relative_to(root))
                records.append(json.dumps({
                    "path_sha256": hashlib.sha256(str(root).encode("utf-8")).hexdigest(),
                    "relative_path_sha256": hashlib.sha256(relative.encode("utf-8")).hexdigest(),
                    "kind": kind,
                    "mode": stat.st_mode,
                    "size": stat.st_size,
                    "mtime_ns": stat.st_mtime_ns,
                    "content_sha256": content,
                }, sort_keys=True, separators=(",", ":")))
        except (OSError, UnicodeError, ValueError):
            LAST_FAILURE_REASON = "protected_path_unreadable"
            return None
    return digest(records)


def classify_link_lines(output: str) -> tuple[list[str], list[str]]:
    owned: list[str] = []
    foreign: list[str] = []
    for line in output.splitlines():
        value = line.strip()
        if not value:
            continue
        # `ip -o link` starts with an integer index and then the interface
        # name. Keep only non-O3K interfaces in the foreign-state digest.
        # The `o3k-` prefix (domains, the managed bridge), the `o3ktap-`
        # prefix (TAPs named by HostNetworkManager::tap_name), and the
        # provisional `o3ktmp-`/`o3kbm-` prefixes (create residue before the
        # ownership record, crates/o3k-network/src/lib.rs) are O3K-owned;
        # without these prefixes a leaked link was previously hashed as
        # foreign state and could stay invisible to the owned-link delta.
        fields = value.split(":", 2)
        name = fields[1].strip().split("@", 1)[0] if len(fields) > 1 else ""
        # Docker bridge ports (kernel-named veth* enslaved to docker0) and the
        # docker0 bridge itself are anonymous, positional artifacts: veth names
        # are random per container lifecycle and docker0's carrier flags flip
        # with port attachment, so neither carries stable identity. Run-scoped
        # O3K containers (the disposable PostgreSQL database) start before the
        # pre-run baseline and are removed by cleanup, making the digest
        # unstable by construction. Container identity is tracked by ownership
        # ledgers, not by bridge interfaces.
        if name == "docker0" or " master docker0 " in f" {value} ":
            continue
        if name.startswith(("o3k-", "o3ktap-", "o3ktmp-", "o3kbm-")):
            if SAFE_ID.fullmatch(name) is None:
                return [], []
            owned.append(name)
        else:
            foreign.append(value)
    return sorted(set(owned)), foreign


def redact_value(value):
    """Scrub secret-shaped strings from any value emitted by this collector."""
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


def json_is_uuid(value: str) -> bool:
    try:
        uuid_module.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False


ARTIFACT_MANIFEST_MAGIC = b"O3KART1"
# proto/compute/v1/compute_agent.proto ArtifactOffer field numbers.
ARTIFACT_OFFER_STRINGS = {
    1: "transfer_id",
    2: "command_id",
    3: "operation_id",
    4: "resource_id",
    5: "agent_id",
    6: "artifact_id",
    10: "format",
}
ARTIFACT_OFFER_VARINTS = {7: "kind", 8: "sha256", 13: "expires_at_unix_ms"}


def _read_varint(data: bytes, cursor: int) -> tuple[int, int] | None:
    result = 0
    shift = 0
    while shift < 64:
        if cursor >= len(data):
            return None
        byte = data[cursor]
        cursor += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return result, cursor
        shift += 7
    return None


def decode_artifact_manifest(data: bytes) -> dict[str, object] | None:
    """Decode the binary artifact manifest written by
    `crates/o3k-compute-agent/src/artifact.rs` (`O3KART1` magic, version byte,
    u32-le protobuf offer length, protobuf `ArtifactOffer`, then i32-le state,
    u64-le next_chunk, u64-le bytes). Returns None for foreign/unparseable
    payloads so the collector fails closed only on genuinely corrupt state.
    """
    try:
        if not data.startswith(ARTIFACT_MANIFEST_MAGIC) or len(data) < 28:
            return None
        cursor = len(ARTIFACT_MANIFEST_MAGIC) + 1
        if data[7] != 1:
            return None
        length = int.from_bytes(data[cursor : cursor + 4], "little")
        cursor += 4
        offer_bytes = data[cursor : cursor + length]
        if len(offer_bytes) != length:
            return None
        cursor += length
        if len(data) - cursor != 16:
            return None
        offer: dict[str, object] = {}
        position = 0
        while position < len(offer_bytes):
            tag = _read_varint(offer_bytes, position)
            if tag is None:
                return None
            field_number, position = tag
            field = field_number >> 3
            wire_type = field_number & 0x7
            if wire_type == 0:
                value, position = _read_varint(offer_bytes, position)
                if value is None:
                    return None
                if field in ARTIFACT_OFFER_VARINTS:
                    offer[ARTIFACT_OFFER_VARINTS[field]] = value
            elif wire_type == 2:
                length_value, position = _read_varint(offer_bytes, position)
                if length_value is None:
                    return None
                payload = offer_bytes[position : position + length_value]
                if len(payload) != length_value:
                    return None
                position += length_value
                if field in ARTIFACT_OFFER_STRINGS:
                    offer[ARTIFACT_OFFER_STRINGS[field]] = payload.decode(
                        "utf-8", errors="replace"
                    )
            elif wire_type == 1:
                position += 8
            elif wire_type == 5:
                position += 4
            else:
                return None
        state = int.from_bytes(data[cursor : cursor + 4], "little", signed=True)
        next_chunk = int.from_bytes(data[cursor + 4 : cursor + 8], "little")
        bytes_received = int.from_bytes(data[cursor + 8 : cursor + 16], "little")
        return {
            "offer": offer,
            "state": state,
            "next_chunk": next_chunk,
            "bytes": bytes_received,
        }
    except (IndexError, ValueError):
        return None


def collect_managed_state(state_root: Path) -> dict[str, object] | None:
    """Inventory the managed state under the state root.

    The disposable-testlab layout keeps managed state under
    ``<state_root>/data``; the installed layout uses ``<state_root>`` itself
    as the data dir (the installer passes it directly as ``--data-dir``), so
    ``data/`` is probed when present and the root is walked otherwise. The
    walk skips the durable ledger (``o3k.sqlite`` and its WAL/SHM, covered by
    the `durable` section) and, in the root layout, env/tls/log files that
    live alongside the managed data.

    A configured root that does not exist is valid clean-host state
    (`status: "absent"`); the durable and dhcp sections still fail closed
    because their configured sources are uninspectable.
    """
    global LAST_FAILURE_REASON
    if not state_root.is_dir():
        return {"status": "absent", "reason": "state_root_missing"}
    data_dir = state_root / "data"
    walk_root = data_dir if data_dir.is_dir() else state_root
    entries: list[dict[str, object]] = []
    total_bytes = 0
    try:
        walker = [walk_root]
        while walker:
            directory = walker.pop()
            try:
                children = sorted(
                    (child for child in directory.iterdir()),
                    key=lambda child: child.name,
                )
            except OSError:
                LAST_FAILURE_REASON = "managed_state_unreadable_dir"
                return None
            for path in children:
                relative = str(path.relative_to(walk_root))
                if relative in ("o3k.sqlite", "o3k.sqlite-wal", "o3k.sqlite-shm"):
                    # The durable ledger is covered by the `durable` section
                    # (read-only sqlite3); WAL churn would otherwise break
                    # snapshot stability and hashing a live ledger adds no
                    # verifier value.
                    continue
                if "/" not in relative and (
                    relative.endswith(".env")
                    or relative.endswith(".log")
                    or relative in ("tls", "log", "bin")
                ):
                    # Root-layout non-managed files: installer env files, the
                    # TLS store, and log output sit next to the data dir in
                    # the installed layout and never inside the testlab
                    # data/ subtree.
                    continue
                try:
                    stat = path.lstat()
                except OSError:
                    LAST_FAILURE_REASON = "managed_state_unreadable"
                    return None
                kind = ("dir" if stat_module.S_ISDIR(stat.st_mode)
                        else "file" if stat_module.S_ISREG(stat.st_mode)
                        else "symlink" if stat_module.S_ISLNK(stat.st_mode) else "other")
                record: dict[str, object] = {
                    "path": relative,
                    "kind": kind,
                    "size": stat.st_size,
                    "classification": "stale_owned",
                    "contract": "unclassified-managed-entry",
                }
                if kind == "file":
                    if stat.st_size > MAX_MANAGED_FILE_BYTES:
                        LAST_FAILURE_REASON = "managed_state_file_too_large"
                        return None
                    total_bytes += stat.st_size
                    if total_bytes > MAX_MANAGED_TOTAL_BYTES:
                        LAST_FAILURE_REASON = "managed_state_total_too_large"
                        return None
                    content_hash = sha256_file(path)
                    if content_hash is None:
                        return None
                    record["sha256"] = content_hash
                elif kind == "symlink":
                    try:
                        record["target_sha256"] = hashlib.sha256(
                            os.readlink(path).encode("utf-8")
                        ).hexdigest()
                    except OSError:
                        LAST_FAILURE_REASON = "managed_state_unreadable"
                        return None
                entries.append(record)
                if kind == "dir":
                    walker.append(path)
                if kind == "file" and (
                    relative.endswith(".o3k-iso-ownership.json")
                    or relative == "network/ownership.json"
                    or relative.startswith("image-cache/ownership/")
                    or (relative.startswith("agent-id.artifacts/.")
                        and relative.endswith(".manifest"))
                ):
                    if (relative.startswith("agent-id.artifacts/.")
                            and relative.endswith(".manifest")):
                        try:
                            raw = path.read_bytes()
                        except OSError:
                            LAST_FAILURE_REASON = "managed_state_manifest_corrupt"
                            return None
                        parsed = decode_artifact_manifest(raw)
                        if parsed is None:
                            # A manifest the runtime cannot decode is corrupt
                            # O3K-owned state; fail closed rather than guess.
                            LAST_FAILURE_REASON = "managed_state_manifest_corrupt"
                            return None
                    else:
                        try:
                            parsed = json.loads(path.read_text(encoding="utf-8"))
                        except (OSError, UnicodeError, json.JSONDecodeError):
                            LAST_FAILURE_REASON = "managed_state_manifest_corrupt"
                            return None
                    record["parsed_manifest"] = redact_value(parsed)
    except (OSError, UnicodeError):
        LAST_FAILURE_REASON = "managed_state_unreadable"
        return None
    if len(entries) > MAX_MANAGED_ENTRIES:
        LAST_FAILURE_REASON = "managed_state_too_many_entries"
        return None
    return {"status": "available", "entries": entries}


def classify_domains(
    domains: list[str],
    provider_domains: dict[str, str],
    live_resources: set[str],
    durable_checked: bool,
) -> dict[str, dict[str, str]]:
    classified: dict[str, dict[str, str]] = {}
    for name in domains:
        if not durable_checked:
            classified[name] = {
                "classification": "active_owned",
                "contract": "host-live-without-durable-cross-check",
            }
            continue
        resource_id = provider_domains.get(name)
        if resource_id is None:
            classified[name] = {
                "classification": "stale_owned",
                "contract": "crates/o3k-compute-agent/src/artifact.rs; provider_refs are the durable domain authority",
            }
        elif resource_id in live_resources:
            classified[name] = {
                "classification": "active_owned",
                "contract": "bins/o3k-compute/src/main.rs delete arm reaps domains",
            }
        else:
            classified[name] = {
                "classification": "stale_owned",
                "contract": "bins/o3k-compute/src/main.rs delete arm reaps domains (undefine/force_stop)",
            }
    return classified


def classify_links(
    network_links: list[str],
    ownership_taps: dict[str, dict[str, object]],
    ownership_bridge: str | None,
    live_resources: set[str],
    live_networks: set[str],
    durable_checked: bool,
) -> dict[str, dict[str, str]]:
    """Classify owned links against the durable network ownership manifest."""
    classified: dict[str, dict[str, str]] = {}
    for name in network_links:
        if name.startswith(("o3ktmp-", "o3kbm-")):
            # Provisional create names (crates/o3k-network/src/lib.rs
            # partial_tap_name/partial_bridge_name): self-identifying crash
            # residue — no manifest record or live domain ever references
            # them, so their presence after a run is always a leak
            # (issues #602, #608).
            classified[name] = {
                "classification": "stale_owned",
                "contract": "bins/o3k-compute/src/main.rs reap_startup_residue -> reap_partial_links; provisional link residue",
            }
            continue
        if name.startswith("o3ktap-"):
            if not durable_checked:
                classified[name] = {
                    "classification": "active_owned",
                    "contract": "host-live-without-durable-cross-check",
                }
                continue
            record = ownership_taps.get(name)
            if record is None:
                classified[name] = {
                    "classification": "stale_owned",
                    "contract": "bins/o3k-compute/src/main.rs reap_stale_instance_networks; orphan TAP without an ownership record",
                }
                continue
            instance_id = str(record.get("instance_id", ""))
            if instance_id in live_resources:
                classified[name] = {
                    "classification": "active_owned",
                    "contract": "crates/o3k-network/src/lib.rs ownership manifest of a live instance",
                }
            else:
                classified[name] = {
                    "classification": "stale_owned",
                    "contract": "bins/o3k-compute/src/main.rs cleanup_instance_network -> delete_taps_for_instance",
                }
            continue
        if name.startswith("o3k-"):
            if not durable_checked:
                classified[name] = {
                    "classification": "active_owned",
                    "contract": "host-live-without-durable-cross-check",
                }
                continue
            if ownership_bridge == name:
                if live_resources or live_networks:
                    classified[name] = {
                        "classification": "active_owned",
                        "contract": "bins/o3k-compute/src/main.rs shared bridge in use",
                    }
                else:
                    classified[name] = {
                        "classification": "stale_owned",
                        "contract": "bins/o3k-compute/src/main.rs cleanup_if_unused removes the unused bridge",
                    }
            else:
                classified[name] = {
                    "classification": "stale_owned",
                    "contract": "crates/o3k-network/src/lib.rs link without an ownership-manifest record",
                }
    return classified


def parse_pool_marker(path: Path) -> dict[str, str] | None:
    """Parse the durable pool ownership marker emitted by
    `scripts/p15-7-libvirt-storage-pool.sh` (define writes
    `.o3k-p15-7-pool-owned` into the exact run-owned target directory). A
    marker dict of `key=value` facts is returned only when the file is a
    regular (non-symlink) file whose magic `o3k-p15-7-pool-owned-v1` appears
    exactly once. None for absent, symbolic, or malformed markers."""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return None
    if lines.count(POOL_MARKER_MAGIC) != 1:
        return None
    fields: dict[str, str] = {}
    for line in lines:
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key] = value
    return fields


def _pool_autostart_map(details_output: str) -> dict[str, str]:
    """Parse the read-only `virsh pool-list --all --details` Autostart column.
    Pool names and the leading columns never contain spaces, so a whitespace
    split of the header and each data row is safe for the fields we read."""
    autostart: dict[str, str] = {}
    header = None
    for line in details_output.splitlines():
        if "Autostart" in line:
            header = line
            break
    if header is None:
        return autostart
    columns = header.split()
    for line in details_output.splitlines()[1:]:
        stripped = line.strip()
        if not stripped or set(stripped) == {"-"}:  # separator row
            continue
        fields = line.split()
        if len(fields) >= len(columns):
            row = dict(zip(columns, fields))
            if row.get("Name"):
                autostart[row["Name"]] = row.get("Autostart")
    return autostart


def classify_pool(
    name: str,
    image_root: Path,
    autostart_map: dict[str, str],
    domain_xmls: list[str],
) -> dict[str, object] | None:
    """Classify one ``o3k-p15-7-`` owned-name libvirt dir storage pool.

    Returns None only on virsh infrastructure failure (fail closed). Every
    other outcome is recorded with a ``classification`` of ``active_owned``
    (name/path/XML conform AND a valid matching durable marker AND no live
    domain references the path) or ``ambiguous`` (anything with broken,
    missing, or self-contradictory ownership evidence — never silently
    foreign, never automatically reaped). The libvirt ``State`` is recorded
    separately as ``libvirt_state`` so an active libvirt state is never
    conflated with active ownership.
    """
    info = command(("virsh", "-c", "qemu:///system", "pool-info", name))
    if info is None:
        return None
    state = None
    for line in info.splitlines():
        if line.startswith("State:"):
            state = line.split(":", 1)[1].strip()
    dump = command(("virsh", "-c", "qemu:///system", "pool-dumpxml", name))
    if dump is None:
        return None
    xml_type = None
    xml_name = None
    target_path = None
    try:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(dump)
        xml_name = root.findtext("name")
        xml_type = root.get("type")
        target_path = root.findtext("target/path")
    except (ET.ParseError, AttributeError, UnicodeError):
        pass

    record: dict[str, object] = {
        "name": name,
        "libvirt_state": state,
        "autostart": autostart_map.get(name),
        "target_path": target_path,
        "marker_present": False,
        "marker_sha256": None,
        "classification": "ambiguous",
    }

    run = name[len(POOL_PREFIX):]
    expected_path = os.path.join(str(image_root), POOL_PREFIX + run)
    conforms = (
        xml_type == "dir"
        and xml_name == name
        and isinstance(target_path, str)
        and target_path == expected_path
        and ".." not in target_path
    )
    if not conforms:
        record["reason"] = "pool_xml_not_run_owned_target"
        return record

    marker_path = Path(target_path) / ".o3k-p15-7-pool-owned"
    marker_present = not marker_path.is_symlink() and marker_path.is_file()
    record["marker_present"] = marker_present
    if marker_present:
        try:
            record["marker_sha256"] = sha256_bytes(marker_path.read_bytes())
        except (OSError, UnicodeError):
            record["marker_sha256"] = None
    marker = parse_pool_marker(marker_path)
    if marker is None:
        record["reason"] = "pool_marker_missing"
        return record
    source_sha = marker.get("source_sha")
    valid = (
        marker.get("run") == run
        and marker.get("pool") == name
        and marker.get("path") == target_path
        and (source_sha == "unknown" or (source_sha is not None and POOL_SHA_RE.fullmatch(source_sha) is not None))
    )
    if not valid:
        record["reason"] = "pool_marker_mismatch"
        return record

    # Domain-attachment check: no live domain may reference the pool path.
    for xml in domain_xmls:
        if target_path in xml:
            record["reason"] = "referenced_by_domain"
            return record

    record["classification"] = "active_owned"
    record["contract"] = (
        "scripts/p15-7-libvirt-storage-pool.sh define writes the durable "
        "o3k-p15-7-pool-owned marker; proven-owned and unused"
    )
    return record


def collect_pools(image_root: Path) -> dict[str, object] | None:
    """Inventory owned-name libvirt dir storage pools for the base snapshot.

    Only pools whose name starts with ``o3k-p15-7-`` are recorded
    individually; foreign pools are counted only (``foreign_count``). Any
    virsh command failure (listing pools, listing domains, dumping a domain
    or an owned pool) fails closed (None) — consistent with how the domains
    section is collected.
    """
    listing = command(("virsh", "-c", "qemu:///system", "pool-list", "--all", "--name"))
    if listing is None:
        return None
    domain_output = command(("virsh", "-c", "qemu:///system", "list", "--all", "--name"))
    if domain_output is None:
        return None
    domain_xmls: list[str] = []
    for dom in (line.strip() for line in domain_output.splitlines() if line.strip()):
        xml = command(("virsh", "-c", "qemu:///system", "dumpxml", dom))
        if xml is None:
            return None
        domain_xmls.append(xml)

    details = command(("virsh", "-c", "qemu:///system", "pool-list", "--all", "--details"))
    autostart_map = _pool_autostart_map(details) if details is not None else {}

    foreign_count = 0
    pools: list[dict[str, object]] = []
    for name in (line.strip() for line in listing.splitlines() if line.strip()):
        if not name.startswith(POOL_PREFIX):
            foreign_count += 1
            continue
        record = classify_pool(name, image_root, autostart_map, domain_xmls)
        if record is None:
            return None
        pools.append(record)
    return {"pools": pools, "foreign_count": foreign_count}


def classification_summary(document: dict[str, object]) -> dict[str, int]:
    """Tally every classified O3K-owned object in the snapshot."""
    counts = {"active_owned": 0, "expected_retained": 0, "stale_owned": 0, "inconsistent": 0}

    def count(value) -> None:
        if isinstance(value, dict):
            classification = value.get("classification")
            if classification in counts:
                counts[classification] += 1
            for item in value.values():
                count(item)
        elif isinstance(value, list):
            for item in value:
                count(item)

    for key in (
        "domain_classifications",
        "link_classifications",
        "managed_state",
        "dhcp",
        "processes",
        "durable",
        "pools",
    ):
        if key in document:
            count(document[key])
    return counts


def collect_injection_root() -> dict[str, object] | None:
    """Inventory the configured O3K-owned test injection root.

    The injection root is a bounded, explicitly O3K-owned managed sink used
    only by the verifier's stale-artifact negative test. Every entry inside
    it is O3K-owned managed state with no durable reference by construction,
    so every entry is classified ``stale_owned``. A configured root that does
    not exist is valid state (`status: "absent"`); an existing but unreadable
    or symlink-containing root fails closed (`None`), and oversized trees
    fail closed. Normal O3K runs never configure this env, so the sink has no
    effect outside the negative-test harness.
    """
    global LAST_FAILURE_REASON
    raw = os.environ.get("O3K_REAL_HOST_MANAGED_INJECTION_ROOT")
    if raw is None:
        return {"status": "not_checked"}
    root = Path(raw)
    if not root.is_dir():
        return {"status": "absent", "reason": "injection_root_missing"}
    entries: list[dict[str, object]] = []
    total_bytes = 0
    try:
        walker = [root]
        while walker:
            directory = walker.pop()
            try:
                children = sorted(
                    (child for child in directory.iterdir()),
                    key=lambda child: child.name,
                )
            except OSError:
                LAST_FAILURE_REASON = "injection_root_unreadable_dir"
                return None
            for path in children:
                try:
                    stat = path.lstat()
                except OSError:
                    LAST_FAILURE_REASON = "injection_root_unreadable"
                    return None
                kind = ("dir" if stat_module.S_ISDIR(stat.st_mode)
                        else "file" if stat_module.S_ISREG(stat.st_mode)
                        else "symlink" if stat_module.S_ISLNK(stat.st_mode) else "other")
                if kind == "symlink" or kind == "other":
                    LAST_FAILURE_REASON = "injection_root_unowned_path"
                    return None
                record: dict[str, object] = {
                    "path": str(path.relative_to(root)),
                    "kind": kind,
                    "size": stat.st_size,
                    "classification": "stale_owned",
                    "contract": (
                        "configured O3K-owned test injection root; entries have "
                        "no durable reference by construction"
                    ),
                }
                if kind == "file":
                    if stat.st_size > MAX_MANAGED_FILE_BYTES:
                        LAST_FAILURE_REASON = "injection_root_file_too_large"
                        return None
                    total_bytes += stat.st_size
                    if total_bytes > MAX_MANAGED_TOTAL_BYTES:
                        LAST_FAILURE_REASON = "injection_root_total_too_large"
                        return None
                    record["sha256"] = sha256_file(path)
                entries.append(record)
                if kind == "dir":
                    walker.append(path)
    except (OSError, UnicodeError):
        LAST_FAILURE_REASON = "injection_root_unreadable"
        return None
    return {"status": "available", "entries": entries}


def collect_durable(state_root: Path) -> dict[str, object] | None:
    """Read-only sqlite3 inventory of the durable ledger with real predicates.

    The ledger lives under ``<state_root>/data`` in the testlab layout and
    directly under ``<state_root>`` in the installed layout; both are probed.
    """
    global LAST_FAILURE_REASON
    if command(("sqlite3", "--version")) is None:
        LAST_FAILURE_REASON = "tool_unavailable:sqlite3"
        return None
    database = state_root / "data" / "o3k.sqlite"
    if not database.is_file():
        database = state_root / "o3k.sqlite"
    if not database.is_file():
        LAST_FAILURE_REASON = "durable_database_missing"
        return None
    uri = f"file:{database}?mode=ro"

    def query(sql: str) -> list[tuple[str, ...]] | None:
        output = command(("sqlite3", "-separator", "|", uri, sql))
        if output is None:
            return None
        rows: list[tuple[str, ...]] = []
        for line in output.splitlines():
            if not line.strip():
                continue
            rows.append(tuple(line.split("|")))
        return rows

    # Non-terminal operations: state NOT IN ('succeeded','failed') per the
    # reconciler's terminal classification (crates/o3k-reconciler/src/lib.rs).
    operations = query(
        "SELECT id, resource_id, state, kind FROM operations "
        "WHERE state NOT IN ('succeeded','failed') ORDER BY id"
    )
    if operations is None:
        return None
    # The owning operation's state decides whether a non-terminal command row
    # is live work or journal history: the reconciler treats operation state as
    # authoritative, so a command row left non-terminal (e.g. `unknown_outcome`)
    # by an operation that reached a terminal state is durable journal evidence
    # of that boundary, not active residue.
    commands = query(
        "SELECT c.command_id, c.resource_id, c.state, o.state "
        "FROM agent_commands c LEFT JOIN operations o ON o.id = c.operation_id "
        "WHERE c.state NOT IN ('succeeded','failed') ORDER BY c.command_id"
    )
    if commands is None:
        return None
    transfers = query(
        "SELECT transfer_id, resource_id, artifact_kind, state FROM artifact_transfers "
        "WHERE state NOT IN ('committed','rejected','expired') ORDER BY transfer_id"
    )
    if transfers is None:
        return None
    resources = query(
        "SELECT id, kind, observed_state FROM resources "
        "WHERE upper(observed_state) != 'DELETED' ORDER BY id"
    )
    if resources is None:
        return None
    ports = query(
        "SELECT id, network_id, status, binding_host, binding_state "
        "FROM network_ports ORDER BY id"
    )
    if ports is None:
        return None
    allocations = query(
        "SELECT id, provider_id, consumer_id FROM placement_allocations ORDER BY id"
    )
    if allocations is None:
        return None
    overlays = query(
        "SELECT overlay_id, resource_id, state FROM image_overlay_ownership ORDER BY overlay_id"
    )
    if overlays is None:
        return None
    networks = query("SELECT id, name, status FROM network_networks ORDER BY id")
    if networks is None:
        return None
    provider_refs = query(
        "SELECT resource_id, provider_name, provider_resource_id FROM provider_refs "
        "ORDER BY resource_id, provider_name"
    )
    if provider_refs is None:
        return None
    retry_count = query("SELECT COUNT(*) FROM operation_retry_state")
    if retry_count is None:
        return None
    image_rows = query("SELECT id FROM image_metadata ORDER BY id")
    if image_rows is None:
        return None
    image_ids = [row[0] for row in image_rows]
    desired = query(
        "SELECT id, desired_state FROM resources "
        "WHERE kind = 'compute_instance' AND upper(observed_state) != 'DELETED' "
        "ORDER BY id"
    )
    if desired is None:
        return None

    live_resources = {row[0] for row in resources}
    provider_domains: dict[str, str] = {}
    for row in provider_refs:
        provider_domains.setdefault(row[2], row[0])

    # Map port_id -> resource_id by parsing create-intent JSON embedded in
    # desired_state of live compute_instance rows.
    port_resources: dict[str, str] = {}
    for row in desired:
        try:
            intent = json.loads(row[1])
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(intent, dict):
            continue
        attachments = intent.get("network_attachments")
        if not isinstance(attachments, list):
            continue
        for attachment in attachments:
            if isinstance(attachment, dict) and isinstance(
                attachment.get("port_id"), str
            ):
                port_resources.setdefault(attachment["port_id"], row[0])

    operation_entries = []
    for row in operations:
        resource_id = row[1]
        state = row[2]
        kind = row[3] if len(row) > 3 else "unknown"
        operation_entries.append({
            "id": row[0],
            "resource_id": resource_id,
            "kind": kind,
            "state": state,
            "classification": (
                "active_owned" if resource_id in live_resources else "inconsistent"
            ),
            "contract": "crates/o3k-reconciler/src/lib.rs terminal states: succeeded, failed",
        })
    command_entries = []
    for row in commands:
        resource_id = row[1]
        operation_state = row[3] if len(row) > 3 else None
        if operation_state in {"succeeded", "failed"}:
            classification = "expected_retained"
            contract = (
                "crates/o3k-reconciler/src/lib.rs operation state is authoritative; "
                "a command row left non-terminal by a terminal operation is journal "
                "evidence of an UnknownOutcome observation (documented follow-up)"
            )
        else:
            classification = (
                "active_owned" if resource_id in live_resources else "inconsistent"
            )
            contract = (
                "crates/o3k-reconciler/src/lib.rs terminal states: succeeded, failed"
            )
        command_entries.append({
            "id": row[0],
            "resource_id": resource_id,
            "state": row[2],
            "operation_state": operation_state,
            "classification": classification,
            "contract": contract,
        })
    transfer_entries = []
    for row in transfers:
        transfer_entries.append({
            "id": row[0],
            "resource_id": row[1],
            "artifact_kind": row[2],
            "state": row[3],
            "classification": (
                "active_owned" if row[1] in live_resources else "inconsistent"
            ),
            "contract": "crates/o3k-store/src/artifact_transfer.rs is_terminal: committed, rejected, expired",
        })
    resource_entries = []
    for row in resources:
        resource_entries.append({
            "id": row[0],
            "kind": row[1],
            "observed_state": row[2],
            "classification": "active_owned",
            "contract": "crates/o3k-domain/src/lib.rs ServerState::Deleted is the only terminal state",
        })
    port_entries = []
    for row in ports:
        port_id = row[0]
        bound = bool(row[4]) and row[4].lower() != "unbound"
        instance = port_resources.get(port_id)
        if bound and instance is None:
            classification = "inconsistent"
            contract = "crates/o3k-compute/src/lib.rs port binding for an absent instance"
        elif instance is not None:
            classification = "active_owned"
            contract = "crates/o3k-store/src/lib.rs bound port of a live instance"
        else:
            classification = "expected_retained"
            contract = "crates/o3k-compute/src/lib.rs ports are reusable after terminal delete"
        port_entries.append({
            "id": port_id,
            "network_id": row[1],
            "status": row[2],
            "binding_host": row[3] or None,
            "binding_state": row[4] or None,
            "classification": classification,
            "contract": contract,
        })
    allocation_entries = []
    for row in allocations:
        consumer = row[2]
        allocation_entries.append({
            "id": row[0],
            "provider_id": row[1],
            "consumer_id": consumer,
            "classification": (
                "active_owned" if consumer in live_resources else "inconsistent"
            ),
            "contract": "crates/o3k-compute/src/lib.rs release_placement_allocation on delete",
        })
    overlay_entries = []
    for row in overlays:
        state = row[2]
        terminal = state == "deleted"
        if terminal:
            classification = "expected_retained"
        elif row[1] in live_resources:
            classification = "active_owned"
        else:
            classification = "inconsistent"
        overlay_entries.append({
            "id": row[0],
            "resource_id": row[1],
            "state": state,
            "classification": classification,
            "contract": "crates/o3k-store/src/lib.rs ImageOverlayState::is_terminal: deleted only",
        })
    network_entries = []
    for row in networks:
        network_entries.append({
            "id": row[0],
            "name": row[1],
            "status": row[2],
            "classification": "active_owned",
            "contract": "crates/o3k-store/migrations/0016_network_metadata.sql network_networks",
        })

    return {
        "status": "available",
        "operations": {"count": len(operation_entries), "entries": operation_entries},
        "agent_commands": {"count": len(command_entries), "entries": command_entries},
        "artifact_transfers": {"count": len(transfer_entries), "entries": transfer_entries},
        "resources": {"count": len(resource_entries), "entries": resource_entries},
        "network_ports": {"count": len(port_entries), "entries": port_entries},
        "placement_allocations": {
            "count": len(allocation_entries),
            "entries": allocation_entries,
        },
        "image_overlay_ownership": {
            "count": len(overlay_entries),
            "entries": overlay_entries,
        },
        "network_networks": {"count": len(network_entries), "entries": network_entries},
        "provider_refs": {"count": len(provider_refs)},
        "operation_retry_state": {"count": int(retry_count[0][0])},
        "image_metadata": {"count": len(image_ids), "entries": image_ids},
        "live_resources": sorted(live_resources),
        "port_resources": port_resources,
        "provider_domains": provider_domains,
    }


def collect_dhcp(state_root: Path, durable: dict[str, object] | None) -> dict[str, object] | None:
    """Classify dnsmasq processes and parse the managed lease/binding state."""
    global LAST_FAILURE_REASON
    dhcp_dir = state_root / "data" / "dhcp"
    owned: list[dict[str, object]] = []
    foreign_cmdlines: list[str] = []
    procdir = Path("/proc")
    if procdir.is_dir():
        for entry in procdir.iterdir():
            if not entry.name.isdigit():
                continue
            cmdline_path = entry / "cmdline"
            try:
                raw = cmdline_path.read_bytes().replace(b"\x00", b" ")
            except OSError:
                continue
            try:
                cmdline = raw.decode("utf-8", errors="replace").strip()
            except UnicodeError:
                continue
            if "dnsmasq" not in cmdline:
                continue
            if str(dhcp_dir) in cmdline:
                owned.append({
                    "pid": entry.name,
                    "args_sha256": sha256_bytes(cmdline.encode("utf-8")),
                    "classification": "active_owned",
                    "contract": "crates/o3k-dhcp/src/lib.rs DnsmasqSupervisor; stopped when the last binding is removed",
                })
            else:
                foreign_cmdlines.append(cmdline)
    else:
        pgrep = command(("pgrep", "-a", "dnsmasq"))
        if pgrep is None:
            LAST_FAILURE_REASON = "dhcp_process_scan_unavailable"
            return None
        for line in pgrep.splitlines():
            if str(dhcp_dir) in line:
                fields = line.split(None, 1)
                owned.append({
                    "pid": fields[0] if fields else "unknown",
                    "args_sha256": sha256_bytes(line.encode("utf-8")),
                    "classification": "active_owned",
                    "contract": "crates/o3k-dhcp/src/lib.rs DnsmasqSupervisor; stopped when the last binding is removed",
                })
            else:
                foreign_cmdlines.append(line)

    leases: list[dict[str, object]] = []
    lease_path = dhcp_dir / "dnsmasq.leases"
    if lease_path.is_file():
        try:
            lease_text = lease_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            LAST_FAILURE_REASON = "dhcp_leases_unreadable"
            return None
        for line in lease_text.splitlines():
            fields = line.split()
            if len(fields) < 3:
                continue
            leases.append({
                "expires_at_unix": fields[0],
                "mac": fields[1],
                "ip": fields[2],
                "classification": "expected_retained",
                "contract": "crates/o3k-dhcp/src/lib.rs managed lease file: dnsmasq runtime records with natural expiry",
            })

    bindings: list[dict[str, object]] = []
    state_path = dhcp_dir / "state.json"
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            LAST_FAILURE_REASON = "dhcp_state_corrupt"
            return None
        raw_bindings = state.get("bindings", {}) if isinstance(state, dict) else {}
        if not isinstance(raw_bindings, dict):
            LAST_FAILURE_REASON = "dhcp_state_corrupt"
            return None
        live_ports = set()
        port_resources: dict[str, str] = {}
        if isinstance(durable, dict):
            for entry in durable.get("network_ports", {}).get("entries", []):
                if entry.get("classification") == "active_owned":
                    live_ports.add(entry["id"])
            port_resources = durable.get("port_resources", {})
        for port_id, value in sorted(raw_bindings.items()):
            mac = ""
            ip = ""
            if isinstance(value, dict):
                mac = str(value.get("mac", ""))
                ip = str(value.get("address", ""))
            has_live_instance = (
                port_id in live_ports or port_id in port_resources
            )
            bindings.append({
                "port_id": port_id,
                "mac": mac,
                "ip": ip,
                "classification": (
                    "active_owned" if has_live_instance else "inconsistent"
                ),
                "contract": "bins/o3k-compute/src/main.rs DhcpRuntime::remove_ports removes bindings on delete",
            })

    pidfiles: list[str] = []
    if dhcp_dir.is_dir():
        for path in sorted(dhcp_dir.glob("dnsmasq-*.pid")):
            pidfiles.append(path.name)

    return {
        "status": "available",
        "processes": {
            "owned": owned,
            "foreign_count": len(foreign_cmdlines),
            "foreign_args_sha256": sha256_bytes(
                "\n".join(sorted(foreign_cmdlines)).encode("utf-8")
            ),
        },
        "leases": leases,
        "bindings": bindings,
        "pidfiles": pidfiles,
    }


def collect_processes(state_root: Path | None) -> dict[str, object] | None:
    """Verify pidfiles against /proc and detect unmanaged O3K daemons."""
    global LAST_FAILURE_REASON
    pid_root_raw = os.environ.get("O3K_REAL_HOST_PID_ROOT")
    if pid_root_raw is None:
        return {"status": "not_checked"}
    pid_root = Path(pid_root_raw)
    if not pid_root.is_dir():
        LAST_FAILURE_REASON = "pid_root_missing"
        return None
    daemons: list[dict[str, object]] = []
    try:
        pidfiles = sorted(pid_root.glob("*.pid"))
    except OSError:
        LAST_FAILURE_REASON = "pid_root_unreadable"
        return None
    verified: set[str] = set()
    for pidfile in pidfiles:
        try:
            content = pidfile.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            LAST_FAILURE_REASON = "pidfile_unreadable"
            return None
        fields = content.split("|")
        if len(fields) != 4:
            LAST_FAILURE_REASON = "pidfile_malformed"
            return None
        pid, start_ticks, uid, binary = (field.strip() for field in fields)
        record: dict[str, object] = {
            "daemon": pidfile.stem,
            "pid": pid,
            "start_ticks": start_ticks,
            "uid": uid,
            "binary": binary,
            "verified": False,
            "classification": "stale_owned",
            "contract": "bins/o3kd pidfiles: pid|start_ticks|uid|binary; a pidfile whose process is gone is stale residue",
        }
        proc_dir = Path("/proc") / pid
        if proc_dir.is_dir():
            try:
                stat_fields = proc_dir.joinpath("stat").read_text(
                    encoding="utf-8", errors="replace"
                ).rsplit(")", 1)[-1].split()
                actual_ticks = stat_fields[19] if len(stat_fields) > 19 else None
                actual_uid = os.stat(proc_dir).st_uid
                exe = os.readlink(proc_dir / "exe")
            except (OSError, UnicodeError):
                exe = ""
                actual_ticks = None
                actual_uid = None
            uid_ok = False
            if uid.isdigit():
                uid_ok = actual_uid is not None and int(uid) == actual_uid
            else:
                try:
                    import pwd
                    uid_ok = actual_uid is not None and pwd.getpwnam(uid).pw_uid == actual_uid
                except (ImportError, KeyError):
                    uid_ok = False
            expected = binary if binary.startswith("/") else None
            if expected is None and state_root is not None:
                expected = str(state_root / "bin" / binary)
            exe_ok = False
            if exe and expected:
                exe_ok = exe == expected or exe.endswith(expected)
            elif exe and not expected:
                exe_ok = os.path.basename(exe) in DAEMON_BINARIES
            if actual_ticks == start_ticks and uid_ok and exe_ok:
                record["verified"] = True
                record["classification"] = "active_owned"
                record["contract"] = "bins/o3kd pidfiles verified against /proc"
                verified.add(pid)
        daemons.append(record)

    unmanaged: list[dict[str, object]] = []
    if state_root is not None:
        bin_dir = state_root / "bin"
        procdir = Path("/proc")
        if procdir.is_dir():
            for entry in procdir.iterdir():
                if not entry.name.isdigit():
                    continue
                if entry.name in verified:
                    continue
                try:
                    exe = os.readlink(entry / "exe")
                except OSError:
                    continue
                try:
                    exe_path = Path(exe)
                    if bin_dir in exe_path.parents or str(exe).startswith(str(bin_dir)):
                        binary = exe_path.name
                        if binary in DAEMON_BINARIES:
                            unmanaged.append({
                                "pid": entry.name,
                                "binary": binary,
                                "classification": "inconsistent",
                                "contract": "state-root daemon without a matching pidfile is a potential leak",
                            })
                except (ValueError, OSError):
                    continue
    return {
        "status": "available",
        "daemons": daemons,
        "unmanaged": unmanaged,
    }


def collect_canaries() -> dict[str, object] | None:
    """Record identity-level state for operator-configured foreign canaries."""
    global LAST_FAILURE_REASON
    config_raw = os.environ.get("O3K_REAL_HOST_CANARIES")
    if config_raw is None:
        return {"status": "not_checked"}
    config_path = Path(config_raw)
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        LAST_FAILURE_REASON = "canary_config_unreadable"
        return None
    if not isinstance(config, dict):
        LAST_FAILURE_REASON = "canary_config_invalid"
        return None
    domains = config.get("libvirt_domains", [])
    links = config.get("network_links", [])
    files = config.get("files", [])
    if not isinstance(domains, list) or not isinstance(links, list) or not isinstance(
        files, list
    ):
        LAST_FAILURE_REASON = "canary_config_invalid"
        return None
    for name in domains + links:
        if not isinstance(name, str) or SAFE_ID.fullmatch(name) is None:
            LAST_FAILURE_REASON = "canary_config_invalid"
            return None
    for file_canary in files:
        if (
            not isinstance(file_canary, dict)
            or not isinstance(file_canary.get("path"), str)
            or not file_canary["path"].startswith("/")
            or not isinstance(file_canary.get("sha256"), str)
            or len(file_canary["sha256"]) != 64
        ):
            LAST_FAILURE_REASON = "canary_config_invalid"
            return None

    domain_records = []
    for name in domains:
        output = command(("virsh", "-c", "qemu:///system", "dumpxml", name))
        if output is None:
            # Distinguish a missing domain (valid `present: false`) from an
            # unrelated failure (fail closed).
            if LAST_FAILURE_REASON.startswith("command_failed:virsh"):
                domain_records.append({
                    "name": name,
                    "present": False,
                    "classification": "foreign",
                })
                continue
            return None
        match = re.search(r"<uuid>([0-9a-fA-F-]+)</uuid>", output)
        domain_records.append({
            "name": name,
            "present": True,
            "uuid": match.group(1) if match else None,
            "xml_sha256": sha256_bytes(output.encode("utf-8")),
            "classification": "foreign",
        })
    link_records = []
    for name in links:
        link_output = command(("ip", "-j", "link", "show", name))
        addr_output = command(("ip", "-j", "addr", "show", name))
        if link_output is None or addr_output is None:
            if LAST_FAILURE_REASON.startswith("command_failed:ip"):
                link_records.append({
                    "name": name,
                    "present": False,
                    "classification": "foreign",
                })
                continue
            return None
        try:
            link_json = json.loads(link_output)
            addr_json = json.loads(addr_output)
        except json.JSONDecodeError:
            LAST_FAILURE_REASON = "canary_link_output_invalid"
            return None
        link_kind = None
        if isinstance(link_json, list) and link_json and isinstance(link_json[0], dict):
            link_kind = link_json[0].get("link_type") or link_json[0].get("type")
        addresses_digest = sha256_bytes(
            json.dumps(addr_json, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        link_records.append({
            "name": name,
            "present": True,
            "kind": link_kind,
            "addresses_sha256": addresses_digest,
            "classification": "foreign",
        })
    file_records = []
    for file_canary in files:
        path = Path(file_canary["path"])
        if not path.is_file():
            file_records.append({
                "path": file_canary["path"],
                "present": False,
                "classification": "foreign",
            })
            continue
        try:
            if path.stat().st_size > MAX_CANARY_FILE_BYTES:
                LAST_FAILURE_REASON = "canary_file_too_large"
                return None
            content_hash = sha256_file(path)
        except OSError:
            LAST_FAILURE_REASON = "canary_file_unreadable"
            return None
        if content_hash is None:
            return None
        file_records.append({
            "path": file_canary["path"],
            "present": True,
            "sha256": content_hash,
            "classification": "foreign",
        })
    return {
        "status": "available",
        "config_sha256": sha256_bytes(
            json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ),
        "libvirt_domains": domain_records,
        "network_links": link_records,
        "files": file_records,
    }


def classify_managed_entries(
    entries: list[dict[str, object]],
    durable: dict[str, object] | None,
) -> None:
    """Assign classifications to managed-state entries in place."""
    live_resources: set[str] = set()
    image_rows: set[str] = set()
    transfer_states: dict[str, str] = {}
    if isinstance(durable, dict):
        live_resources = set(durable.get("live_resources", []))
        image_rows = set(durable.get("image_metadata", {}).get("entries", []))
        for entry in durable.get("artifact_transfers", {}).get("entries", []):
            transfer_states[entry["id"]] = entry["state"]

    def instance_live(instance_id: str) -> bool:
        return instance_id in live_resources

    for entry in entries:
        path = str(entry.get("path", ""))
        name = Path(path).name
        kind = str(entry.get("kind", "file"))
        if kind != "file" and kind != "dir":
            entry["classification"] = "inconsistent"
            entry["contract"] = "unexpected managed-state entry kind"
            continue
        if path.startswith("config-drive/"):
            # Applies to the per-instance directory, ISO, and ISO ownership
            # manifest alike (instance id is the first path component).
            instance_id = name.split(".", 1)[0]
            if instance_live(instance_id):
                entry["classification"] = "active_owned"
                entry["contract"] = "crates/o3k-config-drive/src/lib.rs per-instance store"
            else:
                entry["classification"] = "stale_owned"
                entry["contract"] = (
                    "crates/o3k-config-drive/src/lib.rs ConfigDriveStore::cleanup is the "
                    "intended reaper; no delete path invokes it (observed contract gap)"
                )
            continue
        if kind == "dir":
            if any(pattern.fullmatch(name) for pattern in TEMP_NAME_PATTERNS):
                entry["classification"] = "stale_owned"
                entry["contract"] = "crates/o3k-config-drive/src/lib.rs publication temporary directory"
            else:
                entry["classification"] = "expected_retained"
                entry["contract"] = "managed-state store root"
            continue
        elif path.startswith("image-cache/base/"):
            entry["classification"] = "expected_retained"
            entry["contract"] = "crates/o3k-image/src/lib.rs content-addressed base cache (resolve_base); ADR-0062/0147"
        elif path.startswith("image-cache/overlays/"):
            instance_id = name.split(".", 1)[0]
            if instance_live(instance_id):
                entry["classification"] = "active_owned"
                entry["contract"] = "crates/o3k-image/src/lib.rs overlay of a live instance"
            else:
                entry["classification"] = "stale_owned"
                entry["contract"] = "crates/o3k-image/src/lib.rs delete_overlay reaps instance overlays"
        elif path.startswith("image-cache/ownership/"):
            instance_id = name.split(".", 1)[0]
            if instance_live(instance_id):
                entry["classification"] = "active_owned"
                entry["contract"] = "crates/o3k-compute-agent/src/image.rs ownership manifest of a live instance"
            else:
                entry["classification"] = "stale_owned"
                entry["contract"] = "crates/o3k-compute-agent/src/image.rs delete_instance removes the manifest"
        elif path.startswith("images/content/"):
            image_id = name
            if image_id in image_rows:
                entry["classification"] = "expected_retained"
                entry["contract"] = "crates/o3k-image/src/lib.rs committed content store; ImageContentStore::delete reaps on image delete"
            else:
                entry["classification"] = "stale_owned"
                entry["contract"] = "crates/o3k-image/src/lib.rs committed content without an image_metadata row"
        elif path.startswith("agent-id.artifacts/"):
            if kind == "dir":
                entry["classification"] = "expected_retained"
                entry["contract"] = "crates/o3k-compute-agent/src/artifact.rs artifact store root"
            elif name.startswith(".") and name.endswith(".manifest"):
                manifest_state = entry.get("parsed_manifest")
                resource_id = None
                artifact_kind = None
                if isinstance(manifest_state, dict):
                    offer = manifest_state.get("offer")
                    if isinstance(offer, dict):
                        resource_id = offer.get("resource_id")
                        # proto ArtifactKind: 1 = image_base, 2 = config_drive_iso.
                        raw_kind = offer.get("kind")
                        if isinstance(raw_kind, int):
                            artifact_kind = {1: "image_base", 2: "config_drive_iso"}.get(
                                raw_kind
                            )
                if (
                    artifact_kind == "config_drive_iso"
                    and resource_id is not None
                    and not instance_live(resource_id)
                ):
                    entry["classification"] = "stale_owned"
                    entry["contract"] = "crates/o3k-compute-agent/src/artifact.rs cleanup_config_drive_for_resource reaps config-drive manifests on delete"
                else:
                    entry["classification"] = "expected_retained"
                    entry["contract"] = "crates/o3k-compute-agent/src/artifact.rs committed manifest history"
            elif name.startswith(".") and name.endswith(".part"):
                transfer_id = name[1:-5]
                state = transfer_states.get(transfer_id)
                if state is not None and state in ("offered", "receiving"):
                    entry["classification"] = "expected_retained"
                    entry["contract"] = "crates/o3k-compute-agent/src/artifact.rs in-flight transfer part"
                else:
                    entry["classification"] = "stale_owned"
                    entry["contract"] = "crates/o3k-compute-agent/src/artifact.rs orphan transfer part (incomplete transfer temp)"
            else:
                entry["classification"] = "expected_retained"
                entry["contract"] = "crates/o3k-compute-agent/src/artifact.rs content-addressed committed artifact"
        elif path in ("agent-id", "agent-id.commands", "agent-id.state"):
            entry["classification"] = "expected_retained"
            entry["contract"] = "crates/o3k-compute-agent/src/lib.rs identity and durable command journal"
        elif path == "network/ownership.json":
            entry["classification"] = "expected_retained"
            entry["contract"] = "crates/o3k-network/src/lib.rs durable host-network ownership manifest"
        elif path.startswith("network/"):
            entry["classification"] = "expected_retained"
            entry["contract"] = "crates/o3k-network/src/lib.rs network manager state"
        elif path.startswith("dhcp/"):
            entry["classification"] = "expected_retained"
            entry["contract"] = "crates/o3k-dhcp/src/lib.rs durable DHCP configuration and runtime files"
        elif path.startswith("placement/"):
            if name in ("placement.json", "allocation-intents.json") or name.endswith(
                ".imported"
            ):
                entry["classification"] = "expected_retained"
                entry["contract"] = "crates/o3k-placement/src/lib.rs placement journal files"
            else:
                entry["classification"] = "stale_owned"
                entry["contract"] = "crates/o3k-placement/src/lib.rs unexpected placement directory entry"
        elif path.startswith("console/"):
            instance_id = name.split(".", 1)[0]
            if instance_live(instance_id):
                entry["classification"] = "active_owned"
                entry["contract"] = "crates/o3k-api/src/compute.rs console of a live instance"
            else:
                entry["classification"] = "stale_owned"
                entry["contract"] = "crates/o3k-api/src/compute.rs delete_server console.cleanup"
        else:
            entry["classification"] = "stale_owned"
            entry["contract"] = "unclassified managed-state entry"


def snapshot() -> dict[str, object] | None:
    global LAST_FAILURE_REASON
    domain_output = command(("virsh", "-c", "qemu:///system", "list", "--all", "--name"))
    link_output = command(("ip", "-o", "link", "show"))
    if domain_output is None or link_output is None:
        return None

    domains: list[str] = []
    foreign_domains: list[str] = []
    for value in (line.strip() for line in domain_output.splitlines() if line.strip()):
        if value.startswith("o3k-"):
            if SAFE_ID.fullmatch(value) is None:
                return None
            domains.append(value)
        else:
            foreign_domains.append(value)

    openstack_requested = os.environ.get("O3K_REAL_HOST_OPENSTACK_INVENTORY", "false") == "true"
    openstack_status = "not_checked"
    resources: dict[str, list[str]] = {}
    if openstack_requested and not os.environ.get("OS_PASSWORD"):
        # A protected run that requests provider inventory must not silently
        # turn missing credentials into an empty, apparently clean snapshot.
        return None
    if openstack_requested:
        openstack_status = "available"
        for resource in RESOURCES:
            output = command(("openstack", *RESOURCE_COMMANDS[resource]), scrub_provider_config=True)
            if output is None and resource in DIRECT_COLLECTIONS:
                primary_failure = LAST_FAILURE_REASON
                output = direct_collection(resource)
                if output is None:
                    LAST_FAILURE_REASON = primary_failure
            if output is None:
                return None
            values = named_resource_ids(resource, output)
            if values is None:
                return None
            resources[resource] = values
    else:
        resources = {resource: [] for resource in RESOURCES}

    network_links, foreign_links = classify_link_lines(link_output)
    if not network_links and any(
        line.strip()
        and line.split(":", 2)[1].strip().split("@", 1)[0].startswith(
            ("o3k-", "o3ktap-", "o3ktmp-", "o3kbm-")
        )
        for line in link_output.splitlines()
        if len(line.split(":", 2)) > 1
    ):
        return None

    protected_paths = protected_paths_digest()
    if protected_paths is None:
        return None

    pool_result = collect_pools(
        Path(os.environ.get("O3K_P15_7_LIBVIRT_IMAGE_ROOT", "/var/lib/libvirt/images"))
    )
    if pool_result is None:
        return None

    document: dict[str, object] = {
        "schema_version": 2,
        "status": "available",
        "redacted": True,
        "domains": sorted(set(domains)),
        "pools": pool_result["pools"],
        "network_links": network_links,
        "openstack": {"status": openstack_status, "resources": resources},
        "foreign_state": {
            "domains_sha256": digest(foreign_domains),
            "network_links_sha256": digest(foreign_links),
            "protected_paths_sha256": protected_paths,
            "pools_count": pool_result["foreign_count"],
        },
    }

    extended = any(os.environ.get(env) is not None for env in EXTENDED_ENVS)
    if not extended:
        return document

    state_root_raw = os.environ.get("O3K_REAL_HOST_STATE_ROOT")
    state_root = Path(state_root_raw) if state_root_raw else None
    if state_root is not None:
        managed_state = collect_managed_state(state_root)
        if managed_state is None:
            return None
        if managed_state.get("status") == "available":
            durable = collect_durable(state_root)
            if durable is None:
                return None
            dhcp = collect_dhcp(state_root, durable)
            if dhcp is None:
                return None
        else:
            # A missing configured root records `managed_state.status:
            # "absent"` as valid clean state (pre-bootstrap or post-cleanup
            # host); every other state-root-backed source is absent with the
            # same reason instead of being queried against a nonexistent
            # root. An EXISTING but unreadable root still fails closed in
            # `collect_managed_state` (unavailable, not absent).
            durable = {"status": "absent", "reason": "state_root_missing"}
            dhcp = {"status": "absent", "reason": "state_root_missing"}
    else:
        managed_state = {"status": "not_checked"}
        durable = None
        dhcp = None

    if isinstance(managed_state, dict) and managed_state.get("status") == "available":
        classify_managed_entries(
            managed_state["entries"], durable  # type: ignore[arg-type]
        )
        manifest_map: dict[str, object] = {}
        for entry in managed_state["entries"]:
            parsed = entry.pop("parsed_manifest", None)
            if parsed is not None:
                manifest_map[str(entry["path"])] = parsed
        managed_state["ownership_manifests"] = manifest_map

    processes = collect_processes(state_root)
    if processes is None:
        return None
    canaries = collect_canaries()
    if canaries is None:
        return None
    injection = collect_injection_root()
    if injection is None:
        return None

    durable_checked = isinstance(durable, dict) and durable.get("status") == "available"
    domain_classifications = classify_domains(
        sorted(set(domains)),
        dict(durable.get("provider_domains", {})) if isinstance(durable, dict) else {},
        set(durable.get("live_resources", [])) if isinstance(durable, dict) else set(),
        durable_checked,
    )

    ownership_taps: dict[str, dict[str, object]] = {}
    ownership_bridge: str | None = None
    ownership_manifest = None
    if isinstance(managed_state, dict) and isinstance(
        managed_state.get("ownership_manifests"), dict
    ):
        ownership_manifest = managed_state["ownership_manifests"].get("network/ownership.json")
    if isinstance(ownership_manifest, dict):
        taps = ownership_manifest.get("taps")
        if isinstance(taps, dict):
            for interface, record in taps.items():
                if isinstance(record, dict):
                    ownership_taps[str(interface)] = record
        bridge = ownership_manifest.get("bridge")
        if isinstance(bridge, dict) and isinstance(bridge.get("name"), str):
            ownership_bridge = bridge["name"]
    link_classifications = classify_links(
        network_links,
        ownership_taps,
        ownership_bridge,
        set(durable.get("live_resources", [])) if isinstance(durable, dict) else set(),
        {entry["id"] for entry in durable.get("network_networks", {}).get("entries", [])}
        if isinstance(durable, dict)
        else set(),
        durable_checked,
    )

    document["schema_version"] = 3
    document["managed_state"] = managed_state
    document["durable"] = durable if isinstance(durable, dict) else {"status": "not_checked"}
    document["dhcp"] = dhcp if isinstance(dhcp, dict) else {"status": "not_checked"}
    document["processes"] = processes
    document["canaries"] = canaries
    document["injection_root"] = injection
    document["domain_classifications"] = domain_classifications
    document["link_classifications"] = link_classifications
    document["classification"] = classification_summary(document)
    document = redact_value(document)
    return document


def write_atomic(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, indent=2, sort_keys=True)
            output.write("\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} OUTPUT_JSON", file=sys.stderr)
        return 2
    output = Path(sys.argv[1])
    previous: str | None = None
    for _attempt in range(3):
        current = snapshot()
        if current is None:
            write_atomic(output, {"status": "unavailable", "reason": LAST_FAILURE_REASON, "redacted": True})
            return 1
        canonical = json.dumps(current, sort_keys=True, separators=(",", ":"))
        if previous == canonical:
            write_atomic(output, current)
            return 0
        previous = canonical
    write_atomic(output, {"status": "unavailable", "reason": "inventory_not_stable", "redacted": True})
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
