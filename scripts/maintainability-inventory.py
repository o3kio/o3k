#!/usr/bin/env python3
"""Generate a deterministic maintainability report for the current workspace.

The committed P13.4 files are immutable historical evidence.  This script
reports the architecture that is actually present at the checkout it inspects;
it does not update that historical baseline.
"""

import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "target" / "generated-maintainability"
DOCS_DIR = REPO_ROOT / "docs" / "maintainability"


def repository_relative_path(value):
    """Return a stable repository-relative path for metadata path fields."""
    path = Path(value)
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return str(value)


def repository_relative_member_id(value):
    """Normalize Cargo path member IDs without changing package identity."""
    prefix = "path+file://"
    if not value.startswith(prefix):
        return value
    path_and_version = value[len(prefix):]
    path, separator, version = path_and_version.partition("#")
    relative = repository_relative_path(path)
    normalized = f"{prefix}./{relative}"
    return f"{normalized}{separator}{version}" if separator else normalized


def run(cmd, cwd=None):
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd or REPO_ROOT)
    if result.returncode != 0:
        print(f"WARNING: command {' '.join(cmd)} failed: {result.stderr[:200]}", file=sys.stderr)
    return result.stdout, result.stderr, result.returncode


def get_git_sha():
    stdout, _, _ = run(["git", "rev-parse", "HEAD"])
    return stdout.strip()


def get_branch():
    stdout, _, _ = run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    return stdout.strip()


from rust_source_scope import classify_rust_lines, is_dedicated_test_file

def safety_occurrences(path, lines):
    """Return production safety occurrences for one Rust source file."""
    occurrences = {
        "production_unwrap": [],
        "production_expect": [],
        "production_panic": [],
        "production_allow_overrides": [],
    }
    test_lines = classify_rust_lines(
        lines, dedicated_test=is_dedicated_test_file(path)
    )
    for i, (line, is_test) in enumerate(zip(lines, test_lines), 1):
        stripped = line.strip()
        if is_test:
            continue
        if "unwrap()" in stripped and not stripped.startswith("//"):
            if not any(
                skip in stripped
                for skip in [".lock().unwrap()", ".write().unwrap()", ".read().unwrap()"]
            ):
                occurrences["production_unwrap"].append(
                    {"path": path, "line": i, "content": stripped[:120]}
                )
        if ".expect(" in stripped and not stripped.startswith("//"):
            occurrences["production_expect"].append(
                {"path": path, "line": i, "content": stripped[:120]}
            )
        if "panic!(" in stripped and not stripped.startswith("//") and "// " not in stripped:
            occurrences["production_panic"].append(
                {"path": path, "line": i, "content": stripped[:120]}
            )
        if "#[allow(" in stripped and not stripped.startswith("//"):
            occurrences["production_allow_overrides"].append(
                {"path": path, "line": i, "content": stripped[:120]}
            )
    return occurrences


# ─── 1. Workspace inventory ───

def inventory_workspace():
    """Collect every crate, binary, and Rust source file."""
    stdout, _, _ = run(["cargo", "metadata", "--no-deps", "--format-version", "1"])
    metadata = json.loads(stdout)

    packages = {}
    for pkg in sorted(metadata["packages"], key=lambda item: item["name"]):
        packages[pkg["name"]] = {
            "name": pkg["name"],
            "version": pkg["version"],
            "manifest_path": repository_relative_path(pkg["manifest_path"]),
            "targets": [],
        }
        for tgt in sorted(pkg["targets"], key=lambda item: (item["name"], item["kind"])):
            kinds = tgt["kind"]
            packages[pkg["name"]]["targets"].append({
                "name": tgt["name"],
                "kind": kinds,
                "src_path": repository_relative_path(tgt["src_path"]),
            })

    # Walk all Rust source files
    source_files = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs.sort()
        files.sort()
        # Skip generated/metadata dirs
        rel = Path(root).relative_to(REPO_ROOT)
        parts = rel.parts
        if any(p in (".git", "target", "node_modules") for p in parts):
            continue
        for f in files:
            if f.endswith(".rs"):
                path = Path(root) / f
                try:
                    stat = path.stat()
                    lines = path.read_text().splitlines()
                except Exception:
                    continue
                test_lines = classify_rust_lines(
                    lines,
                    dedicated_test=is_dedicated_test_file(
                        str(path.relative_to(REPO_ROOT))
                    ),
                )
                prod_loc = sum(
                    bool(line.strip()) and not line.strip().startswith("//")
                    for line, is_test in zip(lines, test_lines)
                    if not is_test
                )
                test_loc = sum(
                    bool(line.strip()) and not line.strip().startswith("//")
                    for line, is_test in zip(lines, test_lines)
                    if is_test
                )
                source_files.append({
                    "path": str(path.relative_to(REPO_ROOT)),
                    "byte_size": stat.st_size,
                    "line_count": len(lines),
                    "prod_loc_approx": prod_loc,
                    "test_loc_approx": test_loc,
                })
    source_files.sort(key=lambda item: item["path"])

    # Classify by crate
    crate_to_sources = defaultdict(list)
    for sf in source_files:
        p = REPO_ROOT / sf["path"]
        # Determine which crate it belongs to
        crate = None
        for pkg_name, info in packages.items():
            manifest = Path(info["manifest_path"]).parent
            if not manifest.is_absolute():
                manifest = REPO_ROOT / manifest
            try:
                p.relative_to(manifest)
                crate = pkg_name
                break
            except ValueError:
                continue
        if crate:
            crate_to_sources[crate].append(sf)
    for sources in crate_to_sources.values():
        sources.sort(key=lambda item: item["path"])

    # Find examples, tests, migrations
    examples = list((REPO_ROOT / "examples").glob("**/*"))
    migration_dirs = list((REPO_ROOT / "crates").glob("**/migrations/*"))

    return {
        "git_sha": get_git_sha(),
        "branch": get_branch(),
        "workspace_root": repository_relative_path(metadata["workspace_root"]),
        "packages": packages,
        "workspace_members": sorted(
            repository_relative_member_id(member) for member in metadata["workspace_members"]
        ),
        "source_files": {
            "total_count": len(source_files),
            "total_lines": sum(sf["line_count"] for sf in source_files),
            "total_bytes": sum(sf["byte_size"] for sf in source_files),
            "total_prod_loc": sum(sf["prod_loc_approx"] for sf in source_files),
            "total_test_loc": sum(sf["test_loc_approx"] for sf in source_files),
        },
        "files_by_crate": {k: len(crate_to_sources[k]) for k in sorted(crate_to_sources)},
        "crate_to_sources": {k: crate_to_sources[k] for k in sorted(crate_to_sources)},
    }


# ─── 2. Crate dependency graph ───

def get_dependency_graph():
    """Extract workspace-internal dependency edges from cargo metadata.

    Uses the 'path' field in dependency objects to detect workspace-member
    dependencies, since the 'pkg' field may be absent in some cargo versions.
    """
    stdout, _, _ = run(["cargo", "metadata", "--format-version", "1"])
    full_meta = json.loads(stdout)
    members = set(full_meta["workspace_members"])
    pkg_map = {p["id"]: p for p in full_meta["packages"]}

    # Build a map from package name to manifest directory for path matching
    member_manifest_dirs = {}
    for pid in members:
        pkg = pkg_map.get(pid)
        if pkg:
            member_manifest_dirs[pkg["name"]] = str(Path(pkg["manifest_path"]).parent)

    edges = []
    for pkg_id in members:
        pkg = pkg_map.get(pkg_id)
        if not pkg:
            continue
        for dep in pkg.get("dependencies", []):
            dep_name = dep.get("name")
            if dep_name == pkg["name"]:
                continue
            dep_path = dep.get("path")
            if dep_path:
                # dep_path is the crate directory (e.g. /root/o3k-rust/crates/o3k-domain)
                dep_dir = str(Path(dep_path).resolve())
                for mem_name, mem_dir in member_manifest_dirs.items():
                    if mem_name == pkg["name"]:
                        continue
                    # mem_dir is the parent of the Cargo.toml (e.g. /root/o3k-rust/crates/o3k-domain)
                    if dep_dir == mem_dir:
                        edges.append({"source": pkg["name"], "target": mem_name})
                        break

    # Find non-trivial cycles using DFS
    adj = defaultdict(set)
    for e in edges:
        if e["source"] != e["target"]:
            adj[e["source"]].add(e["target"])

    cycles_found = []
    visited = set()
    path = []

    def dfs(node):
        if node in path:
            cycle_start = path.index(node)
            cycle = path[cycle_start:] + [node]
            cycles_found.append(cycle)
            return
        if node in visited:
            return
        visited.add(node)
        path.append(node)
        for neighbor in sorted(adj.get(node, set())):
            dfs(neighbor)
        path.pop()

    for node in sorted(adj):
        dfs(node)

    # Deduplicate cycles by sorted tuple
    unique_cycles = []
    seen_cycles = set()
    for c in cycles_found:
        key = tuple(sorted(c))
        if key not in seen_cycles:
            seen_cycles.add(key)
            unique_cycles.append(c)

    # Count self-edges separately
    self_edges = [e for e in edges if e["source"] == e["target"]]
    cross_edges = [e for e in edges if e["source"] != e["target"]]

    return {
        "workspace_edges": len(cross_edges),
        "self_edges": len(self_edges),
        "edges": sorted(cross_edges, key=lambda edge: (edge["source"], edge["target"])),
        "self_edge_details": sorted(self_edges, key=lambda edge: (edge["source"], edge["target"])),
        "cycles": sorted(unique_cycles, key=lambda cycle: tuple(cycle)),
    }


# ─── 3. SQL usage inventory ───

SQL_PATTERNS = [
    r"sqlx::query\b",
    r"sqlx::query_as\b",
    r"sqlx::query_scalar\b",
    r"sqlx::query!\b",
    r"sqlx::query_as!\b",
    r"sqlx::query_scalar!\b",
]

def inventory_sql():
    """Find all SQL usage call sites across the workspace."""
    results = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs.sort()
        files.sort()
        rel = Path(root).relative_to(REPO_ROOT)
        parts = rel.parts
        if any(p in (".git", "target", "node_modules") for p in parts):
            continue
        for f in files:
            if not f.endswith(".rs"):
                continue
            path = Path(root) / f
            rel_path = str(path.relative_to(REPO_ROOT))
            lines = path.read_text().splitlines()
            test_lines = classify_rust_lines(
                lines, dedicated_test=is_dedicated_test_file(rel_path)
            )
            for i, line in enumerate(lines, 1):
                for pat in SQL_PATTERNS:
                    if re.search(pat, line):
                        classification = (
                            "test/conformance"
                            if test_lines[i - 1]
                            else classify_sql_site(rel_path)
                        )
                        results.append({
                            "path": rel_path,
                            "line": i,
                            "pattern": pat,
                            "content": line.strip(),
                            "classification": classification,
                        })
                        break
    results.sort(key=lambda item: (item["path"], item["line"], item["pattern"]))
    return results


def classify_sql_site(path):
    """Classify a SQL use site."""
    if "/examples/" in path or path.startswith("examples/"):
        return "example/evidence"
    if "/migrations/" in path or path.startswith("migrations/"):
        return "migration"
    if (
        path.startswith("crates/o3k-store/src/sqlite/")
        or path.startswith("crates/o3k-store/src/postgres/")
        or path in {
            "crates/o3k-store/src/coordination.rs",
            "crates/o3k-store/src/storage.rs",
            "crates/o3k-store/src/quota.rs",
            "crates/o3k-store/src/reusable_policy.rs",
            "crates/o3k-store/src/artifact_transfer.rs",
            "crates/o3k-store/src/server_state.rs",
            "crates/o3k-store/src/conformance.rs",
        }
    ):
        return "persistence-adapter"
    if path.startswith("bins/o3k/src/upgrade/"):
        return "upgrade"
    if path == "bins/o3k/src/db.rs":
        return "diagnostic"
    if "/tests/" in path or path.startswith("tests/") or "test" in path:
        return "test/conformance"
    if "diagnostic" in path or "diagnose" in path:
        return "diagnostic"
    return "unexpected-production-location"


# ─── 4. Host command execution inventory ───

HOST_CMD_PATTERNS = [
    # Process spawning
    (r"std::process::Command::new", "std::process::Command"),
    (r"tokio::process::Command::new", "tokio::process::Command"),
    (r"(?<![A-Za-z0-9_])Command::new\b", "Command::new"),
    (r'"sh"\s*,?\s*-c\s*"', "sh -c"),
    (r'"bash"\s*,?\s*-c\s*"', "bash -c"),
    (r'"sudo"', "sudo"),
    (r'"runuser"', "runuser"),
    # Infrastructure commands
    (r'"lvs"', "lvs"),
    (r'"vgs"', "vgs"),
    (r'"pvs"', "pvs"),
    (r'"lvcreate"', "lvcreate"),
    (r'"lvremove"', "lvremove"),
    (r'"ip"', "ip"),
    (r'"bridge"', "bridge"),
    (r'"nft"', "nft"),
    (r'"virsh"', "virsh"),
    (r'"qemu-img"', "qemu-img"),
    (r'"systemctl"', "systemctl"),
    (r'"mount"', "mount"),
    (r'"umount"', "umount"),
    (r'"df"', "df"),
    (r'"ceph"', "ceph"),
    (r'"rbd"', "rbd"),
    (r'"iptables"', "iptables"),
    (r'"nsenter"', "nsenter"),
    (r'"iscsiadm"', "iscsiadm"),
    (r'"tgtd"', "tgtd"),
    (r'"tgtadm"', "tgtadm"),
    (r'"dmsetup"', "dmsetup"),
    (r'"blkid"', "blkid"),
    (r'"lsblk"', "lsblk"),
    (r'"losetup"', "losetup"),
    (r'"pvcreate"', "pvcreate"),
    (r'"vgcreate"', "vgcreate"),
    (r'"lvchange"', "lvchange"),
    (r'"thin_check"', "thin_check"),
    (r'"dd"', "dd"),
]

def inventory_host_commands():
    results = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs.sort()
        files.sort()
        rel = Path(root).relative_to(REPO_ROOT)
        parts = rel.parts
        if any(p in (".git", "target", "node_modules") for p in parts):
            continue
        for f in files:
            if not f.endswith(".rs"):
                continue
            path = Path(root) / f
            rel_path = str(path.relative_to(REPO_ROOT))
            lines = path.read_text().splitlines()
            test_lines = classify_rust_lines(
                lines, dedicated_test=is_dedicated_test_file(rel_path)
            )
            for i, line in enumerate(lines, 1):
                if test_lines[i - 1]:
                    classification = "test/conformance"
                else:
                    classification = None
                for pat, cmd in HOST_CMD_PATTERNS:
                    if re.search(pat, line):
                        cls = classification or classify_host_cmd_site(rel_path, cmd)
                        results.append({
                            "path": rel_path,
                            "line": i,
                            "command": cmd,
                            "content": line.strip(),
                            "classification": cls,
                        })
                        break
    results.sort(key=lambda item: (item["path"], item["line"], item["command"]))
    return results


def classify_host_cmd_site(path, cmd):
    """Classify host command execution sites."""
    if "/examples/" in path or path.startswith("examples/"):
        return "example/evidence"
    if "/tests/" in path or path.startswith("tests/") or "test" in path:
        return "test/conformance"
    if path == "crates/o3k-image/src/lib.rs":
        return "application reference (not execution)"
    if path == "bins/o3k/src/checks/libvirt.rs":
        return "diagnostic guidance (not execution)"
    if path == "crates/o3k-image/src/execution.rs":
        return "Image execution adapter"
    if path == "bins/o3k-compute/src/iscsi.rs":
        return "Compute host lifecycle adapter"
    if path in {"bins/o3k/src/sys.rs", "bins/o3k/src/upgrade/runner.rs"}:
        return "diagnostic/upgrade tooling"
    # Infrastructure command adapters
    infra_adapters = [
        "o3k-compute-agent", "o3k-libvirt", "o3k-dhcp",
        "o3k-network", "o3k-storage", "o3k-cellhv",
        "o3k-config-drive", "o3k-console",
    ]
    for adapter in infra_adapters:
        if adapter in path:
            return "domain-owned execution adapter"

    if "crates/o3k-provider" in path:
        return "domain-owned execution adapter"

    if "scripts/" in path or "packaging/" in path:
        return "packaging"

    if "example" in path:
        return "example"

    if "diagnostic" in path or "doctor" in path:
        return "diagnostic/doctor"

    if "o3kd" in path and ("native_adapters" in path or "main" in path):
        return "domain-owned execution adapter"

    if "o3k-reconciler" in path:
        return "domain-owned execution adapter"

    if "o3k-cinder" in path or "o3k-compute" in path:
        return "candidate architectural leakage"

    return "candidate architectural leakage"


def source_responsibility(path: str) -> str:
    """Return a stable ownership bucket for non-authoritative monitoring."""
    if path.startswith("bins/o3kd/src/composition/"):
        return "o3kd control-plane composition"
    if path.startswith("bins/o3kd/src/native_adapters/"):
        return "o3kd native adapters"
    if path.startswith("bins/o3kd/"):
        return "o3kd process entry"
    if path.startswith("bins/o3k-compute/src/"):
        return "Compute host/runtime composition"
    if path.startswith("bins/o3k-network/src/"):
        return "Network execution/runtime composition"
    if path.startswith("crates/o3k-store/src/domain/"):
        return "store domain"
    if path.startswith("crates/o3k-store/src/port/"):
        return "store ports"
    if path.startswith("crates/o3k-store/src/sqlite/"):
        return "SQLite persistence"
    if path.startswith("crates/o3k-store/src/postgres/"):
        return "PostgreSQL persistence"
    if path.startswith("crates/o3k-store/"):
        return "store specialized persistence"
    if path.startswith("crates/o3k-network/src/linux_fabric/"):
        return "Network Linux execution"
    if path.startswith("crates/o3k-network/"):
        return "Network application"
    if path.startswith("crates/o3k-compute/"):
        return "Compute application"
    if path.startswith("crates/o3k-image/src/execution.rs"):
        return "Image execution"
    if path.startswith("crates/o3k-image/"):
        return "Image application"
    return "other workspace responsibility"


# ─── 5. Safety/lint exceptions inventory ───

def inventory_safety():
    """Find safety and lint exceptions."""
    results = {
        "workspace_unsafe_policy": "forbid (from workspace Cargo.toml)",
        "production_unwrap": [],
        "production_expect": [],
        "production_panic": [],
        "production_allow_overrides": [],
    }

    for root, dirs, files in os.walk(REPO_ROOT):
        dirs.sort()
        files.sort()
        rel = Path(root).relative_to(REPO_ROOT)
        parts = rel.parts
        if any(p in (".git", "target", "node_modules") for p in parts):
            continue
        for f in files:
            if not f.endswith(".rs"):
                continue
            path = Path(root) / f
            rel_path = str(path.relative_to(REPO_ROOT))
            lines = path.read_text().splitlines()
            occurrences = safety_occurrences(rel_path, lines)
            for key, values in occurrences.items():
                results[key].extend(values)

    for key in ("production_unwrap", "production_expect", "production_panic", "production_allow_overrides"):
        results[key].sort(key=lambda item: (item["path"], item["line"], item["content"]))
    return results


# ─── 6. Architectural role classification ───

ARCHITECTURE_ROLES = {
    "o3k-domain": "contracts/kernel/domain",
    "o3k-kernel": "contracts/kernel/domain",
    "o3k-identity": "application/service",
    "o3k-image": "application/service",
    "o3k-compute": "application/service",
    "o3k-network": "application/service",
    "o3k-placement": "application/service",
    "o3k-scheduler": "application/service",
    "o3k-reconciler": "reconciler/workflow",
    "o3k-cinder": "external-service client",
    "o3k-store": "persistence ports + SQLite/PostgreSQL adapters",
    "o3k-provider": "provider port + adapters",
    "o3k-provider-contract": "provider contract/protocol",
    "o3k-api": "API / OpenStack compatibility projection",
    "o3k-native-api": "API / native API",
    "o3k-config": "diagnostics/upgrade/maintenance",
    "o3k-service-sdk": "protocol / SDK",
    "o3k-controller-protocol": "protocol",
    "o3k-network-protocol": "protocol",
    "o3k-compute-agent": "provider adapter / host execution",
    "o3k-libvirt": "provider adapter / host execution",
    "o3k-cellhv": "provider adapter / host execution",
    "o3k-config-drive": "provider adapter / host execution",
    "o3k-console": "provider adapter / host execution",
    "o3k-dhcp": "provider adapter / host execution",
    "o3k-storage": "provider adapter / host execution",
    "o3k-database-example": "example/evidence",
    "o3k": "CLI/diagnostic entry point",
    "o3k-compute-bin": "Compute host/runtime composition",
    "o3k-network-bin": "Network execution/runtime composition",
    "o3kd": "control-plane composition root",
}

def classify_roles():
    """Map each crate to its architectural role."""
    results = {}
    stdout, _, _ = run(["cargo", "metadata", "--no-deps", "--format-version", "1"])
    meta = json.loads(stdout)
    for pkg in sorted(meta["packages"], key=lambda item: item["name"]):
        name = pkg["name"]
        role = ARCHITECTURE_ROLES.get(name, "unresolved")
        results[name] = {
            "role": role,
            "manifest": repository_relative_path(pkg["manifest_path"]),
            "dependencies": [d["name"] for d in pkg.get("dependencies", [])
                           if not d.get("kind")],
        }
    return results


# ─── 7. Hotspot analysis ───

def analyze_hotspots(crate_to_sources):
    """Identify files with high responsibility concentration or size."""
    hotspots = []
    for crate, sources in crate_to_sources.items():
        for sf in sources:
            score = 0
            reasons = []
            p = Path(sf["path"])
            fname = p.name

            # Size signal
            if sf["prod_loc_approx"] > 500:
                score += 1
                reasons.append(f"large ({sf['prod_loc_approx']} prod LOC)")

            # Name-based hotspot signals
            if fname in ("lib.rs", "mod.rs"):
                score += 0.5
                reasons.append("module root")

            if fname == "main.rs":
                score += 1
                reasons.append("binary entry point")

            if "native_adapters" in sf["path"] or "router" in sf["path"]:
                score += 1
                reasons.append("wiring/composition root")

            if score >= 1 or sf["byte_size"] > 30000:
                hotspots.append({
                    "path": sf["path"],
                    "crate": crate,
                    "byte_size": sf["byte_size"],
                    "line_count": sf["line_count"],
                    "prod_loc_approx": sf["prod_loc_approx"],
                    "score": score,
                    "reasons": reasons,
                })

    hotspots.sort(key=lambda h: (-h["score"], h["path"]))
    return hotspots


# ─── 8. Write outputs ───

def ensure_dirs():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    DOCS_DIR.mkdir(parents=True, exist_ok=True)


def write_json(filename, data):
    path = OUTPUT_DIR / filename
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  wrote {path}")
    return path


def write_md(filename, content):
    path = DOCS_DIR / filename
    with open(path, "w") as f:
        f.write(content)
    print(f"  wrote {path}")
    return path


def responsibility_totals(ws):
    """Aggregate production LOC by stable architectural responsibility."""
    totals = defaultdict(lambda: {"files": 0, "production_loc": 0})
    for sources in ws["crate_to_sources"].values():
        for source in sources:
            responsibility = source_responsibility(source["path"])
            totals[responsibility]["files"] += 1
            totals[responsibility]["production_loc"] += source["prod_loc_approx"]
    return {key: totals[key] for key in sorted(totals)}


def selected_roots(ws, paths):
    """Return selected root files ordered by descending production LOC."""
    sources = [item for group in ws["crate_to_sources"].values() for item in group]
    return sorted(
        (item for item in sources if item["path"] in paths),
        key=lambda item: (-item["prod_loc_approx"], item["path"]),
    )


def main():
    print("O3K Maintainability Architecture Inventory")
    print("=" * 50)

    ensure_dirs()

    # 1. Workspace inventory
    print("\n[1/7] Workspace inventory...")
    ws = inventory_workspace()
    write_json("baseline.json", ws)

    # 2. Dependency graph
    print("\n[2/7] Dependency graph...")
    deps = get_dependency_graph()
    write_json("dependencies.json", deps)

    # 3. SQL inventory
    print("\n[3/7] SQL usage inventory...")
    sql = inventory_sql()
    write_json("sql-inventory.json", {
        "total_sites": len(sql),
        "sites": sql,
    })

    # 4. Host command inventory
    print("\n[4/7] Host command inventory...")
    cmds = inventory_host_commands()
    write_json("host-command-inventory.json", {
        "total_sites": len(cmds),
        "sites": cmds,
    })

    # 5. Safety/lint inventory
    print("\n[5/7] Safety/lint exceptions...")
    safety = inventory_safety()
    write_json("safety-inventory.json", safety)

    # 6. Architecture roles
    print("\n[6/7] Architecture role classification...")
    roles = classify_roles()
    write_json("architecture-roles.json", roles)

    # 7. Hotspots
    print("\n[7/7] Hotspot analysis...")
    hotspots = analyze_hotspots(ws["crate_to_sources"])
    responsibilities = responsibility_totals(ws)
    write_json("responsibility-inventory.json", {
        "git_sha": ws["git_sha"],
        "responsibilities": responsibilities,
    })
    write_json("hotspots.json", {
        "total_hotspots": len(hotspots),
        "hotspots": hotspots[:50],
    })

    # ─── Summary report ───
    print("\n\nGenerating summary report...")

    # Count SQL classifications
    sql_persistence = sum(1 for s in sql if s["classification"] == "persistence-adapter")
    sql_migration = sum(1 for s in sql if s["classification"] == "migration")
    sql_test = sum(1 for s in sql if s["classification"] == "test/conformance")
    sql_diag = sum(1 for s in sql if s["classification"] == "diagnostic")
    sql_unexplained = sum(1 for s in sql if s["classification"] == "unexpected-production-location")

    # Count host command classifications
    cmd_adapter = sum(1 for c in cmds if c["classification"] == "domain-owned execution adapter")
    cmd_test = sum(1 for c in cmds if c["classification"] == "test/conformance")
    cmd_pkg = sum(1 for c in cmds if c["classification"] == "packaging")
    cmd_example = sum(1 for c in cmds if c["classification"] == "example")
    cmd_diag = sum(1 for c in cmds if c["classification"] == "diagnostic/doctor")
    cmd_leakage = sum(1 for c in cmds if c["classification"] == "candidate architectural leakage")
    non_execution_classes = {
        "test/conformance",
        "packaging",
        "example/evidence",
        "application reference (not execution)",
        "diagnostic guidance (not execution)",
    }

    # Count unsafe items
    total_unwrap = len(safety["production_unwrap"])
    total_expect = len(safety["production_expect"])
    total_panic = len(safety["production_panic"])
    total_allows = len(safety["production_allow_overrides"])

    # Workspace stats
    total_sources = ws["source_files"]["total_count"]
    total_prod = ws["source_files"]["total_prod_loc"]
    total_test = ws["source_files"]["total_test_loc"]

    report = f"""# Current Maintainability Architecture Report

## Report snapshot

- **SHA**: `{ws['git_sha']}`
- **Branch**: `{ws['branch']}`

## Workspace Summary

| Metric | Value |
|--------|-------|
| Workspace crates | {len(ws['packages'])} |
| Rust source files | {total_sources} |
| Total lines | {ws['source_files']['total_lines']:,} |
| Production LOC (approx) | {total_prod:,} |
| Test LOC (approx) | {total_test:,} |

### Crate source file counts

| Crate | Source files |
|-------|-------------|
"""

    for name, count in sorted(ws["files_by_crate"].items()):
        report += f"| `{name}` | {count} |\n"

    report += f"""
## Crate Dependency Graph

- **Workspace dependency edges**: {deps['workspace_edges']}
- **Cycles found**: {len(deps['cycles'])}
"""

    for cycle in deps["cycles"]:
        cycle_str = " -> ".join(cycle)
        report += f"  - Cycle: {cycle_str}\n"

    report += f"""
## SQL Usage Inventory

- **Total production call sites**: {len(sql)}
- **Persistence adapter locations**: {sql_persistence}
- **Migration locations**: {sql_migration}
- **Test/conformance locations**: {sql_test}
- **Diagnostic locations**: {sql_diag}
- **Unexplained locations**: {sql_unexplained}
"""

    if sql_unexplained > 0:
        report += "\n### Unexplained SQL locations (need review):\n\n"
        for s in sql:
            if s["classification"] == "unexpected-production-location":
                report += f"- `{s['path']}:{s['line']}` — `{s['content'][:80]}`\n"

    report += f"""
## Host Command Execution Inventory

- **Total production execution sites**: {len([c for c in cmds if c['classification'] not in non_execution_classes])}
- **Execution adapter locations**: {cmd_adapter}
- **Mutating commands**: {sum(1 for c in cmds if c['command'] in ('sudo', 'mount', 'umount', 'lvcreate', 'lvremove', 'lvchange', 'pvcreate', 'vgcreate', 'dd', 'virsh', 'systemctl', 'ip', 'bridge', 'nft', 'rbd', 'ceph'))}
- **Read-only commands**: {sum(1 for c in cmds if c['command'] in ('lvs', 'vgs', 'pvs', 'df', 'lsblk', 'blkid', 'losetup'))}
- **Direct shell execution sites (sh/bash -c)**: {sum(1 for c in cmds if c['command'] in ('sh -c', 'bash -c'))}
- **Candidate architectural leakage**: {cmd_leakage}
"""

    if cmd_leakage > 0:
        report += "\n### Candidate architectural leakage sites:\n\n"
        for c in cmds:
            if c["classification"] == "candidate architectural leakage":
                report += f"- `{c['path']}:{c['line']}` — `{c['command']}`\n"

    report += "\n## Production LOC by Architectural Responsibility\n\n"
    report += "| Responsibility | Files | Production LOC (approx) |\n|---|---:|---:|\n"
    for responsibility, totals in responsibilities.items():
        report += f"| {responsibility} | {totals['files']} | {totals['production_loc']:,} |\n"

    application_roots = selected_roots(ws, {
        "crates/o3k-identity/src/lib.rs",
        "crates/o3k-image/src/lib.rs",
        "crates/o3k-compute/src/lib.rs",
        "crates/o3k-network/src/lib.rs",
        "crates/o3k-placement/src/lib.rs",
        "crates/o3k-scheduler/src/lib.rs",
        "crates/o3k-reconciler/src/lib.rs",
    })
    report += "\n## Largest Application Roots\n\n"
    report += "| File | Production LOC (approx) |\n|---|---:|\n"
    for item in application_roots:
        report += f"| `{item['path']}` | {item['prod_loc_approx']:,} |\n"

    composition_roots = selected_roots(ws, {
        "bins/o3kd/src/composition/mod.rs",
        "bins/o3kd/src/native_adapters/mod.rs",
        "bins/o3k-compute/src/main.rs",
        "bins/o3k-network/src/main.rs",
    })
    report += "\n## Composition Roots\n\n"
    report += "| File | Production LOC (approx) |\n|---|---:|\n"
    for item in composition_roots:
        report += f"| `{item['path']}` | {item['prod_loc_approx']:,} |\n"

    report += f"""
## Safety / Lint Exceptions

| Category | Production count |
|----------|-----------------|
| `unsafe_code` | Forbidden at workspace level |
| `.unwrap()` in production | {total_unwrap} |
| `.expect()` in production | {total_expect} |
| `panic!()` in production | {total_panic} |
| `#[allow(...)]` overrides | {total_allows} |
"""

    if total_unwrap + total_expect + total_panic > 0:
        report += "\n### Production safety occurrences (top 20):\n\n"
        count = 0
        for item in safety["production_unwrap"][:10]:
            report += f"- `{item['path']}:{item['line']}` — `{item['content'][:80]}`\n"
            count += 1
        for item in safety["production_expect"][:10]:
            report += f"- `{item['path']}:{item['line']}` — `{item['content'][:80]}`\n"
            count += 1
        if count == 0:
            report += "- None found in production code.\n"

    report += f"""
## Architecture Classification

| Crate | Role |
|-------|------|
"""
    unresolved = []
    for name, info in sorted(roles.items()):
        report += f"| `{name}` | {info['role']} |\n"
        if info["role"] == "unresolved":
            unresolved.append(name)

    report += f"""
- **Unresolved classifications**: {len(unresolved)}
"""

    if unresolved:
        for name in unresolved:
            report += f"  - `{name}`\n"

    report += f"""
## Top Hotspots (by size + responsibility score)

| File | Crate | Prod LOC | Score | Reasons |
|------|-------|----------|-------|---------|
"""

    for h in hotspots[:20]:
        report += f"| `{h['path']}` | {h['crate']} | {h['prod_loc_approx']} | {h['score']} | {', '.join(h['reasons'])} |\n"

    report += """
## Interpretation

This is a current-tree monitoring report, not an immutable baseline and not a
style gate. Size and hotspot metrics identify review surfaces; they do not
impose arbitrary file or LOC limits. The immutable P13.4 baseline remains
under `docs/maintainability/baselines/p13-4/` for dependency-regression
evidence only.

## Validation Status

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo check --workspace --all-targets --all-features`
- [ ] `cargo test --workspace --all-features`
- [ ] nextest PR gate
"""

    with open(OUTPUT_DIR / "summary.md", "w") as f:
        f.write(report)
    print(f"\n  wrote {OUTPUT_DIR / 'summary.md'}")

    # Also write the docs/maintainability architecture-baseline.md
    arch_baseline = f"""# Current Architecture Snapshot

Generated from workspace inventory at `{ws['git_sha']}`.

This is a current-tree monitoring snapshot, not the immutable P13.4 baseline.
That historical evidence remains under
`docs/maintainability/baselines/p13-4/` and is never regenerated here.

## Snapshot

- {total_sources} Rust source files across {len(ws['packages'])} workspace crates
- ~{total_prod:,} production LOC, ~{total_test:,} test LOC
- {len(hotspots)} candidate hotspot files identified

## Crate Roles

See `architecture-roles.md` for the full classification.

## Key Numbers

- SQL usage sites: {len(sql)} ({sql_unexplained} unexplained)
- Host command execution sites: {len([c for c in cmds if c['classification'] not in non_execution_classes])} production
- Dependency cycles: {len(deps['cycles'])}
- Production safety occurrences: {total_unwrap + total_expect + total_panic}

## Production LOC by Responsibility

| Responsibility | Files | Production LOC (approx) |
|---|---:|---:|
"""
    for responsibility, totals in responsibilities.items():
        arch_baseline += f"| {responsibility} | {totals['files']} | {totals['production_loc']:,} |\n"
    arch_baseline += """

## Monitoring interpretation

The inventory reports hotspots, application roots, composition roots, SQL and
host-execution ownership, and dependency cycles for review. It does not enforce
arbitrary file-size or LOC thresholds.

## Integrity

Run `scripts/maintainability-inventory.py` to refresh this current snapshot.
"""
    write_md("architecture-baseline.md", arch_baseline)

    # Write architecture roles doc
    roles_md = "# Current Architecture Role Classification\n\n"
    roles_md += "Role mapping for each workspace crate and binary.\n\n"
    roles_md += "| Crate | Role | Description |\n|-------|------|-------------|\n"
    role_desc = {
        "contracts/kernel/domain": "Canonical domain types, lifecycle state machines, invariants",
        "application/service": "Application service implementing use cases above domain ports",
        "reconciler/workflow": "Reconciliation and compensation orchestration",
        "persistence ports + SQLite/PostgreSQL adapters": "Repository ports, SQLite/PostgreSQL implementations, and unified dispatch",
        "provider port + adapters": "Provider/external-service port definitions + adapters",
        "provider contract/protocol": "Provider wire protocol contracts (protobuf)",
        "API / OpenStack compatibility projection": "HTTP API routers, OpenStack request/response adapters",
        "API / native API": "Native O3K resource API",
        "diagnostics/upgrade/maintenance": "Configuration, diagnostics, operational tooling",
        "protocol / SDK": "Shared protocol types, client SDK helpers",
        "protocol": "Wire protocol definitions",
        "provider adapter / host execution": "Privileged host execution adapters (libvirt, LVM, nftables, etc.)",
        "external-service client": "External OpenStack service client adapters",
        "example/evidence": "Examples, evidence artifacts",
        "control-plane composition root": "o3kd composition, service wiring, and process lifecycle",
        "Compute host/runtime composition": "Compute binary startup and host-runtime composition",
        "Network execution/runtime composition": "Network binary startup and execution-runtime composition",
        "CLI/diagnostic entry point": "O3K CLI and operational entry point",
    }
    for name, info in sorted(roles.items()):
        desc = role_desc.get(info["role"], "")
        roles_md += f"| `{name}` | {info['role']} | {desc} |\n"
    roles_md += "\n## Unresolved\n\n"
    for name, info in sorted(roles.items()):
        if info["role"] == "unresolved":
            roles_md += f"- `{name}`\n"
    if not any(info["role"] == "unresolved" for info in roles.values()):
        roles_md += "None — all crates are classified.\n"
    write_md("architecture-roles.md", roles_md)

    print("\n\nDone. Output in:")
    print(f"  {OUTPUT_DIR}/")
    print(f"  {DOCS_DIR}/")


if __name__ == "__main__":
    main()
