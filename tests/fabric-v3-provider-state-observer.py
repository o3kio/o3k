#!/usr/bin/env python3
"""Read-only, typed observations of run-owned provider state on a guest."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
from typing import Any, Callable


class ObservationError(RuntimeError):
    def __init__(self, command_class: str, diagnostic: str, exit_code: int | None = None):
        super().__init__(diagnostic)
        self.command_class = command_class
        self.exit_code = exit_code


def _safe_name(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise ObservationError("argument_validation", f"invalid {label}")
    return value


def parse_link_result(
    name: str,
    returncode: int,
    stdout: str,
    stderr: str,
    namespace: str | None = None,
) -> dict[str, Any]:
    name = _safe_name(name, "link name")
    if namespace is not None:
        namespace = _safe_name(namespace, "namespace name")
    if returncode == 0:
        try:
            links = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ObservationError("ip_link_inventory", "ip returned malformed JSON", returncode) from exc
        if not isinstance(links, list) or len(links) != 1 or links[0].get("ifname") != name:
            raise ObservationError("ip_link_inventory", "ip returned an ambiguous link inventory", returncode)
        link = links[0]
        return {
            "status": "present",
            "command_class": "ip_link_observation",
            "namespace": namespace,
            "link": {
                "ifname": link.get("ifname"),
                "address": link.get("address"),
                "link_type": link.get("link_type"),
                "linkinfo": link.get("linkinfo"),
            },
        }

    detail = stderr.strip()
    if namespace is not None and detail == f'Cannot open network namespace "{namespace}": No such file or directory':
        return {
            "status": "absent",
            "command_class": "ip_link_observation",
            "exit_code": returncode,
            "reason": "namespace_absent",
        }
    if detail in {
        f'Device "{name}" does not exist.',
        f'Cannot find device "{name}"',
    }:
        return {
            "status": "absent",
            "command_class": "ip_link_observation",
            "exit_code": returncode,
            "reason": "link_absent",
        }
    raise ObservationError("ip_link_observation", detail[:500] or "ip failed without diagnostics", returncode)


def observe_link(
    name: str,
    namespace: str | None = None,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    name = _safe_name(name, "link name")
    argv = ["ip", "-j", "-d", "link", "show", "dev", name]
    if namespace is not None:
        namespace = _safe_name(namespace, "namespace name")
        argv = ["ip", "netns", "exec", namespace, *argv]
    try:
        result = run(argv, check=False, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ObservationError("ip_link_observation", type(exc).__name__) from exc
    return parse_link_result(name, result.returncode, result.stdout, result.stderr, namespace)


def observe_path(path: pathlib.Path, lstat: Callable[[str], os.stat_result] = os.lstat) -> dict[str, Any]:
    try:
        info = lstat(str(path))
    except FileNotFoundError:
        return {"status": "absent", "command_class": "exact_path_observation"}
    except OSError as exc:
        raise ObservationError("exact_path_observation", type(exc).__name__, exc.errno) from exc
    kind = "symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "file"
    return {
        "status": "present",
        "command_class": "exact_path_observation",
        "kind": kind,
        "mode": stat.S_IMODE(info.st_mode),
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
    }


def observe_process(
    executable: str,
    argv_contains: str,
    proc_root: pathlib.Path = pathlib.Path("/proc"),
) -> dict[str, Any]:
    executable = _safe_name(executable, "process executable")
    if not argv_contains or "\x00" in argv_contains:
        raise ObservationError("owned_process_inventory", "invalid process ownership path")
    try:
        entries = sorted(item for item in proc_root.iterdir() if item.name.isdecimal())
    except OSError as exc:
        raise ObservationError("owned_process_inventory", type(exc).__name__, exc.errno) from exc

    matching: list[dict[str, Any]] = []
    needle = os.fsencode(argv_contains)
    for entry in entries:
        try:
            process_executable = entry.joinpath("exe").readlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ObservationError("owned_process_inventory", type(exc).__name__, exc.errno) from exc
        normalized = str(process_executable).removesuffix(" (deleted)")
        if pathlib.PurePosixPath(normalized).name != executable:
            continue
        try:
            command_line = entry.joinpath("cmdline").read_bytes()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ObservationError("owned_process_inventory", type(exc).__name__, exc.errno) from exc
        if not command_line:
            raise ObservationError("owned_process_inventory", "matching process has empty command line")
        matching.append({"pid": int(entry.name), "owned": needle in command_line})

    owned_pids = sorted(item["pid"] for item in matching if item["owned"])
    return {
        "status": "present" if owned_pids else "absent",
        "command_class": "owned_process_inventory",
        "executable": executable,
        "matching_process_count": len(matching),
        "owned_process_count": len(owned_pids),
        "owned_pids": owned_pids,
    }


def parse_namespace_list(returncode: int, stdout: str, stderr: str, name: str) -> dict[str, Any]:
    name = _safe_name(name, "namespace name")
    if returncode:
        raise ObservationError("ip_namespace_inventory", stderr.strip()[:500] or "ip netns list failed", returncode)
    names = sorted({line.split(" ", 1)[0] for line in stdout.splitlines() if line.strip()})
    return {
        "status": "present" if name in names else "absent",
        "command_class": "ip_namespace_inventory",
        "namespaces": names,
    }


def observe_namespace(
    name: str,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    name = _safe_name(name, "namespace name")
    try:
        result = run(["ip", "netns", "list"], check=False, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ObservationError("ip_namespace_inventory", type(exc).__name__) from exc
    return parse_namespace_list(result.returncode, result.stdout, result.stderr, name)


def observe_tree(path: pathlib.Path, max_depth: int = 8, max_entries: int = 2000) -> dict[str, Any]:
    try:
        root_info = os.lstat(path)
    except FileNotFoundError:
        return {"status": "absent", "command_class": "owned_tree_inventory", "root_exists": False, "files": []}
    except OSError as exc:
        raise ObservationError("owned_tree_inventory", type(exc).__name__, exc.errno) from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise ObservationError("owned_tree_inventory", "owned state root exists but is not a directory")

    files: list[dict[str, str]] = []
    pending: list[tuple[pathlib.Path, int]] = [(path, 0)]
    while pending:
        directory, depth = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise ObservationError("owned_tree_inventory", type(exc).__name__, exc.errno) from exc
        for entry in entries:
            relative = str(pathlib.Path(entry.path).relative_to(path))
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ObservationError("owned_tree_inventory", type(exc).__name__, exc.errno) from exc
            if stat.S_ISDIR(info.st_mode):
                if depth >= max_depth:
                    raise ObservationError("owned_tree_inventory", "maximum depth exceeded")
                pending.append((pathlib.Path(entry.path), depth + 1))
            else:
                files.append({"path": relative, "kind": "symlink" if stat.S_ISLNK(info.st_mode) else "file"})
                if len(files) > max_entries:
                    raise ObservationError("owned_tree_inventory", "maximum entry count exceeded")
    return {
        "status": "present" if files else "empty",
        "command_class": "owned_tree_inventory",
        "root_exists": True,
        "files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    actions = parser.add_subparsers(dest="action", required=True)
    link = actions.add_parser("link")
    link.add_argument("--name", required=True)
    link.add_argument("--namespace")
    namespace = actions.add_parser("namespace")
    namespace.add_argument("--name", required=True)
    path = actions.add_parser("path")
    path.add_argument("--path", required=True, type=pathlib.Path)
    process = actions.add_parser("process")
    process.add_argument("--executable", required=True)
    process.add_argument("--argv-contains", required=True)
    tree = actions.add_parser("tree")
    tree.add_argument("--path", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.action == "link":
            result = observe_link(args.name, args.namespace)
        elif args.action == "namespace":
            result = observe_namespace(args.name)
        elif args.action == "path":
            result = observe_path(args.path)
        elif args.action == "process":
            result = observe_process(args.executable, args.argv_contains)
        else:
            result = observe_tree(args.path)
        print(json.dumps(result, sort_keys=True))
        return 0
    except ObservationError as exc:
        print(json.dumps({
            "status": "error",
            "command_class": exc.command_class,
            "exit_code": exc.exit_code,
            "diagnostic": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
