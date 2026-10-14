#!/usr/bin/env python3
"""Record whether the pre-delete shared Fabric namespace remains after Remove."""

import json
import os
from pathlib import Path
import re
import sys


class HarnessEvidenceError(Exception):
    """The ownership or namespace inventory is unavailable or invalid."""


def inspect(pre_ownership_path: Path, post_ownership_path: Path, namespaces_path: Path) -> dict:
    try:
        pre_ownership = json.loads(pre_ownership_path.read_text(encoding="utf-8"))
        post_ownership = json.loads(post_ownership_path.read_text(encoding="utf-8"))
        namespaces = namespaces_path.read_text(encoding="utf-8")
    except (OSError, json.JSONDecodeError) as error:
        raise HarnessEvidenceError("pre/post ownership or post-Remove namespace inventory is unreadable") from error
    if not isinstance(pre_ownership, dict) or not isinstance(post_ownership, dict):
        raise HarnessEvidenceError("pre/post ownership evidence must be JSON objects")

    fabric = pre_ownership.get("fabric")
    if not isinstance(fabric, dict):
        raise HarnessEvidenceError("pre-delete ownership has no shared Fabric identity")
    namespace = fabric.get("namespace")
    if not isinstance(namespace, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", namespace):
        raise HarnessEvidenceError("pre-delete shared Fabric namespace identity is invalid")

    observed_names = {
        line.split()[0]
        for line in namespaces.splitlines()
        if line.split()
    }
    state = "present" if namespace in observed_names else "absent"
    post_fabric = post_ownership.get("fabric")
    if post_fabric is None:
        post_namespace = None
    elif isinstance(post_fabric, dict):
        post_namespace = post_fabric.get("namespace")
        if not isinstance(post_namespace, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", post_namespace):
            raise HarnessEvidenceError("post ownership shared Fabric namespace identity is invalid")
    else:
        raise HarnessEvidenceError("post ownership shared Fabric identity is invalid")
    post_ownership_claims_namespace = (
        post_namespace == namespace
    )
    return {
        "artifact_type": "fabric-v3-shared-namespace-observation",
        "namespace": namespace,
        "state": state,
        "observer": "ip-netns-list",
        "post_ownership_namespace": post_namespace,
        "post_ownership_claims_namespace": post_ownership_claims_namespace,
        "meaning": "absence means namespace-scoped links, FDB, and policy cannot remain",
    }


def write_evidence(output: Path, evidence: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(evidence, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(arguments: list[str]) -> int:
    if len(arguments) != 4:
        print(
            "usage: fabric-v3-shared-fabric-namespace.py PRE_OWNERSHIP POST_OWNERSHIP NAMESPACES OUTPUT",
            file=sys.stderr,
        )
        return 2
    pre_ownership, post_ownership, namespaces, output = map(Path, arguments)
    try:
        write_evidence(output, inspect(pre_ownership, post_ownership, namespaces))
    except (HarnessEvidenceError, OSError) as error:
        print(f"HARNESS_GAP: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
