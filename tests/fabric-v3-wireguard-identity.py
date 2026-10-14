#!/usr/bin/env python3
"""Compare captured public WireGuard identity; never read private-key material."""

from collections import Counter
import json
from pathlib import Path
import sys


def compare(host: str, expected: str, peers: list[str], public: str, observed: str) -> dict:
    public_lines = public.splitlines()
    observed_peers = observed.splitlines()
    counts = Counter(observed_peers)
    missing = sorted(set(peers) - set(observed_peers))
    unexpected = sorted(set(observed_peers) - set(peers))
    duplicates = sorted(peer for peer, count in counts.items() if count > 1)
    key_matches = public_lines == [expected]
    failures = []
    if not key_matches:
        failures.append("local_public_key_mismatch")
    if missing:
        failures.append("missing_peers")
    if unexpected:
        failures.append("unexpected_peers")
    if duplicates:
        failures.append("duplicate_peers")
    return {
        "artifact_type": "fabric-v3-wireguard-identity",
        "host": host,
        "status": "failed" if failures else "passed",
        "classification": "PROVIDER_CONFORMANCE_DEFECT" if failures else None,
        "observer_type": "ssh_sudo_read_only",
        "namespace": "o3k-fabric",
        "interface": "o3k-wg",
        "expected_public_key": expected,
        "observed_public_keys": public_lines,
        "expected_peers": sorted(peers),
        "observed_peers": sorted(observed_peers),
        "local_public_key_matches": key_matches,
        "missing_peers": missing,
        "unexpected_peers": unexpected,
        "duplicate_peers": duplicates,
        "failed_predicates": failures,
    }


def main(arguments: list[str]) -> int:
    if len(arguments) not in {6, 7}:
        print(
            "HARNESS_GAP: expected host, public key, one or two peers, two observations, output",
            file=sys.stderr,
        )
        return 2
    host, public = arguments[:2]
    peers = arguments[2:-3]
    public_path, peers_path, output = arguments[-3:]
    if (
        host not in {"host-a", "host-b", "host-c"}
        or not 1 <= len(peers) <= 2
        or any(not peer for peer in peers)
        or len(set(peers)) != len(peers)
    ):
        print("HARNESS_GAP: invalid expected WireGuard identity", file=sys.stderr)
        return 2
    try:
        result = compare(
            host,
            public,
            peers,
            Path(public_path).read_text(),
            Path(peers_path).read_text(),
        )
        Path(output).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    except OSError:
        print(f"HARNESS_GAP: public identity evidence unavailable for {host}", file=sys.stderr)
        return 2
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
