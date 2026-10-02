"""Shared validation for P15.7 scale checkpoint relationships."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def _eligible_block_ids(checkpoint: Mapping[str, Any]) -> set[str]:
    blocks = checkpoint.get("blocks")
    if not isinstance(blocks, Sequence) or isinstance(blocks, (str, bytes)):
        raise ValueError("scale checkpoint blocks must be a list")
    result: set[str] = set()
    for entry in blocks:
        if not isinstance(entry, Mapping):
            raise ValueError("scale checkpoint block entry must be an object")
        if entry.get("placement_eligible") is True:
            block_id = entry.get("block_id")
            if not isinstance(block_id, str) or not block_id:
                raise ValueError("eligible scale checkpoint block must have a block_id")
            result.add(block_id)
    return result


def validate_bootstrap_scale_membership(
    initial_checkpoint: Mapping[str, Any],
    final_checkpoint: Mapping[str, Any],
    bootstrap_block_id: str,
    drain_agent: str,
    bootstrap_agent: str,
) -> None:
    """Validate bootstrap eligibility against the observed drain outcome.

    The bootstrap BuildingBlock is eligible initially. It remains in the final
    set when a child is drained; when Placement selects bootstrap for drain,
    that identity is removed and the replacement child restores cardinality.
    """
    if not bootstrap_block_id or not bootstrap_agent:
        raise ValueError("bootstrap identity must be non-empty")

    initial_ids = _eligible_block_ids(initial_checkpoint)
    final_ids = _eligible_block_ids(final_checkpoint)
    if bootstrap_block_id not in initial_ids:
        raise ValueError("bootstrap BuildingBlock must be in the initial eligible Ready set")

    bootstrap_drained = drain_agent == bootstrap_agent
    expected = "absent" if bootstrap_drained else "present"
    if final_checkpoint.get("bootstrap_expect") != expected:
        raise ValueError(
            f"post-replacement bootstrap_expect must be {expected!r} for the observed drain target"
        )
    bootstrap_is_eligible = bootstrap_block_id in final_ids
    if bootstrap_is_eligible != (not bootstrap_drained):
        raise ValueError(
            "post-replacement bootstrap eligibility does not match the observed drain target"
        )
