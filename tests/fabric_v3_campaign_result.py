"""Shared predicate checks for Fabric real-host campaign result artifacts."""
from __future__ import annotations

from typing import Any

CLEANUP_PREDICATE_KEYS = (
    "api_resources",
    "owned_guests_and_storage",
    "controller_process",
    "post_cleanup_host_inventory",
    "foreign_state_unchanged",
    "run_owned_dhcp_capture",
    "image_store_pool_refresh",
)
ALLOWED_CLEANUP_STATUSES = frozenset({"PASS", "NOT_APPLICABLE"})


def cleanup_predicates_pass(cleanup: Any) -> bool:
    """Return true only when every declared cleanup predicate passes.

    Artifacts also contain descriptive metadata such as ``acceptance_gate``.
    Metadata is intentionally excluded from this predicate list.
    """
    if not isinstance(cleanup, dict):
        return False
    return all(cleanup.get(key) in ALLOWED_CLEANUP_STATUSES for key in CLEANUP_PREDICATE_KEYS)
