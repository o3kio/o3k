# Issue #937 / P15.7 evidence contract

Status: `not-executed`

The protected real-host gate is implemented by
`tests/p15_7_scale_composition.sh` and validates the redacted artifact
`p15-7-scale-composition-evidence.json` with
`scripts/validate_p15_7_evidence.py`.  The artifact must be produced by a
runner-supplied journey driver using a real `o3kd`, authenticated multi-block
joins, PostgreSQL, SQLite parity, and the real compute-agent/libvirt boundary.

The gate rejects fake or skipped providers, fewer than two blocks, missing
restart/failure/security negatives, non-zero owned leaks or foreign mutations,
and broad claims such as HA, multi-region, evacuation, or datacenter scale.
No real-host P15.7 artifact is committed here; this document therefore makes
no completion or product-readiness claim.
