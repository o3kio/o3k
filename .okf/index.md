---
okf_version: "0.2"
---

# O3K repository memory

This OKF bundle is an evidence index for development continuity. It does not
replace O3K's normative ADRs, specs, contracts, tests, compatibility evidence,
or Git history.

- [Current workstream projections](current/workstreams/) - generated bounded views for resuming work.
- [Development workstreams](workstreams/) - append-only deterministic run records.
- [Memory protocol](../docs/OKF_MEMORY.md) - trust model, workflow, and limitations.

`workstreams/*/runs/` is canonical tracked progress memory. `current/` is a
deterministic projection and may be regenerated at any time.
