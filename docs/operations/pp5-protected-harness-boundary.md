# PP.5 protected pre-S1 harness boundary

The protected harness microgate validates the runner boundary after the generic
TestLab epoch has been removed and after a fresh PP.5 TestLab has bootstrapped.
Its success is a read-only prerequisite for S1 workload creation. Local or
unit-test fixtures cannot prove the root-owned runner state boundary; the
protected microgate is the authoritative integration evidence.

| Observation | Access class | Required proof |
| --- | --- | --- |
| `.o3k-run-owned` | `sudo read-only` | Exact `/var/lib/o3k-testlab/<run>-pp5` root; root-owned regular file, mode `0600`; bounded `sudo -n cat`; exact source SHA and run identity. |
| TestLab state root | `sudo read-only` | Exact expected path, real directory, no symlink, resolved path unchanged. |
| PID root and PID records | `runner-readable` | Exact `RUNNER_TEMP` phase paths, runner-owned directories and records, expected mode, numeric process identity. |
| PID executable and owner | `sudo read-only` | Start ticks, executable path, and process UID match the run-owned PID record and TestLab binary. |
| Inventory root and marker | `runner-readable` | Exact run path, runner ownership, expected mode, source SHA and phase identity. |
| OpenStack virtualenv | `runner-readable` / `runner-executable` | Exact runner-temp virtualenv, runner-owned marker and CLI, and `PATH` resolves to that CLI. |
| OpenStack project identity | `API observation` | Project ID returned by the project-scoped API lookup matches the fresh bootstrap artifact. |
| Server and port inventories | `API observation` | Project-scoped OpenStack CLI queries; each inventory must be empty before S1. No all-projects port query is used. |
| Libvirt domains | `libvirt observation` | `virsh -c qemu:///system list --all --name`; no run-owned PP.5 domain may exist. |
| Bootstrap compute identity | `sudo read-only` | Bounded read of the root-owned TLS agent ID after marker verification. |
| Building blocks and provider diagnostics | `API observation` | Canonical topology contains exactly the bootstrap host for S1, with no child hosts. |
| Capacity diagnostics and provider allocations | `API observation` | Every capacity dimension and provider allocation is zero before workload creation. |
| Foreign host state | `libvirt observation` | Host-only domain, link, and pool fingerprints equal the pre-generic baseline. |

The microgate writes `pp5-lane-initial-state.json` and a separate
`pp5-protected-harness-microgate.json`. The S1 wrapper validates both artifacts
against the current workflow run and source SHA before invoking the workload
journey. The journey writes its later checkpoint to
`pp5-lane-journey-initial-state.json`, preserving the microgate's authoritative
pre-mutation artifact.

All subprocess failures record only an operation name, observer class, resource
class, command basename, and exit status. Command output, credentials, bearer
tokens, and protected file contents are excluded from evidence.
