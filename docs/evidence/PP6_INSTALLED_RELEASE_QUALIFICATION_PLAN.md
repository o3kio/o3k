# PP.6 installed-release qualification plan (infrastructure assessment)

**Status:** plan/assessment — no qualification claim. **Date:** 2026-11-03.
**Authority:** follow-up to PP.6 follow-up PR for #1204/#1206 (publisher
provenance compatibility). #975 and #1086 remain open; A10.1 migration
publication remains disabled in production; no PostgreSQL restore mutation,
no controller activation, no PP.7/Araf work is part of this plan.

## Why this plan exists

Installed-release and power-loss qualification must run against an immutable,
exact-source, authenticated release candidate through the protected release
workflow. Two facts drive the current blocker:

1. Published `v0.4.0-rc.25` (`42de13cee64a37d69e900fd4272ff5e849a328b8`)
   does **not** contain PR #1206 (merged at protected main
   `9512832ad79da3cc555739dfd94e5708598e2ca4`) or this follow-up. Its release
   provenance verifiers would reject the authentic seven-entry signed
   `release-digests.txt`, so an rc.25-based installed host cannot pass
   A10.1 source/target provenance authentication even before this fix, and
   would not exercise the fixed code at all.
2. Authenticated installed-release qualification therefore needs a successor
   candidate (rc.26) built from protected source that includes #1206 plus
   this follow-up. That tag must be created **only** through the protected
   release workflow (release environment approval, GitHub OIDC/Sigstore
   provenance, supported verifier) and **only** with owner authorization.
   No tag may be moved or reused.

## Harness prerequisites and what this shared runner already satisfies

PR #1200 added `tests/pp6-qualification/host-env.py`. Its provisioning
refusal conditions and host requirements, checked read-only on this shared
runner on 2026-11-03 (nothing was changed):

| Prerequisite (host-env.py / PR #1200) | This runner (read-only observation) | Verdict |
|---|---|---|
| Root + `virsh`, `virt-install`, `qemu-img`, `genisoimage`, `ssh`, `ssh-keygen` | All tools present; sudo available for the qualification user | Satisfiable |
| `/dev/kvm` | Present (`crw-rw---- root:kvm`) | Satisfiable |
| ≥ 8 CPUs | 16 CPUs | Satisfied |
| ≥ 16 GiB available memory | ~58.8 GiB available | Satisfied |
| ≥ 35 GiB free on the `/var/lib` filesystem | ~147 GiB free, ext4 | Satisfied |
| **IPv4 and IPv6 forwarding disabled on every interface** | `net.ipv4.ip_forward=1`; `conf/*/forwarding=1` for all interfaces (v4 and v6) | **Refused — cannot be changed on this shared runner** |
| No production credentials/services/routes/data; isolated qualification machine | Shared CI runner: existing libvirt networks (`default`, `f3u261006`, `p14-9c-source`) and a running third-party VM (`o3k-a10-systemd-qualification`); docker bridges | **Not satisfied — dedicated host required** |
| Trusted, pinned official Debian 12 and Ubuntu 24.04 cloud images (caller-supplied SHA-256 verified) | None present (only an unrelated cirros test image) | Not satisfied — images must be independently pinned and supplied |
| ext4 state/journal guests | Harness creates qcow2 files on the host filesystem; host `/` is ext4 | Satisfiable on a dedicated host |
| Host power-loss evidence | Guest `force-restart` is explicitly *not* host power-loss evidence; requires physical power-cut/BMC control of the qualification machine | Requires external dedicated host with BMC/PDU control |

Read-only checks performed (no sysctl, route, guest, firewall, or disk
changes were made): `/proc/sys/net/ipv4/ip_forward`,
`/proc/sys/net/ipv4/conf/*/forwarding`,
`/proc/sys/net/ipv6/conf/*/forwarding`, `/dev/kvm`, tool presence,
`nproc`, `/proc/meminfo` MemAvailable, `df /var/lib`, `lsblk -f`,
`virsh list --all`, `virsh net-list --all`, image search under
`/var/lib/libvirt/images`, `/var/tmp`, `/opt`, `/srv`.

## Plan

1. **This PR** lands the publisher provenance compatibility fix with
   source/unit evidence only (see `PP6_PUBLISHER_PROVENANCE_COMPAT.md`).
2. **Owner-authorized successor candidate:** after protected merge, create
   `v0.4.0-rc.26` (or the owner-chosen successor) only through the protected
   release workflow. Never reuse or move rc.25. The Sigstore-signed bundle
   must contain the authentic seven-entry `release-digests.txt`.
3. **Dedicated qualification host:** obtain an isolated machine with
   forwarding disabled, trusted pinned official guest images, ext4
   state/journal capacity, and BMC/PDU power-cut control. This shared
   runner must not be repurposed (its forwarding is enabled and it carries
   unrelated workloads).
4. **Stage 2 qualification on the dedicated host:** provision the PR #1200
   guests from the pinned images, install the rc.26-class authenticated
   candidate, run `capture-installation` against the verified Sigstore
   identity, execute the A10.1 installed-release migration journey, the
   systemd denial tests, and the bounded ext4 power-loss matrix. Keep
   guest force-restart evidence labeled as *not* host power-loss evidence.
5. **Evidence discipline:** keep source/unit, protected CI, real-filesystem
   process, authenticated installed-release, and host power-loss categories
   distinct. Never turn NOT_RUN into PASS.

## Explicit non-goals

- No tag or release is created, moved, or published by this plan.
- No enabling of A10.1 migration publication in production binaries.
- No weakening of signed authority, D8/C1/C1.1, or anti-rollback checks.
- No PostgreSQL restore mutation, controller activation, PP.7/Araf work.
