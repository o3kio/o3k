# Fabric v3 O3K lifecycle integration record

Status: historical implementation record; the entries below are superseded by later candidate and campaign evidence

## Provenance

- Base product SHA: `4cdb50eddc41de8de1b78535950f6f9bf698f0dc`
- Base tree SHA: `08babcd839f3651472bd96b83fea77b16c8fec0b`
- Base branch: `fabric-v3-runtime`
- Remote base visibility: the SHA is not present on the remote; remote `fabric-v3-runtime` is `09ce9255604e943eaf1416d00c88f12e0862626a`, an ancestor of the base.
- New branch: `fabric-v3-o3k-lifecycle-gate-a`, created directly from the base SHA.
- Remote successor SHA: pending implementation commit and push; no acceptance testing before it is remotely resolvable.

## Issue and selected profile

Implement the supported O3K lifecycle integration required by the Fabric v3 Nested Conformance Gate A task. The evidence profile is the nested three-compute conformance profile; physical-host acceptance and PP.5 are explicit non-goals.

## Authority and boundaries

- Canonical service/domain: O3K Network and Compute orchestration in `o3kd`; canonical Network, AddressRealm, endpoint, binding, placement, and operation records remain authoritative.
- OpenStack adapter: Neutron-compatible Network/Subnet/Port API only at the existing API boundary.
- Authority mode: `o3k-implemented` control plane plus execution providers; Linux Fabric remains a bounded plan executor.
- Public operations/resources: network, subnet/AddressRealm, port/endpoint, server attachment, host Fabric enrollment, and internal realm reconciliation.
- Shared provider: pinned `o3kio/fabric` `fabric-plan`/`fabric-linux` contract is consumed as-is. Any material conflict with ADR-0186, SPEC-0049, or the accepted O3K contract is a stop condition.
- Durable state: reuse `o3k-store` SQLite/PostgreSQL abstractions, canonical Network tables, durable VNI binding, operation/journal, and existing generation fences. No second placement or retry authority.
- Cross-service workflow: compute placement/attachment waits on network realization according to existing operation outcome and compensation semantics; ambiguous mutation remains unknown until observed.

## Expected execution scope

- Cargo packages/binaries: `o3k-domain`, `o3k-store`, `o3k-network`, `o3k-network-protocol`, `o3k-api`, and `o3kd` as required by the discovered boundary.
- Expected source areas: canonical Fabric host identity model and repositories/migrations; host-to-agent relationship/target-aware dispatcher; deterministic realm-directory/participant/HER plan derivation; production network and compute lifecycle composition; bounded reconciliation and outcome recording.
- Expected tests: identity validation and persistence (SQLite and PostgreSQL where available), participant/HER derivation, distinct target dispatch and epoch fencing, partial failure/replay, lifecycle composition, deterministic plan identity, and focused nested three-host O3K-driven milestone.
- Normative inputs consulted: ADR-0168, ADR-0186, ADR-0176, SPEC-0033, SPEC-0049, `contracts/edge-fabric-stretched-l2.md`, and the repository authority/test-strategy documents. Constraints carried forward: canonical placement and identity remain in O3K; HER is derived only from the current endpoint directory; VNI is durable and generation fenced; provider observations are not authority; journal before mutation; no Geneve fallback; no secret material in canonical state.
- Public reference/provenance: pinned shared `o3kio/fabric` crates and their contract/version only; no private or non-public source is implementation input.

## Non-goals

No Fabric dataplane redesign, shared-provider semantic change, scheduler redesign, blind failure evacuation, PP.5 execution, Gate B physical acceptance, broad OpenStack parity, or unrelated service work.

## Known uncertainties and widening conditions

The current canonical endpoint rows do not themselves encode accepted compute host and placement generation, while compatibility port records carry a binding host. The implementation must use the existing accepted attachment/placement workflow as the source for that join, or stop if the required generation cannot be established. `AgentNodeSnapshot` is compute-agent lifecycle state and must not be overloaded with Fabric transport identity. Multi-host dispatch must resolve each command target independently and must have no static-endpoint fallback for v3. Scope may widen only where store/protocol/composition evidence proves these boundaries cannot otherwise be implemented safely.

## Validation ladder

First add focused fail-before tests for identity validation/persistence, complete participant/HER derivation, target separation/epoch fencing, and partial multi-host convergence. Then run package-level store/network/API/composition checks, PostgreSQL-required tests when configured, shared fabric conformance, and the narrow nested O3K-driven A/B/C milestone. Run workspace fmt/clippy/test and the broader Gate A suite only after the narrow milestone succeeds. Do not run PP.5 S1-S4.

## Defects and validation notes

- `PRODUCT_DEFECT`: the agent compute provider invokes `resolve` and then
  `resolve_artifacts`; the latter previously called the network resolver again.
  In v3 that repeats realm-plan mutations under the same operation/realm/host
  command identity but a newly computed deadline, which can produce a replay
  fingerprint conflict. Fixed by deriving config-drive network metadata from
  the already-resolved attachment input. A focused regression covers that
  derivation; the multi-host composition test also passes.
- `PRODUCT_DEFECT`: realm reconciliation treated the second endpoint on one
  accepted host as a conflicting host identity. Participant derivation now
  deduplicates matching identities and fails closed only on conflicting
  identity data. The multi-host composition regression now places two
  endpoints on compute-a while retaining endpoints on compute-b and compute-c.
- The first workspace test run failed because the SQLite reopen expectation
  omitted the newly durable port binding generation. Updated the expected
  generation and reran that test successfully.
- Historical status only: the `SUPPORTED_API_GAP`, guest credential
  `ENVIRONMENT_GAP`, and controller-restart reconciliation notes above describe
  earlier candidates. Later source-bound campaigns exercised supported HTTP
  lifecycle, deterministic guest provisioning, and controller restart on the
  current frozen product. They are not open blockers for this harness task.

## Historical acceptance failure ledger

The entries below preserve superseded failure evidence. They are resolved for
the current frozen product/harness profile; old runs remain failures and are
never converted into passing evidence.

| Historical issue | Failing identity and classification | Preserved evidence | Resolution |
| --- | --- | --- | --- |
| Supported HTTP lifecycle was not exercised | Product `4cdb50eddc41de8de1b78535950f6f9bf698f0dc`; `SUPPORTED_API_GAP` | The earlier composition-only result is retained in the original campaign records; no archive digest is asserted here because the source record did not include one. | Successor lifecycle coverage uses supported HTTP APIs; fresh three-host campaigns create network, subnet, ports, and servers through HTTP. Current product `e3f5ce764b4d7ee1bba34f645da8ec6c156bde99`. |
| Optional `config_drive=false` was mishandled | Product `ad741747cc9e772f429d011130452340ce2020ee`; `PRODUCT_DEFECT` | Failed candidate evidence retained with that candidate. | Fixed in product successor `ba23a65e312ae8755673e2af131937760b4fb248`; optional-create regressions pass. |
| iproute2 TAP subtype expected the wrong JSON field | Product `ad741747cc9e772f429d011130452340ce2020ee`; `ATTACHMENT_DEFECT` | Real-host `ip -j -d link` observation and failed candidate retained. | Product successor `ba23a65e312ae8755673e2af131937760b4fb248` recognizes `info_data.type=tap`; later TAP ownership validation is included in `e3f5ce764b4d7ee1bba34f645da8ec6c156bde99`. |
| QEMU could not traverse run-owned overlay storage | Product `ba23a65e312ae8755673e2af131937760b4fb248`; `HARNESS_GAP` | QEMU runner failure archive retained in the campaign evidence area. | Harness dynamically provisions QEMU access and preflights storage as the execution identity; product remained frozen. |
| Fabric DHCP authority/return path did not provide cross-host leases | Product `e4ca1805dc16839b855e969e7e17928a54cc211f`; `DATAPLANE_DEFECT` | Remote DHCP boundary captures and failed three-host runs retained under `/var/tmp/fabric-v3-remote-dhcp-boundary-*` and `/var/tmp/fabric-v3-minimal-three-host-*`. | Fixed in product successor `e3f5ce764b4d7ee1bba34f645da8ec6c156bde99`; fresh campaign reached A/B/C ACTIVE and DHCP DORA PASS. |
| Tenant-IPv4 SSH was used as mandatory guest command transport | Product `e3f5ce764b4d7ee1bba34f645da8ec6c156bde99`; `HARNESS_GAP` | `fabric-v3-minimal-three-host-20261008T-guestssh-knownhosts.tar.gz`, SHA-256 `46086f9924b3143232c9a0eca8499716a9aee18bb7d3438cb3f0edbe11ed3e7e`. | Replaced by the independent host-local IPv6 link-local command channel in the harness successor. |
| File-backed serial was mistaken for an interactive shell | Product `e3f5ce764b4d7ee1bba34f645da8ec6c156bde99`; `HARNESS_GAP` | `fabric-v3-minimal-three-host-20261008-serial-channel-183000.tar.gz`, SHA-256 `7d9febb2776556df649343ab7072b848494ce67c953a88f847c48c2e31c8f8bc`. | Live serial capability is classified from domain XML; the deterministic probe guest control path is host-local IPv6 link-local SSH. |
| Probe image exceeded the frozen image API upload limit | Product `e3f5ce764b4d7ee1bba34f645da8ec6c156bde99`; `SUPPORTED_API_GAP` | `fabric-v3-minimal-three-host-20261008T192033Z-localcontrol-01.tar.gz`, SHA-256 `b114210202063280c08c79bc457a7ce3e394123179779e1ad8b9da1434b41acf`. | Harness recipe now builds a pinned CirrOS 0.6.3 probe image, validates its source checksum and generated size against the 64 MiB product upload limit, and records the image/toolchain identities. The failed run remains a failure. |
| Host-local control capture logs were redirected before privilege elevation | Product `e3f5ce764b4d7ee1bba34f645da8ec6c156bde99`; `HARNESS_GAP` | Run `20261008T230000Z-localcontrol-03`, archive `/var/tmp/fabric-v3-minimal-three-host-20261008T230000Z-localcontrol-03.tar.gz`, SHA-256 `35ef2ed3b79b27f9a65d7de1a286e02cec90f0d26858f4977c9d1144a7b12bdb`; cleanup supplement `/var/tmp/fabric-v3-minimal-three-host-20261008T230000Z-localcontrol-03-cleanup-supplement.tar.gz`, SHA-256 `f47dc03a9ba91459f835794dc254edcf5f697d435f7cd36a9a21422da978fec3`, records ownership-checked domain and disk removal. | Capture launch now redirects from a privileged shell and proves both bounded captures are live before link-local SSH readiness probes. This run stopped after server A ACTIVE and before packet tests; it is not acceptance evidence. |
| Probe-image Dropbear started after a potentially blocking metadata lookup | Product `e3f5ce764b4d7ee1bba34f645da8ec6c156bde99`; `HARNESS_GAP` | Run `20261008T200500Z-localcontrol-04`, archive `/var/tmp/fabric-v3-minimal-three-host-20261008T200500Z-localcontrol-04.tar.gz`, SHA-256 `4f88769ca4dbef4f21ace6bd38fbeb3f2100e763d0cdca954c02cbeb3f7b2dfe`; diagnostic supplement `/var/tmp/fabric-v3-minimal-three-host-20261008T200500Z-localcontrol-04-diagnostic-supplement.tar.gz`, SHA-256 `7f066b544451a49182b1655dd6bd4366d3e4393d1a4cbc8ce0736e8ded4f1fbc`. The preserved serial log ends during the optional `169.254.169.254` metadata lookup, while bounded host-local SSH SYNs receive RST. No packet acceptance predicate ran. | Harness image recipe moves the existing Dropbear runlevel entry from `S50` to `S42`, after `S40-network` and before `S45-cirros-net-ds`. The rebuilt image booted the Dropbear init script before the optional metadata lookup; a new source-bound run is required. The failed archive remains unchanged. |
| Probe-image public key could not authenticate | Product `e3f5ce764b4d7ee1bba34f645da8ec6c156bde99`; `HARNESS_GAP` | Run `20261008T202100Z-guestcontrol-05`, archive `/var/tmp/fabric-v3-minimal-three-host-20261008T202100Z-guestcontrol-05.tar.gz`, SHA-256 `03935a3c4263ab915b73e2502543547e87a1bde75709c112b75e9a8ec007b353`; diagnostic supplement `/var/tmp/fabric-v3-minimal-three-host-20261008T202100Z-guestcontrol-05-diagnostic-supplement.tar.gz`, SHA-256 `c48a36d656d54e6c773ab69b40deb4cf1a68886cdffbe6562f09d418c49529e8`; recipe-fix validation `/var/tmp/fabric-v3-minimal-three-host-20261008T202100Z-guestcontrol-05-recipe-fix-validation.tar.gz`, SHA-256 `32633e53be79c52ceb5fbc1c9bd3de311eda7925c3005b165b3148b7f29df6df`. Server A reached `ACTIVE`; DHCP DORA passed; host-local route and SSH host-key scan passed; `true` failed with `Permission denied (publickey)`. No packet predicate ran. | The image recipe set the `cirros` key file to UID/GID 1000 but then `cpio --owner=0:0` rewrote every archived entry as root. The recipe now preserves source ownership, asserts that `authorized_keys` remains UID/GID 1000, and two same-input builds produced identical initramfs SHA-256 values. A fresh campaign is required. |
| Probe command wrapper invoked unavailable Bash | Product `e3f5ce764b4d7ee1bba34f645da8ec6c156bde99`; `HARNESS_GAP` | Run `20261008T204500Z-guestcontrol-06`, archive `/var/tmp/fabric-v3-minimal-three-host-20261008T204500Z-guestcontrol-06.tar.gz`, SHA-256 `b178aa3b42b1042a52da0964143f47adc397732c39b579b200a846bed2508802`. Server A reached `ACTIVE`, DHCP DORA and link-local host-key preflight passed; `true` returned `sh: bash: not found`. No packet predicate ran. | The guest command wrapper now invokes POSIX `sh`, available in the pinned CirrOS probe image, and removes its temporary command file using the image's `rm`. Failed `true` attempts preserve local bridge/Fabric namespace captures. A fresh campaign is required. |
| Outer SSH wrapper invoked unavailable Bash | Product `e3f5ce764b4d7ee1bba34f645da8ec6c156bde99`; `HARNESS_GAP` | Run `20261008T211000Z-guestcontrol-07`, archive `/var/tmp/fabric-v3-minimal-three-host-20261008T211000Z-guestcontrol-07.tar.gz`, SHA-256 `bb368a437da8dca6f2b92de4b81d1f92f95ef80729738932048549a9655be72f`. Server A reached `ACTIVE`; DHCP DORA passed; host-local IPv6 route, key scan, and local bridge capture succeeded; the independent Fabric namespace capture was empty; `true` failed with `sh: bash: not found`. No packet predicate ran. | The outer compute-host SSH command now uses POSIX `sh -c` as well as the guest-side command wrapper. The preserved captures show the control attempt on the local Realm bridge and no matching control packets in the Fabric namespace. A fresh campaign is required. |

Historical evidence archives are immutable. A future fix creates a new run ID
and archive; it does not update these records or revise the old classification.
