# o3k-araf-demo — PP.3 Araf demo deployment (o3k-demo-v1)

Deployment material for the PP.3 pinned compatibility tuple defined in
[`contracts/araf-compatibility-v1.yaml`](../../contracts/araf-compatibility-v1.yaml)
(`pp3_tuple`). O3K pins the tuple; Araf remains separately versioned and is
consumed only as digest-pinned OCI artifacts.

## Contents

- `compose.yaml` — the single-host demo stack (4 Araf services + demo IdP +
  loopback TLS proxy), all images digest-pinned, all resources labelled
  `o3k.io/pp-owner: o3k-araf-demo` for lifecycle ownership fencing.
- `nginx.conf` — TLS proxy vhosts for the four loopback demo names.
- `realm.json` — Keycloak realm template (clients without secrets; secrets
  are rendered in at install time into the 0600 state dir, never committed).

The orchestrator is [`packaging/o3k-araf-demo.sh`](../../packaging/o3k-araf-demo.sh).

## Trust model (frozen for PP.3)

- Araf BFFs run `ARAF_RUNTIME_PROFILE=production`,
  `ARAF_UPSTREAM_ADAPTER=o3k`; fixture mode is impossible in this profile.
- Araf OIDC is the per-surface confidential-client authorization-code + PKCE
  flow against a demo-scoped local IdP (Keycloak `start-dev`, embedded H2).
  This is not a production IdP claim.
- Browser/console/IdP/API traffic is HTTPS on loopback only, terminated by
  the demo TLS proxy with a locally minted demo CA
  (`/var/lib/o3k/araf-demo/tls/ca.crt`). Browser trust installation is PP.4
  scope; PP.3 evidence uses `--cacert`.
- `api.o3k.demo` terminates TLS and forwards to the O3K native API bound at
  `127.0.0.1:18080` (plain HTTP, loopback only). This is a documented local
  trusted hop, not a remote deployment pattern.
- o3kd OIDC federation is enabled by a marker-managed block in
  `/etc/o3k/o3kd.env` (`O3K_OIDC_*` + `O3K_TESTLAB_FEDERATED_*`, all shipped
  in the pinned O3K release). O3K readiness never depends on Araf.

## Lifecycle

```text
reset != uninstall != purge
```

- `install` — convergent; rerunning changes nothing when already installed.
- `uninstall` — removes containers/network and the o3kd federation block;
  preserves the state dir so reinstall converges on the same identities.
- `purge` — additionally removes state dir, session volumes, and the
  marker-managed `/etc/hosts` entries. Only `o3k-araf-demo`-labelled
  resources are ever deleted; no global prune commands are used.

## Non-goals

No source builds on the target (no Rust/Cargo/Node/pnpm), no Docker/Podman
duality (Docker Engine + Compose v2 only), no Araf multi-node HA
(o3kio/araf#106), no production-IdP or production-Araf claim.
