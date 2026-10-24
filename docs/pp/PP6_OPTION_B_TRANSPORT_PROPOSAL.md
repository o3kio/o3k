# PP.6 PostgreSQL Option B signer transport and trust amendment (PROPOSED)

Status: **PROPOSED — not accepted and not implemented**  
Scope: #1085 PostgreSQL backup adapter and #1087 PKI lifecycle  
Base: protected main `b50f537557bcc313a3663900b90572bd7b6f98f4`  
Accepted semantic authority: ADR-0189, ADR-0190, SPEC-0050 and the technical
approval at `9ce23ff81218e8e35d917ef6ee4478ae69e8f28e`.

## Bounded implementation plan

This amendment is a reviewable contract proposal only. It does not change the
accepted artifact format, signer authority, restore journal, fencing, or PKI
decisions; it supplies the missing transport and trust-document wire details
needed before production Option B code can be written.

Affected package is the PostgreSQL backup/signing boundary under `bins/o3k`.
No daemon, public O3K API, controller authority, or database schema is added.
The first implementation would be a test-only protocol validator and a
purpose-isolated software signer. A real HSM, custody, mTLS, revocation and
installed-release campaign remain separate evidence gates.

Selected profile: PostgreSQL 16 `o3k-small-edge-v1`. Canonical domain is Cloud
Kernel backup/trust, `o3k-implemented`, with a purpose-isolated external signing
authority; there is no OpenStack compatibility adapter. The only changed file
is this proposal. Relevant operations are backup-manifest signing and public
trust/revocation verification, never restore authorization or activation.
No target database, provider mutation, compensation or runtime process is
changed. Future execution dependencies are the isolated signer, PKCS#11 device,
mTLS identity authority, offline root/custodians and separate trust endpoint.

Repository mission, clean-implementation, architecture, normative-source and
test-strategy constraints remain applicable, alongside ADR-0165/0166/0167 and
the accepted PP.6 authorities named above. Reference input is the exact protected
repository and accepted technical revision, not a private implementation.
The evidence tier here is contract review; falsifiers are conflict with accepted
D1/D2 semantics, missing request bytes, ID/nonce reuse, expiry extension or
conflation of artifact, TLS and offline authorities. Workspace formatting,
Clippy and normal parallel tests remain required checks. Production code,
new backup formats, new authority scopes and HSM acceptance are explicit
non-goals. Widen scope only after review identifies a concrete missing field;
remaining uncertainties are listed for exact-revision human resolution below.

## Existing contract comparison

SPEC-0050 and the exact technical approval define the signer purpose, D1 bytes,
site/profile scope, PKCS#11 v3.0 Ed25519 key, TLS 1.3 mutual authentication,
request ID, 256-bit nonce, 15-minute expiry, replay behavior, offline trust
root, certificate fields, monotonic revocation and fail-closed rules.

The repository has no accepted signer request/response wire schema, mTLS
client/server identity profile, online-key certificate encoding, revocation-list
encoding, trust-distribution protocol, replay-ledger record, or stable signer
error vocabulary. `control-plane-backup-v1.proposed.schema.json` describes the
artifact, not this transport. `packaging/backup-trust.example.json` is local
installation configuration and its `revoked_key_ids` array is not a signed
revocation protocol.

## Smallest proposed wire contract

The proposed encoding is canonical RFC 8785 JSON UTF-8. No alternate encoding
is proposed. This draft identifies remaining acceptance questions below; it is
not yet a complete implementation schema. Unknown fields,
duplicate JSON keys, noncanonical encodings, oversized values and missing
required fields fail closed.

`SignerRequest` required fields:

* `protocol`: `o3k-pp6-signer-v1`;
* `purpose`: exactly `backup_manifest`;
* `request_id`: UUID text;
* `nonce`: exactly 32 random bytes, unpadded base64url;
* `artifact_id`: UUID text;
* `manifest`: the complete bounded canonical manifest object, including its
  member records and ciphertext metadata, supplied as the request's signed
  canonical JSON value (not merely a digest);
* `member_digests`: the complete path-sorted D1 digest entries, each carrying
  the bounded UTF-8 path and ciphertext/tag SHA-256 digest;
* `manifest_digest`: lowercase SHA-256 hex, recomputed by the signer from the
  canonical manifest bytes;
* `signature_input_digest`: lowercase SHA-256 hex, recomputed by the signer
  from the exact D1 domain prefix, manifest length, canonical manifest without
  signature, and concatenated member digest entries;
* `site_id`, `profile_id`: exact configured values;
* `key_id`: online signing certificate key ID;
* `issued_at`, `expires_at`: UTC timestamps with an exact 15-minute validity
  interval (subject only to an accepted bounded clock-skew allowance),
  authenticated through mTLS and immutable for the ledger record;
* `client_release`: exact release/source identity bound to the installed client.

The request body is authenticated by TLS client identity and the signer
recomputes both digests from the supplied bounded manifest and member entries.
A digest field is never trusted as a substitute for those bytes. The signer
rejects duplicate paths/nonces, oversized members, and any D1 input exceeding
the accepted artifact bounds before invoking the HSM.

The signer accepts a request only when its immutable `issued_at` is within the
accepted clock-skew window and `expires_at - issued_at` is exactly 15 minutes;
it does not extend the window based on retry or receipt time. The ledger stores
the signer receipt time and clock basis for audit/replay decisions.

`SignerResponse` required fields:

* `protocol`, `request_id`, `nonce`, `artifact_id`, `manifest_digest`, `key_id`;
* `signature`: exactly 64-byte Ed25519 signature, unpadded base64url;
* `certificate_id` and `revocation_sequence`;
* `replay`: `new` or `identical_retry`;
* `expires_at` and `server_time`.

The response is signed only over the accepted D1 input. Response metadata does
not authorize restore, journal transitions, fencing, release signing or
activation.

The signer maintains a durable ledger with unique constraints on both
`request_id` and `nonce` (independently and together). It stores the canonical
request bytes/digest, artifact and scope bindings, immutable `issued_at` and
`expires_at`, key ID, and a pending/completed response state. The completed
response is durably persisted before acknowledgement. A crash or lost response
leaves the request pending/unknown; the client must query the same immutable
request identity and never assume that signing succeeded. An identical request
returns the original signature before expiry. Any changed field, scope, digest,
artifact ID, request ID, or nonce for an existing ID/nonce returns
`replay-conflict` and never signs. Retention duration and pending-record
reconciliation remain acceptance questions. After immutable expiry, the
request is `request-expired`; a new artifact ID and recapture are required.

Stable fail-closed errors are: `unauthenticated-client`, `scope-denied`,
`purpose-denied`, `malformed-request`, `digest-mismatch`, `nonce-reuse`,
`replay-conflict`, `request-expired`, `key-revoked`, `trust-stale`,
`signer-unavailable`, `hsm-sign-failed`, and `publication-incomplete`.
Errors contain no paths, credentials, token material, SQL, or provider data.

## Trust-document proposal

The **online artifact-signing certificate**, issued by the separate offline
backup-trust root, is canonical JSON with exactly:
`format`, `key_id`, `public_key`, `purpose`, `site_id`, `profile_id`, `serial`,
`not_before`, `not_after`, and `issuer_key_id`; its root signature is carried
outside the signed object in a fixed `signature` field. `purpose` must equal
`backup_manifest`; validity is at most 90 days.

This artifact-signing certificate is distinct from the TLS server certificate,
TLS client certificate, and release-bound backup-client identity used for mTLS
authentication. Their certificate profiles, issuance authority, SANs, rotation,
and pinning are intentionally separate acceptance questions; possession of one
must not authorize the other.

The signed revocation list is canonical JSON with exactly `format`, `sequence`,
`issued_at`, `next_update`, `issuer_key_id`, and sorted `revoked` entries. Each
entry has `key_id`, `serial`, `reason`, and `revoked_at`. `next_update` is at
most 24 hours after issuance. The root signs the canonical object and the
verifier persists the highest sequence and its digest. Equal sequence with a
different digest is equivocation and fails closed; lower sequence, expired
list, missing root signature, unknown issuer, or unavailable required trust
state fails closed.

The distribution endpoint is read-only trust material delivery and is
administered separately from the signer. Transport authentication, endpoint
identity pinning, cache rules and release-manifest trust-anchor provisioning
must be accepted before production use. No private key, HSM handle, token or
credential is present in the artifact, request, response, logs or evidence.

## Acceptance checklist (exact revision required)

Human acceptance must identify the exact amendment revision and explicitly
approve or reject:

1. This concrete canonical-JSON encoding and canonicalization rules (no
   alternate protobuf encoding is proposed here);
2. TLS 1.3 mTLS identity and release/site/profile authorization;
3. request/response fields, digest recomputation and stable errors;
4. durable replay-ledger uniqueness on each ID and nonce, retention, pending
   reconciliation, and crash atomicity;
5. certificate and revocation-list schemas, root signature and sequence rules;
6. trust-distribution endpoint, cache expiry and fail-closed behavior;
7. PKCS#11 mechanism/key-usage restriction and signer authority boundary;
8. rotation, compromise revocation, two-of-three custody and recovery;
9. software-signer negative tests and exact evidence binding;
10. TLS client/server certificate profiles, release-client identity binding,
    clock-skew policy, and real HSM, mTLS, custody, revocation and
    installed-release evidence gates.

Until all applicable items are accepted, only a test signer may be used. A
software key is protocol evidence and must never be labeled HSM qualification.
Signer availability or trust failure blocks backup publication; it never falls
back to SQLite Option A or an embedded PostgreSQL key.

