"""Falsifiable, non-runtime PP.6 contract decision prototypes.

These models test bounds and authority decisions. They do not implement
cryptography, a backup service, database locking, Redfish, or restore.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from dataclasses import dataclass
from pathlib import Path

GIB = 1024**3
PHASES = (
    "PREFLIGHTED", "SOURCE_FENCED", "TARGET_RESERVED", "STAGING",
    "DATABASE_RESTORED", "FILES_RESTORED", "TARGET_FENCED", "STARTED",
    "RECONCILED", "COMMITTED",
)


def reservation(source_bytes: int, available_bytes: int) -> int:
    if source_bytes < 0 or source_bytes > 4 * GIB:
        raise ValueError("source_bound")
    required = max(2 * source_bytes + GIB, 6 * GIB)
    if required > 9 * GIB or available_bytes < required:
        raise ValueError("space_unavailable")
    return required


def signer_authorize(*, backend: str, purpose: str, profile: str, site: str,
                     configured_profile: str, configured_site: str,
                     client_identity_valid: bool = True,
                     key_cert_valid: bool = True, key_revoked: bool = False,
                     now: int = 0, expires_at: int = 900) -> bool:
    return (backend == "postgresql" and purpose == "backup_manifest"
            and profile == "o3k-small-edge-v1"
            and profile == configured_profile and site == configured_site
            and client_identity_valid and key_cert_valid and not key_revoked
            and now <= expires_at and expires_at - now <= 900)


def selected_signing_mode(*, backend: str, profile: str) -> str | None:
    if backend == "postgresql" and profile == "o3k-small-edge-v1":
        return "online_hsm"
    if backend == "sqlite" and profile in ("o3k-small-edge-v1", "o3k-demo-v1"):
        return "offline_operator"
    return None


def capture_excluded(*, local_openers_stopped: bool, startup_lock_held: bool,
                     ingress_acl_backup_only: bool, hba_rules_valid: bool,
                     hba_reload_complete: bool, writer_logins_disabled: bool,
                     pools_stopped: bool, dump_sessions: int,
                     writer_sessions: int, unapproved_sessions: int,
                     generation_matches: bool,
                     local_socket_reconnect_denied: bool) -> bool:
    return (local_openers_stopped and startup_lock_held
            and ingress_acl_backup_only and hba_rules_valid
            and hba_reload_complete and writer_logins_disabled and pools_stopped
            and dump_sessions == 1 and writer_sessions == 0
            and unapproved_sessions == 0 and generation_matches
            and local_socket_reconnect_denied)


@dataclass(frozen=True)
class FenceEvidence:
    source: str
    site: str
    target: str
    operation: str
    observed_at: int
    power_state: str
    authenticated_tls: bool
    tls_version: str
    serial_matches: bool
    actor_authorized: bool
    certificate_fingerprint: str
    expected_fingerprint: str
    evidence_key_id: str
    expected_evidence_key_id: str
    recovery_acl_held: bool
    monitor_alive: bool
    monitor_lease_expires_at: int
    challenge: str
    expected_challenge: str
    challenge_unused: bool
    monitor_sequence: int
    expected_monitor_sequence: int
    journal_hash: str
    expected_journal_hash: str
    lease_journal_hash_matches: bool
    nonce_unused: bool


def fence_valid(e: FenceEvidence, *, source: str, site: str, target: str,
                operation: str, now: int) -> bool:
    age = now - e.observed_at
    return (e.source == source and e.site == site and e.target == target
            and e.operation == operation and 0 <= age <= 300
            and e.power_state == "Off" and e.authenticated_tls
            and e.tls_version == "TLSv1.3" and e.serial_matches and e.actor_authorized
            and e.certificate_fingerprint == e.expected_fingerprint
            and e.evidence_key_id == e.expected_evidence_key_id
            and e.recovery_acl_held and e.monitor_alive
            and 0 <= e.monitor_lease_expires_at - now <= 2
            and e.challenge == e.expected_challenge and e.challenge_unused
            and e.monitor_sequence == e.expected_monitor_sequence
            and e.journal_hash == e.expected_journal_hash
            and e.lease_journal_hash_matches and e.nonce_unused)


def accept_transition(*, sequence: int, previous_hash: str,
                      expected_sequence: int, expected_previous_hash: str,
                      phase: str, signature_verified: bool) -> bool:
    if phase not in PHASES or not signature_verified:
        return False
    if sequence != expected_sequence or previous_hash != expected_previous_hash:
        return False
    return True


def validate_toc(actual: list[str], expected: set[str], forbidden: set[str]) -> bool:
    if len(actual) != len(set(actual)):
        return False
    listed = set(actual)
    return listed == expected and not (listed & forbidden)


def validate_inventory(actual: dict[str, set[str]],
                       approved: dict[str, set[str]]) -> bool:
    return actual == approved


def accept_signing_retry(request_id: str, nonce: str, scope: str, payload: bytes,
                         ledger: dict[tuple[str, str], tuple[str, bytes]]) -> bool:
    prior = ledger.get((request_id, nonce))
    candidate = (scope, payload)
    if prior is not None:
        return prior == candidate
    ledger[(request_id, nonce)] = candidate
    return True


def manifest_nonce_unique(members: list[dict[str, object]]) -> bool:
    nonces = [m.get("nonce") for m in members]
    return all(isinstance(n, str) for n in nonces) and len(nonces) == len(set(nonces))


def consume_activation_nonce(*, signed_boot_id: str, current_boot_id: str,
                             launch_nonce: str, consumed_nonces: set[str],
                             consume_lock: Lock, signed_started: bool,
                             fresh_fence: bool) -> bool:
    if (not signed_started or not fresh_fence or signed_boot_id != current_boot_id
            or not launch_nonce):
        return False
    with consume_lock:  # models the durable journal's atomic compare-and-consume
        if launch_nonce in consumed_nonces:
            return False
        consumed_nonces.add(launch_nonce)
        return True


def enough_custodians(present: int) -> bool:
    return present >= 2 and present <= 3


def trust_state_valid(*, available: bool, now: int, next_update: int,
                      sequence: int, sequence_digest: str,
                      highest_seen_sequence: int,
                      highest_seen_digest: str) -> bool:
    return (available and now <= next_update
            and (sequence > highest_seen_sequence
                 or (sequence == highest_seen_sequence
                     and sequence_digest == highest_seen_digest)))


def agent_certificate_accepted(*, issuer_id: str, trusted_issuer_id: str,
                               serial: str, revoked_serials: set[str],
                               not_after: int, now: int,
                               certificate_fingerprint: str,
                               enrolled_fingerprint: str) -> bool:
    """Bounded verifier predicate for the existing certificate identity.

    This models the PP.6 lifecycle authority only: the issuer/trust source and
    certificate-bound agent identity are inputs, while private keys never
    enter the predicate or its evidence.
    """
    return (bool(issuer_id) and issuer_id == trusted_issuer_id and bool(serial)
            and serial not in revoked_serials and now < not_after
            and bool(certificate_fingerprint)
            and certificate_fingerprint == enrolled_fingerprint)


def renewal_permitted(*, now: int, not_after: int, renewal_window: int,
                      issuer_available: bool, replacement_trust_ready: bool,
                      old_serial_revoked: bool) -> bool:
    """Renew before expiry, with issuer/trust readiness and old-key retirement."""
    return (issuer_available and replacement_trust_ready
            and now < not_after and not_after - now <= renewal_window
            and old_serial_revoked)


def lifecycle_evidence_has_no_sensitive_markers(payload: str) -> bool:
    """Reject known sensitive markers in serialized lifecycle evidence.

    This is a contract predicate, not a comprehensive content sanitizer.
    """
    forbidden = ("PRIVATE KEY", "BEGIN CERTIFICATE", "bearer", "enrollment_secret",
                 "client_secret", "token")
    lowered = payload.lower()
    return not any(marker.lower() in lowered for marker in forbidden)


# PROPOSED amendment A10. These predicates model a proposed contract only;
# they are not accepted authority and must not be cited as such.
INACTIVE_PHASES = (
    "TARGET_RESERVED_INACTIVE", "STAGING_INACTIVE",
    "DATABASE_RESTORED_INACTIVE", "FILES_RESTORED_INACTIVE",
    "INACTIVE_VERIFIED",
)
INACTIVE_TRANSITIONS = {
    "PREFLIGHTED": {"TARGET_RESERVED_INACTIVE", "ABORTED"},
    "TARGET_RESERVED_INACTIVE": {"STAGING_INACTIVE", "ABORTED", "QUARANTINED"},
    "STAGING_INACTIVE": {"DATABASE_RESTORED_INACTIVE", "FAILED_RECOVERABLE",
                         "QUARANTINED"},
    "DATABASE_RESTORED_INACTIVE": {"FILES_RESTORED_INACTIVE",
                                   "FAILED_RECOVERABLE", "QUARANTINED"},
    "FILES_RESTORED_INACTIVE": {"INACTIVE_VERIFIED", "FAILED_RECOVERABLE",
                                "QUARANTINED"},
    "FAILED_RECOVERABLE": {"DISCARDED", "QUARANTINED"},
    "QUARANTINED": {"DISCARDED"},
}
ACTIVATION_ONLY_PHASES = {
    "SOURCE_FENCED", "TARGET_RESERVED", "STAGING", "DATABASE_RESTORED",
    "FILES_RESTORED", "TARGET_FENCED", "STARTED", "RECONCILED", "COMMITTED",
}


def inactive_profile_permitted(*, profile: str, backend: str, deployment: str,
                               policy_enabled: bool) -> bool:
    return (profile == "o3k-small-edge-v1" and backend == "postgresql"
            and deployment == "virtualized" and policy_enabled)


def resume_preconditions_permitted(*, branch: str,
                                  target_identity_matches: bool,
                                  target_observed: bool,
                                  target_state_attributable: bool,
                                  target_empty: bool,
                                  first_target_mutation_pending: bool,
                                  fresh_fence: bool,
                                  signed_installation_policy: bool) -> bool:
    """Model D12 resume gates for existing activation and proposed A10."""
    if (not target_identity_matches or not target_observed
            or not target_state_attributable):
        return False
    if first_target_mutation_pending and not target_empty:
        return False
    if branch == "activation":
        return fresh_fence
    if branch == "inactive":
        return signed_installation_policy
    return False


def resume_step_disposition(*, outcome_known_complete: bool,
                            outcome_unknown: bool,
                            operation_idempotent: bool) -> str:
    """Unknown non-idempotent work must quarantine rather than be replayed."""
    if outcome_known_complete:
        return "ADVANCE"
    if operation_idempotent:
        return "RETRY"
    if outcome_unknown:
        return "QUARANTINE"
    return "QUARANTINE"


def accept_inactive_transition(*, sequence: int, previous_hash: str,
                               expected_sequence: int,
                               expected_previous_hash: str,
                               recorded_branch: str | None,
                               from_phase: str, to_phase: str,
                               signature_verified: bool, profile: str,
                               backend: str, deployment: str,
                               policy_enabled: bool,
                               verification_bound: bool = False) -> bool:
    """PROPOSED A10 policy model; not accepted contract authority."""
    if not signature_verified:
        return False
    if sequence != expected_sequence or previous_hash != expected_previous_hash:
        return False
    if recorded_branch is None:
        if from_phase != "PREFLIGHTED":
            return False
    elif recorded_branch != "inactive":
        return False
    if not inactive_profile_permitted(profile=profile, backend=backend,
                                      deployment=deployment,
                                      policy_enabled=policy_enabled):
        return False
    if from_phase in ACTIVATION_ONLY_PHASES or to_phase in ACTIVATION_ONLY_PHASES:
        return False
    if to_phase not in INACTIVE_TRANSITIONS.get(from_phase, set()):
        return False
    if to_phase == "INACTIVE_VERIFIED" and not verification_bound:
        return False
    return True


class ProposedInactiveMaterializationTests(unittest.TestCase):
    """PROPOSED A10 tests only; they do not make the amendment accepted."""

    def kwargs(self, **overrides):
        base = dict(sequence=2, previous_hash="p" * 64,
                    expected_sequence=2, expected_previous_hash="p" * 64,
                    recorded_branch=None, from_phase="PREFLIGHTED",
                    to_phase="TARGET_RESERVED_INACTIVE",
                    signature_verified=True,
                    profile="o3k-small-edge-v1", backend="postgresql",
                    deployment="virtualized", policy_enabled=True)
        base.update(overrides)
        return base

    def test_profile_and_policy_restriction(self):
        self.assertTrue(accept_inactive_transition(**self.kwargs()))
        for field, value in (("profile", "o3k-demo-v1"),
                             ("backend", "sqlite"),
                             ("deployment", "physical"),
                             ("policy_enabled", False)):
            with self.subTest(field=field):
                self.assertFalse(accept_inactive_transition(
                    **self.kwargs(**{field: value})))

    def test_resume_keeps_fence_for_activation_and_uses_policy_for_inactive(self):
        common = dict(target_identity_matches=True, target_observed=True,
                      target_state_attributable=True,
                      target_empty=True, first_target_mutation_pending=True,
                      signed_installation_policy=True)
        self.assertTrue(resume_preconditions_permitted(
            branch="activation", fresh_fence=True, **common))
        self.assertFalse(resume_preconditions_permitted(
            branch="activation", fresh_fence=False, **common))
        self.assertTrue(resume_preconditions_permitted(
            branch="inactive", fresh_fence=False, **common))
        self.assertFalse(resume_preconditions_permitted(
            branch="inactive", fresh_fence=True,
            **{**common, "signed_installation_policy": False}))

    def test_resume_requires_empty_target_only_before_first_mutation(self):
        common = dict(branch="inactive", target_identity_matches=True,
                      target_observed=True, target_state_attributable=True,
                      fresh_fence=False,
                      signed_installation_policy=True)
        # First mutation must still see the exact fresh empty target.
        self.assertFalse(resume_preconditions_permitted(
            **common, target_empty=False, first_target_mutation_pending=True))
        # After this operation mutated the target, resume observes that same
        # target; non-emptiness alone is not a reason to discard or overwrite it.
        self.assertTrue(resume_preconditions_permitted(
            **common, target_empty=False, first_target_mutation_pending=False))
        self.assertFalse(resume_preconditions_permitted(
            **{**common, "target_identity_matches": False},
            target_empty=False, first_target_mutation_pending=False))
        self.assertFalse(resume_preconditions_permitted(
            **{**common, "target_observed": False},
            target_empty=False, first_target_mutation_pending=False))
        self.assertFalse(resume_preconditions_permitted(
            **{**common, "target_state_attributable": False},
            target_empty=False, first_target_mutation_pending=False))

    def test_resume_never_replays_unknown_pg_restore(self):
        self.assertEqual(resume_step_disposition(
            outcome_known_complete=False, outcome_unknown=True,
            operation_idempotent=False), "QUARANTINE")
        self.assertEqual(resume_step_disposition(
            outcome_known_complete=True, outcome_unknown=False,
            operation_idempotent=False), "ADVANCE")
        self.assertEqual(resume_step_disposition(
            outcome_known_complete=False, outcome_unknown=True,
            operation_idempotent=True), "RETRY")

    def test_inactive_branch_reaches_only_inactive_verified(self):
        chain = [
            ("PREFLIGHTED", "TARGET_RESERVED_INACTIVE"),
            ("TARGET_RESERVED_INACTIVE", "STAGING_INACTIVE"),
            ("STAGING_INACTIVE", "DATABASE_RESTORED_INACTIVE"),
            ("DATABASE_RESTORED_INACTIVE", "FILES_RESTORED_INACTIVE"),
            ("FILES_RESTORED_INACTIVE", "INACTIVE_VERIFIED"),
        ]
        for index, (source, target) in enumerate(chain, start=2):
            with self.subTest(phase=target):
                self.assertTrue(accept_inactive_transition(
                    **self.kwargs(
                        sequence=index, expected_sequence=index,
                        recorded_branch="inactive", from_phase=source,
                        to_phase=target,
                        verification_bound=(target == "INACTIVE_VERIFIED"))))
        self.assertEqual({target for _, target in chain}, set(INACTIVE_PHASES))
        for forbidden in ACTIVATION_ONLY_PHASES:
            with self.subTest(forbidden=forbidden):
                self.assertFalse(accept_inactive_transition(
                    **self.kwargs(recorded_branch="inactive",
                                  from_phase="INACTIVE_VERIFIED",
                                  to_phase=forbidden)))

    def test_inactive_branch_rejects_cross_branch_switch_and_unsigned_records(self):
        self.assertFalse(accept_inactive_transition(
            **self.kwargs(recorded_branch="activation")))
        self.assertFalse(accept_inactive_transition(
            **self.kwargs(recorded_branch=None,
                          from_phase="TARGET_RESERVED_INACTIVE",
                          to_phase="STAGING_INACTIVE")))
        self.assertFalse(accept_inactive_transition(
            **self.kwargs(signature_verified=False)))
        self.assertFalse(accept_inactive_transition(
            **self.kwargs(from_phase="SOURCE_FENCED",
                          to_phase="TARGET_RESERVED_INACTIVE")))
        self.assertFalse(accept_inactive_transition(
            **self.kwargs(sequence=3)))
        self.assertFalse(accept_inactive_transition(
            **self.kwargs(previous_hash="f" * 64)))
        self.assertFalse(accept_inactive_transition(
            **self.kwargs(recorded_branch="inactive",
                          from_phase="FILES_RESTORED_INACTIVE",
                          to_phase="INACTIVE_VERIFIED",
                          verification_bound=False)))
        self.assertTrue(accept_inactive_transition(
            **self.kwargs(recorded_branch="inactive",
                          from_phase="FILES_RESTORED_INACTIVE",
                          to_phase="INACTIVE_VERIFIED",
                          verification_bound=True)))


class ContractDecisionPrototypeTests(unittest.TestCase):
    def test_d9_exact_reservation_edges_and_failures(self):
        self.assertEqual(reservation(4 * GIB, 9 * GIB), 9 * GIB)
        self.assertEqual(reservation(0, 6 * GIB), 6 * GIB)
        with self.assertRaisesRegex(ValueError, "source_bound"):
            reservation(4 * GIB + 1, 20 * GIB)
        with self.assertRaisesRegex(ValueError, "space_unavailable"):
            reservation(4 * GIB, 9 * GIB - 1)

    def test_d2_online_signer_scope_and_forbidden_authorities(self):
        args = dict(backend="postgresql", profile="o3k-small-edge-v1", site="site-17",
                    configured_profile="o3k-small-edge-v1", configured_site="site-17")
        self.assertTrue(signer_authorize(purpose="backup_manifest", **args))
        self.assertFalse(signer_authorize(
            purpose="backup_manifest", **{**args, "backend": "sqlite"}))
        for forbidden in ("restore", "journal", "fence", "activation", "release"):
            self.assertFalse(signer_authorize(purpose=forbidden, **args))
        self.assertFalse(signer_authorize(
            purpose="backup_manifest", backend="postgresql", profile="o3k-demo-v1", site="site-17",
            configured_profile="o3k-small-edge-v1", configured_site="site-17"))
        self.assertFalse(signer_authorize(
            purpose="backup_manifest", backend="postgresql", profile="o3k-small-edge-v1", site="other",
            configured_profile="o3k-small-edge-v1", configured_site="site-17"))
        for extra in ({"client_identity_valid": False}, {"key_cert_valid": False},
                      {"key_revoked": True}, {"now": 901, "expires_at": 900},
                      {"now": 0, "expires_at": 901}):
            self.assertFalse(signer_authorize(purpose="backup_manifest", **args, **extra))
        self.assertTrue(enough_custodians(2))
        self.assertTrue(enough_custodians(3))
        self.assertFalse(enough_custodians(1))
        self.assertEqual(selected_signing_mode(
            backend="postgresql", profile="o3k-small-edge-v1"), "online_hsm")
        self.assertEqual(selected_signing_mode(
            backend="sqlite", profile="o3k-small-edge-v1"), "offline_operator")
        self.assertEqual(selected_signing_mode(
            backend="sqlite", profile="o3k-demo-v1"), "offline_operator")
        self.assertIsNone(selected_signing_mode(
            backend="mysql", profile="o3k-small-edge-v1"))

    def test_d2_exact_retry_is_idempotent_and_replay_conflict_fails(self):
        ledger = {}
        scope = "site-17/postgresql/o3k-small-edge-v1"
        self.assertTrue(accept_signing_retry("req-1", "nonce-1", scope, b"manifest-A", ledger))
        self.assertTrue(accept_signing_retry("req-1", "nonce-1", scope, b"manifest-A", ledger))
        self.assertFalse(accept_signing_retry("req-1", "nonce-1", scope, b"manifest-B", ledger))
        self.assertFalse(accept_signing_retry(
            "req-1", "nonce-1", "site-18/postgresql/o3k-small-edge-v1", b"manifest-A", ledger))

    def test_d2_revocation_state_must_be_fresh_and_monotonic(self):
        args = dict(now=10, next_update=10, sequence=4, sequence_digest="digest-4",
                    highest_seen_sequence=4, highest_seen_digest="digest-4")
        self.assertTrue(trust_state_valid(available=True, **args))
        self.assertFalse(trust_state_valid(available=False, **args))
        self.assertFalse(trust_state_valid(available=True, **{**args, "now": 11}))
        self.assertFalse(trust_state_valid(available=True, **{**args, "sequence": 3}))
        self.assertFalse(trust_state_valid(
            available=True, **{**args, "sequence_digest": "equivocated-digest"}))
        self.assertTrue(trust_state_valid(
            available=True, **{**args, "sequence": 5, "sequence_digest": "digest-5"}))

    def test_d3_agent_identity_rejects_expired_revoked_replaced_or_wrong_issuer(self):
        args = dict(issuer_id="site-issuer-v1", trusted_issuer_id="site-issuer-v1",
                    serial="agent-serial-1", revoked_serials=set(), not_after=100,
                    now=10, certificate_fingerprint="fp-new",
                    enrolled_fingerprint="fp-new")
        self.assertTrue(agent_certificate_accepted(**args))
        for change in (
            {"now": 100},
            {"revoked_serials": {"agent-serial-1"}},
            {"certificate_fingerprint": "fp-old"},
            {"issuer_id": "other-site-issuer"},
            {"trusted_issuer_id": "other-site-issuer"},
            {"issuer_id": "", "trusted_issuer_id": ""},
        ):
            with self.subTest(change=change):
                self.assertFalse(agent_certificate_accepted(**{**args, **change}))

    def test_d3_renewal_requires_overlap_window_trust_and_old_serial_retirement(self):
        args = dict(now=80, not_after=100, renewal_window=25,
                    issuer_available=True, replacement_trust_ready=True,
                    old_serial_revoked=True)
        self.assertTrue(renewal_permitted(**args))
        for change in (
            {"now": 10},
            {"issuer_available": False},
            {"replacement_trust_ready": False},
            {"old_serial_revoked": False},
            {"not_after": 110},
        ):
            with self.subTest(change=change):
                self.assertFalse(renewal_permitted(**{**args, **change}))

    def test_d3_evidence_rejects_known_sensitive_markers(self):
        self.assertTrue(lifecycle_evidence_has_no_sensitive_markers(
            '{"issuer_id":"site-issuer-v2","serial":"s2","result":"rejected"}'))
        for secret in ("-----BEGIN PRIVATE KEY-----", "BEGIN CERTIFICATE",
                       "bearer abc", "enrollment_secret=abc", "client_secret=abc",
                       "token=abc"):
            with self.subTest(secret=secret):
                self.assertFalse(lifecycle_evidence_has_no_sensitive_markers(secret))

    def test_manifest_schema_binds_site_plaintext_size_and_unique_nonce(self):
        schema = json.loads((Path(__file__).parents[1] / "contracts" /
                             "control-plane-backup-v1.proposed.schema.json").read_text())
        self.assertIn("site_id", schema["required"])
        member = schema["properties"]["members"]["items"]
        self.assertIn("plaintext_size_bytes", member["required"])
        self.assertIn("nonce", member["required"])
        self.assertTrue(manifest_nonce_unique([{"nonce": "AAAAAAAAAAAAAAAA"},
                                               {"nonce": "BBBBBBBBBBBBBBBB"}]))
        self.assertFalse(manifest_nonce_unique([{"nonce": "AAAAAAAAAAAAAAAA"},
                                                {"nonce": "AAAAAAAAAAAAAAAA"}]))

    def test_manifest_schema_encodes_d9_bounds_and_d13_mapping(self):
        schema = json.loads((Path(__file__).parents[1] / "contracts" /
                             "control-plane-backup-v1.proposed.schema.json").read_text())
        self.assertEqual(schema["properties"]["members"]["maxItems"], 64)
        member = schema["properties"]["members"]["items"]["properties"]
        self.assertEqual(member["plaintext_size_bytes"]["maximum"], 1024**3)
        self.assertEqual(member["size_bytes"]["maximum"], 1024**3 + 16)
        inventory = schema["properties"]["state_inventory"]["items"]
        self.assertEqual(inventory["$ref"], "#/$defs/repository_inventory_entry")
        entry = schema["$defs"]["repository_inventory_entry"]
        self.assertIn("repository_id", entry["required"])
        self.assertIn("sqlite_objects", entry["required"])
        self.assertIn("postgres_objects", entry["required"])
        self.assertIn("migration_ids", entry["required"])
        kinds = schema["$defs"]["catalog_object"]["properties"]["kind"]["enum"]
        self.assertTrue({"index", "constraint", "function", "trigger"}.issubset(kinds))
        self.assertIn("definition_sha256", schema["$defs"]["catalog_object"]["required"])

    def test_d4_local_flock_alone_cannot_exclude_remote_postgres_writers(self):
        self.assertFalse(capture_excluded(
            local_openers_stopped=True, startup_lock_held=True,
            ingress_acl_backup_only=False, hba_rules_valid=True,
            hba_reload_complete=True, writer_logins_disabled=True, pools_stopped=True,
            dump_sessions=1, writer_sessions=1,
            unapproved_sessions=1, generation_matches=True,
            local_socket_reconnect_denied=True))
        self.assertFalse(capture_excluded(
            local_openers_stopped=True, startup_lock_held=True,
            ingress_acl_backup_only=True, hba_rules_valid=True,
            hba_reload_complete=True, writer_logins_disabled=True, pools_stopped=True,
            dump_sessions=1, writer_sessions=1,
            unapproved_sessions=0, generation_matches=True,
            local_socket_reconnect_denied=True))
        self.assertFalse(capture_excluded(
            local_openers_stopped=True, startup_lock_held=True,
            ingress_acl_backup_only=True, hba_rules_valid=True,
            hba_reload_complete=True, writer_logins_disabled=True, pools_stopped=True,
            dump_sessions=1, writer_sessions=0,
            unapproved_sessions=1, generation_matches=False,
            local_socket_reconnect_denied=True))
        self.assertFalse(capture_excluded(
            local_openers_stopped=True, startup_lock_held=True,
            ingress_acl_backup_only=True, hba_rules_valid=True,
            hba_reload_complete=True, writer_logins_disabled=True, pools_stopped=True,
            dump_sessions=0, writer_sessions=0,
            unapproved_sessions=0, generation_matches=True,
            local_socket_reconnect_denied=True))
        self.assertFalse(capture_excluded(
            local_openers_stopped=True, startup_lock_held=True,
            ingress_acl_backup_only=True, hba_rules_valid=True,
            hba_reload_complete=True, writer_logins_disabled=True, pools_stopped=True,
            dump_sessions=1, writer_sessions=0, unapproved_sessions=0,
            generation_matches=True, local_socket_reconnect_denied=False))
        self.assertTrue(capture_excluded(
            local_openers_stopped=True, startup_lock_held=True,
            ingress_acl_backup_only=True, hba_rules_valid=True,
            hba_reload_complete=True, writer_logins_disabled=True, pools_stopped=True,
            dump_sessions=1, writer_sessions=0, unapproved_sessions=0,
            generation_matches=True, local_socket_reconnect_denied=True))

    def test_d7_fence_is_bound_fresh_authenticated_and_off(self):
        good = FenceEvidence(
            source="src-1", site="site-1", target="target-1", operation="op-1",
            observed_at=700, power_state="Off", authenticated_tls=True,
            tls_version="TLSv1.3", serial_matches=True, actor_authorized=True,
            certificate_fingerprint="bmc-fp", expected_fingerprint="bmc-fp",
            evidence_key_id="evidence-key-1", expected_evidence_key_id="evidence-key-1",
            recovery_acl_held=True, monitor_alive=True,
            monitor_lease_expires_at=1002,
            challenge="challenge-1", expected_challenge="challenge-1",
            challenge_unused=True, monitor_sequence=7, expected_monitor_sequence=7,
            journal_hash="journal-hash-7", expected_journal_hash="journal-hash-7",
            lease_journal_hash_matches=True, nonce_unused=True)
        self.assertTrue(fence_valid(good, source="src-1", site="site-1",
                                    target="target-1", operation="op-1", now=1000))
        for field, value in (("observed_at", 699), ("power_state", "On"),
                             ("authenticated_tls", False), ("tls_version", "TLSv1.2"),
                             ("serial_matches", False),
                             ("actor_authorized", False),
                             ("certificate_fingerprint", "wrong-fp"),
                             ("evidence_key_id", "wrong-key"),
                             ("recovery_acl_held", False), ("monitor_alive", False),
                             ("monitor_lease_expires_at", 1003),
                             ("challenge", "replayed-challenge"),
                             ("challenge_unused", False),
                             ("monitor_sequence", 6),
                             ("journal_hash", "prior-journal-hash"),
                             ("lease_journal_hash_matches", False),
                             ("nonce_unused", False), ("target", "foreign")):
            with self.subTest(field=field):
                altered = FenceEvidence(**{**good.__dict__, field: value})
                self.assertFalse(fence_valid(altered, source="src-1", site="site-1",
                                             target="target-1", operation="op-1", now=1000))

    def test_d8_boot_binding_and_single_use_activation_nonce(self):
        consumed = set()
        kwargs = dict(signed_boot_id="boot-A", current_boot_id="boot-A",
                      launch_nonce="launch-1", consumed_nonces=consumed,
                      consume_lock=Lock(), signed_started=True, fresh_fence=True)
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: consume_activation_nonce(**kwargs), range(16)))
        self.assertEqual(sum(results), 1)
        self.assertIn("launch-1", consumed)
        self.assertFalse(consume_activation_nonce(**kwargs))  # restart/replay
        self.assertFalse(consume_activation_nonce(**{**kwargs, "launch_nonce": "launch-2",
                                                     "current_boot_id": "boot-B"}))
        self.assertFalse(consume_activation_nonce(**{**kwargs, "launch_nonce": "launch-3",
                                                     "fresh_fence": False}))

    def test_d8_unsigned_replay_and_forked_journal_records_fail(self):
        parent = hashlib.sha256(b"signed record 1").hexdigest()
        self.assertTrue(accept_transition(sequence=2, previous_hash=parent,
                                          expected_sequence=2,
                                          expected_previous_hash=parent,
                                          phase="SOURCE_FENCED",
                                          signature_verified=True))
        self.assertFalse(accept_transition(sequence=2, previous_hash=parent,
                                           expected_sequence=2,
                                           expected_previous_hash=parent,
                                           phase="SOURCE_FENCED",
                                           signature_verified=False))
        self.assertFalse(accept_transition(sequence=1, previous_hash=parent,
                                           expected_sequence=2,
                                           expected_previous_hash=parent,
                                           phase="SOURCE_FENCED",
                                           signature_verified=True))
        self.assertFalse(accept_transition(sequence=2, previous_hash="fork",
                                           expected_sequence=2,
                                           expected_previous_hash=parent,
                                           phase="SOURCE_FENCED",
                                           signature_verified=True))

    def test_d10_toc_requires_complete_unique_exact_inventory(self):
        expected = {"TABLE public resources", "TABLE DATA public resources",
                    "SEQUENCE public resources_id_seq"}
        self.assertTrue(validate_toc(sorted(expected), expected, {"ACL", "EXTENSION"}))
        self.assertFalse(validate_toc(sorted(expected) + ["ACL public resources"],
                                      expected, {"ACL public resources"}))
        self.assertFalse(validate_toc(sorted(expected - {"TABLE DATA public resources"}),
                                      expected, set()))
        self.assertFalse(validate_toc(sorted(expected) + ["TABLE public resources"],
                                      expected, set()))

    def test_d13_missing_extra_or_unregistered_repository_fails(self):
        baseline = {"resources": {"resources", "resource_owners"},
                    "audit": {"audit_events"}, "empty_repo": set()}
        self.assertTrue(validate_inventory(dict(baseline), baseline))
        self.assertFalse(validate_inventory(
            {**baseline, "audit": set()}, baseline))
        self.assertFalse(validate_inventory(
            {**baseline, "foreign": {"foreign_table"}}, baseline))
        self.assertFalse(validate_inventory(
            {"resources": baseline["resources"], "audit": baseline["audit"]},
            baseline))


POLICY_V2_REQUIRED = {
    "format", "installation_id", "site_id", "profile", "backend",
    "backend_version", "deployment", "restore_branch_authorization",
    "release_identity", "release_version", "source_commit",
    "release_manifest_sha256", "data_root", "target_device", "target_inode",
    "policy_revision", "prior_policy_digest", "policy_path",
    "trust_bundle_path", "trust_bundle_digest", "recovery_state_root",
    "recovery_state_device", "recovery_state_inode", "journal_directory",
    "journal_device", "journal_inode", "journal_trust_root_id",
    "journal_trust_root_public_key", "evidence_trust_root_id",
    "evidence_trust_root_public_key", "signer_key_id",
}


def proposed_policy_v2_permitted(payload: dict, manifest: dict,
                                 envelope_key_id: str, *,
                                 selected_policy_format: str,
                                 migration_event_valid: bool) -> bool:
    """Proposed A10.1 contract predicate; it is not runtime authority."""
    authority = manifest.get("installation_policy_v2_authority", {})
    return (
        selected_policy_format == "o3k-installation-policy-v2"
        and migration_event_valid
        and set(payload) == POLICY_V2_REQUIRED
        and payload.get("format") == "o3k-installation-policy-v2"
        and payload.get("profile") == "o3k-small-edge-v1"
        and payload.get("backend") == "postgresql"
        and payload.get("backend_version") == "16"
        and payload.get("deployment") == "virtualized"
        and payload.get("restore_branch_authorization") ==
            "inactive-materialization-only"
        and payload.get("release_identity") == manifest.get("release_artifact_sha256")
        and payload.get("release_version") == manifest.get("version")
        and payload.get("source_commit") == manifest.get("source_commit")
        and payload.get("release_manifest_sha256") ==
            manifest.get("exact_bytes_sha256")
        and payload.get("policy_revision", 0) >= 2
        and payload.get("policy_path") == "/etc/o3k/installation-policy.json"
        and payload.get("signer_key_id") == envelope_key_id
        and authority.get("format") == "o3k-installation-policy-v2"
        and authority.get("path") == payload.get("policy_path")
        and authority.get("key_id") == envelope_key_id
        and bool(authority.get("ed25519_public_key"))
        and all(payload.get(field) not in (None, "", 0) for field in (
            "installation_id", "site_id", "target_device", "target_inode",
            "recovery_state_root", "recovery_state_device",
            "recovery_state_inode", "journal_directory", "journal_device",
            "journal_inode", "policy_revision", "prior_policy_digest",
            "release_manifest_sha256"))
    )


def proposed_policy_format_epoch(policy_format: str) -> int | None:
    return {
        "o3k-installation-policy-v1": 1,
        "o3k-installation-policy-v2": 2,
    }.get(policy_format)


def proposed_policy_migration_permitted(*, old_format: str, new_format: str,
                                       old_revision: int, new_revision: int,
                                       old_digest: str, new_prior_digest: str,
                                       signer_manifest_digest: str,
                                       new_release_manifest_digest: str,
                                       state: str, checkpoint_present: bool,
                                       journal_v2_exists: bool,
                                       signer_key_unchanged: bool,
                                       identity_preserved: bool,
                                       migration_event_valid: bool) -> bool:
    """Proposed format-migration contract predicate only."""
    if (old_format != "o3k-installation-policy-v1"
            or new_format != "o3k-installation-policy-v2"
            or new_revision != old_revision + 1
            or new_prior_digest != old_digest
            or signer_manifest_digest != new_release_manifest_digest
            or journal_v2_exists or not signer_key_unchanged
            or not identity_preserved or not migration_event_valid):
        return False
    if state == "NEVER_RECOVERED":
        return not checkpoint_present
    if state in {"RECOVERY_DESIGNATED", "RELEASED"}:
        return checkpoint_present
    return False


class ProposedInstallationPolicyV2Tests(unittest.TestCase):
    """Proposed A10.1 contract tests; not implementation or acceptance."""

    def setUp(self):
        self.manifest = {
            "version": "v0.4.0-rc.5",
            "source_commit": "a" * 40,
            "release_artifact_sha256": "1" * 64,
            "exact_bytes_sha256": "2" * 64,
            "installation_policy_v2_authority": {
                "format": "o3k-installation-policy-v2",
                "path": "/etc/o3k/installation-policy.json",
                "key_id": "policy-key-1",
                "ed25519_public_key": "3" * 64,
            },
        }
        self.payload = {
            "format": "o3k-installation-policy-v2",
            "installation_id": "install-1", "site_id": "site-1",
            "profile": "o3k-small-edge-v1", "backend": "postgresql",
            "backend_version": "16", "deployment": "virtualized",
            "restore_branch_authorization": "inactive-materialization-only",
            "release_identity": "1" * 64,
            "release_version": "v0.4.0-rc.5", "source_commit": "a" * 40,
            "release_manifest_sha256": "2" * 64,
            "data_root": "/var/lib/o3k", "target_device": 1,
            "target_inode": 2, "policy_revision": 2,
            "prior_policy_digest": "4" * 64,
            "policy_path": "/etc/o3k/installation-policy.json",
            "trust_bundle_path": "/etc/o3k/recovery/trust.json",
            "trust_bundle_digest": "5" * 64,
            "recovery_state_root": "/var/lib/o3k-recovery-state/install-1",
            "recovery_state_device": 3, "recovery_state_inode": 4,
            "journal_directory": "/var/lib/o3k-recovery/install-1",
            "journal_device": 5, "journal_inode": 6,
            "journal_trust_root_id": "journal-root",
            "journal_trust_root_public_key": "6" * 64,
            "evidence_trust_root_id": "evidence-root",
            "evidence_trust_root_public_key": "7" * 64,
            "signer_key_id": "policy-key-1",
        }

    def test_v2_schema_and_exact_release_manifest_authority(self):
        import json
        from pathlib import Path

        schema_path = (Path(__file__).resolve().parents[1] / "contracts" /
                       "o3k-installation-policy-v2.proposed.schema.json")
        schema = json.loads(schema_path.read_text())
        self.assertEqual(set(schema["properties"]["payload"]["required"]),
                         POLICY_V2_REQUIRED)
        migration_schema_path = (Path(__file__).resolve().parents[1] / "contracts" /
                                 "o3k-installation-policy-migration-v1.proposed.schema.json")
        migration_schema = json.loads(migration_schema_path.read_text())
        self.assertEqual(set(migration_schema["properties"]["payload"]["required"]), {
            "format", "installation_id", "site_id", "sequence",
            "prior_record_digest", "preserved_state", "prior_policy_format",
            "prior_policy_revision", "prior_policy_digest", "new_policy_format",
            "new_policy_revision", "new_policy_digest",
            "prior_release_manifest_sha256", "new_release_manifest_sha256",
            "prior_release_identity", "new_release_identity", "target_device",
            "target_inode", "trust_bundle_digest", "checkpoint_digest",
            "signer_manifest_digest",
        })
        self.assertTrue(proposed_policy_v2_permitted(
            self.payload, self.manifest, "policy-key-1",
            selected_policy_format="o3k-installation-policy-v2",
            migration_event_valid=True))
        for field, value in (
            ("restore_branch_authorization", None),
            ("restore_branch_authorization", "future-value"),
            ("format", "o3k-installation-policy-v1"),
            ("profile", "o3k-demo-v1"), ("backend", "sqlite"),
            ("backend_version", "15"), ("deployment", "physical"),
            ("restore_branch_authorization", "activation"),
            ("release_identity", "9" * 64),
            ("policy_revision", 1),
            ("release_manifest_sha256", "8" * 64),
            ("journal_inode", 0), ("recovery_state_root", ""),
            ("recovery_state_inode", 0), ("journal_directory", ""),
        ):
            with self.subTest(field=field):
                payload = {**self.payload, field: value}
                self.assertFalse(proposed_policy_v2_permitted(
                    payload, self.manifest, "policy-key-1",
                    selected_policy_format="o3k-installation-policy-v2",
                    migration_event_valid=True))
        self.assertFalse(proposed_policy_v2_permitted(
            {**self.payload, "unknown": True}, self.manifest, "policy-key-1",
            selected_policy_format="o3k-installation-policy-v2",
            migration_event_valid=True))
        self.assertFalse(proposed_policy_v2_permitted(
            self.payload, self.manifest, "wrong-key",
            selected_policy_format="o3k-installation-policy-v2",
            migration_event_valid=True))
        wrong_manifest_authority = {**self.manifest,
            "installation_policy_v2_authority": {
                **self.manifest["installation_policy_v2_authority"],
                "key_id": "mixed-key"}}
        self.assertFalse(proposed_policy_v2_permitted(
            self.payload, wrong_manifest_authority, "policy-key-1",
            selected_policy_format="o3k-installation-policy-v2",
            migration_event_valid=True))
        no_v2_manifest_authority = {key: value for key, value in self.manifest.items()
                                    if key != "installation_policy_v2_authority"}
        self.assertFalse(proposed_policy_v2_permitted(
            self.payload, no_v2_manifest_authority, "policy-key-1",
            selected_policy_format="o3k-installation-policy-v2",
            migration_event_valid=True))
        # The release can authenticate v2 while the durable installation
        # state still selects v1. Manifest capability alone grants no A10.
        self.assertFalse(proposed_policy_v2_permitted(
            self.payload, self.manifest, "policy-key-1",
            selected_policy_format="o3k-installation-policy-v1",
            migration_event_valid=False))
        self.assertFalse(proposed_policy_v2_permitted(
            self.payload, self.manifest, "policy-key-1",
            selected_policy_format="ambiguous",
            migration_event_valid=True))
        self.assertFalse(proposed_policy_v2_permitted(
            self.payload, self.manifest, "policy-key-1",
            selected_policy_format="o3k-installation-policy-v2",
            migration_event_valid=False))

    def test_v1_does_not_select_a10_and_policy_migration_is_monotonic(self):
        base = dict(old_format="o3k-installation-policy-v1",
                    new_format="o3k-installation-policy-v2",
                    old_revision=7, new_revision=8,
                    old_digest="a" * 64, new_prior_digest="a" * 64,
                    signer_manifest_digest="b" * 64,
                    new_release_manifest_digest="b" * 64,
                    state="NEVER_RECOVERED", checkpoint_present=False,
                    journal_v2_exists=False, signer_key_unchanged=True,
                    identity_preserved=True, migration_event_valid=True)
        self.assertTrue(proposed_policy_migration_permitted(**base))
        self.assertEqual(proposed_policy_format_epoch(base["old_format"]), 1)
        self.assertEqual(proposed_policy_format_epoch(base["new_format"]), 2)
        self.assertIsNone(proposed_policy_format_epoch("o3k-installation-policy-v3"))
        for overrides in (
            {"new_revision": 7}, {"new_prior_digest": "b" * 64},
            {"signer_manifest_digest": "c" * 64},
            {"new_format": "o3k-installation-policy-v1"},
            {"old_format": "o3k-installation-policy-v2"},
            {"journal_v2_exists": True}, {"signer_key_unchanged": False},
            {"identity_preserved": False}, {"migration_event_valid": False},
            {"state": "RECOVERY_DESIGNATED"},
        ):
            with self.subTest(overrides=overrides):
                self.assertFalse(proposed_policy_migration_permitted(
                    **{**base, **overrides}))

    def test_recovery_state_requires_checkpoint_and_v2_chain_is_not_rotatable(self):
        base = dict(old_format="o3k-installation-policy-v1",
                    new_format="o3k-installation-policy-v2",
                    old_revision=7, new_revision=8,
                    old_digest="a" * 64, new_prior_digest="a" * 64,
                    signer_manifest_digest="b" * 64,
                    new_release_manifest_digest="b" * 64,
                    state="RECOVERY_DESIGNATED", checkpoint_present=True,
                    journal_v2_exists=False, signer_key_unchanged=True,
                    identity_preserved=True, migration_event_valid=True)
        self.assertTrue(proposed_policy_migration_permitted(**base))
        self.assertFalse(proposed_policy_migration_permitted(
            **{**base, "checkpoint_present": False}))
        self.assertFalse(proposed_policy_migration_permitted(
            **{**base, "journal_v2_exists": True}))

    def test_old_verifier_and_downgrade_fail_closed(self):
        def startup_permitted(*, policy_format, verifier_formats,
                              migration_event_valid, downgrade):
            return (policy_format in verifier_formats and migration_event_valid
                    and not downgrade)

        self.assertTrue(startup_permitted(
            policy_format="o3k-installation-policy-v1",
            verifier_formats={"o3k-installation-policy-v1"},
            migration_event_valid=True, downgrade=False))
        self.assertFalse(startup_permitted(
            policy_format="o3k-installation-policy-v2",
            verifier_formats={"o3k-installation-policy-v1"},
            migration_event_valid=True, downgrade=False))
        self.assertFalse(startup_permitted(
            policy_format="o3k-installation-policy-v1",
            verifier_formats={"o3k-installation-policy-v2"},
            migration_event_valid=True, downgrade=True))
        self.assertFalse(startup_permitted(
            policy_format="o3k-installation-policy-v2",
            verifier_formats={"o3k-installation-policy-v2"},
            migration_event_valid=False, downgrade=False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
