use crate::recovery_identity::*;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;
#[derive(Debug, PartialEq, Eq)]
pub enum TrustError {
    Invalid,
    Identity(IdentityError),
}
impl From<IdentityError> for TrustError {
    fn from(value: IdentityError) -> Self {
        Self::Identity(value)
    }
}
#[derive(Debug, Clone)]
pub struct VerifiedTrust {
    pub bundle: TrustBundle,
    journal: BTreeMap<String, VerifyingKey>,
    evidence: BTreeMap<String, VerifyingKey>,
}
impl VerifiedTrust {
    pub fn journal_key(&self, id: &str) -> Option<&VerifyingKey> {
        self.journal.get(id)
    }
    pub fn evidence_key(&self, id: &str) -> Option<&VerifyingKey> {
        self.evidence.get(id)
    }
}
pub fn verify_trust_bundle(
    b: TrustBundle,
    jr: &VerifyingKey,
    er: &VerifyingKey,
    now: i64,
    jh: Option<(u64, &str)>,
    eh: Option<(u64, &str)>,
) -> Result<VerifiedTrust, TrustError> {
    verify_installed_trust(b.clone(), jr, er, now, jh, eh)
}
pub fn verify_installed_trust(
    b: TrustBundle,
    jr: &VerifyingKey,
    er: &VerifyingKey,
    now: i64,
    jh: Option<(u64, &str)>,
    eh: Option<(u64, &str)>,
) -> Result<VerifiedTrust, TrustError> {
    verify_bundle(b, jr, er, now, jh, eh, TrustUse::Current)
}

/// Cryptographic history verification only. Never authorizes a transition:
/// callers must separately verify a new policy and fresh revalidation evidence.
pub(crate) fn verify_historical_trust(
    b: TrustBundle,
    jr: &VerifyingKey,
    er: &VerifyingKey,
    jh: Option<(u64, &str)>,
    eh: Option<(u64, &str)>,
) -> Result<VerifiedTrust, TrustError> {
    verify_bundle(b, jr, er, 0, jh, eh, TrustUse::History)
}

/// Accept a fresh root-signed revocation update even when it revokes the
/// active signer. The returned verification result grants no operational use.
pub(crate) fn verify_revocation_update(
    b: TrustBundle,
    jr: &VerifyingKey,
    er: &VerifyingKey,
    now: i64,
    jh: Option<(u64, &str)>,
    eh: Option<(u64, &str)>,
) -> Result<(), TrustError> {
    verify_bundle(b, jr, er, now, jh, eh, TrustUse::RevocationUpdate).map(|_| ())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TrustUse {
    Current,
    History,
    RevocationUpdate,
}

fn verify_bundle(
    b: TrustBundle,
    jr: &VerifyingKey,
    er: &VerifyingKey,
    now: i64,
    jh: Option<(u64, &str)>,
    eh: Option<(u64, &str)>,
    usage: TrustUse,
) -> Result<VerifiedTrust, TrustError> {
    let historical = usage == TrustUse::History;
    if b.format != "o3k-recovery-trust-v1"
        || b.site_id.is_empty()
        || b.profile.is_empty()
        || b.installation_id.is_empty()
        || b.backend.is_empty()
        || b.journal_root_key_id.is_empty()
        || b.evidence_root_key_id.is_empty()
        || b.journal_root_key_id == b.evidence_root_key_id
    {
        return Err(TrustError::Invalid);
    }
    let j = hex::decode(&b.journal_root_public_key).map_err(|_| TrustError::Invalid)?;
    let e = hex::decode(&b.evidence_root_public_key).map_err(|_| TrustError::Invalid)?;
    if j.as_slice() != jr.as_bytes() || e.as_slice() != er.as_bytes() || j == e {
        return Err(TrustError::Invalid);
    }
    let jc = verify_signed(
        &canonical(&b.journal_certificate)?,
        "o3k-journal-authority-v1",
        &b.journal_root_key_id,
        jr,
    )?;
    let ec = verify_signed(
        &canonical(&b.evidence_certificate)?,
        "o3k-evidence-authority-v1",
        &b.evidence_root_key_id,
        er,
    )?;
    let jv = verify_signed(
        &canonical(&b.journal_revocations)?,
        "o3k-recovery-revocations-v1",
        &b.journal_root_key_id,
        jr,
    )?;
    let ev = verify_signed(
        &canonical(&b.evidence_revocations)?,
        "o3k-recovery-revocations-v1",
        &b.evidence_root_key_id,
        er,
    )?;
    verify_certificate_binding(
        &jc,
        CertificateScope {
            purpose: "restore_journal",
            site: &b.site_id,
            installation: &b.installation_id,
            profile: &b.profile,
            backend: &b.backend,
            issuer: &b.journal_root_key_id,
            now: if historical { jc.not_before } else { now },
        },
    )?;
    verify_certificate_binding(
        &ec,
        CertificateScope {
            purpose: "recovery_evidence",
            site: &b.site_id,
            installation: &b.installation_id,
            profile: &b.profile,
            backend: &b.backend,
            issuer: &b.evidence_root_key_id,
            now: if historical { ec.not_before } else { now },
        },
    )?;
    verify_revocation(
        &jv,
        &b.site_id,
        &b.profile,
        if historical { jv.issued_at } else { now },
        None,
    )?;
    verify_revocation(
        &ev,
        &b.site_id,
        &b.profile,
        if historical { ev.issued_at } else { now },
        None,
    )?;
    if (usage == TrustUse::Current
        && (jv.revoked_serials.iter().any(|x| x == &jc.serial)
            || jv.revoked_key_ids.iter().any(|x| x == &jc.key_id)
            || ev.revoked_serials.iter().any(|x| x == &ec.serial)
            || ev.revoked_key_ids.iter().any(|x| x == &ec.key_id)))
        || jv.sequence != b.journal_revocation_sequence
        || ev.sequence != b.evidence_revocation_sequence
        || digest(&b.journal_revocations)? != b.journal_revocation_digest
        || digest(&b.evidence_revocations)? != b.evidence_revocation_digest
    {
        return Err(TrustError::Invalid);
    }
    for (d, h) in [(&b.journal_revocations, jh), (&b.evidence_revocations, eh)] {
        if h.is_some_and(|(s, x)| {
            d.payload.sequence < s
                || d.payload.sequence == s && digest(d).ok().as_deref() != Some(x)
        }) {
            return Err(TrustError::Invalid);
        }
    }
    let jk = VerifyingKey::from_bytes(
        &hex::decode(&jc.public_key)
            .map_err(|_| TrustError::Invalid)?
            .try_into()
            .map_err(|_| TrustError::Invalid)?,
    )
    .map_err(|_| TrustError::Invalid)?;
    let ek = VerifyingKey::from_bytes(
        &hex::decode(&ec.public_key)
            .map_err(|_| TrustError::Invalid)?
            .try_into()
            .map_err(|_| TrustError::Invalid)?,
    )
    .map_err(|_| TrustError::Invalid)?;
    if jc.key_id == ec.key_id
        || jk == ek
        || jk == *jr
        || jk == *er
        || ek == *jr
        || ek == *er
        || jc.key_id == b.journal_root_key_id
        || jc.key_id == b.evidence_root_key_id
        || ec.key_id == b.journal_root_key_id
        || ec.key_id == b.evidence_root_key_id
    {
        return Err(TrustError::Invalid);
    }
    let mut jm = BTreeMap::new();
    jm.insert(jc.key_id, jk);
    let mut em = BTreeMap::new();
    em.insert(ec.key_id, ek);
    Ok(VerifiedTrust {
        bundle: b,
        journal: jm,
        evidence: em,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Serialize;

    const NOW: i64 = 1_800_000_000;
    const JOURNAL_ROOT_ID: &str = "journal-root-1";
    const EVIDENCE_ROOT_ID: &str = "evidence-root-1";
    const JOURNAL_SIGNER_ID: &str = "journal-signer-1";
    const EVIDENCE_SIGNER_ID: &str = "evidence-signer-1";

    fn keypair(seed: u8) -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        (signing.clone(), signing.verifying_key())
    }

    fn sign<T: Serialize + Clone>(
        payload: &T,
        signing: &SigningKey,
        signer_key_id: &str,
    ) -> Signed<T> {
        let canonical_payload = canonical(payload).expect("canonical payload");
        Signed {
            payload: payload.clone(),
            envelope: SignatureEnvelope {
                algorithm: "Ed25519".to_string(),
                signer_key_id: signer_key_id.to_string(),
                signature: hex::encode(signing.sign(&canonical_payload).to_bytes()),
            },
        }
    }

    fn certificate(
        purpose: &str,
        key_id: &str,
        public_key: &str,
        issuer: &str,
    ) -> TrustCertificate {
        let format = match purpose {
            "restore_journal" => "o3k-journal-authority-v1",
            "recovery_evidence" => "o3k-evidence-authority-v1",
            _ => "unknown-purpose",
        };
        TrustCertificate {
            format: format.to_string(),
            key_id: key_id.to_string(),
            public_key: public_key.to_string(),
            purpose: purpose.to_string(),
            site_id: "site-1".to_string(),
            installation_id: "inst-1".to_string(),
            profile: "o3k-demo-v1".to_string(),
            backend: "sqlite".to_string(),
            serial: format!("serial-{key_id}"),
            not_before: NOW - 1000,
            not_after: NOW + 1000,
            issuer: issuer.to_string(),
        }
    }

    fn revocations(sequence: u64) -> RevocationDocument {
        RevocationDocument {
            format: "o3k-recovery-revocations-v1".to_string(),
            site_id: "site-1".to_string(),
            profile: "o3k-demo-v1".to_string(),
            sequence,
            issued_at: NOW - 100,
            next_update: NOW + 100,
            revoked_serials: vec![],
            revoked_key_ids: vec![],
        }
    }

    struct TrustFixture {
        journal_root: SigningKey,
        evidence_root: SigningKey,
        journal_signer_verify: VerifyingKey,
        evidence_signer_verify: VerifyingKey,
        bundle: TrustBundle,
    }

    fn valid_fixture() -> TrustFixture {
        let (journal_root, journal_root_verify) = keypair(1);
        let (evidence_root, evidence_root_verify) = keypair(2);
        let (_, journal_signer_verify) = keypair(3);
        let (_, evidence_signer_verify) = keypair(4);
        let journal_certificate = sign(
            &certificate(
                "restore_journal",
                JOURNAL_SIGNER_ID,
                &hex::encode(journal_signer_verify.as_bytes()),
                JOURNAL_ROOT_ID,
            ),
            &journal_root,
            JOURNAL_ROOT_ID,
        );
        let evidence_certificate = sign(
            &certificate(
                "recovery_evidence",
                EVIDENCE_SIGNER_ID,
                &hex::encode(evidence_signer_verify.as_bytes()),
                EVIDENCE_ROOT_ID,
            ),
            &evidence_root,
            EVIDENCE_ROOT_ID,
        );
        let journal_revocations = sign(&revocations(1), &journal_root, JOURNAL_ROOT_ID);
        let evidence_revocations = sign(&revocations(1), &evidence_root, EVIDENCE_ROOT_ID);
        let bundle = TrustBundle {
            format: "o3k-recovery-trust-v1".to_string(),
            site_id: "site-1".to_string(),
            profile: "o3k-demo-v1".to_string(),
            installation_id: "inst-1".to_string(),
            backend: "sqlite".to_string(),
            journal_root_key_id: JOURNAL_ROOT_ID.to_string(),
            journal_root_public_key: hex::encode(journal_root_verify.as_bytes()),
            evidence_root_key_id: EVIDENCE_ROOT_ID.to_string(),
            evidence_root_public_key: hex::encode(evidence_root_verify.as_bytes()),
            journal_revocation_sequence: 1,
            journal_revocation_digest: digest(&journal_revocations).expect("digest"),
            evidence_revocation_sequence: 1,
            evidence_revocation_digest: digest(&evidence_revocations).expect("digest"),
            journal_certificate,
            evidence_certificate,
            journal_revocations,
            evidence_revocations,
        };
        TrustFixture {
            journal_root,
            evidence_root,
            journal_signer_verify,
            evidence_signer_verify,
            bundle,
        }
    }

    fn verify(fixture: &TrustFixture) -> Result<VerifiedTrust, TrustError> {
        verify_trust_bundle(
            fixture.bundle.clone(),
            &fixture.journal_root.verifying_key(),
            &fixture.evidence_root.verifying_key(),
            NOW,
            None,
            None,
        )
    }

    /// Re-sign and re-bind the journal revocation document after a payload
    /// mutation so the test exercises the intended check rather than the
    /// signature mismatch.
    fn refresh_journal_revocations(fixture: &mut TrustFixture) {
        fixture.bundle.journal_revocations = sign(
            &fixture.bundle.journal_revocations.payload,
            &fixture.journal_root,
            JOURNAL_ROOT_ID,
        );
        fixture.bundle.journal_revocation_digest =
            digest(&fixture.bundle.journal_revocations).expect("digest");
        fixture.bundle.journal_revocation_sequence =
            fixture.bundle.journal_revocations.payload.sequence;
    }

    fn refresh_journal_certificate(fixture: &mut TrustFixture) {
        fixture.bundle.journal_certificate = sign(
            &fixture.bundle.journal_certificate.payload,
            &fixture.journal_root,
            JOURNAL_ROOT_ID,
        );
    }

    #[test]
    fn valid_bundle_installs_distinct_purpose_bound_keys() {
        let fixture = valid_fixture();
        let trust = verify(&fixture).expect("valid bundle verifies");
        assert_eq!(
            trust.journal_key(JOURNAL_SIGNER_ID),
            Some(&fixture.journal_signer_verify)
        );
        assert_eq!(
            trust.evidence_key(EVIDENCE_SIGNER_ID),
            Some(&fixture.evidence_signer_verify)
        );
        assert_eq!(trust.journal_key(EVIDENCE_SIGNER_ID), None);
        assert_eq!(trust.journal_key("unknown-signer"), None);
    }

    #[test]
    fn rejects_wrong_format_empty_scope_and_shared_root_ids() {
        let mut fixture = valid_fixture();
        fixture.bundle.format = "o3k-recovery-trust-v2".to_string();
        assert_eq!(verify(&fixture).unwrap_err(), TrustError::Invalid);

        let mut fixture = valid_fixture();
        fixture.bundle.journal_root_key_id = fixture.bundle.evidence_root_key_id.clone();
        assert_eq!(verify(&fixture).unwrap_err(), TrustError::Invalid);

        let mut fixture = valid_fixture();
        fixture.bundle.site_id.clear();
        assert_eq!(verify(&fixture).unwrap_err(), TrustError::Invalid);
    }

    #[test]
    fn rejects_root_public_keys_that_do_not_match_installed_roots() {
        let fixture = valid_fixture();
        let (_, other_root) = keypair(99);
        let result = verify_trust_bundle(
            fixture.bundle.clone(),
            &other_root,
            &fixture.evidence_root.verifying_key(),
            NOW,
            None,
            None,
        );
        assert_eq!(result.unwrap_err(), TrustError::Invalid);
        let result = verify_trust_bundle(
            fixture.bundle.clone(),
            &fixture.journal_root.verifying_key(),
            &other_root,
            NOW,
            None,
            None,
        );
        assert_eq!(result.unwrap_err(), TrustError::Invalid);
        let result = verify_trust_bundle(
            fixture.bundle.clone(),
            &fixture.journal_root.verifying_key(),
            &fixture.journal_root.verifying_key(),
            NOW,
            None,
            None,
        );
        assert_eq!(result.unwrap_err(), TrustError::Invalid);
    }

    #[test]
    fn rejects_revoked_signer_certificate_and_key() {
        for revoked in [
            {
                let mut fixture = valid_fixture();
                fixture
                    .bundle
                    .journal_revocations
                    .payload
                    .revoked_serials
                    .push("serial-journal-signer-1".to_string());
                refresh_journal_revocations(&mut fixture);
                fixture
            },
            {
                let mut fixture = valid_fixture();
                fixture
                    .bundle
                    .journal_revocations
                    .payload
                    .revoked_key_ids
                    .push(JOURNAL_SIGNER_ID.to_string());
                refresh_journal_revocations(&mut fixture);
                fixture
            },
            {
                let mut fixture = valid_fixture();
                fixture
                    .bundle
                    .evidence_revocations
                    .payload
                    .revoked_serials
                    .push("serial-evidence-signer-1".to_string());
                fixture.bundle.evidence_revocations = sign(
                    &fixture.bundle.evidence_revocations.payload,
                    &fixture.evidence_root.clone(),
                    EVIDENCE_ROOT_ID,
                );
                fixture.bundle.evidence_revocation_digest =
                    digest(&fixture.bundle.evidence_revocations).expect("digest");
                fixture
            },
        ] {
            assert_eq!(verify(&revoked).unwrap_err(), TrustError::Invalid);
        }
    }

    #[test]
    fn rejects_expired_certificate_and_stale_revocation_freshness() {
        // Expired signer certificate, re-signed so expiry is the failing check.
        let mut fixture = valid_fixture();
        fixture.bundle.journal_certificate.payload.not_after = NOW - 1;
        refresh_journal_certificate(&mut fixture);
        assert_eq!(
            verify(&fixture).unwrap_err(),
            TrustError::Identity(IdentityError::TrustInvalid)
        );

        // Stale revocation freshness, re-signed so freshness is the failing check.
        let mut fixture = valid_fixture();
        fixture.bundle.journal_revocations.payload.next_update = NOW - 1;
        refresh_journal_revocations(&mut fixture);
        assert_eq!(
            verify(&fixture).unwrap_err(),
            TrustError::Identity(IdentityError::TrustInvalid)
        );

        // Certificate outside the bundle site scope, re-signed.
        let mut fixture = valid_fixture();
        fixture.bundle.journal_certificate.payload.site_id = "site-2".to_string();
        refresh_journal_certificate(&mut fixture);
        assert_eq!(
            verify(&fixture).unwrap_err(),
            TrustError::Identity(IdentityError::TrustInvalid)
        );
    }

    #[test]
    fn rejects_certificate_signed_by_the_wrong_root() {
        let mut fixture = valid_fixture();
        // Re-sign the journal certificate with the evidence root: the envelope
        // still names the journal root, so the signature must not verify.
        fixture.bundle.journal_certificate = sign(
            &fixture.bundle.journal_certificate.payload,
            &fixture.evidence_root.clone(),
            JOURNAL_ROOT_ID,
        );
        assert!(matches!(verify(&fixture), Err(TrustError::Identity(_))));
    }

    #[test]
    fn rejects_bundle_high_water_mismatch_and_equivocation() {
        // Bundle sequence does not match the signed revocation document.
        let mut fixture = valid_fixture();
        fixture.bundle.journal_revocation_sequence = 2;
        assert_eq!(verify(&fixture).unwrap_err(), TrustError::Invalid);

        // Bundle digest does not cover the signed revocation document.
        let mut fixture = valid_fixture();
        fixture.bundle.journal_revocation_digest = hex::encode([0xabu8; 32]);
        assert_eq!(verify(&fixture).unwrap_err(), TrustError::Invalid);

        // Installed high-water ahead of the bundle document is rollback.
        let fixture = valid_fixture();
        let result = verify_trust_bundle(
            fixture.bundle.clone(),
            &fixture.journal_root.verifying_key(),
            &fixture.evidence_root.verifying_key(),
            NOW,
            Some((5, &hex::encode([0xcu8; 32]))),
            None,
        );
        assert_eq!(result.unwrap_err(), TrustError::Invalid);

        // Same sequence with a different digest is equivocation.
        let fixture = valid_fixture();
        let result = verify_trust_bundle(
            fixture.bundle.clone(),
            &fixture.journal_root.verifying_key(),
            &fixture.evidence_root.verifying_key(),
            NOW,
            Some((1, &hex::encode([0xcu8; 32]))),
            None,
        );
        assert_eq!(result.unwrap_err(), TrustError::Invalid);

        // Same sequence with the identical digest is idempotent.
        let fixture = valid_fixture();
        let dg = digest(&fixture.bundle.journal_revocations).expect("digest");
        let trust = verify_trust_bundle(
            fixture.bundle.clone(),
            &fixture.journal_root.verifying_key(),
            &fixture.evidence_root.verifying_key(),
            NOW,
            Some((1, &dg)),
            None,
        );
        assert!(trust.is_ok());
    }

    #[test]
    fn rejects_signer_key_confusion_with_roots() {
        // Journal signer key ID equal to the journal root ID.
        let mut fixture = valid_fixture();
        fixture.bundle.journal_certificate.payload.key_id = JOURNAL_ROOT_ID.to_string();
        fixture.bundle.journal_certificate = sign(
            &fixture.bundle.journal_certificate.payload,
            &fixture.journal_root,
            JOURNAL_ROOT_ID,
        );
        assert_eq!(verify(&fixture).unwrap_err(), TrustError::Invalid);

        // Journal and evidence signer certificates sharing a key ID.
        let mut fixture = valid_fixture();
        fixture.bundle.evidence_certificate.payload.key_id = JOURNAL_SIGNER_ID.to_string();
        fixture.bundle.evidence_certificate = sign(
            &fixture.bundle.evidence_certificate.payload,
            &fixture.evidence_root,
            EVIDENCE_ROOT_ID,
        );
        assert_eq!(verify(&fixture).unwrap_err(), TrustError::Invalid);
    }

    #[test]
    fn rejects_signer_reusing_either_root_key_or_cross_purpose_root_id() {
        for journal in [false, true] {
            for root_is_journal in [false, true] {
                for reuse_public_key in [false, true] {
                    let mut fixture = valid_fixture();
                    let root_id = if root_is_journal {
                        JOURNAL_ROOT_ID
                    } else {
                        EVIDENCE_ROOT_ID
                    };
                    let root_key = if root_is_journal {
                        fixture.journal_root.verifying_key()
                    } else {
                        fixture.evidence_root.verifying_key()
                    };
                    let cert = if journal {
                        &mut fixture.bundle.journal_certificate
                    } else {
                        &mut fixture.bundle.evidence_certificate
                    };
                    if reuse_public_key {
                        cert.payload.public_key = hex::encode(root_key.as_bytes());
                    } else {
                        cert.payload.key_id = root_id.to_string();
                    }
                    *cert = if journal {
                        sign(&cert.payload, &fixture.journal_root, JOURNAL_ROOT_ID)
                    } else {
                        sign(&cert.payload, &fixture.evidence_root, EVIDENCE_ROOT_ID)
                    };
                    assert_eq!(verify(&fixture).unwrap_err(), TrustError::Invalid);
                }
            }
        }
    }

    #[test]
    fn historical_verification_checks_signatures_without_authorizing_revoked_keys() {
        let mut fixture = valid_fixture();
        let mut doc = fixture.bundle.journal_revocations.payload.clone();
        doc.sequence += 1;
        doc.revoked_key_ids.push(JOURNAL_SIGNER_ID.to_string());
        fixture.bundle.journal_revocations = sign(&doc, &fixture.journal_root, JOURNAL_ROOT_ID);
        fixture.bundle.journal_revocation_sequence = doc.sequence;
        fixture.bundle.journal_revocation_digest =
            digest(&fixture.bundle.journal_revocations).expect("digest");
        assert!(
            verify(&fixture).is_err(),
            "current authorization stays denied"
        );
        let historical = |bundle| {
            verify_historical_trust(
                bundle,
                &fixture.journal_root.verifying_key(),
                &fixture.evidence_root.verifying_key(),
                None,
                None,
            )
        };
        assert!(historical(fixture.bundle.clone()).is_ok());
        assert!(
            verify_revocation_update(
                fixture.bundle.clone(),
                &fixture.journal_root.verifying_key(),
                &fixture.evidence_root.verifying_key(),
                NOW,
                None,
                None
            )
            .is_ok()
        );
        assert!(
            verify_revocation_update(
                fixture.bundle.clone(),
                &fixture.journal_root.verifying_key(),
                &fixture.evidence_root.verifying_key(),
                NOW + 10000,
                None,
                None
            )
            .is_err(),
            "revocation publication still requires fresh authority"
        );
        let mut forged = fixture.bundle.clone();
        forged.journal_certificate.envelope.signature = "00".repeat(64);
        assert!(
            historical(forged).is_err(),
            "history still requires valid signatures"
        );
        let mut forged = fixture.bundle.clone();
        forged.journal_revocations.envelope.signature = "00".repeat(64);
        forged.journal_revocation_digest = digest(&forged.journal_revocations).expect("digest");
        assert!(
            historical(forged).is_err(),
            "revocations remain root authenticated"
        );
    }

    #[test]
    fn rejects_malformed_signer_public_keys() {
        let mut fixture = valid_fixture();
        fixture.bundle.journal_certificate.payload.public_key = "not-hex".to_string();
        fixture.bundle.journal_certificate = sign(
            &fixture.bundle.journal_certificate.payload,
            &fixture.journal_root,
            JOURNAL_ROOT_ID,
        );
        assert_eq!(verify(&fixture).unwrap_err(), TrustError::Invalid);
    }
}
