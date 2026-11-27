//! Authority core for the SPEC-0015 enrollment RPC.
//!
//! This module deliberately does not load a CA key.  Production callers must
//! provide a narrow signer boundary (for example a root-owned helper); the
//! daemon receives only the signed result.

use std::sync::{Arc, Mutex};

use openssl::x509::X509Req;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentGrantBinding {
    pub grant_id: String,
    pub token_digest: [u8; 32],
    pub agent_id: String,
    pub agent_epoch: String,
    pub expires_at_unix_ms: u64,
    pub consumed_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedEnrollment {
    pub agent_id: String,
    pub client_certificate_chain_pem: Vec<u8>,
    pub ca_certificate_pem: Vec<u8>,
    pub ca_fingerprint_sha256: String,
    pub certificate_expires_at_unix_ms: u64,
    pub rotation_deadline_unix_ms: u64,
}

pub trait EnrollmentSigner: Send + Sync {
    fn sign_csr(
        &self,
        agent_id: &str,
        agent_epoch: &str,
        csr_pem: &[u8],
    ) -> Result<IssuedEnrollment, String>;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnrollmentIssueError {
    #[error("grant is unknown, expired, consumed, or token does not match")]
    UnauthorizedGrant,
    #[error("CSR is invalid or does not contain the grant-bound identity")]
    InvalidCsr,
    #[error("certificate signer failed")]
    Signer,
    #[error("issuer state is unavailable")]
    State,
}

pub struct EnrollmentIssuer<S> {
    grants: Arc<Mutex<Vec<EnrollmentGrantBinding>>>,
    signer: S,
}

impl<S: EnrollmentSigner> EnrollmentIssuer<S> {
    pub fn new(grants: Vec<EnrollmentGrantBinding>, signer: S) -> Self {
        Self {
            grants: Arc::new(Mutex::new(grants)),
            signer,
        }
    }

    pub fn issue(
        &self,
        grant_id: &str,
        token: &[u8],
        csr_pem: &[u8],
        now_unix_ms: u64,
    ) -> Result<IssuedEnrollment, EnrollmentIssueError> {
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| EnrollmentIssueError::State)?;
        let grant = grants
            .iter_mut()
            .find(|grant| grant.grant_id == grant_id)
            .ok_or(EnrollmentIssueError::UnauthorizedGrant)?;
        let mut digest = Sha256::new();
        digest.update(token);
        if grant.consumed_at_unix_ms.is_some()
            || now_unix_ms >= grant.expires_at_unix_ms
            || digest.finalize().as_slice() != grant.token_digest
        {
            return Err(EnrollmentIssueError::UnauthorizedGrant);
        }
        validate_csr(csr_pem, &grant.agent_id, &grant.agent_epoch)?;
        let issued = self
            .signer
            .sign_csr(&grant.agent_id, &grant.agent_epoch, csr_pem)
            .map_err(|_| EnrollmentIssueError::Signer)?;
        if issued.agent_id != grant.agent_id || issued.certificate_expires_at_unix_ms <= now_unix_ms
        {
            return Err(EnrollmentIssueError::Signer);
        }
        grant.consumed_at_unix_ms = Some(now_unix_ms);
        Ok(issued)
    }
}

fn validate_csr(csr_pem: &[u8], agent_id: &str, epoch: &str) -> Result<(), EnrollmentIssueError> {
    let csr = X509Req::from_pem(csr_pem).map_err(|_| EnrollmentIssueError::InvalidCsr)?;
    let public_key = csr
        .public_key()
        .map_err(|_| EnrollmentIssueError::InvalidCsr)?;
    if !csr.verify(&public_key).unwrap_or(false) {
        return Err(EnrollmentIssueError::InvalidCsr);
    }
    let text = String::from_utf8_lossy(
        csr.to_text()
            .map_err(|_| EnrollmentIssueError::InvalidCsr)?
            .as_slice(),
    )
    .into_owned();
    if !text.contains(&format!("URI:urn:o3k:compute:agent:{agent_id}"))
        || !text.contains(&format!("URI:urn:o3k:compute:epoch:{epoch}"))
    {
        return Err(EnrollmentIssueError::InvalidCsr);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EnrollmentIdentity;

    struct Signer;
    impl EnrollmentSigner for Signer {
        fn sign_csr(&self, agent_id: &str, _: &str, _: &[u8]) -> Result<IssuedEnrollment, String> {
            Ok(IssuedEnrollment {
                agent_id: agent_id.into(),
                client_certificate_chain_pem: vec![1],
                ca_certificate_pem: vec![2],
                ca_fingerprint_sha256: "fp".into(),
                certificate_expires_at_unix_ms: 10_000,
                rotation_deadline_unix_ms: 9_000,
            })
        }
    }

    #[test]
    fn validates_identity_and_consumes_grant_once() {
        let identity = EnrollmentIdentity::generate("node-1", "epoch-1").unwrap();
        let csr = identity.csr_pem();
        let token = b"secret";
        let mut hash = Sha256::new();
        hash.update(token);
        let issuer = EnrollmentIssuer::new(
            vec![EnrollmentGrantBinding {
                grant_id: "g".into(),
                token_digest: hash.finalize().into(),
                agent_id: "node-1".into(),
                agent_epoch: "epoch-1".into(),
                expires_at_unix_ms: 100,
                consumed_at_unix_ms: None,
            }],
            Signer,
        );
        assert!(issuer.issue("g", token, &csr, 10).is_ok());
        assert_eq!(
            issuer.issue("g", token, &csr, 11),
            Err(EnrollmentIssueError::UnauthorizedGrant)
        );
    }

    #[test]
    fn rejects_wrong_csr_identity_without_consuming_grant() {
        let identity = EnrollmentIdentity::generate("other", "epoch-1").unwrap();
        let token = b"secret";
        let mut hash = Sha256::new();
        hash.update(token);
        let issuer = EnrollmentIssuer::new(
            vec![EnrollmentGrantBinding {
                grant_id: "g".into(),
                token_digest: hash.finalize().into(),
                agent_id: "node-1".into(),
                agent_epoch: "epoch-1".into(),
                expires_at_unix_ms: 100,
                consumed_at_unix_ms: None,
            }],
            Signer,
        );
        assert_eq!(
            issuer.issue("g", token, identity.csr_pem(), 10),
            Err(EnrollmentIssueError::InvalidCsr)
        );
    }
}
