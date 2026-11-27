//! Authority core for the SPEC-0015 enrollment RPC.
//!
//! This module deliberately does not load a CA key.  Production callers must
//! provide a narrow signer boundary (for example a root-owned helper); the
//! daemon receives only the signed result.

use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

use openssl::x509::X509Req;
use serde::{Deserialize, Serialize};
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedEnrollment {
    pub agent_id: String,
    pub agent_epoch: String,
    pub client_certificate_chain_pem: Vec<u8>,
    pub ca_certificate_pem: Vec<u8>,
    pub ca_fingerprint_sha256: String,
    pub certificate_expires_at_unix_ms: u64,
    pub rotation_deadline_unix_ms: u64,
}

/// Signer boundary for the installation-local root helper.  The helper is a
/// fixed-purpose root-owned executable; this process sends only a bounded
/// request over stdin and receives the signed response.  The CA private key
/// therefore never enters the agent or controller address space.
#[derive(Clone, Debug)]
pub struct RootHelperEnrollmentSigner {
    command: PathBuf,
}

impl RootHelperEnrollmentSigner {
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
        }
    }

    fn validate_command(&self) -> Result<(), String> {
        if !self.command.starts_with("/usr/libexec/o3k/") {
            return Err("signer path is outside packaged directory".to_owned());
        }
        let meta = std::fs::metadata(&self.command)
            .map_err(|_| "signer executable is unavailable".to_owned())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != 0 || (meta.mode() & 0o022) != 0 || (meta.mode() & 0o111) == 0 {
                return Err("signer executable ownership or mode is unsafe".to_owned());
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct SignRequest<'a> {
    grant_id: &'a str,
    token: &'a [u8],
    agent_id: &'a str,
    agent_epoch: &'a str,
    csr_pem: &'a [u8],
}

impl EnrollmentSigner for RootHelperEnrollmentSigner {
    fn sign_csr(
        &self,
        grant_id: &str,
        token: &[u8],
        agent_id: &str,
        agent_epoch: &str,
        csr_pem: &[u8],
    ) -> Result<IssuedEnrollment, String> {
        self.validate_command()?;
        let request = serde_json::to_vec(&SignRequest {
            grant_id,
            token,
            agent_id,
            agent_epoch,
            csr_pem,
        })
        .map_err(|_| "cannot encode signer request".to_owned())?;
        if request.len() > 1024 * 1024 {
            return Err("signer request too large".to_owned());
        }
        let mut child = Command::new(&self.command)
            .arg("sign-csr")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "cannot start enrollment signer".to_owned())?;
        use std::io::Write;
        child
            .stdin
            .take()
            .ok_or_else(|| "signer stdin unavailable".to_owned())?
            .write_all(&request)
            .map_err(|_| "cannot send signer request".to_owned())?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while child
            .try_wait()
            .map_err(|_| "signer failed".to_owned())?
            .is_none()
        {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                return Err("signer timed out".to_owned());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let output = child
            .wait_with_output()
            .map_err(|_| "signer failed".to_owned())?;
        if output.stdout.len() > 1024 * 1024 {
            return Err("signer response too large".to_owned());
        }
        if !output.status.success() {
            return Err("signer rejected request".to_owned());
        }
        serde_json::from_slice(&output.stdout).map_err(|_| "invalid signer response".to_owned())
    }
}

pub trait EnrollmentSigner: Send + Sync {
    fn sign_csr(
        &self,
        grant_id: &str,
        token: &[u8],
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
            .sign_csr(
                grant_id,
                token,
                &grant.agent_id,
                &grant.agent_epoch,
                csr_pem,
            )
            .map_err(|_| EnrollmentIssueError::Signer)?;
        if issued.agent_id != grant.agent_id
            || issued.agent_epoch != grant.agent_epoch
            || issued.client_certificate_chain_pem.is_empty()
            || issued.ca_certificate_pem.is_empty()
            || issued.ca_fingerprint_sha256.len() != 64
            || !issued
                .ca_fingerprint_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit())
            || issued.certificate_expires_at_unix_ms <= now_unix_ms
            || issued.rotation_deadline_unix_ms <= now_unix_ms
            || issued.rotation_deadline_unix_ms > issued.certificate_expires_at_unix_ms
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
#[allow(clippy::unwrap_used, clippy::needless_borrow)]
mod tests {
    use super::*;
    use crate::EnrollmentIdentity;

    struct Signer;
    impl EnrollmentSigner for Signer {
        fn sign_csr(
            &self,
            _: &str,
            _: &[u8],
            agent_id: &str,
            _: &str,
            _: &[u8],
        ) -> Result<IssuedEnrollment, String> {
            Ok(IssuedEnrollment {
                agent_id: agent_id.into(),
                agent_epoch: "epoch-1".into(),
                client_certificate_chain_pem: vec![1],
                ca_certificate_pem: vec![2],
                ca_fingerprint_sha256: "a".repeat(64),
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
