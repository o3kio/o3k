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

use openssl::{
    stack::Stack,
    x509::{X509, X509Req},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tonic::{Request, Response, Status};

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
pub struct DurableEnrollmentIssue {
    pub grant_id: String,
    pub agent_id: String,
    pub agent_epoch: String,
    pub token_digest_hex: String,
    pub csr_sha256: String,
    pub certificate_fingerprint_sha256: String,
    pub issued: IssuedEnrollment,
    pub issued_at_unix_ms: u64,
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

#[async_trait::async_trait]
pub trait AsyncDurableEnrollmentGrants: Send + Sync {
    async fn lookup(
        &self,
        grant_id: &str,
        token_digest_hex: &str,
        now_unix_ms: u64,
    ) -> Result<EnrollmentGrantBinding, EnrollmentIssueError>;
    async fn existing_issue(
        &self,
        grant_id: &str,
        token_digest_hex: &str,
        agent_id: &str,
        agent_epoch: &str,
        csr_sha256: &str,
        now_unix_ms: u64,
    ) -> Result<Option<IssuedEnrollment>, EnrollmentIssueError>;
    async fn complete_issue(
        &self,
        issue: &DurableEnrollmentIssue,
        now_unix_ms: u64,
    ) -> Result<IssuedEnrollment, EnrollmentIssueError>;
}

pub struct EnrollmentIssuer<S> {
    grants: Arc<Mutex<Vec<EnrollmentGrantBinding>>>,
    signer: S,
}

/// gRPC adapter for the versioned ComputeEnrollment contract.  The adapter
/// deliberately contains no certificate authority state; callers inject the
/// narrow signer above and keep grant state in the controller's durable store.
pub struct ComputeEnrollmentService<S> {
    issuer: Arc<EnrollmentIssuer<S>>,
}

/// Durable-store variant used by controller composition.  Keeping this as a
/// separate adapter avoids accidentally deploying the test-only in-memory
/// grant implementation.
pub struct DurableComputeEnrollmentService<S, R> {
    issuer: Arc<EnrollmentIssuer<S>>,
    grants: Arc<R>,
}

impl<S, R> DurableComputeEnrollmentService<S, R> {
    pub fn new(issuer: EnrollmentIssuer<S>, grants: R) -> Self {
        Self {
            issuer: Arc::new(issuer),
            grants: Arc::new(grants),
        }
    }
}

#[tonic::async_trait]
impl<S, R> crate::proto::compute_enrollment_server::ComputeEnrollment
    for DurableComputeEnrollmentService<S, R>
where
    S: EnrollmentSigner + 'static,
    R: AsyncDurableEnrollmentGrants + 'static,
{
    async fn enroll(
        &self,
        request: Request<crate::proto::EnrollRequest>,
    ) -> Result<Response<crate::proto::EnrollResponse>, Status> {
        let request = request.into_inner();
        let (grant_id, _) = request
            .bootstrap_token
            .split_once('.')
            .ok_or_else(|| Status::unauthenticated("invalid enrollment grant"))?;
        let issued = self
            .issuer
            .issue_durable_async(
                self.grants.as_ref(),
                grant_id,
                request.bootstrap_token.as_bytes(),
                &request.certificate_signing_request_pem,
                unix_ms(),
            )
            .await
            .map_err(|_| Status::unauthenticated("enrollment rejected"))?;
        Ok(Response::new(crate::proto::EnrollResponse {
            agent_id: issued.agent_id,
            client_certificate_chain_pem: issued.client_certificate_chain_pem,
            ca_certificate_pem: issued.ca_certificate_pem,
            ca_fingerprint_sha256: issued.ca_fingerprint_sha256,
            certificate_expires_at_unix_ms: issued.certificate_expires_at_unix_ms as i64,
            rotation_deadline_unix_ms: issued.rotation_deadline_unix_ms as i64,
            selected_version: request.supported_versions.into_iter().next(),
        }))
    }

    async fn rotate_certificate(
        &self,
        _request: Request<crate::proto::RotateCertificateRequest>,
    ) -> Result<Response<crate::proto::RotateCertificateResponse>, Status> {
        Err(Status::unimplemented("certificate rotation is not enabled"))
    }
}

impl<S: EnrollmentSigner + 'static> ComputeEnrollmentService<S> {
    pub fn new(issuer: EnrollmentIssuer<S>) -> Self {
        Self {
            issuer: Arc::new(issuer),
        }
    }
}

#[tonic::async_trait]
impl<S: EnrollmentSigner + 'static> crate::proto::compute_enrollment_server::ComputeEnrollment
    for ComputeEnrollmentService<S>
{
    async fn enroll(
        &self,
        request: Request<crate::proto::EnrollRequest>,
    ) -> Result<Response<crate::proto::EnrollResponse>, Status> {
        let request = request.into_inner();
        if request.bootstrap_token.is_empty()
            || request.certificate_signing_request_pem.is_empty()
            || request.certificate_signing_request_pem.len() > 128 * 1024
        {
            return Err(Status::invalid_argument("invalid enrollment request"));
        }
        // The bootstrap token is an opaque durable grant identifier in the
        // current wire contract.  The controller maps it to its grant record
        // before constructing this service; it is never logged or echoed.
        let token = request.bootstrap_token.as_bytes();
        let issued = self
            .issuer
            .issue(
                &request.requested_host_label,
                token,
                &request.certificate_signing_request_pem,
                unix_ms(),
            )
            .map_err(|error| match error {
                EnrollmentIssueError::UnauthorizedGrant => {
                    Status::unauthenticated("enrollment grant rejected")
                }
                EnrollmentIssueError::InvalidCsr => {
                    Status::invalid_argument("CSR identity rejected")
                }
                EnrollmentIssueError::Signer => {
                    Status::failed_precondition("enrollment signer unavailable")
                }
                EnrollmentIssueError::State => Status::internal("enrollment state unavailable"),
            })?;
        Ok(Response::new(crate::proto::EnrollResponse {
            agent_id: issued.agent_id,
            client_certificate_chain_pem: issued.client_certificate_chain_pem,
            ca_certificate_pem: issued.ca_certificate_pem,
            ca_fingerprint_sha256: issued.ca_fingerprint_sha256,
            selected_version: request.supported_versions.into_iter().next(),
            certificate_expires_at_unix_ms: issued.certificate_expires_at_unix_ms as i64,
            rotation_deadline_unix_ms: issued.rotation_deadline_unix_ms as i64,
        }))
    }

    async fn rotate_certificate(
        &self,
        _request: Request<crate::proto::RotateCertificateRequest>,
    ) -> Result<Response<crate::proto::RotateCertificateResponse>, Status> {
        Err(Status::unimplemented(
            "certificate rotation requires an authenticated existing agent",
        ))
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
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
        let _ = validate_csr(csr_pem, &grant.agent_id, &grant.agent_epoch)?;
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
            || (!grant.agent_epoch.is_empty() && issued.agent_epoch != grant.agent_epoch)
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

    pub async fn issue_durable_async<R: AsyncDurableEnrollmentGrants>(
        &self,
        grants: &R,
        grant_id: &str,
        token: &[u8],
        csr_pem: &[u8],
        now_unix_ms: u64,
    ) -> Result<IssuedEnrollment, EnrollmentIssueError> {
        if token.len() > 4096 || csr_pem.len() > 128 * 1024 {
            return Err(EnrollmentIssueError::UnauthorizedGrant);
        }
        let token_digest = hex_lower(&Sha256::digest(token));
        let grant = grants.lookup(grant_id, &token_digest, now_unix_ms).await?;
        let (agent_id, agent_epoch) = validate_csr(csr_pem, &grant.agent_id, &grant.agent_epoch)?;
        let csr_sha256 = hex_lower(&Sha256::digest(csr_pem));
        if let Some(prior) = grants
            .existing_issue(
                grant_id,
                &token_digest,
                &agent_id,
                &agent_epoch,
                &csr_sha256,
                now_unix_ms,
            )
            .await?
        {
            if prior.certificate_expires_at_unix_ms > now_unix_ms {
                return Ok(prior);
            }
            return Err(EnrollmentIssueError::UnauthorizedGrant);
        }
        let issued = self
            .signer
            .sign_csr(grant_id, token, &agent_id, &agent_epoch, csr_pem)
            .map_err(|_| EnrollmentIssueError::Signer)?;
        let certificate_fingerprint_sha256 =
            validate_issued_binding(&issued, csr_pem, now_unix_ms)?;
        if issued.agent_id != agent_id || issued.agent_epoch != agent_epoch {
            return Err(EnrollmentIssueError::Signer);
        }
        grants
            .complete_issue(
                &DurableEnrollmentIssue {
                    grant_id: grant_id.to_owned(),
                    agent_id,
                    agent_epoch,
                    token_digest_hex: token_digest,
                    csr_sha256,
                    certificate_fingerprint_sha256,
                    issued,
                    issued_at_unix_ms: now_unix_ms,
                },
                now_unix_ms,
            )
            .await
    }
}

fn validate_issued_binding(
    issued: &IssuedEnrollment,
    csr_pem: &[u8],
    now_unix_ms: u64,
) -> Result<String, EnrollmentIssueError> {
    let fingerprint = validate_issued_enrollment(issued, now_unix_ms)?;
    let chain = X509::stack_from_pem(&issued.client_certificate_chain_pem)
        .map_err(|_| EnrollmentIssueError::Signer)?;
    let leaf = chain.first().ok_or(EnrollmentIssueError::Signer)?;
    let key = X509Req::from_pem(csr_pem)
        .and_then(|r| r.public_key())
        .map_err(|_| EnrollmentIssueError::Signer)?;
    if !leaf
        .public_key()
        .map_err(|_| EnrollmentIssueError::Signer)?
        .public_eq(&key)
    {
        return Err(EnrollmentIssueError::Signer);
    }
    Ok(fingerprint)
}

/// Validate a returned or persisted issuance against the installation-local
/// CA, agent/epoch URI SANs and declared time bounds.
pub fn validate_issued_enrollment(
    issued: &IssuedEnrollment,
    now_unix_ms: u64,
) -> Result<String, EnrollmentIssueError> {
    let chain = X509::stack_from_pem(&issued.client_certificate_chain_pem)
        .map_err(|_| EnrollmentIssueError::Signer)?;
    let ca =
        X509::from_pem(&issued.ca_certificate_pem).map_err(|_| EnrollmentIssueError::Signer)?;
    let leaf = chain.first().ok_or(EnrollmentIssueError::Signer)?;
    let subject_alt_names = leaf
        .subject_alt_names()
        .ok_or(EnrollmentIssueError::Signer)?;
    let expected_agent_uri = format!("urn:o3k:compute:agent:{}", issued.agent_id);
    let expected_epoch_uri = format!("urn:o3k:compute:epoch:{}", issued.agent_epoch);
    let uri_names: Vec<&str> = subject_alt_names
        .iter()
        .filter_map(|name| name.uri())
        .collect();
    if uri_names.len() != 2
        || !uri_names.contains(&expected_agent_uri.as_str())
        || !uri_names.contains(&expected_epoch_uri.as_str())
    {
        return Err(EnrollmentIssueError::Signer);
    }
    let mut roots =
        openssl::x509::store::X509StoreBuilder::new().map_err(|_| EnrollmentIssueError::Signer)?;
    roots
        .add_cert(ca.clone())
        .map_err(|_| EnrollmentIssueError::Signer)?;
    let roots = roots.build();
    let chain_rest = Stack::new().map_err(|_| EnrollmentIssueError::Signer)?;
    let mut ctx =
        openssl::x509::X509StoreContext::new().map_err(|_| EnrollmentIssueError::Signer)?;
    ctx.init(&roots, leaf, &chain_rest, |c| c.verify_cert())
        .map_err(|_| EnrollmentIssueError::Signer)?;
    let digest = hex_lower(&Sha256::digest(
        ca.to_der().map_err(|_| EnrollmentIssueError::Signer)?,
    ));
    if !digest.eq_ignore_ascii_case(&issued.ca_fingerprint_sha256)
        || issued.certificate_expires_at_unix_ms <= now_unix_ms
        || issued.rotation_deadline_unix_ms > issued.certificate_expires_at_unix_ms
    {
        return Err(EnrollmentIssueError::Signer);
    }
    Ok(hex_lower(&Sha256::digest(
        leaf.to_der().map_err(|_| EnrollmentIssueError::Signer)?,
    )))
}

/// Return the SHA-256 fingerprint of the DER leaf certificate in a PEM chain.
/// This keeps enrollment-result binding independent of PEM whitespace and
/// line-ending choices made by callers.
pub fn certificate_fingerprint_sha256(pem: &[u8]) -> Result<String, EnrollmentIssueError> {
    let chain = X509::stack_from_pem(pem).map_err(|_| EnrollmentIssueError::Signer)?;
    let leaf = chain.first().ok_or(EnrollmentIssueError::Signer)?;
    Ok(hex_lower(&Sha256::digest(
        leaf.to_der().map_err(|_| EnrollmentIssueError::Signer)?,
    )))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn validate_csr(
    csr_pem: &[u8],
    agent_id: &str,
    epoch: &str,
) -> Result<(String, String), EnrollmentIssueError> {
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
    let uris: Vec<&str> = text
        .lines()
        .flat_map(|line| line.split_whitespace())
        .filter_map(|token| token.strip_prefix("URI:"))
        // OpenSSL's human-readable rendering may print comma separators at
        // line ends when multiple GeneralNames share one extension. Remove
        // only that presentation delimiter before exact identity matching.
        .map(|uri| uri.trim_end_matches(','))
        .collect();
    let agent_ids: Vec<&str> = uris
        .iter()
        .filter_map(|uri| uri.strip_prefix("urn:o3k:compute:agent:"))
        .collect();
    let epochs: Vec<&str> = uris
        .iter()
        .filter_map(|uri| uri.strip_prefix("urn:o3k:compute:epoch:"))
        .collect();
    if agent_ids.len() != 1 || epochs.len() != 1 || agent_ids[0].is_empty() || epochs[0].is_empty()
    {
        return Err(EnrollmentIssueError::InvalidCsr);
    }
    let parsed_agent = agent_ids[0].to_owned();
    let parsed_epoch = epochs[0].to_owned();
    if (agent_id != "*" && parsed_agent != agent_id) || (!epoch.is_empty() && parsed_epoch != epoch)
    {
        return Err(EnrollmentIssueError::InvalidCsr);
    }
    Ok((parsed_agent, parsed_epoch))
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
