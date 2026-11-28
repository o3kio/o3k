//! Compute agent domain types: errors, configuration, node registry.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use thiserror::Error;

use o3k_provider_contract::compute_proto as proto;

use openssl::{
    ec::EcKey,
    nid::Nid,
    pkey::PKey,
    x509::{X509Extension, X509NameBuilder, X509Req},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub(crate) const MAX_HOST_LABEL: usize = 255;

/// Locally generated enrollment identity. Private key bytes are intentionally
/// not exposed or serializable; only the CSR is sent to the controller.
pub struct EnrollmentIdentity {
    agent_id: String,
    agent_epoch: String,
    private_key_pem: Vec<u8>,
    csr_pem: Vec<u8>,
}

impl std::fmt::Debug for EnrollmentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentIdentity")
            .field("agent_id", &self.agent_id)
            .field("agent_epoch", &self.agent_epoch)
            .field("private_key_pem", &"<redacted>")
            .field("csr_pem", &"<redacted>")
            .finish()
    }
}

impl EnrollmentIdentity {
    pub fn generate(agent_id: &str, agent_epoch: &str) -> Result<Self, AgentError> {
        if !valid_enrollment_component(agent_id) || !valid_enrollment_component(agent_epoch) {
            return Err(AgentError::InvalidConfiguration(
                "invalid enrollment identity",
            ));
        }
        let group = openssl::ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|_| AgentError::TlsMaterial)?;
        let key = EcKey::generate(&group).map_err(|_| AgentError::TlsMaterial)?;
        let pkey = PKey::from_ec_key(key).map_err(|_| AgentError::TlsMaterial)?;
        let mut name = X509NameBuilder::new().map_err(|_| AgentError::TlsMaterial)?;
        name.append_entry_by_text("CN", agent_id)
            .map_err(|_| AgentError::TlsMaterial)?;
        let name = name.build();
        let mut req = X509Req::builder().map_err(|_| AgentError::TlsMaterial)?;
        req.set_subject_name(&name)
            .map_err(|_| AgentError::TlsMaterial)?;
        req.set_pubkey(&pkey).map_err(|_| AgentError::TlsMaterial)?;
        #[allow(deprecated)]
        let san = X509Extension::new_nid(
            None,
            None,
            Nid::SUBJECT_ALT_NAME,
            &format!(
                "URI:urn:o3k:compute:agent:{agent_id},URI:urn:o3k:compute:epoch:{agent_epoch}"
            ),
        )
        .map_err(|_| AgentError::TlsMaterial)?;
        let mut extensions = openssl::stack::Stack::new().map_err(|_| AgentError::TlsMaterial)?;
        extensions.push(san).map_err(|_| AgentError::TlsMaterial)?;
        req.add_extensions(&extensions)
            .map_err(|_| AgentError::TlsMaterial)?;
        req.sign(&pkey, openssl::hash::MessageDigest::sha256())
            .map_err(|_| AgentError::TlsMaterial)?;
        Ok(Self {
            agent_id: agent_id.to_owned(),
            agent_epoch: agent_epoch.to_owned(),
            private_key_pem: pkey
                .private_key_to_pem_pkcs8()
                .map_err(|_| AgentError::TlsMaterial)?,
            csr_pem: req.build().to_pem().map_err(|_| AgentError::TlsMaterial)?,
        })
    }
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
    pub fn agent_epoch(&self) -> &str {
        &self.agent_epoch
    }
    pub fn csr_pem(&self) -> &[u8] {
        &self.csr_pem
    }
    pub fn write_private_key(&self, path: &std::path::Path) -> Result<(), AgentError> {
        use std::os::unix::fs::OpenOptionsExt;
        let parent = path.parent().ok_or(AgentError::InvalidConfiguration(
            "private-key path has no parent",
        ))?;
        std::fs::create_dir_all(parent).map_err(AgentError::IdentityStore)?;
        let tmp = parent.join(format!(
            ".{}.tmp-{}",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("key"),
            uuid::Uuid::new_v4()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true).mode(0o600);
        use std::io::Write;
        let result = (|| {
            let mut file = options.open(&tmp).map_err(AgentError::IdentityStore)?;
            file.write_all(&self.private_key_pem)
                .map_err(AgentError::IdentityStore)?;
            file.sync_all().map_err(AgentError::IdentityStore)?;
            std::fs::hard_link(&tmp, path).map_err(AgentError::IdentityStore)?;
            std::fs::remove_file(&tmp).map_err(AgentError::IdentityStore)
        })();
        let _ = std::fs::remove_file(&tmp);
        result
    }
}

impl Drop for EnrollmentIdentity {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}

fn valid_enrollment_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("invalid compute-agent configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("compute-agent identity store is unavailable")]
    IdentityStore(#[source] std::io::Error),
    #[error("compute-agent transport is unavailable: {0}")]
    Transport(#[source] tonic::transport::Error),
    #[error("compute-agent TLS material is unavailable")]
    TlsMaterial,
    #[error("compute-agent protocol error: {0}")]
    Protocol(String),
    #[error("compute-agent startup admission denied: {0}")]
    StartupAdmission(String),
}

#[derive(Clone)]
pub struct TlsFiles {
    pub ca_certificate: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

impl std::fmt::Debug for TlsFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsFiles")
            .field("ca_certificate", &self.ca_certificate)
            .field("certificate", &self.certificate)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl TlsFiles {
    pub(crate) fn read(&self) -> Result<TlsMaterial, AgentError> {
        let ca = fs::read(&self.ca_certificate).map_err(|_| AgentError::TlsMaterial)?;
        let cert = fs::read(&self.certificate).map_err(|_| AgentError::TlsMaterial)?;
        let key = fs::read(&self.private_key).map_err(|_| AgentError::TlsMaterial)?;
        if ca.is_empty() || cert.is_empty() || key.is_empty() {
            return Err(AgentError::InvalidConfiguration(
                "TLS files must not be empty",
            ));
        }
        Ok(TlsMaterial { ca, cert, key })
    }
}

pub(crate) struct TlsMaterial {
    pub(crate) ca: Vec<u8>,
    pub(crate) cert: Vec<u8>,
    pub(crate) key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub endpoint: String,
    pub server_name: String,
    pub tls: TlsFiles,
    pub identity_file: PathBuf,
    /// A canonical enrollment epoch supplied by `o3k join`. When absent the
    /// agent creates a fresh process epoch for portable development setups.
    pub agent_epoch: Option<String>,
    pub host_label: String,
    pub software_version: String,
    pub heartbeat_interval: Duration,
    pub max_reconnect_delay: Duration,
    pub capabilities: proto::Capabilities,
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), AgentError> {
        if !self.endpoint.starts_with("https://") || self.server_name.trim().is_empty() {
            return Err(AgentError::InvalidConfiguration(
                "endpoint must be HTTPS and server name must be set",
            ));
        }
        if self.host_label.is_empty() || self.host_label.len() > MAX_HOST_LABEL {
            return Err(AgentError::InvalidConfiguration(
                "host label length is invalid",
            ));
        }
        if self.software_version.trim().is_empty()
            || self.heartbeat_interval.is_zero()
            || self.max_reconnect_delay.is_zero()
        {
            return Err(AgentError::InvalidConfiguration(
                "version and retry intervals must be set",
            ));
        }
        if self.agent_epoch.as_deref().is_some_and(|epoch| {
            epoch.is_empty()
                || epoch.len() > 128
                || !epoch
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        }) {
            return Err(AgentError::InvalidConfiguration(
                "agent epoch contains invalid characters",
            ));
        }
        let _ = self.tls.read()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Available,
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    pub agent_id: String,
    pub agent_epoch: String,
    pub host_label: String,
    pub software_version: String,
    pub capabilities: proto::Capabilities,
    pub desired_state: i32,
    pub applied_state: i32,
    pub availability: Availability,
    pub active_operation_count: u32,
    pub last_heartbeat_sequence: u64,
    pub last_heartbeat_at: SystemTime,
    pub transition_sequence: u64,
    pub last_heartbeat_state: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedAgent {
    pub agent_id: String,
    pub certificate_sha256: [u8; 32],
}

impl AuthorizedAgent {
    pub fn new(agent_id: impl Into<String>, certificate: &[u8]) -> Self {
        let digest = Sha256::digest(normalize_certificate(certificate));
        let mut certificate_sha256 = [0_u8; 32];
        certificate_sha256.copy_from_slice(&digest);
        Self {
            agent_id: agent_id.into(),
            certificate_sha256,
        }
    }
}

pub(crate) fn normalize_certificate(certificate: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(certificate) else {
        return certificate.to_vec();
    };
    let Some(body) = text
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|value| value.split("-----END CERTIFICATE-----").next())
    else {
        return certificate.to_vec();
    };
    BASE64
        .decode(body.split_whitespace().collect::<String>())
        .unwrap_or_else(|_| certificate.to_vec())
}

pub fn parse_authorized_agents(value: &str) -> Result<Vec<AuthorizedAgent>, AgentError> {
    let mut agents = Vec::new();
    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (agent_id, fingerprint) =
            entry
                .split_once('=')
                .ok_or(AgentError::InvalidConfiguration(
                    "authorized agent must be id=sha256hex",
                ))?;
        if agent_id.trim().is_empty() || fingerprint.len() != 64 || !fingerprint.is_ascii() {
            return Err(AgentError::InvalidConfiguration(
                "authorized agent must be id=sha256hex",
            ));
        }
        let mut certificate_sha256 = [0_u8; 32];
        for (index, byte) in certificate_sha256.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&fingerprint[offset..offset + 2], 16).map_err(|_| {
                AgentError::InvalidConfiguration("authorized agent fingerprint is not hex")
            })?;
        }
        agents.push(AuthorizedAgent {
            agent_id: agent_id.to_owned(),
            certificate_sha256,
        });
    }
    if agents.is_empty() {
        return Err(AgentError::InvalidConfiguration(
            "at least one authorized agent is required",
        ));
    }
    Ok(agents)
}
