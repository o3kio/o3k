//! Libvirt provider domain types: errors, configuration, capabilities.

use thiserror::Error;

use crate::{ErrorCategory, proto};

pub const LOCAL_SYSTEM_URI: &str = "qemu:///system";
pub const O3K_METADATA_NAMESPACE: &str = "urn:o3k:compute:domain";

#[derive(Debug, Error)]
#[error("libvirt {category:?}: {message}")]
pub struct LibvirtError {
    pub category: ErrorCategory,
    message: String,
}

impl LibvirtError {
    pub fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
        }
    }

    /// Returns the bounded provider detail retained for host-local diagnostics.
    ///
    /// The compute-agent protocol still projects only the finite error category;
    /// this accessor exists so the execution boundary can record the exact
    /// libvirt operation and provider message without putting it on the wire.
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone)]
pub struct LibvirtConfig {
    pub uri: String,
    pub managed_domain_prefix: String,
}

impl Default for LibvirtConfig {
    fn default() -> Self {
        Self {
            uri: LOCAL_SYSTEM_URI.to_owned(),
            managed_domain_prefix: "o3k-".to_owned(),
        }
    }
}

impl LibvirtConfig {
    pub(crate) fn validate(&self) -> Result<(), LibvirtError> {
        if self.uri != LOCAL_SYSTEM_URI {
            return Err(LibvirtError::new(
                ErrorCategory::InvalidRequest,
                "only the local qemu:///system URI is supported",
            ));
        }
        if self.managed_domain_prefix.is_empty() || self.managed_domain_prefix.len() > 64 {
            return Err(LibvirtError::new(
                ErrorCategory::InvalidRequest,
                "managed domain prefix is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct LibvirtCapabilities {
    pub uri: String,
    pub libvirt_version: Option<String>,
    pub hypervisor_version: Option<String>,
    pub architecture: Option<String>,
    pub cpu_model: Option<String>,
    pub total_memory_kib: Option<u64>,
    pub total_vcpus: Option<u32>,
    pub machine_types: Vec<String>,
    pub kvm_available: bool,
    pub supported_operations: Vec<String>,
}

impl LibvirtCapabilities {
    pub fn unavailable(uri: &str) -> Self {
        Self {
            uri: uri.to_owned(),
            supported_operations: Vec::new(),
            ..Self::default()
        }
    }

    pub fn to_protocol_capabilities(&self) -> proto::Capabilities {
        proto::Capabilities {
            architecture: self.architecture.clone().unwrap_or_default(),
            agent_provider_name: "o3k-libvirt".to_owned(),
            agent_provider_version: self.libvirt_version.clone().unwrap_or_default(),
            max_vcpus: self.total_vcpus.unwrap_or_default(),
            max_memory_mib: self.total_memory_kib.unwrap_or_default() / 1024,
            lifecycle_actions: self.supported_operations.clone(),
            console_log: true,
            max_console_log_bytes: 64 * 1024,
            flags: vec![
                proto::CapabilityFlag {
                    name: "kvm".to_owned(),
                    supported: self.kvm_available,
                    bounded_value: String::new(),
                },
                proto::CapabilityFlag {
                    name: "config_drive".to_owned(),
                    supported: true,
                    bounded_value: String::new(),
                },
                proto::CapabilityFlag {
                    name: "artifact_transfer".to_owned(),
                    supported: true,
                    bounded_value: String::new(),
                },
            ],
            ..Default::default()
        }
    }
}
