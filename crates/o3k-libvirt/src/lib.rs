//! Typed local libvirt/KVM adapter for the compute agent.
//!
//! The public API is async and keeps all libvirt FFI behind `spawn_blocking`.
//! The `libvirt` feature enables the `virt` bindings; the default build keeps
//! the control plane usable on hosts where libvirt development libraries are
//! not installed and reports a clear readiness error instead.

use std::{
    fmt, fs,
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

pub use o3k_provider_contract::compute_proto as proto;
use sha2::{Digest, Sha256};

#[cfg(feature = "libvirt")]
use virt::{connect::Connect, domain::Domain};

pub const LOCAL_SYSTEM_URI: &str = "qemu:///system";
pub const O3K_METADATA_NAMESPACE: &str = "urn:o3k:compute:domain";

// These values are the stable public libvirt virDomainState values. Keep the
// projection explicit: treating every non-active domain as stopped would turn
// paused, crashed, and unknown observations into a healthy state.
#[cfg(feature = "libvirt")]
const LIBVIRT_STATE_NO_STATE: u32 = 0;
#[cfg(feature = "libvirt")]
const LIBVIRT_STATE_RUNNING: u32 = 1;
#[cfg(feature = "libvirt")]
const LIBVIRT_STATE_BLOCKED: u32 = 2;
#[cfg(feature = "libvirt")]
const LIBVIRT_STATE_PAUSED: u32 = 3;
#[cfg(feature = "libvirt")]
const LIBVIRT_STATE_SHUTDOWN: u32 = 4;
#[cfg(feature = "libvirt")]
const LIBVIRT_STATE_SHUTOFF: u32 = 5;
#[cfg(feature = "libvirt")]
const LIBVIRT_STATE_CRASHED: u32 = 6;
#[cfg(feature = "libvirt")]
const LIBVIRT_STATE_PMSUSPENDED: u32 = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainMetadata {
    pub server_id: String,
    pub project_id: String,
    pub generation: u64,
    pub operation_id: String,
    pub managed_by: String,
}

#[derive(Debug, Clone)]
pub struct DomainSpec {
    pub metadata: DomainMetadata,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub image_id: String,
    /// Host-local materialized config-drive image bound to its content digest.
    pub config_drive_image: Option<ConfigDriveImage>,
    pub network_interfaces: Vec<DomainNetworkInterface>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDriveImage {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainNetworkInterface {
    /// Existing TAP device prepared and owned by the host network subsystem.
    pub tap_name: String,
    pub mac_address: String,
}

/// Project a libvirt observation into the provider lifecycle state.
///
/// The active bit is checked along with the libvirt state so an inconsistent
/// observation cannot be reported as running. States that do not have a safe
/// Nova-like projection are reported as `Error`; reconciliation can then
/// inspect the retained provider message instead of making a destructive
/// assumption.
pub fn project_domain_state(active: bool, state: &str) -> o3k_provider::InstanceState {
    match (active, state) {
        (true, "running") => o3k_provider::InstanceState::Running,
        (false, "shutdown" | "shutoff") => o3k_provider::InstanceState::Stopped,
        _ => o3k_provider::InstanceState::Error,
    }
}

#[cfg(feature = "libvirt")]
fn domain_state_name(state: u32) -> &'static str {
    match state {
        LIBVIRT_STATE_NO_STATE => "no-state",
        LIBVIRT_STATE_RUNNING => "running",
        LIBVIRT_STATE_BLOCKED => "blocked",
        LIBVIRT_STATE_PAUSED => "paused",
        LIBVIRT_STATE_SHUTDOWN => "shutdown",
        LIBVIRT_STATE_SHUTOFF => "shutoff",
        LIBVIRT_STATE_CRASHED => "crashed",
        LIBVIRT_STATE_PMSUSPENDED => "pmsuspended",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltDomainXml {
    pub name: String,
    pub xml: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryResult {
    Owned {
        name: String,
        metadata: DomainMetadata,
    },
    Foreign {
        name: String,
    },
    Quarantined {
        name: String,
        reason: String,
    },
}

pub fn stable_domain_name(server_id: &str) -> String {
    let digest = Sha256::digest(server_id.as_bytes());
    let mut suffix = String::with_capacity(20);
    for byte in digest.iter().take(10) {
        use std::fmt::Write as _;
        let _ = write!(&mut suffix, "{byte:02x}");
    }
    format!("o3k-{suffix}")
}

/// Returns the agent-owned durable serial log path for a domain image path.
pub fn console_log_path(image_path: &str, domain_name: &str) -> Result<String, LibvirtError> {
    let image_path = Path::new(image_path);
    if validate_image_source(image_path.to_str().unwrap_or_default()).is_err()
        || domain_name.is_empty()
        || Path::new(domain_name).file_name().and_then(|v| v.to_str()) != Some(domain_name)
    {
        return Err(LibvirtError::new(
            ErrorCategory::InvalidRequest,
            "console log path is invalid",
        ));
    }
    let root = image_path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| {
            LibvirtError::new(ErrorCategory::InvalidRequest, "image path has no root")
        })?;
    Ok(root
        .join("console")
        .join(format!("{domain_name}.log"))
        .to_string_lossy()
        .into_owned())
}

pub fn build_domain_xml(spec: &DomainSpec) -> Result<BuiltDomainXml, LibvirtError> {
    validate_metadata(&spec.metadata)?;
    if spec.vcpus == 0
        || spec.vcpus > 512
        || spec.memory_mib == 0
        || validate_image_source(&spec.image_id).is_err()
        || spec
            .config_drive_image
            .as_ref()
            .is_some_and(|image| validate_config_drive_image(image).is_err())
        || spec.network_interfaces.iter().any(|interface| {
            validate_tap_name(&interface.tap_name).is_err()
                || validate_mac_address(&interface.mac_address).is_err()
        })
    {
        return Err(LibvirtError::new(
            ErrorCategory::InvalidRequest,
            "domain resource values are invalid",
        ));
    }
    let name = stable_domain_name(&spec.metadata.server_id);
    let console_path = console_log_path(&spec.image_id, &name)?;
    let m = &spec.metadata;
    let config_drive = spec.config_drive_image.as_ref().map(|image| {
            format!(
                "<disk type=\"file\" device=\"cdrom\"><driver name=\"qemu\" type=\"raw\" /><source file=\"{}\" /><target dev=\"sda\" bus=\"sata\" /><readonly /></disk>",
                xml_escape(&image.path)
            )
        })
        .unwrap_or_default();
    let mut network_interfaces = String::new();
    for interface in &spec.network_interfaces {
        use std::fmt::Write as _;
        let _ = write!(
            network_interfaces,
            "<interface type=\"ethernet\"><mac address=\"{}\" /><target dev=\"{}\" managed=\"no\" /><model type=\"virtio\" /></interface>",
            xml_escape(&interface.mac_address),
            xml_escape(&interface.tap_name)
        );
    }
    let xml = format!(
        "<domain type=\"kvm\"><name>{}</name><memory unit=\"MiB\">{}</memory><currentMemory unit=\"MiB\">{}</currentMemory><vcpu>{}</vcpu><metadata><o3k:domain xmlns:o3k=\"{}\" server_id=\"{}\" project_id=\"{}\" generation=\"{}\" operation_id=\"{}\" managed_by=\"{}\" /></metadata><os><type machine=\"pc\">hvm</type></os><devices><controller type=\"scsi\" index=\"0\" model=\"virtio-scsi\" /><controller type=\"pci\" index=\"1\" model=\"pci-bridge\" /><serial type=\"file\"><source path=\"{}\" append=\"on\" /><target type=\"isa-serial\" port=\"0\" /></serial><console type=\"file\"><source path=\"{}\" append=\"on\" /><target type=\"serial\" port=\"0\" /></console><disk type=\"file\" device=\"disk\"><driver name=\"qemu\" type=\"qcow2\" /><source file=\"{}\" /><target dev=\"vda\" bus=\"virtio\" /></disk>{}{}</devices></domain>",
        xml_escape(&name),
        spec.memory_mib,
        spec.memory_mib,
        spec.vcpus,
        O3K_METADATA_NAMESPACE,
        xml_escape(&m.server_id),
        xml_escape(&m.project_id),
        m.generation,
        xml_escape(&m.operation_id),
        xml_escape(&m.managed_by),
        xml_escape(&console_path),
        xml_escape(&console_path),
        xml_escape(&spec.image_id),
        config_drive,
        network_interfaces
    );
    Ok(BuiltDomainXml { name, xml })
}

pub fn discover_domain_xml(name: &str, xml: &str) -> DiscoveryResult {
    let Some(metadata) = parse_metadata(xml) else {
        return DiscoveryResult::Foreign {
            name: name.to_owned(),
        };
    };
    match metadata {
        Ok(metadata) => DiscoveryResult::Owned {
            name: name.to_owned(),
            metadata,
        },
        Err(reason) => DiscoveryResult::Quarantined {
            name: name.to_owned(),
            reason,
        },
    }
}

/// Builds the deterministic libvirt `<disk>` XML for a hotplugged block
/// device. The `o3k-<uuid>` `<serial>` binds the host device to a durable O3K
/// volume identity so detach and observe can find it (libvirt preserves disk
/// serials across attach; it strips custom device `<metadata>`).
///
/// The disk is placed on the domain's pci-bridge (bus `0x01`). PCI bridges
/// reserve slot 0 for the bridge itself, so the caller must supply a slot in
/// `1..=31` (see `free_pci_bridge_slot`); a fixed slot would collide on
/// multi-attach.
pub fn build_attach_disk_xml(
    volume_id: &str,
    attachment_id: &str,
    host_path: &str,
    device: &str,
    slot: u8,
) -> Result<String, LibvirtError> {
    if volume_id.trim().is_empty()
        || attachment_id.trim().is_empty()
        || host_path.trim().is_empty()
        || device.trim().is_empty()
        || device.starts_with('/')
        || slot == 0
        || slot > 31
    {
        return Err(LibvirtError::new(
            ErrorCategory::InvalidRequest,
            "attach disk identity or target is invalid",
        ));
    }
    Ok(format!(
        r#"<disk type="block" device="disk">
  <driver name="qemu" type="raw" cache="none"/>
  <source dev="{host_path}"/>
  <target dev="{device}" bus="virtio"/>
  <serial>{serial}</serial>
  <address type="pci" domain="0x0000" bus="0x01" slot="0x{slot:02x}" function="0x0"/>
</disk>"#,
        serial = o3k_disk_serial(volume_id)
    ))
}

/// Builds the durable disk serial that binds a hotplugged block device to an
/// O3K volume. The serial is preserved by libvirt across attach/dumpxml (the
/// custom `<metadata>` element is not), so observe and detach match on it.
/// Libvirt rejects serials containing unsafe characters (colons, spaces, etc.);
/// UUIDs and the `o3k-` prefix are safe.
pub fn o3k_disk_serial(volume_id: &str) -> String {
    format!("o3k-{volume_id}")
}

/// Parses the PCI slots already in use on a given bus from a domain XML
/// document, returning them as a sorted set. Used to place a hotplugged disk
/// on a free pci-bridge slot.
fn used_pci_slots_on_bus(xml: &str, bus_hex: &str) -> Vec<u8> {
    let mut slots = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = xml[search_from..].find("<address type=\"pci\"") {
        let start = search_from + rel;
        let Some(end) = xml[start..].find("/>") else {
            break;
        };
        let tag = &xml[start..start + end];
        if tag.contains(&format!("bus=\"{bus_hex}\""))
            && let Some(slot) = attr(tag, "slot")
            && let Ok(slot) = u8::from_str_radix(slot.trim_start_matches("0x"), 16)
        {
            slots.push(slot);
        }
        search_from = start + end;
    }
    slots.sort_unstable();
    slots.dedup();
    slots
}

/// Selects the lowest free slot in `1..=31` on the pci-bridge (bus `0x01`).
fn free_pci_bridge_slot(xml: &str) -> Option<u8> {
    let used = used_pci_slots_on_bus(xml, "0x01");
    (1..=31).find(|slot| !used.contains(slot))
}

/// Extracts the O3K-owned disk volume identities from a domain XML document.
/// The durable identity is carried in the disk `<serial>` element (libvirt
/// preserves serials across attach; custom device metadata is not).
pub fn owned_disk_volume_ids(xml: &str) -> Vec<String> {
    let mut volumes = Vec::new();
    let mut search_from = 0;
    while let Some(marker_start) = xml[search_from..].find("<serial>o3k-") {
        let start = search_from + marker_start;
        let Some(end) = xml[start..].find("</serial>") else {
            break;
        };
        let serial = &xml[start + "<serial>o3k-".len()..start + end];
        // Serial format is `o3k-<uuid>`; accept the 36-character UUID.
        if serial.len() == 36 {
            volumes.push(serial.to_owned());
        }
        search_from = start + end;
    }
    volumes
}

pub fn discover_domain_xmls(domains: &[(String, String)]) -> Vec<DiscoveryResult> {
    let mut results = domains
        .iter()
        .map(|(name, xml)| discover_domain_xml(name, xml))
        .collect::<Vec<_>>();
    let mut counts = std::collections::HashMap::new();
    for result in &results {
        if let DiscoveryResult::Owned { metadata, .. } = result {
            *counts.entry(metadata.server_id.clone()).or_insert(0_usize) += 1;
        }
    }
    for result in &mut results {
        let duplicate = match result {
            DiscoveryResult::Owned { name, metadata }
                if counts.get(&metadata.server_id).copied().unwrap_or_default() > 1 =>
            {
                Some((name.clone(), metadata.server_id.clone()))
            }
            _ => None,
        };
        if let Some((name, server_id)) = duplicate {
            *result = DiscoveryResult::Quarantined {
                name,
                reason: format!("duplicate O3K server ID: {server_id}"),
            };
        }
    }
    results
}

fn managed_domain_names(domains: &[(String, String)], prefix: &str) -> Vec<String> {
    discover_domain_xmls(domains)
        .into_iter()
        .filter_map(|result| match result {
            DiscoveryResult::Owned { name, .. } if name.starts_with(prefix) => Some(name),
            _ => None,
        })
        .collect()
}

fn validate_metadata(metadata: &DomainMetadata) -> Result<(), LibvirtError> {
    for value in [
        &metadata.server_id,
        &metadata.project_id,
        &metadata.operation_id,
        &metadata.managed_by,
    ] {
        if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(LibvirtError::new(
                ErrorCategory::InvalidRequest,
                "domain metadata is invalid",
            ));
        }
    }
    if metadata.managed_by != "o3k-compute" {
        return Err(LibvirtError::new(
            ErrorCategory::InvalidRequest,
            "domain managed-by value is invalid",
        ));
    }
    Ok(())
}

fn validate_image_source(value: &str) -> Result<(), ()> {
    if value.trim().is_empty()
        || value.chars().any(char::is_control)
        || value.contains("://")
        || std::path::Path::new(value)
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(());
    }
    Ok(())
}

fn validate_config_drive_image(image: &ConfigDriveImage) -> Result<(), ()> {
    if !Path::new(&image.path).is_absolute()
        || validate_image_source(&image.path).is_err()
        || !valid_sha256(&image.sha256)
    {
        return Err(());
    }
    let metadata = fs::symlink_metadata(&image.path).map_err(|_| ())?;
    if !metadata.is_file() {
        return Err(());
    }
    let bytes = fs::read(&image.path).map_err(|_| ())?;
    if sha256_hex(&bytes) != image.sha256 {
        return Err(());
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

fn validate_tap_name(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 15
        || !value.starts_with("o3ktap-")
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'))
    {
        return Err(());
    }
    Ok(())
}

fn validate_mac_address(value: &str) -> Result<(), ()> {
    if value.len() != 17
        || value.split(':').count() != 6
        || value
            .split(':')
            .any(|octet| octet.len() != 2 || !octet.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(());
    }
    Ok(())
}

fn parse_metadata(xml: &str) -> Option<Result<DomainMetadata, String>> {
    let marker = "<o3k:domain";
    let start = xml.find(marker)?;
    let end = xml[start..].find('>')? + start;
    let tag = &xml[start..end];
    let namespace = attr(tag, "xmlns:o3k")?;
    if namespace != O3K_METADATA_NAMESPACE {
        return Some(Err("metadata namespace is invalid".to_owned()));
    }
    let generation = match attr(tag, "generation").and_then(|value| value.parse().ok()) {
        Some(value) => value,
        None => return Some(Err("generation is invalid".to_owned())),
    };
    let (Some(server_id), Some(project_id), Some(operation_id), Some(managed_by)) = (
        attr(tag, "server_id"),
        attr(tag, "project_id"),
        attr(tag, "operation_id"),
        attr(tag, "managed_by"),
    ) else {
        return Some(Err("metadata fields are incomplete".to_owned()));
    };
    let metadata = DomainMetadata {
        server_id,
        project_id,
        generation,
        operation_id,
        managed_by,
    };
    if validate_metadata(&metadata).is_err() {
        Some(Err("metadata fields are invalid".to_owned()))
    } else {
        Some(Ok(metadata))
    }
}

fn attr(tag: &str, key: &str) -> Option<String> {
    let marker = format!("{key}=\"");
    let start = tag.find(&marker)? + marker.len();
    Some(
        tag[start..]
            .split_once('"')?
            .0
            .replace("&quot;", "\"")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">"),
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Unavailable,
    ConnectionLost,
    NotFound,
    InvalidRequest,
    OperationFailed,
}

pub mod types;
pub use types::*;

#[derive(Debug, Clone)]
pub struct DomainDefinition {
    pub name: String,
    pub xml: String,
}

#[derive(Debug, Clone)]
pub struct DomainInspection {
    pub name: String,
    pub active: bool,
    pub persistent: bool,
    pub state: String,
    pub max_memory_kib: u64,
    pub vcpus: u32,
    pub xml: String,
}

#[derive(Clone)]
pub struct LibvirtAdapter {
    config: Arc<LibvirtConfig>,
}

impl fmt::Debug for LibvirtAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LibvirtAdapter")
            .field("uri", &self.config.uri)
            .field("managed_domain_prefix", &self.config.managed_domain_prefix)
            .finish()
    }
}

impl LibvirtAdapter {
    pub fn new(config: LibvirtConfig) -> Result<Self, LibvirtError> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
        })
    }

    pub async fn capabilities(&self) -> Result<LibvirtCapabilities, LibvirtError> {
        let uri = self.config.uri.clone();
        run_blocking(move || backend_capabilities(&uri)).await
    }

    pub async fn read_console(
        &self,
        name: String,
        max_bytes: usize,
        expected_server_id: String,
    ) -> Result<Vec<u8>, LibvirtError> {
        if max_bytes == 0 || max_bytes > 64 * 1024 {
            return Err(LibvirtError::new(
                ErrorCategory::InvalidRequest,
                "console read bound is invalid",
            ));
        }
        if expected_server_id.trim().is_empty() {
            return Err(LibvirtError::new(
                ErrorCategory::InvalidRequest,
                "console owner is invalid",
            ));
        }
        let uri = self.config.uri.clone();
        run_blocking(move || backend_read_console(&uri, &name, max_bytes, &expected_server_id))
            .await
    }

    pub async fn define(&self, definition: DomainDefinition) -> Result<(), LibvirtError> {
        let uri = self.config.uri.clone();
        run_blocking(move || backend_define(&uri, &definition)).await
    }

    pub async fn start(&self, name: String) -> Result<(), LibvirtError> {
        self.domain_action(name, DomainAction::Start).await
    }

    pub async fn start_owned(
        &self,
        name: String,
        expected_server_id: String,
    ) -> Result<(), LibvirtError> {
        self.owned_domain_action(name, expected_server_id, DomainAction::Start)
            .await
    }

    pub async fn inspect(&self, name: String) -> Result<DomainInspection, LibvirtError> {
        let uri = self.config.uri.clone();
        run_blocking(move || backend_inspect(&uri, &name)).await
    }

    pub async fn shutdown(&self, name: String) -> Result<(), LibvirtError> {
        self.domain_action(name, DomainAction::Shutdown).await
    }

    pub async fn shutdown_owned(
        &self,
        name: String,
        expected_server_id: String,
    ) -> Result<(), LibvirtError> {
        self.owned_domain_action(name, expected_server_id, DomainAction::Shutdown)
            .await
    }

    pub async fn force_stop(&self, name: String) -> Result<(), LibvirtError> {
        self.domain_action(name, DomainAction::ForceStop).await
    }

    pub async fn force_stop_owned(
        &self,
        name: String,
        expected_server_id: String,
    ) -> Result<(), LibvirtError> {
        self.owned_domain_action(name, expected_server_id, DomainAction::ForceStop)
            .await
    }

    pub async fn reboot(&self, name: String) -> Result<(), LibvirtError> {
        self.domain_action(name, DomainAction::Reboot).await
    }

    pub async fn reboot_owned(
        &self,
        name: String,
        expected_server_id: String,
    ) -> Result<(), LibvirtError> {
        self.owned_domain_action(name, expected_server_id, DomainAction::Reboot)
            .await
    }

    pub async fn undefine(&self, name: String) -> Result<(), LibvirtError> {
        self.domain_action(name, DomainAction::Undefine).await
    }

    /// Undefines a domain only when the current libvirt object still carries
    /// the expected O3K server identity.  The ownership check and undefine
    /// operate on the same looked-up domain handle, so callers never perform
    /// a check-then-lookup-by-name destructive race.
    pub async fn undefine_owned(
        &self,
        name: String,
        expected_server_id: String,
    ) -> Result<(), LibvirtError> {
        if expected_server_id.trim().is_empty() {
            return Err(LibvirtError::new(
                ErrorCategory::InvalidRequest,
                "domain owner is invalid",
            ));
        }
        let uri = self.config.uri.clone();
        run_blocking(move || backend_undefine_owned(&uri, &name, &expected_server_id)).await
    }

    pub async fn list_managed_domains(&self) -> Result<Vec<String>, LibvirtError> {
        let uri = self.config.uri.clone();
        let prefix = self.config.managed_domain_prefix.clone();
        run_blocking(move || backend_list(&uri, &prefix)).await
    }

    /// Hotplugs a block device into the domain and records durable volume
    /// identity in the disk metadata. The device is placed on a free
    /// pci-bridge slot so repeated attaches never collide.
    pub async fn attach_disk(
        &self,
        name: String,
        volume_id: String,
        attachment_id: String,
        host_path: String,
        device: String,
    ) -> Result<(), LibvirtError> {
        let uri = self.config.uri.clone();
        run_blocking(move || {
            backend_attach_disk(&uri, &name, &volume_id, &attachment_id, &host_path, &device)
        })
        .await
    }

    /// Detaches the O3K-owned disk for the given volume from the domain.
    pub async fn detach_disk(&self, name: String, volume_id: String) -> Result<bool, LibvirtError> {
        let uri = self.config.uri.clone();
        run_blocking(move || backend_detach_disk(&uri, &name, &volume_id)).await
    }

    /// Observes whether an O3K-owned disk for the volume is attached to the
    /// domain. The result is derived from the durable disk metadata, never
    /// from a host path or guest observation.
    pub async fn observe_disk(
        &self,
        name: String,
        volume_id: String,
    ) -> Result<bool, LibvirtError> {
        let uri = self.config.uri.clone();
        run_blocking(move || backend_observe_disk(&uri, &name, &volume_id)).await
    }

    async fn domain_action(&self, name: String, action: DomainAction) -> Result<(), LibvirtError> {
        let uri = self.config.uri.clone();
        run_blocking(move || backend_action(&uri, &name, action)).await
    }

    async fn owned_domain_action(
        &self,
        name: String,
        expected_server_id: String,
        action: DomainAction,
    ) -> Result<(), LibvirtError> {
        if expected_server_id.trim().is_empty() {
            return Err(LibvirtError::new(
                ErrorCategory::InvalidRequest,
                "domain owner is invalid",
            ));
        }
        let uri = self.config.uri.clone();
        run_blocking(move || backend_owned_action(&uri, &name, &expected_server_id, action)).await
    }
}

#[derive(Debug, Clone, Copy)]
enum DomainAction {
    Start,
    Shutdown,
    ForceStop,
    Reboot,
    Undefine,
}

async fn run_blocking<T, F>(operation: F) -> Result<T, LibvirtError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, LibvirtError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation).await.map_err(|_| {
        LibvirtError::new(ErrorCategory::OperationFailed, "libvirt worker terminated")
    })?
}

#[cfg(not(feature = "libvirt"))]
fn backend_capabilities(uri: &str) -> Result<LibvirtCapabilities, LibvirtError> {
    Err(LibvirtError::new(
        ErrorCategory::Unavailable,
        format!(
            "local libvirt support is not compiled; install libvirt and enable the libvirt feature for {uri}"
        ),
    ))
}

#[cfg(not(feature = "libvirt"))]
fn backend_define(_: &str, _: &DomainDefinition) -> Result<(), LibvirtError> {
    unavailable()
}
#[cfg(not(feature = "libvirt"))]
fn backend_inspect(_: &str, _: &str) -> Result<DomainInspection, LibvirtError> {
    unavailable()
}
#[cfg(not(feature = "libvirt"))]
fn backend_action(_: &str, _: &str, _: DomainAction) -> Result<(), LibvirtError> {
    unavailable()
}
#[cfg(not(feature = "libvirt"))]
fn backend_owned_action(_: &str, _: &str, _: &str, _: DomainAction) -> Result<(), LibvirtError> {
    unavailable()
}
#[cfg(not(feature = "libvirt"))]
fn backend_list(_: &str, _: &str) -> Result<Vec<String>, LibvirtError> {
    unavailable()
}
#[cfg(not(feature = "libvirt"))]
fn backend_read_console(_: &str, _: &str, _: usize, _: &str) -> Result<Vec<u8>, LibvirtError> {
    unavailable()
}
#[cfg(not(feature = "libvirt"))]
fn unavailable<T>() -> Result<T, LibvirtError> {
    Err(LibvirtError::new(
        ErrorCategory::Unavailable,
        "local libvirt support is unavailable",
    ))
}

#[cfg(feature = "libvirt")]
fn open(uri: &str) -> Result<Connect, LibvirtError> {
    Connect::open(Some(uri))
        .map_err(|error| libvirt_provider_error(ErrorCategory::ConnectionLost, "connect", error))
}

/// Retain exact libvirt failure evidence in host-local structured logs while
/// keeping the authenticated execution protocol's finite error taxonomy. The
/// `virt` display includes the symbolic and numeric libvirt code and domain;
/// the returned error carries the same bounded detail for the agent's local
/// warning line. No provider detail is returned to the control plane.
#[cfg(feature = "libvirt")]
fn libvirt_provider_error(
    category: ErrorCategory,
    operation: &'static str,
    error: virt::error::Error,
) -> LibvirtError {
    let detail = format!("{operation}: {error}");
    tracing::error!(
        libvirt_operation = operation,
        libvirt_error_code = %error.code(),
        libvirt_error_domain = %error.domain(),
        libvirt_error_message = %error.message(),
        error = %error,
        "libvirt provider operation failed"
    );
    LibvirtError::new(category, detail)
}

#[cfg(feature = "libvirt")]
fn backend_capabilities(uri: &str) -> Result<LibvirtCapabilities, LibvirtError> {
    let connection = open(uri)?;
    let node = connection.get_node_info().map_err(|_| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "node capability discovery failed",
        )
    })?;
    let capabilities_xml = connection.get_capabilities().map_err(|_| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "capability discovery failed",
        )
    })?;
    Ok(LibvirtCapabilities {
        uri: uri.to_owned(),
        libvirt_version: connection.get_lib_version().ok().map(version),
        hypervisor_version: connection.get_hyp_version().ok().map(version),
        architecture: xml_attribute(&capabilities_xml, "<arch", "name"),
        cpu_model: Some(node.model),
        total_memory_kib: Some(node.memory),
        total_vcpus: Some(node.cpus),
        machine_types: xml_values(&capabilities_xml, "<machine", "name"),
        kvm_available: connection
            .get_type()
            .map(|kind| kind == "QEMU")
            .unwrap_or(false),
        supported_operations: [
            "define",
            "start",
            "inspect",
            "shutdown",
            "force-stop",
            "reboot",
            "undefine",
            "list",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    })
}

#[cfg(feature = "libvirt")]
fn version(value: u32) -> String {
    format!(
        "{}.{}.{}",
        value / 1_000_000,
        (value / 1_000) % 1_000,
        value % 1_000
    )
}

#[cfg(feature = "libvirt")]
fn backend_define(uri: &str, definition: &DomainDefinition) -> Result<(), LibvirtError> {
    let connection = open(uri)?;
    Domain::define_xml(&connection, &definition.xml).map_err(|error| {
        let detail =
            libvirt_provider_error(ErrorCategory::OperationFailed, "domain_define_xml", error);
        tracing::error!(domain = %definition.name, "libvirt domain definition failed");
        detail
    })?;
    Ok(())
}

#[cfg(feature = "libvirt")]
fn backend_inspect(uri: &str, name: &str) -> Result<DomainInspection, LibvirtError> {
    tracing::info!(domain = %name, "libvirt inspect start");
    let connection = open(uri).inspect_err(|error| {
        tracing::warn!(%error, domain = %name, "libvirt inspect connect failed");
    })?;
    let domain = Domain::lookup_by_name(&connection, name).map_err(|error| {
        let detail =
            libvirt_provider_error(ErrorCategory::NotFound, "domain_lookup_by_name", error);
        tracing::warn!(domain = %name, "libvirt inspect domain lookup failed");
        detail
    })?;
    let info = domain.get_info().map_err(|error| {
        libvirt_provider_error(ErrorCategory::OperationFailed, "domain_get_info", error)
    })?;
    let xml = domain.get_xml_desc(0).map_err(|error| {
        libvirt_provider_error(ErrorCategory::OperationFailed, "domain_get_xml_desc", error)
    })?;
    let inspection = DomainInspection {
        name: name.to_owned(),
        active: domain.is_active().unwrap_or(false),
        persistent: domain.is_persistent().unwrap_or(false),
        state: domain_state_name(info.state).to_owned(),
        max_memory_kib: info.max_mem,
        vcpus: info.nr_virt_cpu,
        xml,
    };
    tracing::info!(
        domain = %name,
        active = inspection.active,
        persistent = inspection.persistent,
        state = %inspection.state,
        "libvirt inspect end"
    );
    Ok(inspection)
}

#[cfg(feature = "libvirt")]
fn backend_action(uri: &str, name: &str, action: DomainAction) -> Result<(), LibvirtError> {
    let connection = open(uri)?;
    let domain = Domain::lookup_by_name(&connection, name).map_err(|error| {
        libvirt_provider_error(ErrorCategory::NotFound, "domain_lookup_by_name", error)
    })?;
    let result = match action {
        DomainAction::Start => domain.create().map(|_| ()),
        DomainAction::Shutdown => domain.shutdown().map(|_| ()),
        DomainAction::ForceStop => domain.destroy(),
        DomainAction::Reboot => domain.reboot(0),
        DomainAction::Undefine => domain.undefine(),
    };
    result.map_err(|error| {
        let operation = match action {
            DomainAction::Start => "domain_start",
            DomainAction::Shutdown => "domain_shutdown",
            DomainAction::ForceStop => "domain_destroy",
            DomainAction::Reboot => "domain_reboot",
            DomainAction::Undefine => "domain_undefine",
        };
        let detail = libvirt_provider_error(ErrorCategory::OperationFailed, operation, error);
        tracing::error!(domain = %name, ?action, "libvirt domain lifecycle operation failed");
        detail
    })
}

#[cfg(feature = "libvirt")]
fn backend_owned_action(
    uri: &str,
    name: &str,
    expected_server_id: &str,
    action: DomainAction,
) -> Result<(), LibvirtError> {
    let connection = open(uri)?;
    let domain = Domain::lookup_by_name(&connection, name).map_err(|error| {
        libvirt_provider_error(ErrorCategory::NotFound, "domain_lookup_by_name", error)
    })?;
    let xml = domain.get_xml_desc(0).map_err(|error| {
        libvirt_provider_error(ErrorCategory::OperationFailed, "domain_get_xml_desc", error)
    })?;
    if !rollback_domain_is_owned_xml(name, &xml, expected_server_id) {
        return Err(LibvirtError::new(
            ErrorCategory::NotFound,
            "domain ownership verification failed",
        ));
    }
    let result = match action {
        DomainAction::Start => domain.create().map(|_| ()),
        DomainAction::Shutdown => domain.shutdown().map(|_| ()),
        DomainAction::ForceStop => domain.destroy(),
        DomainAction::Reboot => domain.reboot(0),
        DomainAction::Undefine => domain.undefine(),
    };
    result.map_err(|error| {
        let operation = match action {
            DomainAction::Start => "owned_domain_start",
            DomainAction::Shutdown => "owned_domain_shutdown",
            DomainAction::ForceStop => "owned_domain_destroy",
            DomainAction::Reboot => "owned_domain_reboot",
            DomainAction::Undefine => "owned_domain_undefine",
        };
        let detail = libvirt_provider_error(ErrorCategory::OperationFailed, operation, error);
        tracing::error!(domain = %name, ?action, "libvirt owned domain lifecycle operation failed");
        detail
    })
}

#[cfg(feature = "libvirt")]
fn backend_undefine_owned(
    uri: &str,
    name: &str,
    expected_server_id: &str,
) -> Result<(), LibvirtError> {
    let connection = open(uri)?;
    let domain = Domain::lookup_by_name(&connection, name)
        .map_err(|_| LibvirtError::new(ErrorCategory::NotFound, "domain was not found"))?;
    let xml = domain.get_xml_desc(0).map_err(|_| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "domain ownership metadata unavailable",
        )
    })?;
    if !rollback_domain_is_owned_xml(name, &xml, expected_server_id) {
        return Err(LibvirtError::new(
            ErrorCategory::NotFound,
            "domain ownership verification failed",
        ));
    }
    domain.undefine().map_err(|_| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "owned domain undefine failed",
        )
    })
}

fn rollback_domain_is_owned_xml(name: &str, xml: &str, expected_server_id: &str) -> bool {
    matches!(
        discover_domain_xml(name, xml),
        DiscoveryResult::Owned { metadata, .. } if metadata.server_id == expected_server_id
    )
}

#[cfg(not(feature = "libvirt"))]
fn backend_undefine_owned(
    _uri: &str,
    _name: &str,
    _expected_server_id: &str,
) -> Result<(), LibvirtError> {
    Err(LibvirtError::new(
        ErrorCategory::Unavailable,
        "libvirt undefine is unavailable in this build",
    ))
}

#[cfg(feature = "libvirt")]
fn backend_list(uri: &str, prefix: &str) -> Result<Vec<String>, LibvirtError> {
    let connection = open(uri)?;
    let domains = connection
        .list_all_domains(0)
        .map_err(|_| LibvirtError::new(ErrorCategory::OperationFailed, "domain listing failed"))?;
    let inspected = domains
        .into_iter()
        .filter_map(|domain| {
            let name = domain.get_name().ok()?;
            let xml = domain.get_xml_desc(0).ok()?;
            Some((name, xml))
        })
        .collect::<Vec<_>>();
    Ok(managed_domain_names(&inspected, prefix))
}

#[cfg(feature = "libvirt")]
const VIR_DOMAIN_DEVICE_MODIFY_LIVE: u32 = 1;
#[cfg(feature = "libvirt")]
const VIR_DOMAIN_DEVICE_MODIFY_CONFIG: u32 = 2;

#[cfg(feature = "libvirt")]
fn backend_attach_disk(
    uri: &str,
    name: &str,
    volume_id: &str,
    attachment_id: &str,
    host_path: &str,
    device: &str,
) -> Result<(), LibvirtError> {
    let connection = open(uri)?;
    let domain = Domain::lookup_by_name(&connection, name)
        .map_err(|_| LibvirtError::new(ErrorCategory::NotFound, "domain was not found"))?;
    let xml = domain.get_xml_desc(0).map_err(|_| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "domain XML inspection failed",
        )
    })?;
    let slot = free_pci_bridge_slot(&xml).ok_or_else(|| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "no free pci-bridge slot for block-device attach",
        )
    })?;
    let disk_xml = build_attach_disk_xml(volume_id, attachment_id, host_path, device, slot)?;
    domain
        .attach_device_flags(
            &disk_xml,
            VIR_DOMAIN_DEVICE_MODIFY_LIVE | VIR_DOMAIN_DEVICE_MODIFY_CONFIG,
        )
        .map_err(|_| {
            LibvirtError::new(ErrorCategory::OperationFailed, "block-device attach failed")
        })?;
    Ok(())
}

#[cfg(feature = "libvirt")]
fn backend_detach_disk(uri: &str, name: &str, volume_id: &str) -> Result<bool, LibvirtError> {
    let connection = open(uri)?;
    let domain = Domain::lookup_by_name(&connection, name)
        .map_err(|_| LibvirtError::new(ErrorCategory::NotFound, "domain was not found"))?;
    let xml = domain.get_xml_desc(0).map_err(|_| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "domain XML inspection failed",
        )
    })?;
    let volumes = owned_disk_volume_ids(&xml);
    let matching: Vec<&String> = volumes
        .iter()
        .filter(|value| value.as_str() == volume_id)
        .collect();
    if matching.is_empty() {
        // Already detached or never attached; idempotent success.
        return Ok(false);
    }
    let disk_xml = owned_disk_xml_for_volume(&xml, volume_id).ok_or_else(|| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "attached disk metadata is malformed",
        )
    })?;
    domain
        .detach_device_flags(
            &disk_xml,
            VIR_DOMAIN_DEVICE_MODIFY_LIVE | VIR_DOMAIN_DEVICE_MODIFY_CONFIG,
        )
        .map_err(|_| {
            LibvirtError::new(ErrorCategory::OperationFailed, "block-device detach failed")
        })?;
    Ok(true)
}

#[cfg(feature = "libvirt")]
fn backend_observe_disk(uri: &str, name: &str, volume_id: &str) -> Result<bool, LibvirtError> {
    let connection = open(uri)?;
    let domain = Domain::lookup_by_name(&connection, name)
        .map_err(|_| LibvirtError::new(ErrorCategory::NotFound, "domain was not found"))?;
    let xml = domain.get_xml_desc(0).map_err(|_| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "domain XML inspection failed",
        )
    })?;
    Ok(owned_disk_volume_ids(&xml)
        .iter()
        .any(|value| value == volume_id))
}

#[cfg(not(feature = "libvirt"))]
fn backend_attach_disk(
    _uri: &str,
    _name: &str,
    _volume_id: &str,
    _attachment_id: &str,
    _host_path: &str,
    _device: &str,
) -> Result<(), LibvirtError> {
    Err(LibvirtError::new(
        ErrorCategory::Unavailable,
        "libvirt hotplug is unavailable in this build",
    ))
}

#[cfg(not(feature = "libvirt"))]
fn backend_detach_disk(_uri: &str, _name: &str, _volume_id: &str) -> Result<bool, LibvirtError> {
    Err(LibvirtError::new(
        ErrorCategory::Unavailable,
        "libvirt hotplug is unavailable in this build",
    ))
}

#[cfg(not(feature = "libvirt"))]
fn backend_observe_disk(_uri: &str, _name: &str, _volume_id: &str) -> Result<bool, LibvirtError> {
    Err(LibvirtError::new(
        ErrorCategory::Unavailable,
        "libvirt hotplug is unavailable in this build",
    ))
}

/// Locates the full `<disk>` XML element owning the given volume identity.
#[cfg(feature = "libvirt")]
fn owned_disk_xml_for_volume(xml: &str, volume_id: &str) -> Option<String> {
    let serial = format!("o3k-{volume_id}");
    let mut search_from = 0;
    while let Some(marker_start) = xml[search_from..].find("<disk") {
        let start = search_from + marker_start;
        let Some(close) = xml[start..].find("</disk>") else {
            break;
        };
        let end = start + close + "</disk>".len();
        let element = &xml[start..end];
        if element.contains(&serial) {
            return Some(element.to_owned());
        }
        search_from = end;
    }
    None
}

#[cfg(feature = "libvirt")]
fn backend_read_console(
    uri: &str,
    name: &str,
    max_bytes: usize,
    expected_server_id: &str,
) -> Result<Vec<u8>, LibvirtError> {
    tracing::info!(domain = %name, max_bytes, "libvirt read_console start");
    let connection = open(uri).inspect_err(|error| {
        tracing::warn!(%error, domain = %name, "libvirt read_console connect failed");
    })?;
    let domain = Domain::lookup_by_name(&connection, name).map_err(|_| {
        tracing::warn!(domain = %name, "libvirt read_console domain lookup failed");
        LibvirtError::new(ErrorCategory::NotFound, "domain was not found")
    })?;
    let xml = domain.get_xml_desc(0).map_err(|_| {
        tracing::warn!(domain = %name, "libvirt read_console domain XML failed");
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "domain metadata unavailable",
        )
    })?;
    validate_console_ownership(name, &xml, expected_server_id).inspect_err(|error| {
        tracing::warn!(%error, domain = %name, "libvirt read_console ownership rejected");
    })?;
    let path = console_file_path_from_xml(&xml, name)?;
    let output = read_console_file_tail(&path, max_bytes, std::time::Duration::from_secs(3))?;
    tracing::info!(domain = %name, bytes = output.len(), "libvirt read_console durable end");
    Ok(output)
}

/// Extracts and validates the deterministic O3K-owned durable console path.
#[cfg(any(test, feature = "libvirt"))]
fn console_file_path_from_xml(
    xml: &str,
    domain_name: &str,
) -> Result<std::path::PathBuf, LibvirtError> {
    let console = xml_section(xml, "console", "file").ok_or_else(|| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "durable console path is unavailable",
        )
    })?;
    let path = xml_fragment_attribute(console, "path").ok_or_else(|| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "durable console path is unavailable",
        )
    })?;
    let disk = xml_section(xml, "disk", "file").ok_or_else(|| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "console image source is unavailable",
        )
    })?;
    let image = xml_fragment_attribute(disk, "file").ok_or_else(|| {
        LibvirtError::new(
            ErrorCategory::OperationFailed,
            "console image source is unavailable",
        )
    })?;
    let expected = console_log_path(&image, domain_name)?;
    if path != expected {
        return Err(LibvirtError::new(
            ErrorCategory::OperationFailed,
            "durable console path is not O3K-owned",
        ));
    }
    let path = Path::new(&path);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(LibvirtError::new(
            ErrorCategory::OperationFailed,
            "durable console path is invalid",
        ));
    }
    Ok(path.to_path_buf())
}

#[cfg(any(test, feature = "libvirt"))]
fn xml_section<'a>(xml: &'a str, element: &str, device_type: &str) -> Option<&'a str> {
    for quote in ['"', '\''] {
        let marker = if element == "disk" {
            format!("<{element} type={quote}{device_type}{quote} device={quote}disk{quote}>")
        } else {
            format!("<{element} type={quote}{device_type}{quote}>")
        };
        if let Some(start) = xml.find(&marker) {
            let body = &xml[start + marker.len()..];
            return body
                .split_once(&format!("</{element}>"))
                .map(|(value, _)| value);
        }
    }
    None
}

#[cfg(any(test, feature = "libvirt"))]
fn xml_fragment_attribute(fragment: &str, attribute: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let marker = format!("{attribute}={quote}");
        if let Some((_, value)) = fragment.split_once(&marker)
            && let Some((value, _)) = value.split_once(quote)
        {
            return Some(xml_unescape(value));
        }
    }
    None
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Reads at most `max_bytes` from the end of the durable console file.
///
/// A freshly defined guest may not have created the file yet, so a missing
/// file is retried for a bounded `wait` interval and then reported as an
/// empty snapshot. Every other I/O error (for example insufficient
/// permissions) is a hard failure so a permission problem is never mistaken
/// for an empty console.
#[cfg(any(test, feature = "libvirt"))]
fn read_console_file_tail(
    path: &Path,
    max_bytes: usize,
    wait: std::time::Duration,
) -> Result<Vec<u8>, LibvirtError> {
    if max_bytes == 0
        || max_bytes > 64 * 1024
        || !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(LibvirtError::new(
            ErrorCategory::OperationFailed,
            "durable console read bound or path is invalid",
        ));
    }
    validate_console_path_components(path)?;
    let deadline = std::time::Instant::now() + wait;
    loop {
        match fs::OpenOptions::new().read(true).open(path) {
            Ok(mut file) => {
                let metadata = file.metadata().map_err(|_| {
                    LibvirtError::new(
                        ErrorCategory::OperationFailed,
                        "durable console metadata unavailable",
                    )
                })?;
                if !metadata.file_type().is_file() {
                    return Err(LibvirtError::new(
                        ErrorCategory::OperationFailed,
                        "durable console path is not a regular file",
                    ));
                }
                let length = metadata.len();
                let start = length.saturating_sub(max_bytes as u64);
                file.seek(SeekFrom::Start(start)).map_err(|_| {
                    LibvirtError::new(
                        ErrorCategory::OperationFailed,
                        "durable console seek failed",
                    )
                })?;
                let mut bytes = Vec::with_capacity((length - start).min(max_bytes as u64) as usize);
                file.take(max_bytes as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| {
                        LibvirtError::new(
                            ErrorCategory::OperationFailed,
                            "durable console read failed",
                        )
                    })?;
                return Ok(bytes);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if std::time::Instant::now() >= deadline {
                    tracing::info!(
                        "durable console file absent after bounded wait; returning empty snapshot"
                    );
                    return Ok(Vec::new());
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "durable console log cannot be read");
                return Err(LibvirtError::new(
                    ErrorCategory::OperationFailed,
                    "durable console log cannot be read",
                ));
            }
        }
    }
}

#[cfg(any(test, feature = "libvirt"))]
fn validate_console_path_components(path: &Path) -> Result<(), LibvirtError> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(LibvirtError::new(
                    ErrorCategory::OperationFailed,
                    "durable console path contains a symlink",
                ));
            }
            Ok(metadata) if current != path && !metadata.file_type().is_dir() => {
                return Err(LibvirtError::new(
                    ErrorCategory::OperationFailed,
                    "durable console path component is not a directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => {
                return Err(LibvirtError::new(
                    ErrorCategory::OperationFailed,
                    "durable console path cannot be inspected",
                ));
            }
        }
    }
    Ok(())
}

fn validate_console_ownership(
    name: &str,
    xml: &str,
    expected_server_id: &str,
) -> Result<(), LibvirtError> {
    match discover_domain_xml(name, xml) {
        DiscoveryResult::Owned { metadata, .. } if metadata.server_id == expected_server_id => {
            Ok(())
        }
        _ => Err(LibvirtError::new(
            ErrorCategory::NotFound,
            "domain is not owned by the requested server",
        )),
    }
}

#[cfg(feature = "libvirt")]
fn xml_attribute(xml: &str, tag: &str, attribute: &str) -> Option<String> {
    xml_values(xml, tag, attribute).into_iter().next()
}

#[cfg(feature = "libvirt")]
fn xml_values(xml: &str, tag: &str, attribute: &str) -> Vec<String> {
    xml.split(tag)
        .skip(1)
        .filter_map(|part| part.split_once(&format!("{attribute}=\"")))
        .filter_map(|(_, value)| value.split_once('"').map(|(value, _)| value.to_owned()))
        .collect()
}

/// Compute-provider implementation backed by the local-system libvirt adapter.
#[derive(Clone)]
pub struct LibvirtProvider {
    adapter: LibvirtAdapter,
    operations: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<uuid::Uuid, o3k_provider::Operation>>,
    >,
}

impl LibvirtProvider {
    pub fn new(adapter: LibvirtAdapter) -> Self {
        Self {
            adapter,
            operations: std::sync::Arc::new(
                std::sync::Mutex::new(std::collections::HashMap::new()),
            ),
        }
    }

    fn operation(
        &self,
        request: uuid::Uuid,
        resource: Option<String>,
    ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
        let operation = o3k_provider::Operation {
            provider_operation_id: uuid::Uuid::now_v7(),
            o3k_operation_id: request,
            state: o3k_provider::OperationState::Succeeded,
            error_category: None,
            provider_resource_id: resource,
        };
        self.operations
            .lock()
            .map_err(|_| o3k_provider::ProviderError::Storage)?
            .insert(operation.provider_operation_id, operation.clone());
        Ok(operation)
    }
}

fn provider_error(error: LibvirtError) -> o3k_provider::ProviderError {
    match error.category {
        ErrorCategory::NotFound => o3k_provider::ProviderError::NotFound,
        ErrorCategory::InvalidRequest => o3k_provider::ProviderError::InvalidRequest,
        ErrorCategory::ConnectionLost => o3k_provider::ProviderError::Retryable,
        ErrorCategory::Unavailable | ErrorCategory::OperationFailed => {
            o3k_provider::ProviderError::Terminal
        }
    }
}

fn validate_create_request(
    request: &o3k_provider::CreateInstanceRequest,
) -> Result<(), o3k_provider::ProviderError> {
    if request
        .network_ids
        .iter()
        .any(|network_id| network_id.trim().is_empty())
        || !request.network_ids.is_empty()
    {
        return Err(o3k_provider::ProviderError::InvalidRequest);
    }
    Ok(())
}

fn owned_metadata(
    inspection: &DomainInspection,
    expected_server_id: Option<&str>,
) -> Result<DomainMetadata, o3k_provider::ProviderError> {
    let DiscoveryResult::Owned { metadata, .. } =
        discover_domain_xml(&inspection.name, &inspection.xml)
    else {
        // Foreign or malformed domains are never eligible for provider mutations.
        return Err(o3k_provider::ProviderError::NotFound);
    };
    if expected_server_id.is_some_and(|id| metadata.server_id != id) {
        return Err(o3k_provider::ProviderError::NotFound);
    }
    Ok(metadata)
}

fn rollback_domain_is_owned(inspection: &DomainInspection, server_id: &str) -> bool {
    owned_metadata(inspection, Some(server_id)).is_ok()
}

#[async_trait::async_trait]
impl o3k_provider::ComputeProvider for LibvirtProvider {
    async fn capabilities(
        &self,
    ) -> Result<o3k_provider::Capabilities, o3k_provider::ProviderError> {
        let value = self.adapter.capabilities().await.map_err(provider_error)?;
        Ok(o3k_provider::Capabilities {
            provider_name: "o3k-libvirt".into(),
            provider_version: value.libvirt_version.unwrap_or_else(|| "unknown".into()),
            capabilities: value.supported_operations,
        })
    }

    async fn create_instance(
        &self,
        request: o3k_provider::CreateInstanceRequest,
    ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
        validate_create_request(&request)?;
        let image_id = request
            .image_id
            .clone()
            .ok_or(o3k_provider::ProviderError::InvalidRequest)?;
        let definition = build_domain_xml(&DomainSpec {
            metadata: DomainMetadata {
                server_id: request.o3k_server_id.to_string(),
                project_id: request.project_id,
                generation: 1,
                operation_id: request.operation_id.to_string(),
                managed_by: "o3k-compute".into(),
            },
            vcpus: request.vcpus,
            memory_mib: request.memory_mib,
            image_id,
            config_drive_image: None,
            network_interfaces: Vec::new(),
        })
        .map_err(provider_error)?;
        self.adapter
            .define(DomainDefinition {
                name: definition.name.clone(),
                xml: definition.xml,
            })
            .await
            .map_err(provider_error)?;
        if let Err(error) = self
            .adapter
            .start_owned(definition.name.clone(), request.o3k_server_id.to_string())
            .await
        {
            // Start may fail after libvirt has accepted the definition.  A
            // foreign same-name replacement can race this rollback, so never
            // undefine by name alone.  Re-inspect the current XML and preserve
            // the domain if ownership cannot be proven at this exact moment.
            let expected_server_id = request.o3k_server_id.to_string();
            if let Ok(inspection) = self.adapter.inspect(definition.name.clone()).await
                && rollback_domain_is_owned(&inspection, &expected_server_id)
            {
                let _ = self
                    .adapter
                    .undefine_owned(definition.name.clone(), expected_server_id)
                    .await;
            }
            return Err(provider_error(error));
        }
        self.operation(request.operation_id, Some(definition.name))
    }

    async fn get_instance(
        &self,
        provider_instance_id: &str,
    ) -> Result<o3k_provider::Instance, o3k_provider::ProviderError> {
        let inspection = self
            .adapter
            .inspect(provider_instance_id.to_owned())
            .await
            .map_err(provider_error)?;
        let metadata = owned_metadata(&inspection, None)?;
        Ok(o3k_provider::Instance {
            provider_instance_id: inspection.name,
            o3k_server_id: uuid::Uuid::parse_str(&metadata.server_id)
                .map_err(|_| o3k_provider::ProviderError::Terminal)?,
            state: project_domain_state(inspection.active, &inspection.state),
            observed_message: Some(inspection.state),
        })
    }

    async fn delete_instance(
        &self,
        request: o3k_provider::DeleteInstanceRequest,
    ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
        let name = request.provider_instance_id;
        match self.adapter.inspect(name.clone()).await {
            Ok(inspection) => {
                let metadata = owned_metadata(&inspection, None)?;
                if inspection.active {
                    self.adapter
                        .force_stop_owned(name.clone(), metadata.server_id.clone())
                        .await
                        .map_err(provider_error)?;
                }
                self.adapter
                    .undefine_owned(name, metadata.server_id)
                    .await
                    .map_err(provider_error)?;
            }
            Err(error) if error.category == ErrorCategory::NotFound => {}
            Err(error) => return Err(provider_error(error)),
        }
        self.operation(request.operation_id, None)
    }

    async fn action_instance(
        &self,
        provider_instance_id: &str,
        action: o3k_provider::InstanceAction,
        operation_id: uuid::Uuid,
        _idempotency_key: &str,
    ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
        let name = provider_instance_id.to_owned();
        let inspection = self
            .adapter
            .inspect(name.clone())
            .await
            .map_err(provider_error)?;
        let metadata = owned_metadata(&inspection, None)?;
        let server_id = metadata.server_id;
        match action {
            o3k_provider::InstanceAction::Start => self.adapter.start_owned(name, server_id).await,
            o3k_provider::InstanceAction::Stop => {
                self.adapter.shutdown_owned(name, server_id).await
            }
            o3k_provider::InstanceAction::Reboot => {
                self.adapter.reboot_owned(name, server_id).await
            }
        }
        .map_err(provider_error)?;
        self.operation(operation_id, Some(provider_instance_id.to_owned()))
    }

    async fn get_operation(
        &self,
        id: uuid::Uuid,
    ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
        self.operations
            .lock()
            .map_err(|_| o3k_provider::ProviderError::Storage)?
            .get(&id)
            .cloned()
            .ok_or(o3k_provider::ProviderError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use o3k_provider::ComputeProvider;

    #[tokio::test]
    async fn default_build_reports_missing_libvirt_without_blocking() -> Result<(), LibvirtError> {
        let _adapter = LibvirtAdapter::new(LibvirtConfig::default())?;
        #[cfg(not(feature = "libvirt"))]
        {
            let result = _adapter.capabilities().await;
            assert!(matches!(
                result,
                Err(LibvirtError {
                    category: ErrorCategory::Unavailable,
                    ..
                })
            ));
        }
        Ok(())
    }

    #[test]
    fn only_local_system_uri_is_accepted() {
        assert!(
            LibvirtAdapter::new(LibvirtConfig {
                uri: "qemu:///session".to_owned(),
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn capability_projection_reports_capacity_and_kvm_support() {
        let capabilities = LibvirtCapabilities {
            total_vcpus: Some(8),
            total_memory_kib: Some(16 * 1024 * 1024),
            kvm_available: true,
            ..Default::default()
        }
        .to_protocol_capabilities();
        assert_eq!(capabilities.max_vcpus, 8);
        assert_eq!(capabilities.max_memory_mib, 16 * 1024);
        assert!(
            capabilities
                .flags
                .iter()
                .any(|flag| flag.name == "kvm" && flag.supported)
        );
        assert!(
            capabilities
                .flags
                .iter()
                .any(|flag| flag.name == "artifact_transfer" && flag.supported)
        );
        assert!(
            capabilities
                .flags
                .iter()
                .any(|flag| flag.name == "config_drive" && flag.supported)
        );
    }

    #[test]
    fn domain_xml_is_deterministic_escaped_and_recoverable() -> Result<(), LibvirtError> {
        let spec = DomainSpec {
            metadata: DomainMetadata {
                server_id: "server-1".to_owned(),
                project_id: "project&1".to_owned(),
                generation: 7,
                operation_id: "op-1".to_owned(),
                managed_by: "o3k-compute".to_owned(),
            },
            vcpus: 2,
            memory_mib: 512,
            image_id: "/var/lib/o3k/disk&1.qcow2".to_owned(),
            config_drive_image: None,
            network_interfaces: Vec::new(),
        };
        let first = build_domain_xml(&spec)?;
        let second = build_domain_xml(&spec)?;
        assert_eq!(first, second);
        assert!(first.xml.contains("project&amp;1"));
        assert!(
            first.xml.contains("<console type=\"file\">")
                && first.xml.contains("<serial type=\"file\">")
                && first.xml.matches("append=\"on\"").count() == 2
                && first.xml.contains("/console/o3k-")
        );
        assert_eq!(
            discover_domain_xml(&first.name, &first.xml),
            DiscoveryResult::Owned {
                name: first.name,
                metadata: spec.metadata
            }
        );
        Ok(())
    }

    #[test]
    fn domain_xml_attaches_config_drive_read_only() -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "o3k-config-drive-{}-{}.iso",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        let content = b"verified-config-drive";
        fs::write(&path, content)?;
        let spec = DomainSpec {
            metadata: DomainMetadata {
                server_id: "server-config-drive".to_owned(),
                project_id: "project".to_owned(),
                generation: 1,
                operation_id: "operation".to_owned(),
                managed_by: "o3k-compute".to_owned(),
            },
            vcpus: 1,
            memory_mib: 128,
            image_id: "/var/lib/o3k/image.qcow2".to_owned(),
            config_drive_image: Some(ConfigDriveImage {
                path: path.display().to_string(),
                sha256: sha256_hex(content),
            }),
            network_interfaces: Vec::new(),
        };
        let xml = build_domain_xml(&spec)?.xml;
        assert!(xml.contains("device=\"cdrom\""));
        assert!(xml.contains(&format!("source file=\"{}\"", path.display())));
        assert!(xml.contains("<target dev=\"sda\" bus=\"sata\" /><readonly />"));
        let mut mismatched = spec.clone();
        if let Some(image) = mismatched.config_drive_image.as_mut() {
            image.sha256 = "0".repeat(64);
        }
        assert!(build_domain_xml(&mismatched).is_err());
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn domain_xml_attaches_owned_tap_with_mac() -> Result<(), LibvirtError> {
        let spec = DomainSpec {
            metadata: DomainMetadata {
                server_id: "server-network".to_owned(),
                project_id: "project".to_owned(),
                generation: 1,
                operation_id: "operation".to_owned(),
                managed_by: "o3k-compute".to_owned(),
            },
            vcpus: 1,
            memory_mib: 128,
            image_id: "/var/lib/o3k/image.qcow2".to_owned(),
            config_drive_image: None,
            network_interfaces: vec![DomainNetworkInterface {
                tap_name: "o3ktap-a1b2c3d4".to_owned(),
                mac_address: "02:00:00:00:00:01".to_owned(),
            }],
        };
        let xml = build_domain_xml(&spec)?.xml;
        assert!(xml.contains("<interface type=\"ethernet\">"));
        assert!(xml.contains("mac address=\"02:00:00:00:00:01\""));
        assert!(xml.contains("target dev=\"o3ktap-a1b2c3d4\""));
        Ok(())
    }

    #[test]
    fn domain_state_projection_fails_closed_for_non_running_states() {
        use o3k_provider::InstanceState;

        assert_eq!(
            project_domain_state(true, "running"),
            InstanceState::Running
        );
        assert_eq!(
            project_domain_state(false, "shutdown"),
            InstanceState::Stopped
        );
        assert_eq!(
            project_domain_state(false, "shutoff"),
            InstanceState::Stopped
        );

        for state in [
            "no-state",
            "blocked",
            "paused",
            "crashed",
            "pmsuspended",
            "unknown",
        ] {
            assert_eq!(project_domain_state(true, state), InstanceState::Error);
            assert_eq!(project_domain_state(false, state), InstanceState::Error);
        }
        assert_eq!(
            project_domain_state(false, "running"),
            InstanceState::Error,
            "an inconsistent active bit must not report a running instance"
        );
        assert_eq!(
            project_domain_state(true, "shutoff"),
            InstanceState::Error,
            "an inconsistent active bit must not report a stopped instance"
        );
    }

    #[test]
    fn malformed_or_duplicate_metadata_is_quarantined() -> Result<(), LibvirtError> {
        let malformed = "<domain><metadata><o3k:domain xmlns:o3k=\"urn:o3k:compute:domain\" generation=\"x\" /></metadata></domain>";
        assert!(matches!(
            discover_domain_xml("o3k-bad", malformed),
            DiscoveryResult::Quarantined { .. }
        ));
        let foreign = "<domain><name>foreign</name></domain>";
        assert_eq!(
            discover_domain_xml("foreign", foreign),
            DiscoveryResult::Foreign {
                name: "foreign".to_owned()
            }
        );

        let spec = DomainSpec {
            metadata: DomainMetadata {
                server_id: "duplicate-server".to_owned(),
                project_id: "project".to_owned(),
                generation: 1,
                operation_id: "operation".to_owned(),
                managed_by: "o3k-compute".to_owned(),
            },
            vcpus: 1,
            memory_mib: 128,
            image_id: "/var/lib/o3k/image.qcow2".to_owned(),
            config_drive_image: None,
            network_interfaces: Vec::new(),
        };
        let xml = build_domain_xml(&spec)?.xml;
        let discovered = discover_domain_xmls(&[
            ("o3k-first".to_owned(), xml.clone()),
            ("o3k-second".to_owned(), xml),
        ]);
        assert!(
            discovered
                .iter()
                .all(|result| matches!(result, DiscoveryResult::Quarantined { .. }))
        );
        Ok(())
    }

    #[test]
    fn managed_domain_listing_requires_valid_unique_ownership_metadata() -> Result<(), LibvirtError>
    {
        let owned_spec = DomainSpec {
            metadata: DomainMetadata {
                server_id: "listed-server".to_owned(),
                project_id: "project".to_owned(),
                generation: 1,
                operation_id: "operation".to_owned(),
                managed_by: "o3k-compute".to_owned(),
            },
            vcpus: 1,
            memory_mib: 128,
            image_id: "/var/lib/o3k/image.qcow2".to_owned(),
            config_drive_image: None,
            network_interfaces: Vec::new(),
        };
        let owned_xml = build_domain_xml(&owned_spec)?.xml;
        let malformed_xml = "<domain><metadata><o3k:domain xmlns:o3k=\"urn:o3k:compute:domain\" /></metadata></domain>";
        let foreign_xml = "<domain><name>o3k-foreign</name></domain>";

        assert_eq!(
            managed_domain_names(
                &[
                    ("o3k-owned".to_owned(), owned_xml.clone()),
                    ("o3k-foreign".to_owned(), foreign_xml.to_owned()),
                    ("o3k-malformed".to_owned(), malformed_xml.to_owned()),
                ],
                "o3k-"
            ),
            vec!["o3k-owned"]
        );

        assert!(
            managed_domain_names(
                &[
                    ("o3k-duplicate-a".to_owned(), owned_xml.clone()),
                    ("o3k-duplicate-b".to_owned(), owned_xml),
                ],
                "o3k-"
            )
            .is_empty()
        );
        Ok(())
    }

    #[test]
    fn console_reads_require_exact_owned_server_metadata() -> Result<(), LibvirtError> {
        let spec = DomainSpec {
            metadata: DomainMetadata {
                server_id: "console-server".to_owned(),
                project_id: "project".to_owned(),
                generation: 1,
                operation_id: "operation".to_owned(),
                managed_by: "o3k-compute".to_owned(),
            },
            vcpus: 1,
            memory_mib: 128,
            image_id: "/var/lib/o3k/image.qcow2".to_owned(),
            config_drive_image: None,
            network_interfaces: Vec::new(),
        };
        let owned_xml = build_domain_xml(&spec)?.xml;
        assert!(
            validate_console_ownership(
                &stable_domain_name("console-server"),
                &owned_xml,
                "console-server"
            )
            .is_ok()
        );
        for (name, xml, expected) in [
            (
                stable_domain_name("console-server"),
                owned_xml.as_str(),
                "other-server",
            ),
            (
                "o3k-foreign".to_owned(),
                "<domain><name>o3k-foreign</name></domain>",
                "console-server",
            ),
            (
                "o3k-malformed".to_owned(),
                "<domain><metadata><o3k:domain xmlns:o3k=\"urn:o3k:compute:domain\" /></metadata></domain>",
                "console-server",
            ),
        ] {
            assert!(matches!(
                validate_console_ownership(&name, xml, expected),
                Err(LibvirtError {
                    category: ErrorCategory::NotFound,
                    ..
                })
            ));
        }
        Ok(())
    }

    #[test]
    fn domain_xml_has_deterministic_durable_console_path() -> Result<(), LibvirtError> {
        let spec = DomainSpec {
            metadata: DomainMetadata {
                server_id: "console-server".to_owned(),
                project_id: "project".to_owned(),
                generation: 1,
                operation_id: "operation".to_owned(),
                managed_by: "o3k-compute".to_owned(),
            },
            vcpus: 1,
            memory_mib: 128,
            image_id: "/var/lib/o3k/image.qcow2".to_owned(),
            config_drive_image: None,
            network_interfaces: Vec::new(),
        };
        let xml = build_domain_xml(&spec)?.xml;
        let domain_name = stable_domain_name(&spec.metadata.server_id);
        let path = console_file_path_from_xml(&xml, &domain_name)?;
        assert_eq!(
            path.as_path(),
            Path::new(&console_log_path(&spec.image_id, &domain_name)?)
        );
        Ok(())
    }

    #[test]
    fn console_file_path_from_xml_rejects_missing_source() {
        assert!(
            console_file_path_from_xml("<domain><name>o3k-none</name></domain>", "o3k-none")
                .is_err()
        );
    }

    #[test]
    fn console_file_path_from_xml_rejects_missing_and_unsafe_paths() {
        for xml in [
            "<domain><console type=\"file\"></console></domain>",
            "<domain><console type=\"file\"><source path=\"relative.log\"/></console></domain>",
            "<domain><console type=\"file\"><source path=\"/var/lib/../escape.log\"/></console></domain>",
        ] {
            assert!(matches!(
                console_file_path_from_xml(xml, "o3k-unsafe"),
                Err(LibvirtError {
                    category: ErrorCategory::OperationFailed,
                    ..
                })
            ));
        }
    }

    #[test]
    fn read_console_file_tail_returns_only_the_requested_tail()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "o3k-console-tail-{}-{}.log",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        let content = vec![b'x'; 2048];
        fs::write(&path, &content)?;
        let tail = read_console_file_tail(&path, 100, std::time::Duration::from_millis(1))?;
        let _ = fs::remove_file(&path);
        assert_eq!(tail, content[2048 - 100..]);
        Ok(())
    }

    #[test]
    fn read_console_file_tail_reports_missing_file_as_empty_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "o3k-console-missing-{}-{}.log",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        let bytes = read_console_file_tail(&path, 100, std::time::Duration::from_millis(60))?;
        assert!(bytes.is_empty());
        Ok(())
    }

    #[test]
    fn read_console_file_tail_rejects_unreadable_paths() {
        // A directory cannot be read as a file. The error must surface so a
        // permission-style failure is never mistaken for an empty console.
        let result = read_console_file_tail(
            &std::env::temp_dir(),
            100,
            std::time::Duration::from_millis(1),
        );
        assert!(matches!(
            result,
            Err(LibvirtError {
                category: ErrorCategory::OperationFailed,
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn read_console_file_tail_rejects_symlink_components() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "o3k-console-symlink-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(root.join("real"))?;
        fs::write(root.join("real/console.log"), b"secret")?;
        symlink(root.join("real"), root.join("link"))?;
        let result = read_console_file_tail(
            &root.join("link/console.log"),
            100,
            std::time::Duration::from_millis(1),
        );
        let _ = fs::remove_dir_all(&root);
        assert!(matches!(
            result,
            Err(LibvirtError {
                category: ErrorCategory::OperationFailed,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn read_console_file_tail_bounds_sparse_file_reads() -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "o3k-console-sparse-{}-{}.log",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        let mut file = fs::File::create(&path)?;
        file.set_len(16 * 1024 * 1024 * 1024)?;
        file.seek(SeekFrom::End(-4))?;
        std::io::Write::write_all(&mut file, b"boot")?;
        let tail = read_console_file_tail(&path, 64, std::time::Duration::from_millis(1))?;
        let _ = fs::remove_file(&path);
        assert_eq!(tail.len(), 64);
        assert_eq!(&tail[tail.len() - 4..], b"boot");
        Ok(())
    }

    #[test]
    fn domain_xml_rejects_unsafe_image_sources() {
        let metadata = DomainMetadata {
            server_id: "server".to_owned(),
            project_id: "project".to_owned(),
            generation: 1,
            operation_id: "operation".to_owned(),
            managed_by: "o3k-compute".to_owned(),
        };
        for image_id in ["../outside.qcow2", "https://example.invalid/disk", "disk\n"] {
            assert!(
                build_domain_xml(&DomainSpec {
                    metadata: metadata.clone(),
                    vcpus: 1,
                    memory_mib: 128,
                    image_id: image_id.to_owned(),
                    config_drive_image: None,
                    network_interfaces: Vec::new(),
                })
                .is_err()
            );
        }
        for config_drive_image_path in [
            "../outside.iso",
            "file:///tmp/config-drive.iso",
            "config\n-drive.iso",
        ] {
            assert!(
                build_domain_xml(&DomainSpec {
                    metadata: metadata.clone(),
                    vcpus: 1,
                    memory_mib: 128,
                    image_id: "/var/lib/o3k/image.qcow2".to_owned(),
                    config_drive_image: Some(ConfigDriveImage {
                        path: config_drive_image_path.to_owned(),
                        sha256: "0".repeat(64),
                    }),
                    network_interfaces: Vec::new(),
                })
                .is_err()
            );
        }
        for network_interface in [
            DomainNetworkInterface {
                tap_name: "eth0".to_owned(),
                mac_address: "02:00:00:00:00:01".to_owned(),
            },
            DomainNetworkInterface {
                tap_name: "o3ktap-owned".to_owned(),
                mac_address: "not-a-mac".to_owned(),
            },
        ] {
            assert!(
                build_domain_xml(&DomainSpec {
                    metadata: metadata.clone(),
                    vcpus: 1,
                    memory_mib: 128,
                    image_id: "/var/lib/o3k/image.qcow2".to_owned(),
                    config_drive_image: None,
                    network_interfaces: vec![network_interface],
                })
                .is_err()
            );
        }
    }

    #[test]
    fn provider_ownership_guard_rejects_foreign_or_malformed_domains() -> Result<(), LibvirtError> {
        let foreign = DomainInspection {
            name: "o3k-same-prefix".to_owned(),
            active: true,
            persistent: true,
            state: "running".to_owned(),
            max_memory_kib: 512,
            vcpus: 1,
            xml: "<domain><name>o3k-same-prefix</name></domain>".to_owned(),
        };
        assert_eq!(
            owned_metadata(&foreign, None),
            Err(o3k_provider::ProviderError::NotFound)
        );

        let spec = DomainSpec {
            metadata: DomainMetadata {
                server_id: "server-guard".to_owned(),
                project_id: "project".to_owned(),
                generation: 1,
                operation_id: "operation".to_owned(),
                managed_by: "o3k-compute".to_owned(),
            },
            vcpus: 1,
            memory_mib: 128,
            image_id: "/var/lib/o3k/image.qcow2".to_owned(),
            config_drive_image: None,
            network_interfaces: Vec::new(),
        };
        let built = build_domain_xml(&spec)?;
        let owned = DomainInspection {
            name: built.name,
            active: false,
            persistent: true,
            state: "shutoff".to_owned(),
            max_memory_kib: 128,
            vcpus: 1,
            xml: built.xml,
        };
        assert_eq!(
            owned_metadata(&owned, Some("different-server")),
            Err(o3k_provider::ProviderError::NotFound)
        );
        assert!(!rollback_domain_is_owned(&foreign, "server-guard"));
        assert!(rollback_domain_is_owned(&owned, "server-guard"));
        assert!(!rollback_domain_is_owned_xml(
            &foreign.name,
            &foreign.xml,
            "server-guard"
        ));
        assert!(rollback_domain_is_owned_xml(
            &owned.name,
            &owned.xml,
            "server-guard"
        ));
        Ok(())
    }

    fn create_request(network_ids: Vec<String>) -> o3k_provider::CreateInstanceRequest {
        o3k_provider::CreateInstanceRequest {
            operation_id: uuid::Uuid::now_v7(),
            o3k_server_id: uuid::Uuid::now_v7(),
            project_id: "project".to_owned(),
            name: "server".to_owned(),
            vcpus: 1,
            memory_mib: 128,
            flavor_id: String::new(),
            disk_gib: 0,
            image_id: Some("/var/lib/o3k/image.qcow2".to_owned()),
            key_name: None,
            keypair_id: None,
            network_ids,
            placement_provider_id: None,
            placement_allocation_id: None,
            config_drive: None,
            idempotency_key: "create".to_owned(),
        }
    }

    #[tokio::test]
    async fn create_rejects_network_ids_before_libvirt_definition() -> Result<(), LibvirtError> {
        let adapter = LibvirtAdapter::new(LibvirtConfig::default())?;
        let provider = LibvirtProvider::new(adapter);

        for network_ids in [
            vec!["network-1".to_owned()],
            vec!["   ".to_owned()],
            vec!["network-1".to_owned(), "".to_owned()],
        ] {
            let result = provider.create_instance(create_request(network_ids)).await;
            assert_eq!(result, Err(o3k_provider::ProviderError::InvalidRequest));
        }
        Ok(())
    }

    #[tokio::test]
    async fn create_preserves_image_source_validation_after_network_validation()
    -> Result<(), LibvirtError> {
        let adapter = LibvirtAdapter::new(LibvirtConfig::default())?;
        let provider = LibvirtProvider::new(adapter);
        let mut request = create_request(Vec::new());
        request.image_id = Some("../outside.qcow2".to_owned());

        let result = provider.create_instance(request).await;
        assert_eq!(result, Err(o3k_provider::ProviderError::InvalidRequest));
        Ok(())
    }
}

#[cfg(test)]
mod block_device_tests {
    use super::*;

    #[test]
    fn attach_disk_xml_binds_durable_volume_identity() -> Result<(), LibvirtError> {
        let xml = build_attach_disk_xml("volume-1", "attachment-1", "/dev/sdb", "vdb", 2)?;
        assert!(xml.contains("<disk type=\"block\" device=\"disk\">"));
        assert!(xml.contains("<source dev=\"/dev/sdb\"/>"));
        assert!(xml.contains("<target dev=\"vdb\" bus=\"virtio\"/>"));
        assert!(xml.contains("bus=\"0x01\" slot=\"0x02\""));
        assert!(xml.contains("<serial>o3k-volume-1</serial>"));
        assert!(xml.contains(&format!("o3k-{}{}", "", "volume-1")));
        Ok(())
    }

    #[test]
    fn attach_disk_xml_rejects_invalid_targets() {
        assert!(build_attach_disk_xml("v", "a", "/dev/sdb", "", 2).is_err());
        assert!(build_attach_disk_xml("v", "a", "", "vdb", 2).is_err());
        assert!(build_attach_disk_xml("v", "", "/dev/sdb", "vdb", 2).is_err());
        assert!(build_attach_disk_xml("", "a", "/dev/sdb", "vdb", 2).is_err());
        assert!(build_attach_disk_xml("v", "a", "/dev/sdb", "/dev/vdb", 2).is_err());
        // Slot 0 is reserved on a pci-bridge; slots above 31 are invalid.
        assert!(build_attach_disk_xml("v", "a", "/dev/sdb", "vdb", 0).is_err());
        assert!(build_attach_disk_xml("v", "a", "/dev/sdb", "vdb", 32).is_err());
    }

    #[test]
    fn free_pci_bridge_slot_skips_used_slots_and_slot_zero() {
        let xml = r#"<domain><devices>
  <address type="pci" domain="0x0000" bus="0x01" slot="0x01" function="0x0"/>
  <address type="pci" domain="0x0000" bus="0x01" slot="0x02" function="0x0"/>
  <address type="pci" domain="0x0000" bus="0x00" slot="0x01" function="0x0"/>
</devices></domain>"#;
        assert_eq!(free_pci_bridge_slot(xml), Some(3));
        assert_eq!(used_pci_slots_on_bus(xml, "0x01"), vec![1, 2]);
        assert_eq!(used_pci_slots_on_bus(xml, "0x00"), vec![1]);
    }

    #[test]
    fn owned_disk_volume_ids_extracts_only_o3k_disks() {
        let volume_id = "00000000-0000-0000-0000-000000000001";
        let xml = format!(
            r#"<domain>
  <devices>
    <disk type="file" device="disk"><source file="/var/lib/o3k/root.qcow2"/><target dev="vda" bus="virtio"/></disk>
    <disk type="block" device="disk">
      <source dev="/dev/sdb"/>
      <target dev="vdb" bus="virtio"/>
      <serial>o3k-{volume_id}</serial>
    </disk>
  </devices>
</domain>"#
        );
        let volumes = owned_disk_volume_ids(&xml);
        assert_eq!(volumes, vec![volume_id.to_owned()]);

        let foreign =
            owned_disk_volume_ids("<domain><disk type='file'/><serial>foreign</serial></domain>");
        assert!(foreign.is_empty());
    }

    #[cfg(feature = "libvirt")]
    #[test]
    fn owned_disk_xml_for_volume_finds_whole_element() -> Result<(), LibvirtError> {
        let volume_id = "00000000-0000-0000-0000-000000000002";
        let xml = format!(
            r#"<domain><devices>
  <disk type="block" device="disk">
    <driver name="qemu" type="raw"/>
    <source dev="/dev/sdb"/>
    <target dev="vdb" bus="virtio"/>
    <serial>o3k-{volume_id}</serial>
  </disk>
</devices></domain>"#
        );
        let element = owned_disk_xml_for_volume(&xml, volume_id)
            .ok_or_else(|| LibvirtError::new(ErrorCategory::NotFound, "disk element missing"))?;
        assert!(element.contains("<source dev=\"/dev/sdb\"/>"));
        assert!(element.ends_with("</disk>"));
        assert!(owned_disk_xml_for_volume(&xml, "00000000-0000-0000-0000-00000000ffff").is_none());
        Ok(())
    }
}
