//! Linux command boundary for Fabric DHCP bridge-address ownership.

use serde::Deserialize;
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone, Copy)]
pub(crate) enum GatewayAddressAction {
    Add,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DhcpExecutionError {
    Command,
    Observation,
}

#[derive(Debug, Deserialize)]
struct LinkAddressObservation {
    ifname: String,
    addr_info: Vec<AddressInfoObservation>,
}

#[derive(Debug, Deserialize)]
struct LinkIdentityObservation {
    ifname: String,
}

#[derive(Debug, Deserialize)]
struct AddressInfoObservation {
    local: Ipv4Addr,
    prefixlen: u8,
}

pub(crate) struct DhcpNetworkExecutor {
    ip_binary: PathBuf,
}

impl DhcpNetworkExecutor {
    pub(crate) fn new(ip_binary: impl AsRef<Path>) -> Self {
        Self {
            ip_binary: ip_binary.as_ref().to_owned(),
        }
    }

    pub(crate) fn observe_ipv4(
        &self,
        interface: &str,
    ) -> Result<Vec<(Ipv4Addr, u8)>, DhcpExecutionError> {
        // `ip -j -4 addr` emits [] for a link without IPv4 state, so verify
        // the link independently before interpreting that as an empty list.
        let link_output = Command::new(&self.ip_binary)
            .args(["-j", "link", "show", "dev", interface])
            .output()
            .map_err(|_| DhcpExecutionError::Command)?;
        if !link_output.status.success() {
            return Err(DhcpExecutionError::Command);
        }
        let links: Vec<LinkIdentityObservation> = serde_json::from_slice(&link_output.stdout)
            .map_err(|_| DhcpExecutionError::Observation)?;
        if links.len() != 1 || links[0].ifname != interface {
            return Err(DhcpExecutionError::Observation);
        }

        let output = Command::new(&self.ip_binary)
            .args(["-j", "-4", "addr", "show", "dev", interface])
            .output()
            .map_err(|_| DhcpExecutionError::Command)?;
        if !output.status.success() {
            return Err(DhcpExecutionError::Command);
        }
        let links: Vec<LinkAddressObservation> =
            serde_json::from_slice(&output.stdout).map_err(|_| DhcpExecutionError::Observation)?;
        if links.is_empty() {
            return Ok(Vec::new());
        }
        if links.len() != 1 || links[0].ifname != interface {
            return Err(DhcpExecutionError::Observation);
        }
        Ok(links[0]
            .addr_info
            .iter()
            .map(|address| (address.local, address.prefixlen))
            .collect())
    }

    pub(crate) fn mutate_gateway_address(
        &self,
        action: GatewayAddressAction,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), DhcpExecutionError> {
        let verb = match action {
            GatewayAddressAction::Add => "add",
            GatewayAddressAction::Delete => "del",
        };
        let address = format!("{address}/{prefix_len}");
        let output = Command::new(&self.ip_binary)
            .args(["addr", verb, &address, "dev", interface])
            .output()
            .map_err(|_| DhcpExecutionError::Command)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(DhcpExecutionError::Command)
        }
    }
}
