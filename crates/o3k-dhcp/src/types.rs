//! DHCP domain types: config, binding, errors.

use std::{io, net::Ipv4Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhcpConfig {
    pub subnet: String,
    pub gateway: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub interface: String,
    pub lease_seconds: u32,
    /// Optional RFC 2132 interface MTU advertised to fixed-address guests.
    #[serde(default)]
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Binding {
    pub port_id: String,
    pub mac: String,
    pub address: Ipv4Addr,
}

#[derive(Debug, Error)]
pub enum DhcpError {
    #[error("DHCP configuration is invalid")]
    InvalidConfig,
    #[error("DHCP binding conflicts with an existing address or MAC")]
    Conflict,
    #[error("DHCP storage failed")]
    Storage(#[source] io::Error),
    #[error("DHCP state is corrupt")]
    CorruptState(#[source] serde_json::Error),
    #[error("dnsmasq command failed")]
    CommandFailed,
}
