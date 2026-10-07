use super::LinuxFabricCommand;
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpectedEndpointTap {
    pub(crate) interface: String,
    pub(crate) provider_mac: String,
    pub(crate) realm_bridge: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveEndpointTap {
    pub(crate) interface: String,
    pub(crate) ifindex: u32,
    pub(crate) mac: Option<String>,
    pub(crate) master: Option<LiveLinkMaster>,
    pub(crate) kind: Option<String>,
    pub(crate) subtype: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiveLinkMaster {
    Name(String),
    Ifindex(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TapObservationError {
    Absent,
    MultipleLinks,
    Malformed,
    WrongInterface,
    WrongLinkType,
    WrongMac,
    WrongBridge,
}

impl fmt::Display for TapObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

/// Reads and parses exactly one link returned by iproute2. Expectations are
/// checked separately so callers can use the observed ifindex for safe
/// rollback of an object created during the current reconciliation attempt.
pub(crate) fn observe_endpoint_tap(
    command: &dyn LinuxFabricCommand,
    interface: &str,
) -> Result<Option<LiveEndpointTap>, TapObservationError> {
    let (exists, output) = command
        .output("ip", &["-j", "-d", "link", "show", "dev", interface])
        .map_err(|_| TapObservationError::Malformed)?;
    if !exists {
        return Ok(None);
    }
    let links: Value = serde_json::from_str(&output).map_err(|_| TapObservationError::Malformed)?;
    let links = links.as_array().ok_or(TapObservationError::Malformed)?;
    if links.len() != 1 {
        return Err(if links.is_empty() {
            TapObservationError::Absent
        } else {
            TapObservationError::MultipleLinks
        });
    }
    let link = links[0].as_object().ok_or(TapObservationError::Malformed)?;
    let name = link
        .get("ifname")
        .and_then(Value::as_str)
        .ok_or(TapObservationError::Malformed)?;
    let ifindex = link
        .get("ifindex")
        .and_then(Value::as_u64)
        .and_then(|index| u32::try_from(index).ok())
        .filter(|index| *index > 0)
        .ok_or(TapObservationError::Malformed)?;
    let mac = match link.get("address") {
        Some(Value::String(mac)) => Some(mac.clone()),
        Some(Value::Null) | None => None,
        Some(_) => return Err(TapObservationError::Malformed),
    };
    let master = match link.get("master") {
        Some(Value::String(name)) => Some(LiveLinkMaster::Name(name.clone())),
        Some(Value::Number(index)) => {
            let index = index
                .as_u64()
                .and_then(|index| u32::try_from(index).ok())
                .filter(|index| *index > 0)
                .ok_or(TapObservationError::Malformed)?;
            Some(LiveLinkMaster::Ifindex(index))
        }
        Some(Value::Null) | None => None,
        Some(_) => return Err(TapObservationError::Malformed),
    };
    let (kind, subtype) = match link.get("linkinfo") {
        Some(Value::Object(linkinfo)) => {
            let kind = optional_string(linkinfo.get("info_kind"))?;
            let subtype = match linkinfo.get("info_data") {
                Some(Value::Object(info_data)) => optional_string(info_data.get("type"))?,
                Some(Value::Null) | None => None,
                Some(_) => return Err(TapObservationError::WrongLinkType),
            };
            (kind, subtype)
        }
        Some(Value::Null) | None => (None, None),
        Some(_) => return Err(TapObservationError::WrongLinkType),
    };
    Ok(Some(LiveEndpointTap {
        interface: name.to_owned(),
        ifindex,
        mac,
        master,
        kind,
        subtype,
    }))
}

fn optional_string(value: Option<&Value>) -> Result<Option<String>, TapObservationError> {
    match value {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(TapObservationError::WrongLinkType),
    }
}

/// Validates the complete live Linux TAP contract. The bridge observation is
/// independently checked and numeric master references are accepted only
/// when they resolve to that exact bridge's ifindex.
pub(crate) fn attest_endpoint_tap(
    command: &dyn LinuxFabricCommand,
    expected: &ExpectedEndpointTap,
    observed: &LiveEndpointTap,
) -> Result<(), TapObservationError> {
    if observed.interface != expected.interface {
        return Err(TapObservationError::WrongInterface);
    }
    if observed.kind.as_deref() != Some("tun") || observed.subtype.as_deref() != Some("tap") {
        return Err(TapObservationError::WrongLinkType);
    }
    if !observed
        .mac
        .as_deref()
        .is_some_and(|mac| mac.eq_ignore_ascii_case(&expected.provider_mac))
    {
        return Err(TapObservationError::WrongMac);
    }

    let bridge = observe_endpoint_tap(command, &expected.realm_bridge)?
        .ok_or(TapObservationError::WrongBridge)?;
    if bridge.interface != expected.realm_bridge || bridge.kind.as_deref() != Some("bridge") {
        return Err(TapObservationError::WrongBridge);
    }
    let bridge_index = bridge.ifindex;
    match &observed.master {
        Some(LiveLinkMaster::Name(master)) if master == &expected.realm_bridge => Ok(()),
        Some(LiveLinkMaster::Ifindex(master)) if *master == bridge_index => Ok(()),
        _ => Err(TapObservationError::WrongBridge),
    }
}

pub(crate) fn is_same_created_tap(
    observed: &LiveEndpointTap,
    expected: &ExpectedEndpointTap,
    created_ifindex: u32,
) -> bool {
    observed.interface == expected.interface
        && observed.ifindex == created_ifindex
        && observed.kind.as_deref() == Some("tun")
        && observed.subtype.as_deref() == Some("tap")
        && observed.master.as_ref().is_some_and(
            |master| matches!(master, LiveLinkMaster::Name(name) if name == &expected.realm_bridge),
        )
}
