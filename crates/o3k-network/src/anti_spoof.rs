//! Fail closed ingress identity checks for the stretched-L2 provider.
//!
//! This module is deliberately independent of packet parsing and nftables.  The
//! control plane supplies the identity snapshot and the provider applies the
//! same predicates to TAP and VXLAN ingress.  In particular, an inner IP or
//! MAC never selects a realm or a source host.

use std::{collections::BTreeMap, net::Ipv4Addr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointIdentity {
    pub realm_id: String,
    pub endpoint_id: String,
    pub fixed_ip: Ipv4Addr,
    pub canonical_mac: String,
    pub host_id: String,
    pub placement_generation: u64,
    pub source_host_generation: u64,
    pub binding_generation: u64,
    pub vni: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngressIdentity {
    pub realm_id: String,
    pub source_host: String,
    pub source_host_generation: u64,
    pub vni: u32,
    pub source_mac: String,
    pub source_ip: Ipv4Addr,
    pub arp_sender_mac: Option<String>,
    pub arp_sender_ip: Option<Ipv4Addr>,
    pub placement_generation: u64,
    pub binding_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IngressRejection {
    UnknownRealm,
    UnknownEndpoint,
    WrongVni,
    WrongSourceHost,
    WrongSourceMac,
    WrongSourceIp,
    WrongArpSenderMac,
    WrongArpSenderIp,
    StalePlacementGeneration,
    StaleSourceHostGeneration,
    StaleBindingGeneration,
}

/// Validate one frame against the current canonical endpoint snapshot.
///
/// The key includes the realm so overlapping tenant CIDRs remain isolated.
/// Callers should treat every error as a drop and increment the corresponding
/// bounded provider counter.
pub fn validate_ingress<'a>(
    endpoints: &'a BTreeMap<(String, Ipv4Addr), EndpointIdentity>,
    ingress: &IngressIdentity,
) -> Result<&'a EndpointIdentity, IngressRejection> {
    let realm_exists = endpoints
        .keys()
        .any(|(realm, _)| realm == &ingress.realm_id);
    if !realm_exists {
        return Err(IngressRejection::UnknownRealm);
    }
    let endpoint = endpoints
        .get(&(ingress.realm_id.clone(), ingress.source_ip))
        .ok_or(IngressRejection::UnknownEndpoint)?;
    if endpoint.vni != ingress.vni {
        return Err(IngressRejection::WrongVni);
    }
    if endpoint.host_id != ingress.source_host {
        return Err(IngressRejection::WrongSourceHost);
    }
    if !mac_equal(&endpoint.canonical_mac, &ingress.source_mac) {
        return Err(IngressRejection::WrongSourceMac);
    }
    if let Some(mac) = &ingress.arp_sender_mac
        && !mac_equal(&endpoint.canonical_mac, mac)
    {
        return Err(IngressRejection::WrongArpSenderMac);
    }
    if ingress
        .arp_sender_ip
        .is_some_and(|ip| ip != endpoint.fixed_ip)
    {
        return Err(IngressRejection::WrongArpSenderIp);
    }
    if endpoint.placement_generation != ingress.placement_generation {
        return Err(IngressRejection::StalePlacementGeneration);
    }
    if endpoint.source_host_generation != ingress.source_host_generation {
        return Err(IngressRejection::StaleSourceHostGeneration);
    }
    if endpoint.binding_generation != ingress.binding_generation {
        return Err(IngressRejection::StaleBindingGeneration);
    }
    Ok(endpoint)
}

fn mac_equal(left: &str, right: &str) -> bool {
    left.split(':')
        .map(str::to_ascii_lowercase)
        .eq(right.split(':').map(str::to_ascii_lowercase))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::type_complexity,
    clippy::unwrap_used
)]
mod tests {
    use super::*;

    fn snapshot() -> BTreeMap<(String, Ipv4Addr), EndpointIdentity> {
        let mut map = BTreeMap::new();
        for (realm, host, mac) in [
            ("a", "h1", "02:00:00:00:00:0a"),
            ("b", "h2", "02:00:00:00:00:0b"),
        ] {
            let ep = EndpointIdentity {
                realm_id: realm.into(),
                endpoint_id: format!("{realm}-ep"),
                fixed_ip: "10.0.0.10".parse().unwrap(),
                canonical_mac: mac.into(),
                host_id: host.into(),
                placement_generation: 3,
                source_host_generation: 4,
                binding_generation: 5,
                vni: if realm == "a" { 100 } else { 200 },
            };
            map.insert((realm.into(), ep.fixed_ip), ep);
        }
        map
    }

    fn ingress(realm: &str) -> IngressIdentity {
        IngressIdentity {
            realm_id: realm.into(),
            source_host: if realm == "a" { "h1" } else { "h2" }.into(),
            source_host_generation: 4,
            vni: if realm == "a" { 100 } else { 200 },
            source_mac: if realm == "a" {
                "02:00:00:00:00:0a"
            } else {
                "02:00:00:00:00:0b"
            }
            .into(),
            source_ip: "10.0.0.10".parse().unwrap(),
            arp_sender_mac: None,
            arp_sender_ip: None,
            placement_generation: 3,
            binding_generation: 5,
        }
    }

    #[test]
    fn accepts_each_overlapping_realm_only_with_its_identity() {
        let s = snapshot();
        assert!(validate_ingress(&s, &ingress("a")).is_ok());
        assert!(validate_ingress(&s, &ingress("b")).is_ok());
        let mut i = ingress("a");
        i.source_mac = "02:00:00:00:00:0b".into();
        assert_eq!(
            validate_ingress(&s, &i),
            Err(IngressRejection::WrongSourceMac)
        );
    }

    #[test]
    fn rejects_mac_ip_arp_vni_host_and_generations() {
        let s = snapshot();
        let cases: [(fn(&mut IngressIdentity), IngressRejection); 8] = [
            (
                |i: &mut IngressIdentity| i.source_mac = "02:00:00:00:00:ff".into(),
                IngressRejection::WrongSourceMac,
            ),
            (
                |i: &mut IngressIdentity| i.source_ip = "10.0.0.11".parse().unwrap(),
                IngressRejection::UnknownEndpoint,
            ),
            (
                |i: &mut IngressIdentity| i.arp_sender_mac = Some("02:00:00:00:00:ff".into()),
                IngressRejection::WrongArpSenderMac,
            ),
            (
                |i: &mut IngressIdentity| i.vni = 999,
                IngressRejection::WrongVni,
            ),
            (
                |i: &mut IngressIdentity| i.source_host = "h9".into(),
                IngressRejection::WrongSourceHost,
            ),
            (
                |i: &mut IngressIdentity| i.placement_generation = 9,
                IngressRejection::StalePlacementGeneration,
            ),
            (
                |i: &mut IngressIdentity| i.source_host_generation = 9,
                IngressRejection::StaleSourceHostGeneration,
            ),
            (
                |i: &mut IngressIdentity| i.binding_generation = 9,
                IngressRejection::StaleBindingGeneration,
            ),
        ];
        for (mutator, expected) in cases {
            let mut i = ingress("a");
            mutator(&mut i);
            assert_eq!(validate_ingress(&s, &i), Err(expected));
        }
        let mut arp = ingress("a");
        arp.arp_sender_ip = Some("10.0.0.11".parse().unwrap());
        assert_eq!(
            validate_ingress(&s, &arp),
            Err(IngressRejection::WrongArpSenderIp)
        );
    }
}
