use o3k_kernel::{ActionId, LimitKey, ResourceType, ServiceNamespace};

pub mod canonical_policy;
pub mod execution;
pub mod fabric;
pub mod gateway;
mod host;
pub mod linux_fabric;
mod plan;
pub mod policy;
pub mod public;
pub use policy::{PolicyEndpoint, PolicyNetworkError, StatefulPolicyProvider};
pub mod routed;
mod service;

pub use canonical_policy::{
    CanonicalPolicyCompileError, CanonicalPolicyService, CanonicalPolicyServiceError,
    LinuxPolicySnapshotRealizer, PolicyApplyOutcome, PolicyObservation, PolicySnapshotRealizer,
    compile_endpoint_policy,
};
pub use execution::{
    FlatNetworkError, FlatNetworkRealizer, NetworkAgentIdentity, NetworkControllerLease,
    NetworkDispatchError, NetworkExecutionError, NetworkPlanAction, NetworkPlanCommand,
    NetworkPlanDispatcher, NetworkPlanExecutor, NetworkPlanRealizer, NetworkPlanStatus,
    PlanAdmission, journal_path,
};
pub use fabric::{FabricBackend, FabricError, FabricRealizer, InMemoryFabricBackend};
pub use gateway::{
    InMemoryL3GatewayBackend, L3GatewayBackend, L3GatewayError, L3GatewayRealizer,
    LinuxL3GatewayProvider, RealmExecutionContext, compile_l3_gateway_execution_plan,
    gateway_plan_fingerprint,
};
pub use host::{
    BridgeOwnership, GatewayOwnership, GatewaySpec, HostNetworkConfig, HostNetworkError,
    HostNetworkManager, NetworkOwnershipManifest, TapAccess, TapOwnership, TapSpec,
};
pub use linux_fabric::{LinuxFabricBackend, LinuxFabricConfig, LinuxFabricError};
pub use o3k_store::{NetworkRecord, PortRecord, SubnetRecord};
pub use plan::{
    AttachmentPlanInput, NODE_NETWORK_PLAN_SCHEMA_VERSION, NetworkPlanError, NodeNetworkPlan,
    add_l3_gateway_routing, canonical_plan_fingerprint, compile_attachment_plan,
    compile_attachment_plan_with_defaults, compile_l3_gateway_network_plan,
    compile_node_network_plan, validate_plan_replay,
};
pub use public::{
    PublicAddressAllocator, PublicAddressBinding, PublicAddressError, PublicAddressPool,
    PublicAddressRealizer,
};
pub use routed::{LinuxRoutedProvider, RoutedExternalConfig, RoutedNetworkError};
pub use service::{
    CanonicalNetworkSnapshot, GatewayIntentMap, NetworkError, NetworkService, PortBindingState,
    RealmCleanupObservation, RealmCleanupProgress, SERVER_OWNED_ENDPOINT_PREFIX,
    ServerOwnedEndpointRelease, compile_l3_gateway_intents, is_server_owned_endpoint_name,
    server_owned_endpoint_context,
};

/// Stable shared vocabulary for the P9 control-plane boundary. These values
/// are used by authorization, quota, audit, and compatibility projections;
/// provider-native names never become part of this vocabulary.
pub struct NetworkVocabulary;

impl NetworkVocabulary {
    pub fn actions() -> Vec<ActionId> {
        [
            "CreateNetworkIntent",
            "ReadNetworkIntent",
            "UpdateNetworkIntent",
            "DeleteNetworkIntent",
            "AllocateAddress",
            "ReleaseAddress",
        ]
        .into_iter()
        .map(|action| ActionId::new_unchecked("network", action))
        .collect()
    }

    pub fn resources() -> Vec<ResourceType> {
        ["network_intent", "endpoint", "address_allocation"]
            .into_iter()
            .map(|name| ResourceType::new_unchecked("network", name))
            .collect()
    }

    pub fn quota_keys() -> Vec<LimitKey> {
        ["networks", "ports"]
            .into_iter()
            .map(|name| LimitKey::new_unchecked(ServiceNamespace::network(), name.to_owned()))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod vocabulary_tests {
    use super::NetworkVocabulary;

    #[test]
    fn p9_vocabulary_is_typed_and_stable() {
        assert_eq!(NetworkVocabulary::actions().len(), 6);
        assert_eq!(NetworkVocabulary::resources().len(), 3);
        assert_eq!(NetworkVocabulary::quota_keys().len(), 2);
        assert_eq!(
            NetworkVocabulary::actions()[0].to_string(),
            "network:CreateNetworkIntent"
        );
        assert_eq!(
            NetworkVocabulary::resources()[0].to_string(),
            "network:network_intent"
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod p9_plan_tests {
    use std::{
        collections::{BTreeMap, HashSet},
        net::Ipv4Addr,
    };

    use o3k_domain::{
        AddressRealm, EndpointIntent, EndpointLocation, FabricEndpointRoute, FabricPeer,
        FabricProviderKind, Ipv4Prefix, NamespacedRoutedFabricPlan, NetworkCapability,
        NetworkIntent, NetworkPlanIntent, NetworkProtocol, PolicyAction, PolicyDirection,
        PolicyIntent, PortRange, RealmEncapsulationBinding, RouteIntent,
    };
    use uuid::Uuid;

    use crate::{
        NODE_NETWORK_PLAN_SCHEMA_VERSION, NetworkPlanError, canonical_plan_fingerprint,
        compile_l3_gateway_intents, compile_node_network_plan, validate_plan_replay,
    };

    fn prefix(value: &str, length: u8) -> Ipv4Prefix {
        Ipv4Prefix::new(value.parse().expect("test address"), length).expect("test prefix")
    }

    fn capabilities() -> HashSet<NetworkCapability> {
        [
            NetworkCapability::Ipv4,
            NetworkCapability::EndpointAttachment,
            NetworkCapability::Routing,
            NetworkCapability::StatefulPolicy,
        ]
        .into_iter()
        .collect()
    }

    fn overlapping_capabilities() -> HashSet<NetworkCapability> {
        let mut capabilities = capabilities();
        capabilities.insert(NetworkCapability::OverlappingAddressRealms);
        capabilities.insert(NetworkCapability::EncapsulationModes);
        capabilities
    }

    fn intent() -> NetworkIntent {
        let id = Uuid::from_u128(1);
        NetworkIntent {
            id,
            project_id: "project-a".to_owned(),
            realm: AddressRealm {
                id: Uuid::from_u128(2),
                network_id: id,
                project_id: "project-a".to_owned(),
                prefix: prefix("10.0.0.0", 24),
                overlapping_prefixes: false,
            },
            address_pools: vec![],
            endpoints: vec![EndpointIntent {
                id: Uuid::from_u128(3),
                project_id: "project-a".to_owned(),
                realm_id: Uuid::from_u128(2),
                mac: "02:00:00:00:00:03".to_owned(),
                fixed_ip: Ipv4Addr::new(10, 0, 0, 3),
                generation: 4,
            }],
            routes: vec![RouteIntent {
                destination: prefix("0.0.0.0", 0),
                next_hop: Some(Ipv4Addr::new(10, 0, 0, 1)),
            }],
            gateways: vec![],
            egress: vec![],
            public_addresses: vec![],
            policies: vec![PolicyIntent {
                id: Uuid::from_u128(10),
                endpoint_id: Uuid::from_u128(3),
                direction: PolicyDirection::Egress,
                protocol: NetworkProtocol::Tcp,
                ports: Some(PortRange {
                    start: 443,
                    end: 443,
                }),
                source: None,
                destination: Some(prefix("0.0.0.0", 0)),
                action: PolicyAction::Allow,
            }],
            generation: 5,
            state: o3k_domain::NetworkIntentState::Requested,
        }
    }

    #[test]
    fn prefixes_are_canonical_and_overlap_is_explicit() {
        assert!(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 1), 24).is_none());
        let broad = prefix("10.0.0.0", 16);
        let narrow = prefix("10.0.1.0", 24);
        assert!(broad.overlaps(narrow));
        assert!(!prefix("10.1.0.0", 16).overlaps(narrow));
    }

    #[test]
    fn plan_fingerprint_is_deterministic_and_semantic() {
        let value = intent();
        let operation = Uuid::from_u128(6);
        let first =
            compile_node_network_plan(&value, "node-a", operation, 123, &capabilities(), &[])
                .expect("plan");
        let second =
            compile_node_network_plan(&value, "node-a", operation, 123, &capabilities(), &[])
                .expect("plan");
        assert_eq!(first, second);
        assert_eq!(first.plan_id, value.id);
        assert_eq!(first.schema_version, NODE_NETWORK_PLAN_SCHEMA_VERSION);
        assert!(
            first
                .intents
                .iter()
                .any(|item| matches!(item, NetworkPlanIntent::EndpointAttachment { .. }))
        );
        assert_eq!(first.fingerprint_sha256.len(), 64);
    }

    #[test]
    fn fabric_payload_is_fingerprinted_and_admission_validated() {
        let base = compile_node_network_plan(
            &intent(),
            "node-a",
            Uuid::from_u128(6),
            123,
            &capabilities(),
            &[],
        )
        .expect("plan");
        let destination = prefix("10.0.0.3", 32);
        let fabric = NamespacedRoutedFabricPlan {
            local_host: "node-a".to_owned(),
            local_fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 1),
            local_fabric_generation: 2,
            local_underlay_mtu: 1500,
            local_fabric_mtu: 1420,
            realm_id: Uuid::from_u128(2),
            realm_prefix: prefix("10.0.0.0", 24),
            encapsulation: RealmEncapsulationBinding {
                fabric_domain_id: Uuid::from_u128(100),
                realm_id: Uuid::from_u128(2),
                provider_kind: FabricProviderKind::Geneve,
                provider_segment_id: 101,
                binding_generation: 1,
            },
            directory_generation: 3,
            directory: o3k_domain::RealmEndpointDirectory {
                realm_id: Uuid::from_u128(2),
                prefix: prefix("10.0.0.0", 24),
                directory_generation: 3,
                proxy_mac: "02:11:22:33:44:55".to_owned(),
                entries: vec![EndpointLocation {
                    endpoint_id: Uuid::from_u128(3),
                    project_id: "project-a".to_owned(),
                    realm_id: Uuid::from_u128(2),
                    fixed_ip: Ipv4Addr::new(10, 0, 0, 3),
                    mac: "02:00:00:00:00:03".to_owned(),
                    selected_host: "node-b".to_owned(),
                    endpoint_generation: 4,
                    placement_generation: 5,
                }],
            },
            proxy_mac: "02:11:22:33:44:55".to_owned(),
            tenant_mtu: 1400,
            policy_generation: 1,
            policies: Vec::new(),
            policy_defaults: Vec::new(),
            public_bindings: Vec::new(),
            routes: vec![FabricEndpointRoute {
                realm_id: Uuid::from_u128(2),
                destination,
                endpoint_id: Uuid::from_u128(3),
                target_host: "node-b".to_owned(),
                target_fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 2),
                endpoint_generation: 4,
                placement_generation: 5,
                realm_binding_generation: 1,
                fabric_generation: 6,
            }],
            peers: vec![FabricPeer {
                host_id: "node-b".to_owned(),
                public_key: "public-key".to_owned(),
                underlay_endpoint: "192.0.2.2:65001".to_owned(),
                fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 2),
                fabric_generation: 6,
            }],
        };
        let plan = base.clone().with_fabric(fabric).expect("valid P11 plan");
        assert_ne!(plan.fingerprint_sha256, base.fingerprint_sha256);
        assert_eq!(plan.validate_fabric(), Ok(()));

        let mut invalid = plan.clone();
        invalid.fabric.as_mut().expect("fabric").routes[0].destination = prefix("10.0.0.0", 24);
        assert_eq!(
            invalid.validate_fabric(),
            Err(NetworkPlanError::InvalidFabricPlan)
        );
    }

    #[test]
    fn equivalent_retry_with_new_deadline_keeps_plan_fingerprint() {
        let value = intent();
        let operation = Uuid::from_u128(6);
        let first =
            compile_node_network_plan(&value, "node-a", operation, 123, &capabilities(), &[])
                .expect("plan");
        let retried =
            compile_node_network_plan(&value, "node-a", operation, 456, &capabilities(), &[])
                .expect("retried plan");
        assert_eq!(first.fingerprint_sha256, retried.fingerprint_sha256);
        assert_eq!(
            canonical_plan_fingerprint(&first).expect("fingerprint"),
            first.fingerprint_sha256
        );
        assert_eq!(
            canonical_plan_fingerprint(&retried).expect("fingerprint"),
            retried.fingerprint_sha256
        );
    }

    #[test]
    fn plan_rejects_overlap_before_provider_mutation() {
        let existing = AddressRealm {
            id: Uuid::from_u128(7),
            network_id: Uuid::from_u128(70),
            project_id: "project-b".to_owned(),
            prefix: prefix("10.0.0.0", 16),
            overlapping_prefixes: false,
        };
        assert_eq!(
            compile_node_network_plan(
                &intent(),
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[existing],
            ),
            Err(NetworkPlanError::OverlappingRealm)
        );
    }

    #[test]
    fn geneve_capability_allows_overlap_only_when_realm_and_provider_opt_in() {
        let existing = AddressRealm {
            id: Uuid::from_u128(7),
            network_id: Uuid::from_u128(70),
            project_id: "project-b".to_owned(),
            prefix: prefix("10.0.0.0", 16),
            overlapping_prefixes: false,
        };
        let mut overlapping = intent();
        overlapping.realm.overlapping_prefixes = true;
        let plan = compile_node_network_plan(
            &overlapping,
            "node-a",
            Uuid::from_u128(6),
            123,
            &overlapping_capabilities(),
            &[existing],
        )
        .expect("overlap-capable provider plan");
        assert!(
            plan.intents
                .iter()
                .any(|item| matches!(item, NetworkPlanIntent::AddressRealm { .. }))
        );

        let mut missing_encapsulation = overlapping_capabilities();
        missing_encapsulation.remove(&NetworkCapability::EncapsulationModes);
        assert_eq!(
            compile_node_network_plan(
                &overlapping,
                "node-a",
                Uuid::from_u128(6),
                123,
                &missing_encapsulation,
                &[AddressRealm {
                    id: Uuid::from_u128(7),
                    network_id: Uuid::from_u128(70),
                    project_id: "project-b".to_owned(),
                    prefix: prefix("10.0.0.0", 16),
                    overlapping_prefixes: false,
                }],
            ),
            Err(NetworkPlanError::OverlappingRealm)
        );
    }

    #[test]
    fn plan_rejects_unsupported_capability_before_mutation() {
        let mut missing = capabilities();
        missing.remove(&NetworkCapability::Routing);
        assert_eq!(
            compile_node_network_plan(&intent(), "node-a", Uuid::from_u128(6), 123, &missing, &[],),
            Err(NetworkPlanError::UnsupportedCapability(
                NetworkCapability::Routing
            ))
        );
    }

    #[test]
    fn plan_carries_gateway_egress_public_binding_and_deadline() {
        let mut value = intent();
        value.gateways.push(o3k_domain::GatewayIntent {
            destination: prefix("0.0.0.0", 0),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            external: true,
        });
        value.egress.push(o3k_domain::EgressIntent {
            external_realm_id: Uuid::from_u128(8),
            enabled: true,
            nat: true,
        });
        value
            .public_addresses
            .push(o3k_domain::PublicAddressBindingIntent {
                id: Uuid::from_u128(9),
                project_id: "project-a".to_owned(),
                public_address: Ipv4Addr::new(198, 51, 100, 10),
                endpoint_id: Uuid::from_u128(3),
                generation: 6,
            });
        let mut capabilities = capabilities();
        capabilities.insert(NetworkCapability::Nat);
        capabilities.insert(NetworkCapability::PublicAddressRealization);
        let plan = compile_node_network_plan(
            &value,
            "node-a",
            Uuid::from_u128(6),
            456,
            &capabilities,
            &[],
        )
        .expect("plan");
        assert_eq!(plan.deadline_unix_ms, 456);
        assert!(
            plan.intents
                .iter()
                .any(|item| matches!(item, NetworkPlanIntent::Gateway(_)))
        );
        assert!(
            plan.intents
                .iter()
                .any(|item| matches!(item, NetworkPlanIntent::Egress(_)))
        );
        assert!(
            plan.intents
                .iter()
                .any(|item| matches!(item, NetworkPlanIntent::PublicAddressBinding(_)))
        );
    }

    #[test]
    fn canonical_l3_gateway_compiles_connected_realm_intents() {
        let gateway = o3k_store::CanonicalL3GatewayRecord {
            id: Uuid::from_u128(100),
            project_id: "project-a".into(),
            name: "gw".into(),
            external_realm_id: Some(Uuid::from_u128(200)),
            enable_snat: true,
            generation: 1,
            state: "active".into(),
        };
        let realms = vec![
            o3k_store::CanonicalAddressRealmRecord {
                id: Uuid::from_u128(1),
                network_id: Uuid::from_u128(10),
                project_id: "project-a".into(),
                prefix: "10.0.0.0/24".into(),
                overlapping_prefixes: false,
                generation: 1,
                state: "active".into(),
            },
            o3k_store::CanonicalAddressRealmRecord {
                id: Uuid::from_u128(2),
                network_id: Uuid::from_u128(11),
                project_id: "project-a".into(),
                prefix: "10.1.0.0/24".into(),
                overlapping_prefixes: false,
                generation: 1,
                state: "active".into(),
            },
        ];
        let attachments = vec![
            o3k_store::CanonicalL3GatewayAttachmentRecord {
                id: Uuid::from_u128(3),
                gateway_id: gateway.id,
                realm_id: realms[0].id,
                project_id: "project-a".into(),
                generation: 1,
                state: "active".into(),
            },
            o3k_store::CanonicalL3GatewayAttachmentRecord {
                id: Uuid::from_u128(4),
                gateway_id: gateway.id,
                realm_id: realms[1].id,
                project_id: "project-a".into(),
                generation: 1,
                state: "active".into(),
            },
        ];
        let compiled =
            compile_l3_gateway_intents(&gateway, &attachments, &realms, &BTreeMap::new())
                .expect("gateway plan");
        assert_eq!(compiled.len(), 2);
        assert_eq!(
            compiled[&realms[0].id].0[0].destination.network,
            Ipv4Addr::new(10, 1, 0, 0)
        );
        assert_eq!(
            compiled[&realms[0].id].1[0].external_realm_id,
            Uuid::from_u128(200)
        );
    }

    #[test]
    fn plan_rejects_nat_without_provider_capability() {
        let mut value = intent();
        value.egress.push(o3k_domain::EgressIntent {
            external_realm_id: Uuid::from_u128(8),
            enabled: true,
            nat: true,
        });
        assert_eq!(
            compile_node_network_plan(
                &value,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::UnsupportedCapability(
                NetworkCapability::Nat
            ))
        );
    }

    #[test]
    fn plan_rejects_cross_project_endpoint() {
        let mut value = intent();
        value.endpoints[0].project_id = "project-b".to_owned();
        assert_eq!(
            compile_node_network_plan(
                &value,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::AddressOutsideRealm)
        );
    }

    #[test]
    fn plan_rejects_cross_project_bindings_and_invalid_policies() {
        let mut binding = intent();
        binding
            .public_addresses
            .push(o3k_domain::PublicAddressBindingIntent {
                id: Uuid::from_u128(9),
                project_id: "project-b".to_owned(),
                public_address: Ipv4Addr::new(198, 51, 100, 10),
                endpoint_id: Uuid::from_u128(3),
                generation: 1,
            });
        let mut provider_capabilities = capabilities();
        provider_capabilities.insert(NetworkCapability::PublicAddressRealization);
        assert_eq!(
            compile_node_network_plan(
                &binding,
                "node-a",
                Uuid::from_u128(6),
                123,
                &provider_capabilities,
                &[],
            ),
            Err(NetworkPlanError::OwnershipViolation)
        );

        let mut policy = intent();
        policy.policies[0].endpoint_id = Uuid::from_u128(99);
        assert_eq!(
            compile_node_network_plan(
                &policy,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::InvalidPolicy)
        );

        let mut invalid_ports = intent();
        invalid_ports.policies[0].ports = Some(PortRange {
            start: 5000,
            end: 80,
        });
        assert_eq!(
            compile_node_network_plan(
                &invalid_ports,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::InvalidPolicy)
        );
    }

    #[test]
    fn plan_rejects_foreign_realm_and_pool() {
        let mut value = intent();
        value.realm.project_id = "project-b".to_owned();
        assert_eq!(
            compile_node_network_plan(
                &value,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::OwnershipViolation)
        );

        let mut value = intent();
        value.address_pools.push(o3k_domain::AddressPool {
            id: Uuid::from_u128(10),
            realm_id: value.realm.id,
            project_id: "project-a".to_owned(),
            prefix: prefix("10.1.0.0", 24),
            gateway: Some(Ipv4Addr::new(10, 1, 0, 1)),
            first_usable: Ipv4Addr::new(10, 1, 0, 2),
            last_usable: Ipv4Addr::new(10, 1, 0, 20),
        });
        assert_eq!(
            compile_node_network_plan(
                &value,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::InvalidAddressPool)
        );

        let mut value = intent();
        value.realm.prefix = prefix("10.0.0.0", 16);
        value.address_pools = vec![
            o3k_domain::AddressPool {
                id: Uuid::from_u128(12),
                realm_id: value.realm.id,
                project_id: value.project_id.clone(),
                prefix: prefix("10.0.0.0", 24),
                gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
                first_usable: Ipv4Addr::new(10, 0, 0, 2),
                last_usable: Ipv4Addr::new(10, 0, 0, 20),
            },
            o3k_domain::AddressPool {
                id: Uuid::from_u128(13),
                realm_id: value.realm.id,
                project_id: value.project_id.clone(),
                prefix: prefix("10.0.1.0", 24),
                gateway: Some(Ipv4Addr::new(10, 0, 1, 130)),
                first_usable: Ipv4Addr::new(10, 0, 1, 130),
                last_usable: Ipv4Addr::new(10, 0, 1, 140),
            },
        ];
        assert_eq!(
            compile_node_network_plan(
                &value,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::InvalidAddressPool)
        );
    }

    #[test]
    fn plan_rejects_duplicate_endpoint_addresses_and_macs() {
        let mut duplicate_address = intent();
        duplicate_address.endpoints.push(EndpointIntent {
            id: Uuid::from_u128(99),
            project_id: duplicate_address.project_id.clone(),
            realm_id: duplicate_address.realm.id,
            mac: "02:00:00:00:00:99".to_owned(),
            fixed_ip: Ipv4Addr::new(10, 0, 0, 3),
            generation: 1,
        });
        assert_eq!(
            compile_node_network_plan(
                &duplicate_address,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::ConflictingEndpoint)
        );

        let mut duplicate_mac = intent();
        duplicate_mac.endpoints.push(EndpointIntent {
            id: Uuid::from_u128(99),
            project_id: duplicate_mac.project_id.clone(),
            realm_id: duplicate_mac.realm.id,
            mac: duplicate_mac.endpoints[0].mac.clone(),
            fixed_ip: Ipv4Addr::new(10, 0, 0, 99),
            generation: 1,
        });
        assert_eq!(
            compile_node_network_plan(
                &duplicate_mac,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::ConflictingEndpoint)
        );

        let mut invalid_mac = intent();
        invalid_mac.endpoints[0].mac = "not-a-mac".to_owned();
        assert_eq!(
            compile_node_network_plan(
                &invalid_mac,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::ConflictingEndpoint)
        );
    }

    #[test]
    fn plan_rejects_pool_gateway_from_the_allocatable_range() {
        let mut value = intent();
        value.address_pools.push(o3k_domain::AddressPool {
            id: Uuid::from_u128(10),
            realm_id: value.realm.id,
            project_id: value.project_id.clone(),
            prefix: prefix("10.0.0.0", 24),
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            first_usable: Ipv4Addr::new(10, 0, 0, 1),
            last_usable: Ipv4Addr::new(10, 0, 0, 20),
        });
        assert_eq!(
            compile_node_network_plan(
                &value,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::InvalidAddressPool)
        );

        let mut value = intent();
        value.address_pools.push(o3k_domain::AddressPool {
            id: Uuid::from_u128(11),
            realm_id: value.realm.id,
            project_id: value.project_id.clone(),
            prefix: prefix("10.0.0.0", 24),
            gateway: Some(Ipv4Addr::new(10, 0, 0, 255)),
            first_usable: Ipv4Addr::new(10, 0, 0, 2),
            last_usable: Ipv4Addr::new(10, 0, 0, 20),
        });
        assert_eq!(
            compile_node_network_plan(
                &value,
                "node-a",
                Uuid::from_u128(6),
                123,
                &capabilities(),
                &[],
            ),
            Err(NetworkPlanError::InvalidAddressPool)
        );
    }

    #[test]
    fn equivalent_plan_replay_is_allowed_but_payload_conflict_is_rejected() {
        let plan = compile_node_network_plan(
            &intent(),
            "node-a",
            Uuid::from_u128(6),
            123,
            &capabilities(),
            &[],
        )
        .expect("plan");
        assert_eq!(validate_plan_replay(&plan, &plan), Ok(()));
        let mut conflicting = plan.clone();
        conflicting.fingerprint_sha256 = "conflicting".to_owned();
        assert_eq!(
            validate_plan_replay(&plan, &conflicting),
            Err(NetworkPlanError::ConflictingPlan)
        );
    }
}
