use o3k_network_bin::agent;

use agent::proto::network_agent_server::NetworkAgentServer;
use o3k_domain::NetworkPlanIntent;
use o3k_network::{
    FabricRealizer, FlatNetworkRealizer, HostNetworkConfig, L3GatewayRealizer,
    LinuxL3GatewayProvider, LinuxRoutedProvider, NetworkAgentIdentity, NetworkControllerLease,
    NetworkPlanExecutor, NetworkPlanRealizer, NodeNetworkPlan, PolicyEndpoint,
    PublicAddressRealizer, RoutedExternalConfig, StatefulPolicyProvider, TapAccess,
};
use std::collections::BTreeSet;
use std::{env, fs, net::SocketAddr, path::PathBuf};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::info;
use uuid::Uuid;

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("missing required environment variable {name}").into())
}

#[cfg(test)]
mod public_removal_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn routed_plan() -> NodeNetworkPlan {
        NodeNetworkPlan {
            schema_version: 1,
            plan_id: Uuid::from_u128(1),
            node_id: "test-node".to_owned(),
            operation_id: Uuid::from_u128(2),
            deadline_unix_ms: 1,
            resource_generations: BTreeMap::new(),
            intents: vec![NetworkPlanIntent::Egress(o3k_domain::EgressIntent {
                external_realm_id: Uuid::from_u128(3),
                enabled: true,
                nat: true,
            })],
            fabric: None,
            gateway: None,
            fingerprint_sha256: "test".to_owned(),
        }
    }

    #[test]
    fn only_remove_reconciles_routed_snapshot_without_public_binding() {
        let plan = routed_plan();
        assert!(should_reconcile_public_on_remove(&plan, true));
        assert!(!should_reconcile_public_on_remove(&plan, false));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The workspace intentionally contains dependencies that expose both
    // Rustls provider families.  Select the workspace's explicit `ring`
    // provider before tonic constructs server TLS state; otherwise a
    // process-level provider cannot be inferred reliably from feature
    // unification.
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt::init();
    let agent_id = required("O3K_NETWORK_AGENT_ID")?;
    let agent_epoch = required("O3K_NETWORK_AGENT_EPOCH")?;
    let root = PathBuf::from(required("O3K_NETWORK_ROOT")?);
    let bridge_name = required("O3K_NETWORK_BRIDGE")?;
    let uplink = env::var("O3K_NETWORK_UPLINK").ok();
    let external_realm = env::var("O3K_NETWORK_EXTERNAL_REALM_ID")
        .ok()
        .map(|value| value.parse::<Uuid>())
        .transpose()?;
    // In routed mode the external uplink is a distinct north/south link for
    // nftables/routing. It must never be enslaved into the tenant bridge by
    // the flat attachment realizer. Flat-only mode retains the historical
    // optional bridge-uplink behavior.
    let flat_uplink = match env::var("O3K_NETWORK_BRIDGE_UPLINK").ok() {
        Some(value) => Some(value),
        None if external_realm.is_none() => uplink.clone(),
        None => None,
    };
    let ownership_root = PathBuf::from(required("O3K_NETWORK_OWNERSHIP_ROOT")?);
    let dhcp_root = PathBuf::from(required("O3K_NETWORK_DHCP_ROOT")?);
    let dnsmasq = PathBuf::from(required("O3K_NETWORK_DNSMASQ")?);
    let address: SocketAddr = required("O3K_NETWORK_LISTEN")?.parse()?;
    let server_cert = fs::read(required("O3K_NETWORK_TLS_CERT")?)?;
    let server_key = fs::read(required("O3K_NETWORK_TLS_KEY")?)?;
    let client_ca = fs::read(required("O3K_NETWORK_TLS_CLIENT_CA")?)?;

    let executor = NetworkPlanExecutor::open(
        root,
        NetworkAgentIdentity {
            agent_id,
            agent_epoch,
        },
        NetworkControllerLease {
            controller_id: String::new(),
            controller_epoch: String::new(),
            fencing_token: 0,
        },
    )?;
    let tap_access = match (
        env::var("O3K_NETWORK_TAP_USER")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        env::var("O3K_NETWORK_TAP_GROUP")
            .ok()
            .filter(|value| !value.trim().is_empty()),
    ) {
        (None, None) => None,
        (Some(user), Some(group)) => Some(TapAccess { user, group }),
        _ => {
            return Err(
                "O3K_NETWORK_TAP_USER and O3K_NETWORK_TAP_GROUP must be set together".into(),
            );
        }
    };
    let flat = FlatNetworkRealizer::open_with_tap_access(
        HostNetworkConfig {
            bridge_name,
            uplink: flat_uplink,
        },
        ownership_root,
        dhcp_root.clone(),
        dnsmasq.clone(),
        tap_access,
    )?;
    let routed = match external_realm {
        Some(realm) => Some(LinuxRoutedProvider::open(
            RoutedExternalConfig {
                external_realm_id: realm,
                uplink: required("O3K_NETWORK_UPLINK")?,
                bridge: required("O3K_NETWORK_BRIDGE")?,
            },
            PathBuf::from(required("O3K_NETWORK_ROUTED_ROOT")?),
        )?),
        None => None,
    };
    let policy = match env::var("O3K_NETWORK_POLICY_ROOT") {
        Ok(root) => Some(StatefulPolicyProvider::open(root)?),
        Err(_) => None,
    };
    let public = match env::var("O3K_NETWORK_PUBLIC_ROOT") {
        Ok(root) => Some(PublicAddressRealizer::open(
            root,
            required("O3K_NETWORK_UPLINK")?,
        )?),
        Err(_) => None,
    };
    let fabric = match env::var("O3K_NETWORK_FABRIC_ROOT") {
        Ok(root) => Some(FabricRealizer::new(o3k_network::LinuxFabricBackend::open(
            o3k_network::LinuxFabricConfig::for_root(root)
                .with_public_uplink(required("O3K_NETWORK_UPLINK")?),
        )?)),
        Err(_) => None,
    };
    let fabric_dhcp = match (&fabric, env::var("O3K_NETWORK_FABRIC_HOST_ID")) {
        (Some(_), Ok(host_id)) if !host_id.trim().is_empty() => Some(
            o3k_network::FabricDhcpRealizer::open(dhcp_root.clone(), host_id, dnsmasq.clone())?,
        ),
        (Some(_), _) => {
            return Err("Fabric network agent requires O3K_NETWORK_FABRIC_HOST_ID".into());
        }
        (None, _) => None,
    };
    let gateway = match env::var("O3K_NETWORK_GATEWAY_ROOT") {
        Ok(root) => {
            let contexts = match env::var("O3K_NETWORK_REALM_CONTEXTS") {
                Ok(path) => serde_json::from_slice(&fs::read(path)?)?,
                Err(_) => fabric
                    .as_ref()
                    .map(|fabric| fabric.backend().realm_execution_contexts())
                    .unwrap_or_default(),
            };
            Some(L3GatewayRealizer::new(LinuxL3GatewayProvider::open(
                root, contexts,
            )?))
        }
        Err(_) => None,
    };
    let realizer = CompositeRealizer {
        flat,
        routed,
        policy,
        public,
        fabric,
        fabric_dhcp,
        gateway,
    };
    let service = agent::NetworkAgentService::new_dynamic(executor, realizer)?;
    let recovered = service.reconcile_pending()?;
    info!(
        pending = recovered.len(),
        "reconciled pending network plans at startup"
    );
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert, server_key))
        .client_ca_root(Certificate::from_pem(client_ca));
    let listener = TcpListener::bind(address).await?;
    info!(%address, "o3k-network execution agent listening");
    Server::builder()
        .tls_config(tls)?
        .add_service(NetworkAgentServer::new(service))
        .serve_with_incoming(TcpListenerStream::new(listener))
        .await?;
    Ok(())
}

struct CompositeRealizer {
    flat: FlatNetworkRealizer,
    routed: Option<LinuxRoutedProvider>,
    policy: Option<StatefulPolicyProvider>,
    public: Option<PublicAddressRealizer>,
    fabric: Option<FabricRealizer<o3k_network::LinuxFabricBackend>>,
    fabric_dhcp: Option<o3k_network::FabricDhcpRealizer>,
    gateway: Option<L3GatewayRealizer<LinuxL3GatewayProvider>>,
}

#[derive(Debug, thiserror::Error)]
enum CompositeRealizerError {
    #[error("flat realization failed: {0}")]
    Flat(#[from] o3k_network::FlatNetworkError),
    #[error("routed realization failed: {0}")]
    Routed(#[from] o3k_network::RoutedNetworkError),
    #[error("policy realization failed: {0}")]
    Policy(#[from] o3k_network::PolicyNetworkError),
    #[error("public address realization failed: {0}")]
    Public(#[from] o3k_network::PublicAddressError),
    #[error("routed intents require O3K_NETWORK_EXTERNAL_REALM_ID configuration")]
    RoutedNotConfigured,
    #[error("policy intents require O3K_NETWORK_POLICY_ROOT configuration")]
    PolicyNotConfigured,
    #[error("public bindings require O3K_NETWORK_PUBLIC_ROOT configuration")]
    PublicNotConfigured,
    #[error("Edge fabric plans require an activated host fabric provider")]
    FabricNotConfigured,
    #[error("Edge fabric realization failed: {0}")]
    Fabric(String),
    #[error("Edge Fabric DHCP realization failed: {0}")]
    FabricDhcp(String),
    #[error("Edge fabric plan contains an intent not yet activated by the Fabric provider")]
    FabricUnsupportedIntent,
    #[error("L3 gateway realization failed: {0}")]
    Gateway(#[from] o3k_network::L3GatewayError),
}

impl NetworkPlanRealizer for CompositeRealizer {
    type Error = CompositeRealizerError;

    fn realize(&mut self, plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
        if let Some(gateway) = &plan.gateway {
            let realizer = self
                .gateway
                .as_mut()
                .ok_or(CompositeRealizerError::Gateway(
                    o3k_network::L3GatewayError::Backend(
                        "gateway plan requires O3K_NETWORK_GATEWAY_ROOT".to_owned(),
                    ),
                ))?;
            if gateway.attachments.is_empty() && gateway.external_realm_id.is_none() {
                // An unattached canonical gateway is valid desired state, but
                // has no provider topology to realize.  Treat the empty
                // execution snapshot as removal so an interface detach cannot
                // leave an orphaned gateway namespace/table behind.
                realizer.remove(gateway.gateway_id, &gateway.project_id)?;
            } else {
                realizer.apply(gateway)?;
                let observed = realizer.observe(gateway.gateway_id, &gateway.project_id)?;
                if observed.as_ref() != Some(gateway) {
                    return Err(CompositeRealizerError::Gateway(
                        o3k_network::L3GatewayError::Backend(
                            "gateway apply was not observed at the requested snapshot".to_owned(),
                        ),
                    ));
                }
            }
        }
        if plan.fabric.is_some() {
            if plan.intents.iter().any(|intent| {
                is_routed_intent(intent)
                    || (is_public_intent(intent) && !fabric_public_intents_match(plan))
                    || (is_policy_intent(intent) && !fabric_policy_intents_match(plan))
            }) {
                return Err(CompositeRealizerError::FabricUnsupportedIntent);
            }
            self.fabric
                .as_mut()
                .ok_or(CompositeRealizerError::FabricNotConfigured)?
                .realize(plan)
                .map_err(|error| CompositeRealizerError::Fabric(error.to_string()))?;
            let fabric_plan = plan
                .fabric
                .as_ref()
                .ok_or(CompositeRealizerError::FabricNotConfigured)?;
            let contexts = self
                .fabric
                .as_ref()
                .ok_or(CompositeRealizerError::FabricNotConfigured)?
                .backend()
                .realm_execution_contexts();
            let context = contexts.get(&fabric_plan.realm_id).ok_or_else(|| {
                CompositeRealizerError::FabricDhcp(
                    "Fabric Realm bridge context is absent".to_owned(),
                )
            })?;
            self.fabric_dhcp
                .as_mut()
                .ok_or_else(|| {
                    CompositeRealizerError::FabricDhcp("Fabric DHCP is not configured".to_owned())
                })?
                .realize(fabric_plan, &context.namespace, &context.bridge)
                .map_err(|error| CompositeRealizerError::FabricDhcp(error.to_string()))?;
            let fabric_observed = self
                .fabric
                .as_mut()
                .ok_or(CompositeRealizerError::FabricNotConfigured)?
                .observe(plan)
                .map_err(|error| CompositeRealizerError::Fabric(error.to_string()))?;
            let dhcp_observed = self
                .fabric_dhcp
                .as_mut()
                .ok_or_else(|| {
                    CompositeRealizerError::FabricDhcp("Fabric DHCP is not configured".to_owned())
                })?
                .observe(fabric_plan, &context.namespace, &context.bridge)
                .map_err(|error| CompositeRealizerError::FabricDhcp(error.to_string()))?;
            if !fabric_observed || !dhcp_observed {
                return Err(CompositeRealizerError::FabricDhcp(
                    "Fabric or DHCP postcondition was not observed".to_owned(),
                ));
            }
            return Ok(());
        }
        let mut flat_plan = plan.clone();
        flat_plan.intents.retain(is_flat_intent);
        self.flat.realize(&flat_plan)?;
        if plan.intents.iter().any(is_routed_intent) {
            self.routed
                .as_mut()
                .ok_or(CompositeRealizerError::RoutedNotConfigured)?
                .apply(&plan.intents)?;
        }
        if plan.intents.iter().any(is_policy_intent) {
            let endpoints = policy_endpoints(plan);
            let provider = self
                .policy
                .as_mut()
                .ok_or(CompositeRealizerError::PolicyNotConfigured)?;
            for endpoint_id in policy_targets(plan) {
                let endpoint_intents = plan
                    .intents
                    .iter()
                    .filter(|intent| policy_intent_endpoint(intent) == Some(endpoint_id))
                    .cloned()
                    .collect::<Vec<_>>();
                provider.apply_endpoint_snapshot(endpoint_id, &endpoint_intents, &endpoints)?;
            }
        }
        if plan.intents.iter().any(is_public_intent) {
            self.public
                .as_mut()
                .ok_or(CompositeRealizerError::PublicNotConfigured)?
                .apply(&plan.intents)?;
        }
        Ok(())
    }

    fn remove(&mut self, plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
        if let Some(gateway) = &plan.gateway {
            let realizer = self
                .gateway
                .as_mut()
                .ok_or(CompositeRealizerError::Gateway(
                    o3k_network::L3GatewayError::Backend(
                        "gateway plan requires O3K_NETWORK_GATEWAY_ROOT".to_owned(),
                    ),
                ))?;
            realizer.remove(gateway.gateway_id, &gateway.project_id)?;
            if realizer
                .observe(gateway.gateway_id, &gateway.project_id)?
                .is_some()
            {
                return Err(CompositeRealizerError::Gateway(
                    o3k_network::L3GatewayError::Backend(
                        "gateway removal was not observed as absent".to_owned(),
                    ),
                ));
            }
        }
        if plan.fabric.is_some() {
            if plan.intents.iter().any(|intent| {
                is_routed_intent(intent)
                    || (is_public_intent(intent) && !fabric_public_intents_match(plan))
                    || (is_policy_intent(intent) && !fabric_policy_intents_match(plan))
            }) {
                return Err(CompositeRealizerError::FabricUnsupportedIntent);
            }
            let fabric_plan = plan
                .fabric
                .as_ref()
                .ok_or(CompositeRealizerError::FabricNotConfigured)?;
            let contexts = self
                .fabric
                .as_ref()
                .ok_or(CompositeRealizerError::FabricNotConfigured)?
                .backend()
                .realm_execution_contexts();
            let context = contexts.get(&fabric_plan.realm_id).ok_or_else(|| {
                CompositeRealizerError::FabricDhcp(
                    "Fabric Realm bridge context is absent".to_owned(),
                )
            })?;
            self.fabric_dhcp
                .as_mut()
                .ok_or_else(|| {
                    CompositeRealizerError::FabricDhcp("Fabric DHCP is not configured".to_owned())
                })?
                .withdraw(fabric_plan, &context.namespace)
                .map_err(|error| CompositeRealizerError::FabricDhcp(error.to_string()))?;
            if !self
                .fabric_dhcp
                .as_ref()
                .ok_or_else(|| {
                    CompositeRealizerError::FabricDhcp("Fabric DHCP is not configured".to_owned())
                })?
                .is_withdrawn(fabric_plan.realm_id)
                .map_err(|error| CompositeRealizerError::FabricDhcp(error.to_string()))?
            {
                return Err(CompositeRealizerError::FabricDhcp(
                    "Fabric DHCP withdrawal was not observed".to_owned(),
                ));
            }
            self.fabric
                .as_mut()
                .ok_or(CompositeRealizerError::FabricNotConfigured)?
                .remove(plan)
                .map_err(|error| CompositeRealizerError::Fabric(error.to_string()))?;
            return Ok(());
        }
        if should_reconcile_public_on_remove(plan, self.public.is_some()) {
            let public = self
                .public
                .as_mut()
                .ok_or(CompositeRealizerError::PublicNotConfigured)?;
            if plan.intents.iter().any(is_public_intent) {
                public.remove_for_plan(&plan.intents)?;
            } else {
                // A delete snapshot for a routed endpoint may no longer
                // contain the public binding.  Reconcile the addressed realm
                // only on Remove; Apply snapshots can be partial and must not
                // tear down a still-live Floating IP association.
                public.apply(&plan.intents)?;
            }
        }
        if plan.intents.iter().any(is_policy_intent) {
            let endpoints = policy_endpoints(plan);
            let provider = self
                .policy
                .as_mut()
                .ok_or(CompositeRealizerError::PolicyNotConfigured)?;
            for endpoint_id in policy_targets(plan)
                .into_iter()
                .chain(endpoints.iter().map(|endpoint| endpoint.endpoint_id))
                .collect::<BTreeSet<_>>()
            {
                provider.apply_endpoint_snapshot(endpoint_id, &[], &endpoints)?;
            }
        }
        if plan.intents.iter().any(is_routed_intent) {
            self.routed
                .as_mut()
                .ok_or(CompositeRealizerError::RoutedNotConfigured)?
                .remove()?;
        }
        let mut flat_plan = plan.clone();
        flat_plan.intents.retain(is_flat_intent);
        self.flat.remove(&flat_plan)?;
        Ok(())
    }

    fn observe(&mut self, plan: &NodeNetworkPlan) -> Result<bool, Self::Error> {
        if let Some(gateway) = &plan.gateway {
            let observed = self
                .gateway
                .as_ref()
                .ok_or(CompositeRealizerError::Gateway(
                    o3k_network::L3GatewayError::Backend(
                        "gateway plan requires O3K_NETWORK_GATEWAY_ROOT".to_owned(),
                    ),
                ))?
                .observe(gateway.gateway_id, &gateway.project_id)?;
            if observed.as_ref() != Some(gateway) {
                return Ok(false);
            }
        }
        if plan.fabric.is_some() {
            let fabric_plan = plan
                .fabric
                .as_ref()
                .ok_or(CompositeRealizerError::FabricNotConfigured)?;
            let contexts = self
                .fabric
                .as_ref()
                .ok_or(CompositeRealizerError::FabricNotConfigured)?
                .backend()
                .realm_execution_contexts();
            let context = contexts.get(&fabric_plan.realm_id).ok_or_else(|| {
                CompositeRealizerError::FabricDhcp(
                    "Fabric Realm bridge context is absent".to_owned(),
                )
            })?;
            let fabric_ok = self
                .fabric
                .as_mut()
                .ok_or(CompositeRealizerError::FabricNotConfigured)?
                .observe(plan)
                .map_err(|error| CompositeRealizerError::Fabric(error.to_string()))?;
            let dhcp_ok = self
                .fabric_dhcp
                .as_mut()
                .ok_or_else(|| {
                    CompositeRealizerError::FabricDhcp("Fabric DHCP is not configured".to_owned())
                })?
                .observe(fabric_plan, &context.namespace, &context.bridge)
                .map_err(|error| CompositeRealizerError::FabricDhcp(error.to_string()))?;
            return Ok(fabric_ok && dhcp_ok);
        }
        let mut flat_plan = plan.clone();
        flat_plan.intents.retain(is_flat_intent);
        if !self.flat.observe(&flat_plan)? {
            return Ok(false);
        }
        let mut healthy = true;
        if plan.intents.iter().any(is_routed_intent) {
            healthy &= self
                .routed
                .as_ref()
                .ok_or(CompositeRealizerError::RoutedNotConfigured)
                .and_then(|provider| provider.observe().map_err(Into::into))?;
        }
        if plan.intents.iter().any(is_policy_intent) {
            healthy &= self
                .policy
                .as_ref()
                .ok_or(CompositeRealizerError::PolicyNotConfigured)
                .and_then(|provider| provider.observe().map_err(Into::into))?;
        }
        if plan.intents.iter().any(is_public_intent) {
            healthy &= self
                .public
                .as_ref()
                .ok_or(CompositeRealizerError::PublicNotConfigured)
                .and_then(|provider| provider.observe().map_err(Into::into))?;
        }
        Ok(healthy)
    }
}

fn is_flat_intent(intent: &NetworkPlanIntent) -> bool {
    matches!(
        intent,
        NetworkPlanIntent::AddressRealm { .. }
            | NetworkPlanIntent::EndpointAttachment { .. }
            | NetworkPlanIntent::AddressAssignment { .. }
    )
}

fn is_routed_intent(intent: &NetworkPlanIntent) -> bool {
    matches!(
        intent,
        NetworkPlanIntent::Route(_) | NetworkPlanIntent::Gateway(_) | NetworkPlanIntent::Egress(_)
    )
}

fn is_policy_intent(intent: &NetworkPlanIntent) -> bool {
    matches!(
        intent,
        NetworkPlanIntent::Policy(_) | NetworkPlanIntent::PolicyDefault(_)
    )
}

fn policy_intent_endpoint(intent: &NetworkPlanIntent) -> Option<Uuid> {
    match intent {
        NetworkPlanIntent::Policy(policy) => Some(policy.endpoint_id),
        NetworkPlanIntent::PolicyDefault(default) => Some(default.endpoint_id),
        _ => None,
    }
}

fn policy_targets(plan: &NodeNetworkPlan) -> BTreeSet<Uuid> {
    plan.intents
        .iter()
        .filter_map(policy_intent_endpoint)
        .collect()
}

fn fabric_policy_intents_match(plan: &NodeNetworkPlan) -> bool {
    let Some(fabric) = &plan.fabric else {
        return false;
    };
    let policies = plan
        .intents
        .iter()
        .filter_map(|intent| match intent {
            NetworkPlanIntent::Policy(policy) => Some(policy.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    policies == fabric.policies
}

fn fabric_public_intents_match(plan: &NodeNetworkPlan) -> bool {
    let Some(fabric) = &plan.fabric else {
        return false;
    };
    let bindings = plan
        .intents
        .iter()
        .filter_map(|intent| match intent {
            NetworkPlanIntent::PublicAddressBinding(binding) => Some(binding.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    bindings == fabric.public_bindings
}

fn is_public_intent(intent: &NetworkPlanIntent) -> bool {
    matches!(intent, NetworkPlanIntent::PublicAddressBinding(_))
}

fn should_reconcile_public_on_remove(plan: &NodeNetworkPlan, public_configured: bool) -> bool {
    plan.intents.iter().any(is_public_intent)
        || (public_configured && plan.intents.iter().any(is_routed_intent))
}

fn policy_endpoints(plan: &NodeNetworkPlan) -> Vec<PolicyEndpoint> {
    plan.intents
        .iter()
        .filter_map(|intent| match intent {
            NetworkPlanIntent::AddressAssignment {
                endpoint_id,
                address,
                ..
            } => Some(PolicyEndpoint {
                endpoint_id: *endpoint_id,
                address: *address,
            }),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod transport_tests {
    use super::*;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    struct NoopRealizer;

    impl NetworkPlanRealizer for NoopRealizer {
        type Error = std::convert::Infallible;

        fn realize(&mut self, _plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
            Ok(())
        }

        fn remove(&mut self, _plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/o3k-compute-agent/tests/fixtures")
            .join(name)
    }

    #[tokio::test]
    async fn m_tls_client_dispatches_a_fenced_plan_to_the_executor()
    -> Result<(), Box<dyn std::error::Error>> {
        // The workspace also uses rustls through sqlx and tonic.  Those
        // integrations do not guarantee that a process-level provider has
        // been selected before this binary-only test constructs TLS state.
        // Install the explicitly configured provider so the test is
        // independent of test ordering.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let root = std::env::temp_dir().join(format!("o3k-network-transport-{}", Uuid::now_v7()));
        let executor = NetworkPlanExecutor::open(
            &root,
            NetworkAgentIdentity {
                agent_id: "agent-transport".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
            },
            NetworkControllerLease {
                controller_id: "controller-transport".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 1,
            },
        )?;
        let service = agent::NetworkAgentService::new_legacy(executor, NoopRealizer);
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                fs::read(fixture("server-chain.pem"))?,
                fs::read(fixture("server-key.pem"))?,
            ))
            .client_ca_root(Certificate::from_pem(fs::read(fixture("ca.pem"))?));
        let server_task = tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .expect("tls")
                .add_service(NetworkAgentServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
        });
        let operation_id = Uuid::now_v7();
        let deadline_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as u64
            + 60_000;
        let mut plan = NodeNetworkPlan {
            schema_version: 1,
            plan_id: Uuid::now_v7(),
            node_id: "agent-transport".to_owned(),
            operation_id,
            deadline_unix_ms,
            resource_generations: BTreeMap::new(),
            intents: Vec::new(),
            fabric: None,
            gateway: None,
            fingerprint_sha256: String::new(),
        };
        plan.fingerprint_sha256 = o3k_network::canonical_plan_fingerprint(&plan)?;
        let client = o3k_network_protocol::NetworkAgentClient::connect(
            &format!("https://{address}"),
            "o3k-control-plane",
            fixture("ca.pem"),
            fixture("agent-chain.pem"),
            fixture("agent-key-pkcs8.pem"),
        )
        .await?;
        let result = client
            .execute(
                agent::proto::Register {
                    agent_id: "agent-transport".to_owned(),
                    agent_epoch: "epoch-1".to_owned(),
                },
                agent::proto::NetworkCommand {
                    command_id: Uuid::now_v7().to_string(),
                    operation_id: operation_id.to_string(),
                    idempotency_key: "transport-test".to_owned(),
                    agent_id: "agent-transport".to_owned(),
                    agent_epoch: "epoch-1".to_owned(),
                    controller_id: "controller-transport".to_owned(),
                    controller_epoch: "epoch-1".to_owned(),
                    fencing_token: 1,
                    deadline_unix_ms,
                    plan_json: serde_json::to_string(&plan)?,
                    remove: false,
                },
            )
            .await?;
        assert_eq!(result.status, "succeeded");
        assert!(!result.replayed);
        server_task.abort();
        let _ = server_task.await;
        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}
