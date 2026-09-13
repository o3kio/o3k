//! Declarative CloudProfile composition contracts (P15.4).
//!
//! A profile is desired composition state.  Runtime manifests are observed
//! state and remain owned by [`ManifestRegistry`]; this module never mutates
//! or duplicates that authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{ManifestRegistry, ServiceLifecycleState};

pub const MAX_SERVICES: usize = 128;
pub const MAX_DEPENDENCIES: usize = 512;
pub const MAX_CAPABILITIES: usize = 256;
pub const MAX_CONFIG_REFS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceOwnershipMode {
    O3kImplemented,
    ExternalHosted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSelection {
    pub service_id: String,
    pub ownership: ServiceOwnershipMode,
    pub version_requirement: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default)]
    pub locality: Option<String>,
    #[serde(default)]
    pub placement_requirement: Option<String>,
    #[serde(default)]
    pub config_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudProfile {
    pub profile_id: String,
    pub generation: u64,
    pub selected_services: Vec<ServiceSelection>,
    /// Each inner vector is one deterministic upgrade wave. No executor is
    /// implied; the order is declarative evidence for a future reconciler.
    #[serde(default)]
    pub upgrade_order: Vec<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudProfileError {
    Invalid(&'static str),
}

impl std::fmt::Display for CloudProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cloud profile validation failed: {}",
            match self {
                Self::Invalid(v) => v,
            }
        )
    }
}
impl std::error::Error for CloudProfileError {}

impl CloudProfile {
    pub fn validate(&self) -> Result<(), CloudProfileError> {
        if self.profile_id.trim().is_empty() || self.profile_id.len() > 128 {
            return Err(CloudProfileError::Invalid("profile_id"));
        }
        if self.selected_services.is_empty() || self.selected_services.len() > MAX_SERVICES {
            return Err(CloudProfileError::Invalid("selected_services"));
        }
        let mut ids = BTreeSet::new();
        let mut dependency_count = 0;
        let mut capability_count = 0;
        let mut config_count = 0;
        for service in &self.selected_services {
            if service.service_id.trim().is_empty()
                || service.service_id.len() > 128
                || !ids.insert(service.service_id.clone())
            {
                return Err(CloudProfileError::Invalid("service_id"));
            }
            if service.version_requirement.trim().is_empty()
                || service.version_requirement.len() > 128
            {
                return Err(CloudProfileError::Invalid("version_requirement"));
            }
            dependency_count += service.dependencies.len();
            capability_count += service.required_capabilities.len();
            config_count += service.config_refs.len();
            for value in service
                .dependencies
                .iter()
                .chain(service.required_capabilities.iter())
                .chain(service.config_refs.iter())
            {
                if value.trim().is_empty() || value.len() > 256 || value.bytes().any(|b| b == 0) {
                    return Err(CloudProfileError::Invalid("bounded profile reference"));
                }
            }
            if service.config_refs.iter().any(|r| {
                let lower = r.to_ascii_lowercase();
                lower.contains("password=")
                    || lower.contains("secret=")
                    || lower.contains("token=")
                    || lower.contains("private_key=")
            }) {
                return Err(CloudProfileError::Invalid(
                    "config_refs must be secret-free references",
                ));
            }
            if service
                .locality
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 256)
                || service
                    .placement_requirement
                    .as_ref()
                    .is_some_and(|v| v.is_empty() || v.len() > 256)
            {
                return Err(CloudProfileError::Invalid("placement/locality reference"));
            }
        }
        if dependency_count > MAX_DEPENDENCIES
            || capability_count > MAX_CAPABILITIES
            || config_count > MAX_CONFIG_REFS
        {
            return Err(CloudProfileError::Invalid("profile collection bound"));
        }
        for service in &self.selected_services {
            if service.dependencies.iter().any(|dep| !ids.contains(dep)) {
                return Err(CloudProfileError::Invalid(
                    "dependency references unselected service",
                ));
            }
        }
        let mut order_ids = BTreeSet::new();
        for wave in &self.upgrade_order {
            if wave.is_empty() {
                return Err(CloudProfileError::Invalid("empty upgrade wave"));
            }
            for id in wave {
                if !ids.contains(id) || !order_ids.insert(id.clone()) {
                    return Err(CloudProfileError::Invalid(
                        "upgrade order must cover each service once",
                    ));
                }
            }
        }
        if !order_ids.is_empty() && order_ids.len() != ids.len() {
            return Err(CloudProfileError::Invalid(
                "upgrade order must cover all selected services",
            ));
        }
        // Dependency graph must be acyclic; deterministic Kahn traversal.
        let mut indegree = ids
            .iter()
            .map(|id| (id.clone(), 0usize))
            .collect::<BTreeMap<_, _>>();
        for service in &self.selected_services {
            for _ in &service.dependencies {
                if let Some(value) = indegree.get_mut(&service.service_id) {
                    *value += 1;
                }
            }
        }
        let mut ready = indegree
            .iter()
            .filter(|(_, n)| **n == 0)
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>();
        let mut seen = 0;
        while let Some(id) = ready.pop_first() {
            seen += 1;
            for service in &self.selected_services {
                if service.dependencies.iter().any(|d| d == &id)
                    && let Some(n) = indegree.get_mut(&service.service_id)
                {
                    *n -= 1;
                    if *n == 0 {
                        ready.insert(service.service_id.clone());
                    }
                }
            }
        }
        if seen != ids.len() {
            return Err(CloudProfileError::Invalid("dependency cycle"));
        }
        Ok(())
    }

    #[must_use]
    pub fn implicit_default() -> Self {
        Self {
            profile_id: "default".to_owned(),
            generation: 0,
            selected_services: vec![ServiceSelection {
                service_id: "compute".to_owned(),
                ownership: ServiceOwnershipMode::O3kImplemented,
                version_requirement: "*".to_owned(),
                dependencies: vec![],
                required_capabilities: vec![],
                locality: None,
                placement_requirement: None,
                config_refs: vec![],
            }],
            upgrade_order: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(id: &str) -> ServiceSelection {
        ServiceSelection {
            service_id: id.to_owned(),
            ownership: ServiceOwnershipMode::O3kImplemented,
            version_requirement: "*".to_owned(),
            dependencies: vec![],
            required_capabilities: vec![],
            locality: None,
            placement_requirement: None,
            config_refs: vec![],
        }
    }

    #[test]
    fn validates_dependencies_and_rejects_cycles_and_inline_secrets() {
        let mut profile = CloudProfile {
            profile_id: "edge".into(),
            generation: 1,
            selected_services: vec![service("a"), service("b")],
            upgrade_order: vec![],
        };
        profile.selected_services[1].dependencies = vec!["a".into()];
        assert!(profile.validate().is_ok());
        profile.selected_services[0].dependencies = vec!["b".into()];
        assert!(matches!(
            profile.validate(),
            Err(CloudProfileError::Invalid("dependency cycle"))
        ));
        profile.selected_services[0].dependencies.clear();
        profile.selected_services[0].config_refs = vec!["password=secret".into()];
        assert!(matches!(
            profile.validate(),
            Err(CloudProfileError::Invalid(
                "config_refs must be secret-free references"
            ))
        ));
    }

    #[test]
    fn observation_is_separate_and_deterministic() {
        let profile = CloudProfile {
            profile_id: "edge".into(),
            generation: 2,
            selected_services: vec![service("missing")],
            upgrade_order: vec![],
        };
        let first = profile.observe(&ManifestRegistry::new());
        let second = profile.observe(&ManifestRegistry::new());
        assert_eq!(first, second);
        assert!(!first.consumable);
        assert_eq!(first.drifts[0].kind, DriftKind::Missing);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    Missing,
    NotReady,
    VersionMismatch,
    CapabilityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionDrift {
    pub service_id: String,
    pub kind: DriftKind,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionObservation {
    pub profile_id: String,
    pub profile_generation: u64,
    pub drifts: Vec<CompositionDrift>,
    pub consumable: bool,
}

impl CloudProfile {
    /// Compare desired composition to observed manifests. This is read-only,
    /// bounded, and deterministic; callers persist any resulting operation.
    #[must_use]
    pub fn observe(&self, registry: &ManifestRegistry) -> CompositionObservation {
        let mut drifts = Vec::new();
        for service in &self.selected_services {
            match registry.lifecycle_state(&service.service_id) {
                None => drifts.push(CompositionDrift {
                    service_id: service.service_id.clone(),
                    kind: DriftKind::Missing,
                    detail: "service identity is not observed".to_owned(),
                }),
                Some(ServiceLifecycleState::Ready) => {
                    if let Some(manifest) = registry.get(&service.service_id)
                        && service.version_requirement != "*"
                        && service.version_requirement != manifest.service_version
                    {
                        drifts.push(CompositionDrift {
                            service_id: service.service_id.clone(),
                            kind: DriftKind::VersionMismatch,
                            detail: "observed version does not satisfy requirement".to_owned(),
                        });
                    }
                }
                Some(state) => drifts.push(CompositionDrift {
                    service_id: service.service_id.clone(),
                    kind: DriftKind::NotReady,
                    detail: format!("observed lifecycle is {state:?}"),
                }),
            }
        }
        drifts.sort_by(|a, b| {
            a.service_id
                .cmp(&b.service_id)
                .then_with(|| format!("{:?}", a.kind).cmp(&format!("{:?}", b.kind)))
        });
        CompositionObservation {
            profile_id: self.profile_id.clone(),
            profile_generation: self.generation,
            consumable: drifts.is_empty(),
            drifts,
        }
    }
}
