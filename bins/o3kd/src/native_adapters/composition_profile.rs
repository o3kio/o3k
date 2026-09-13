use std::sync::{Arc, RwLock};

use o3k_kernel::{AuthContext, CloudProfile, ManifestRegistry};
use o3k_store::{AuditEventRecord, CloudProfileRecord, CompositionRepository, O3kStore};

/// Production composition adapter. It persists only desired CloudProfile
/// state; manifests remain the observed runtime registry supplied by o3kd.
pub struct CloudProfileAdapter {
    pub store: Arc<O3kStore>,
    pub registry: Arc<RwLock<ManifestRegistry>>,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[async_trait::async_trait]
impl o3k_native_api::composition::CompositionReader for CloudProfileAdapter {
    async fn get(&self, id: &str) -> Result<Option<CloudProfile>, String> {
        self.store
            .get_cloud_profile(id)
            .await
            .map_err(|e| e.to_string())?
            .map(|r| r.profile().map_err(|e| e.to_string()))
            .transpose()
    }
    async fn put(
        &self,
        profile: CloudProfile,
        expected: Option<u64>,
        auth: &AuthContext,
    ) -> Result<CloudProfile, String> {
        profile.validate().map_err(|e| e.to_string())?;
        let record =
            CloudProfileRecord::from_profile(&profile, now()).map_err(|e| e.to_string())?;
        let audit = AuditEventRecord {
            event_id: format!(
                "cloud-profile:{}:{}",
                profile.profile_id, profile.generation
            ),
            timestamp: now(),
            request_id: auth.request_id().to_owned(),
            audit_id: auth.audit_id().to_owned(),
            principal_id: auth.principal().id().to_string(),
            principal_kind: "user".to_owned(),
            effective_scope: auth.effective_scope().id().as_str().to_owned(),
            service: "composition".to_owned(),
            action: "composition:ManageCloudProfile".to_owned(),
            resource_type: Some("composition:cloud_profile".to_owned()),
            resource_id: Some(profile.profile_id.clone()),
            owner_scope: None,
            operation_id: None,
            outcome: "succeeded".to_owned(),
            reason_category: None,
        };
        self.store
            .upsert_cloud_profile_with_audit(&record, expected, &audit)
            .await
            .map_err(|e| e.to_string())?;
        Ok(profile)
    }
    async fn reconcile(
        &self,
        id: &str,
        _auth: &AuthContext,
    ) -> Result<o3k_native_api::composition::CloudProfileView, String> {
        let profile = self
            .get(id)
            .await?
            .ok_or_else(|| "profile not found".to_owned())?;
        let registry = self
            .registry
            .read()
            .map_err(|_| "registry unavailable".to_owned())?;
        let observation = profile.observe(&registry);
        Ok(o3k_native_api::composition::CloudProfileView {
            profile,
            consumable: Some(observation.consumable),
            drift: Some(observation.drifts),
        })
    }
}
