//! Persistence for the reusable, provider-independent NetworkPolicy model.
//!
//! This is intentionally separate from `canonical_network_policies`, which is
//! the legacy endpoint-scoped PolicyIntent persistence used by P9/P11.

use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    CanonicalNetworkPolicyRuleRecord, CanonicalPolicyAttachmentRecord,
    CanonicalPolicyRealizationRecord, CanonicalReusableNetworkPolicyRecord, StoreError,
    checked_generation, map_canonical_insert_error, parse_uuid, validate_canonical_state,
};

const POLICY_COLUMNS: &str = "id, project_id, name, description, stateful_mode, unmatched_action, generation, state, created_at, updated_at";
const RULE_COLUMNS: &str = "id, policy_id, project_id, direction, address_family, protocol, port_min, port_max, remote_selector, action, state, generation, enforcement_key";
const ATTACHMENT_COLUMNS: &str = "id, policy_id, endpoint_id, project_id, state, generation";

const REALIZATION_COLUMNS: &str = "endpoint_id, project_id, attempt_id, desired_fingerprint, desired_generation, observed_fingerprint, observed_generation, state, provider_resource_id, last_outcome";

#[async_trait]
pub trait CanonicalPolicyRepository {
    async fn insert_reusable_policy(
        &self,
        policy: &CanonicalReusableNetworkPolicyRecord,
    ) -> Result<(), StoreError>;
    async fn get_reusable_policy(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalReusableNetworkPolicyRecord>, StoreError>;
    async fn list_reusable_policies(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalReusableNetworkPolicyRecord>, StoreError>;
    async fn update_reusable_policy(
        &self,
        policy: &CanonicalReusableNetworkPolicyRecord,
        expected_generation: u64,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError>;
    async fn transition_reusable_policy_state(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        state: &str,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError>;
    async fn delete_reusable_policy(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError>;
    async fn insert_policy_rule(
        &self,
        rule: &CanonicalNetworkPolicyRuleRecord,
    ) -> Result<(), StoreError>;
    async fn get_policy_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalNetworkPolicyRuleRecord>, StoreError>;
    async fn list_policy_rules(
        &self,
        project_id: &str,
        policy_id: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError>;
    async fn begin_policy_rule_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalNetworkPolicyRuleRecord, StoreError>;
    /// Durable transitional inventory used by policy startup recovery.
    async fn list_deleting_policy_rules(
        &self,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError>;
    async fn finalize_policy_rule_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError>;
    async fn delete_policy_rule(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError>;
    async fn insert_policy_attachment(
        &self,
        attachment: &CanonicalPolicyAttachmentRecord,
    ) -> Result<(), StoreError>;
    async fn get_policy_attachment(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalPolicyAttachmentRecord>, StoreError>;
    async fn list_policy_attachments(
        &self,
        project_id: &str,
        policy_id: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError>;
    async fn list_endpoint_policy_attachments(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError>;
    /// Atomically applies a requested policy membership set. Existing active
    /// memberships are preserved, additions are inserted, and removals are
    /// reserved as deleting. The returned rows are the deletion reservations
    /// that still require provider convergence before finalization.
    async fn replace_policy_attachment_set(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
        policy_ids: &[Uuid],
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError>;
    async fn begin_policy_attachment_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalPolicyAttachmentRecord, StoreError>;
    /// Durable transitional inventory used by policy startup recovery.
    async fn list_deleting_policy_attachments(
        &self,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError>;
    async fn finalize_policy_attachment_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError>;
    async fn delete_policy_attachment(&self, project_id: &str, id: &Uuid)
    -> Result<(), StoreError>;
    /// Replace the derived realization truth for one Endpoint. This does not
    /// mutate canonical policy desired state.
    async fn upsert_policy_realization(
        &self,
        realization: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError>;
    async fn get_policy_realization(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<Option<CanonicalPolicyRealizationRecord>, StoreError>;
    async fn list_policy_realizations(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalPolicyRealizationRecord>, StoreError>;
    #[allow(clippy::too_many_arguments)]
    async fn set_policy_realization_outcome(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
        expected_fingerprint: &str,
        expected_attempt_id: &Uuid,
        state: &str,
        observed_fingerprint: Option<&str>,
        observed_generation: Option<u64>,
        provider_resource_id: Option<&str>,
        last_outcome: Option<&str>,
    ) -> Result<(), StoreError>;
    /// Replace desired realization metadata only if this worker still owns
    /// the attempt it read. This prevents a late worker from overwriting a
    /// newer desired/observed result.
    async fn requeue_policy_realization(
        &self,
        expected_attempt_id: &Uuid,
        realization: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError>;
}

fn validate_policy(policy: &CanonicalReusableNetworkPolicyRecord) -> Result<i64, StoreError> {
    if policy.id.is_nil() || policy.project_id.trim().is_empty() {
        return Err(StoreError::Corrupt(
            "invalid reusable policy identity".into(),
        ));
    }
    if !matches!(policy.stateful_mode.as_str(), "Stateful" | "Stateless")
        || !matches!(policy.unmatched_action.as_str(), "Allow" | "Deny")
    {
        return Err(StoreError::Corrupt(
            "invalid reusable policy mode or unmatched action".into(),
        ));
    }
    validate_canonical_state(&policy.state)?;
    checked_generation(policy.generation)
}

fn validate_rule(rule: &CanonicalNetworkPolicyRuleRecord) -> Result<i64, StoreError> {
    if rule.id.is_nil()
        || rule.policy_id.is_nil()
        || rule.project_id.trim().is_empty()
        || rule.enforcement_key.trim().is_empty()
    {
        return Err(StoreError::Corrupt(
            "invalid reusable policy rule identity".into(),
        ));
    }
    if !matches!(rule.direction.as_str(), "Ingress" | "Egress")
        || !matches!(rule.address_family.as_str(), "Ipv4" | "Ipv6")
        || !matches!(rule.protocol.as_str(), "Any" | "Tcp" | "Udp" | "Icmp")
        || !matches!(rule.action.as_str(), "Allow" | "Deny")
    {
        return Err(StoreError::Corrupt(
            "invalid reusable policy rule semantics".into(),
        ));
    }
    if rule.port_min.is_some() != rule.port_max.is_some()
        || rule
            .port_min
            .zip(rule.port_max)
            .is_some_and(|(min, max)| min > max)
        || (rule.port_min.is_some() && matches!(rule.protocol.as_str(), "Any" | "Icmp"))
    {
        return Err(StoreError::Corrupt(
            "invalid reusable policy rule port range".into(),
        ));
    }
    if rule.address_family == "Ipv6"
        || rule
            .remote_selector
            .as_deref()
            .is_some_and(|v| v.contains(':'))
    {
        return Err(StoreError::Corrupt(
            "IPv6 policy rules are architecture-ready but not enabled".into(),
        ));
    }
    if let Some(selector) = &rule.remote_selector {
        let (address, prefix_len) = selector.split_once('/').ok_or_else(|| {
            StoreError::Corrupt("policy remote selector is missing prefix length".into())
        })?;
        let prefix_len: u8 = prefix_len
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid policy remote selector length".into()))?;
        let address: std::net::Ipv4Addr = address
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid policy remote selector address".into()))?;
        let prefix = o3k_domain::Ipv4Prefix::new(address, prefix_len)
            .ok_or_else(|| StoreError::Corrupt("invalid policy remote selector prefix".into()))?;
        if prefix.network != address {
            return Err(StoreError::Corrupt(
                "policy remote selector is not canonical".into(),
            ));
        }
    }
    let expected_key = format!(
        "{}|{}|{}|{}|{}|{}",
        rule.direction,
        rule.address_family,
        rule.protocol,
        rule.port_min
            .zip(rule.port_max)
            .map_or_else(|| "-".to_owned(), |(min, max)| format!("{min}-{max}")),
        rule.remote_selector.as_deref().unwrap_or("-"),
        rule.action
    );
    if rule.enforcement_key != expected_key {
        return Err(StoreError::Corrupt(
            "policy rule enforcement key is not normalized".into(),
        ));
    }
    validate_canonical_state(&rule.state)?;
    checked_generation(rule.generation)
}

fn validate_attachment(attachment: &CanonicalPolicyAttachmentRecord) -> Result<i64, StoreError> {
    if attachment.id.is_nil()
        || attachment.policy_id.is_nil()
        || attachment.endpoint_id.is_nil()
        || attachment.project_id.trim().is_empty()
    {
        return Err(StoreError::Corrupt(
            "invalid policy attachment identity".into(),
        ));
    }
    validate_canonical_state(&attachment.state)?;
    checked_generation(attachment.generation)
}

fn validate_child_insert_state(state: &str) -> Result<(), StoreError> {
    if matches!(state, "requested" | "active") {
        Ok(())
    } else {
        Err(StoreError::Corrupt(
            "policy child must be requested or active when inserted".into(),
        ))
    }
}

fn validate_policy_insert_state(state: &str) -> Result<(), StoreError> {
    if matches!(state, "requested" | "active") {
        Ok(())
    } else {
        Err(StoreError::Corrupt(
            "policy must be requested or active when inserted".into(),
        ))
    }
}

fn sqlite_policy(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
    Ok(CanonicalReusableNetworkPolicyRecord {
        id: parse_uuid(row.get("id"))?,
        project_id: row.get("project_id"),
        name: row.get("name"),
        description: row.get("description"),
        stateful_mode: row.get("stateful_mode"),
        unmatched_action: row.get("unmatched_action"),
        generation: u64::try_from(row.get::<i64, _>("generation"))
            .map_err(|_| StoreError::Corrupt("negative policy generation".into()))?,
        state: row.get("state"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}
fn sqlite_rule(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<CanonicalNetworkPolicyRuleRecord, StoreError> {
    Ok(CanonicalNetworkPolicyRuleRecord {
        id: parse_uuid(row.get("id"))?,
        policy_id: parse_uuid(row.get("policy_id"))?,
        project_id: row.get("project_id"),
        direction: row.get("direction"),
        address_family: row.get("address_family"),
        protocol: row.get("protocol"),
        port_min: row
            .get::<Option<i64>, _>("port_min")
            .map(|v| u16::try_from(v).map_err(|_| StoreError::Corrupt("invalid rule port".into())))
            .transpose()?,
        port_max: row
            .get::<Option<i64>, _>("port_max")
            .map(|v| u16::try_from(v).map_err(|_| StoreError::Corrupt("invalid rule port".into())))
            .transpose()?,
        remote_selector: row.get("remote_selector"),
        action: row.get("action"),
        state: row.get("state"),
        generation: u64::try_from(row.get::<i64, _>("generation"))
            .map_err(|_| StoreError::Corrupt("negative rule generation".into()))?,
        enforcement_key: row.get("enforcement_key"),
    })
}
fn sqlite_attachment(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<CanonicalPolicyAttachmentRecord, StoreError> {
    Ok(CanonicalPolicyAttachmentRecord {
        id: parse_uuid(row.get("id"))?,
        policy_id: parse_uuid(row.get("policy_id"))?,
        endpoint_id: parse_uuid(row.get("endpoint_id"))?,
        project_id: row.get("project_id"),
        state: row.get("state"),
        generation: u64::try_from(row.get::<i64, _>("generation"))
            .map_err(|_| StoreError::Corrupt("negative attachment generation".into()))?,
    })
}

fn sqlite_realization(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<CanonicalPolicyRealizationRecord, StoreError> {
    Ok(CanonicalPolicyRealizationRecord {
        endpoint_id: parse_uuid(row.get("endpoint_id"))?,
        project_id: row.get("project_id"),
        attempt_id: parse_uuid(row.get("attempt_id"))?,
        desired_fingerprint: row.get("desired_fingerprint"),
        desired_generation: u64::try_from(row.get::<i64, _>("desired_generation"))
            .map_err(|_| StoreError::Corrupt("negative desired policy generation".into()))?,
        observed_fingerprint: row.get("observed_fingerprint"),
        observed_generation: row
            .get::<Option<i64>, _>("observed_generation")
            .map(u64::try_from)
            .transpose()
            .map_err(|_| StoreError::Corrupt("negative observed policy generation".into()))?,
        state: row.get("state"),
        provider_resource_id: row.get("provider_resource_id"),
        last_outcome: row.get("last_outcome"),
    })
}

impl crate::SqliteStore {
    pub async fn insert_reusable_policy(
        &self,
        p: &CanonicalReusableNetworkPolicyRecord,
    ) -> Result<(), StoreError> {
        let generation = validate_policy(p)?;
        validate_policy_insert_state(&p.state)?;
        sqlx::query("INSERT INTO canonical_reusable_network_policies (id, project_id, name, description, stateful_mode, unmatched_action, generation, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(p.id.to_string()).bind(&p.project_id).bind(&p.name).bind(&p.description).bind(&p.stateful_mode).bind(&p.unmatched_action).bind(generation).bind(&p.state).bind(&p.created_at).bind(&p.updated_at).execute(&self.pool).await.map_err(map_canonical_insert_error).map(|_| ())
    }
    pub async fn get_reusable_policy(
        &self,
        project: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalReusableNetworkPolicyRecord>, StoreError> {
        sqlx::query(&format!("SELECT {POLICY_COLUMNS} FROM canonical_reusable_network_policies WHERE id = ? AND project_id = ?")).bind(id.to_string()).bind(project).fetch_optional(&self.pool).await.map_err(StoreError::Database)?.as_ref().map(sqlite_policy).transpose()
    }
    pub async fn list_reusable_policies(
        &self,
        project: &str,
    ) -> Result<Vec<CanonicalReusableNetworkPolicyRecord>, StoreError> {
        let rows=sqlx::query(&format!("SELECT {POLICY_COLUMNS} FROM canonical_reusable_network_policies WHERE project_id = ? ORDER BY id")).bind(project).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.iter().map(sqlite_policy).collect()
    }
    pub async fn update_reusable_policy(
        &self,
        p: &CanonicalReusableNetworkPolicyRecord,
        expected: u64,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
        let new_gen = validate_policy(p)?;
        if p.generation != expected.saturating_add(1) {
            return Err(StoreError::Corrupt(
                "policy update generation must increment by one".into(),
            ));
        }
        let current = self
            .get_reusable_policy(&p.project_id, &p.id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        if current.state != p.state {
            return Err(StoreError::StaleGeneration);
        }
        // Acquire SQLite's writer lock before the read/validate sequence. A
        // deferred transaction can let two writers both read the old state,
        // then one fails upgrading with SQLITE_BUSY instead of returning the
        // validated durable domain result.
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(StoreError::Database)?;
        let current_state: Option<String> = sqlx::query_scalar(
            "SELECT state FROM canonical_reusable_network_policies WHERE id=? AND project_id=?",
        )
        .bind(p.id.to_string())
        .bind(&p.project_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if current_state.as_deref() != Some(p.state.as_str()) {
            return Err(if current_state.is_some() {
                StoreError::StaleGeneration
            } else {
                StoreError::ResourceNotFound
            });
        }
        let incompatible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM canonical_policy_attachments a JOIN canonical_policy_attachments other ON other.endpoint_id=a.endpoint_id AND other.policy_id<>a.policy_id AND other.state='active' JOIN canonical_reusable_network_policies other_policy ON other_policy.id=other.policy_id WHERE a.policy_id=? AND a.state='active' AND other_policy.unmatched_action<>?")
            .bind(p.id.to_string()).bind(&p.unmatched_action).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
        if incompatible != 0 {
            return Err(StoreError::PolicyCompositionConflict);
        }
        let result=sqlx::query("UPDATE canonical_reusable_network_policies SET name=?, description=?, stateful_mode=?, unmatched_action=?, generation=?, updated_at=? WHERE id=? AND project_id=? AND generation=? AND state=?").bind(&p.name).bind(&p.description).bind(&p.stateful_mode).bind(&p.unmatched_action).bind(new_gen).bind(&p.updated_at).bind(p.id.to_string()).bind(&p.project_id).bind(checked_generation(expected)?).bind(&p.state).execute(&mut *tx).await.map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_reusable_policy(&p.project_id, &p.id).await? {
                Some(_) => Err(StoreError::StaleGeneration),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        self.get_reusable_policy(&p.project_id, &p.id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }
    pub async fn transition_reusable_policy_state(
        &self,
        project: &str,
        id: &Uuid,
        expected: u64,
        state: &str,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
        validate_canonical_state(state)?;
        let query = match state {
            "active" => {
                "UPDATE canonical_reusable_network_policies SET state=?, generation=generation+1, updated_at=updated_at WHERE id=? AND project_id=? AND generation=? AND state='requested'"
            }
            "deleting" => {
                "UPDATE canonical_reusable_network_policies SET state=?, generation=generation+1, updated_at=updated_at WHERE id=? AND project_id=? AND generation=? AND state IN ('requested','active','error') AND NOT EXISTS (SELECT 1 FROM canonical_network_policy_rules WHERE policy_id=? AND state IN ('requested','active','deleting')) AND NOT EXISTS (SELECT 1 FROM canonical_policy_attachments WHERE policy_id=? AND state IN ('requested','active','deleting'))"
            }
            "deleted" => {
                "UPDATE canonical_reusable_network_policies SET state=?, generation=generation+1, updated_at=updated_at WHERE id=? AND project_id=? AND generation=? AND state='deleting' AND NOT EXISTS (SELECT 1 FROM canonical_network_policy_rules WHERE policy_id=? AND state IN ('requested','active','deleting')) AND NOT EXISTS (SELECT 1 FROM canonical_policy_attachments WHERE policy_id=? AND state IN ('requested','active','deleting'))"
            }
            "error" => {
                "UPDATE canonical_reusable_network_policies SET state=?, generation=generation+1, updated_at=updated_at WHERE id=? AND project_id=? AND generation=? AND state IN ('requested','active','deleting')"
            }
            "requested" => {
                "UPDATE canonical_reusable_network_policies SET state=?, generation=generation+1, updated_at=updated_at WHERE id=? AND project_id=? AND generation=? AND state='__invalid_requested_transition__'"
            }
            _ => unreachable!(),
        };
        let statement = if matches!(state, "deleting" | "deleted") {
            sqlx::query(query)
                .bind(state)
                .bind(id.to_string())
                .bind(project)
                .bind(checked_generation(expected)?)
                .bind(id.to_string())
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(StoreError::Database)?
        } else {
            sqlx::query(query)
                .bind(state)
                .bind(id.to_string())
                .bind(project)
                .bind(checked_generation(expected)?)
                .execute(&self.pool)
                .await
                .map_err(StoreError::Database)?
        };
        if statement.rows_affected() == 0 {
            if matches!(state, "deleting" | "deleted") {
                let current = self.get_reusable_policy(project, id).await?;
                if let Some(current) = current {
                    if current.generation != expected {
                        return Err(StoreError::StaleGeneration);
                    }
                    let children: i64 = sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM canonical_network_policy_rules WHERE policy_id=? AND state IN ('requested','active','deleting')) + (SELECT COUNT(*) FROM canonical_policy_attachments WHERE policy_id=? AND state IN ('requested','active','deleting'))")
                        .bind(id.to_string()).bind(id.to_string()).fetch_one(&self.pool).await.map_err(StoreError::Database)?;
                    if children > 0 {
                        return Err(StoreError::NetworkInUse);
                    }
                }
            }
            return match self.get_reusable_policy(project, id).await? {
                Some(_) => Err(StoreError::StaleGeneration),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        self.get_reusable_policy(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }
    pub async fn delete_reusable_policy(&self, project: &str, id: &Uuid) -> Result<(), StoreError> {
        let current = self
            .get_reusable_policy(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        let reserved = if current.state == "deleting" {
            current
        } else {
            self.transition_reusable_policy_state(project, id, current.generation, "deleting")
                .await?
        };
        let result = sqlx::query("DELETE FROM canonical_reusable_network_policies WHERE id=? AND project_id=? AND state='deleting' AND generation=? AND NOT EXISTS (SELECT 1 FROM canonical_network_policy_rules WHERE policy_id=? AND state IN ('requested','active','deleting')) AND NOT EXISTS (SELECT 1 FROM canonical_policy_attachments WHERE policy_id=? AND state IN ('requested','active','deleting'))")
            .bind(id.to_string())
            .bind(project)
            .bind(checked_generation(reserved.generation)?)
            .bind(id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            match self.get_reusable_policy(project, id).await? {
                Some(policy) if policy.generation != reserved.generation => {
                    Err(StoreError::StaleGeneration)
                }
                Some(_) => Err(StoreError::NetworkInUse),
                None => Err(StoreError::ResourceNotFound),
            }
        }
    }
    pub async fn insert_policy_rule(
        &self,
        r: &CanonicalNetworkPolicyRuleRecord,
    ) -> Result<(), StoreError> {
        let generation = validate_rule(r)?;
        validate_child_insert_state(&r.state)?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(StoreError::Database)?;
        let parent = sqlx::query(
            "SELECT project_id, state FROM canonical_reusable_network_policies WHERE id=?",
        )
        .bind(r.policy_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        .ok_or(StoreError::ResourceNotFound)?;
        if parent.get::<String, _>("project_id") != r.project_id
            || parent.get::<String, _>("state") != "active"
        {
            return Err(StoreError::OwnershipConflict);
        }
        sqlx::query("INSERT INTO canonical_network_policy_rules (id, policy_id, project_id, direction, address_family, protocol, port_min, port_max, remote_selector, action, state, generation, enforcement_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(r.id.to_string()).bind(r.policy_id.to_string()).bind(&r.project_id).bind(&r.direction).bind(&r.address_family).bind(&r.protocol).bind(r.port_min.map(i64::from)).bind(r.port_max.map(i64::from)).bind(&r.remote_selector).bind(&r.action).bind(&r.state).bind(generation).bind(&r.enforcement_key).execute(&mut *tx).await.map_err(map_canonical_insert_error)?;
        tx.commit().await.map_err(StoreError::Database)
    }
    pub async fn get_policy_rule(
        &self,
        project: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        sqlx::query(&format!(
            "SELECT {RULE_COLUMNS} FROM canonical_network_policy_rules WHERE id=? AND project_id=?"
        ))
        .bind(id.to_string())
        .bind(project)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?
        .as_ref()
        .map(sqlite_rule)
        .transpose()
    }
    pub async fn list_policy_rules(
        &self,
        project: &str,
        policy: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        let rows=sqlx::query(&format!("SELECT {RULE_COLUMNS} FROM canonical_network_policy_rules WHERE policy_id=? AND project_id=? ORDER BY id")).bind(policy.to_string()).bind(project).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.iter().map(sqlite_rule).collect()
    }
    pub async fn list_deleting_policy_rules(
        &self,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {RULE_COLUMNS} FROM canonical_network_policy_rules WHERE state='deleting' ORDER BY project_id,id"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(sqlite_rule).collect()
    }
    pub async fn begin_policy_rule_deletion(
        &self,
        project: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<CanonicalNetworkPolicyRuleRecord, StoreError> {
        let result = sqlx::query("UPDATE canonical_network_policy_rules SET state='deleting', generation=generation+1 WHERE id=? AND project_id=? AND state='active' AND generation=?")
            .bind(id.to_string()).bind(project).bind(checked_generation(expected)?).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_policy_rule(project, id).await? {
                Some(rule) if rule.generation != expected => Err(StoreError::StaleGeneration),
                Some(_) => Err(StoreError::Corrupt("policy rule is not active".into())),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        self.get_policy_rule(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }
    pub async fn finalize_policy_rule_deletion(
        &self,
        project: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM canonical_network_policy_rules WHERE id=? AND project_id=? AND state='deleting' AND generation=?")
            .bind(id.to_string()).bind(project).bind(checked_generation(expected)?).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        match self.get_policy_rule(project, id).await? {
            Some(rule) if rule.generation != expected => Err(StoreError::StaleGeneration),
            Some(_) => Err(StoreError::Corrupt(
                "policy rule is not deletion-reserved".into(),
            )),
            None => Err(StoreError::ResourceNotFound),
        }
    }
    pub async fn delete_policy_rule(&self, project: &str, id: &Uuid) -> Result<(), StoreError> {
        let current = self
            .get_policy_rule(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        let reserved = self
            .begin_policy_rule_deletion(project, id, current.generation)
            .await?;
        self.finalize_policy_rule_deletion(project, id, reserved.generation)
            .await
    }
    pub async fn insert_policy_attachment(
        &self,
        a: &CanonicalPolicyAttachmentRecord,
    ) -> Result<(), StoreError> {
        let generation = validate_attachment(a)?;
        validate_child_insert_state(&a.state)?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(StoreError::Database)?;
        let p = sqlx::query(
            "SELECT project_id,state,unmatched_action FROM canonical_reusable_network_policies WHERE id=?",
        )
        .bind(a.policy_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        .ok_or(StoreError::ResourceNotFound)?;
        if p.get::<String, _>("project_id") != a.project_id
            || p.get::<String, _>("state") != "active"
        {
            return Err(StoreError::OwnershipConflict);
        }
        let incompatible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM canonical_policy_attachments a JOIN canonical_reusable_network_policies existing ON existing.id=a.policy_id WHERE a.endpoint_id=? AND a.state='active' AND existing.unmatched_action <> ?")
            .bind(a.endpoint_id.to_string())
            .bind(p.get::<String, _>("unmatched_action"))
            .fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
        if incompatible != 0 {
            return Err(StoreError::PolicyCompositionConflict);
        }
        let e = sqlx::query("SELECT project_id FROM canonical_endpoints WHERE id=?")
            .bind(a.endpoint_id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?;
        if e.get::<String, _>("project_id") != a.project_id {
            return Err(StoreError::OwnershipConflict);
        }
        sqlx::query("INSERT INTO canonical_policy_attachments (id,policy_id,endpoint_id,project_id,state,generation) VALUES (?,?,?,?,?,?)").bind(a.id.to_string()).bind(a.policy_id.to_string()).bind(a.endpoint_id.to_string()).bind(&a.project_id).bind(&a.state).bind(generation).execute(&mut *tx).await.map_err(map_canonical_insert_error)?;
        tx.commit().await.map_err(StoreError::Database)
    }
    pub async fn get_policy_attachment(
        &self,
        project: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalPolicyAttachmentRecord>, StoreError> {
        sqlx::query(&format!("SELECT {ATTACHMENT_COLUMNS} FROM canonical_policy_attachments WHERE id=? AND project_id=?")).bind(id.to_string()).bind(project).fetch_optional(&self.pool).await.map_err(StoreError::Database)?.as_ref().map(sqlite_attachment).transpose()
    }
    pub async fn list_policy_attachments(
        &self,
        project: &str,
        policy: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        let rows=sqlx::query(&format!("SELECT {ATTACHMENT_COLUMNS} FROM canonical_policy_attachments WHERE policy_id=? AND project_id=? ORDER BY id")).bind(policy.to_string()).bind(project).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.iter().map(sqlite_attachment).collect()
    }
    pub async fn list_endpoint_policy_attachments(
        &self,
        project: &str,
        endpoint: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        let rows=sqlx::query(&format!("SELECT {ATTACHMENT_COLUMNS} FROM canonical_policy_attachments WHERE endpoint_id=? AND project_id=? ORDER BY id")).bind(endpoint.to_string()).bind(project).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.iter().map(sqlite_attachment).collect()
    }
    pub async fn list_deleting_policy_attachments(
        &self,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {ATTACHMENT_COLUMNS} FROM canonical_policy_attachments WHERE state='deleting' ORDER BY project_id,id"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(sqlite_attachment).collect()
    }
    pub async fn replace_policy_attachment_set(
        &self,
        project: &str,
        endpoint: &Uuid,
        policy_ids: &[Uuid],
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        let requested = policy_ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let mut backoff = std::time::Duration::from_millis(10);
        for attempt in 0..crate::SQLITE_BUSY_MAX_ATTEMPTS {
            let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
            let began = sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut *connection)
                .await;
            let outcome = match began {
                Ok(_) => {
                    let outcome: Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> =
                        async {
                            let endpoint_row =
                                sqlx::query("SELECT project_id FROM canonical_endpoints WHERE id=?")
                                    .bind(endpoint.to_string())
                                    .fetch_optional(&mut *connection)
                                    .await
                                    .map_err(StoreError::Database)?
                                    .ok_or(StoreError::ResourceNotFound)?;
                            if endpoint_row.get::<String, _>("project_id") != project {
                                return Err(StoreError::OwnershipConflict);
                            }
                            let existing = sqlx::query(&format!(
                                "SELECT {ATTACHMENT_COLUMNS} FROM canonical_policy_attachments WHERE endpoint_id=? AND project_id=? ORDER BY id"
                            ))
                            .bind(endpoint.to_string())
                            .bind(project)
                            .fetch_all(&mut *connection)
                            .await
                            .map_err(StoreError::Database)?;
                            let existing = existing
                                .iter()
                                .map(sqlite_attachment)
                                .collect::<Result<Vec<_>, _>>()?;
                            for policy_id in &requested {
                                let policy = sqlx::query(
                                    "SELECT project_id,state,unmatched_action FROM canonical_reusable_network_policies WHERE id=?",
                                )
                                .bind(policy_id.to_string())
                                .fetch_optional(&mut *connection)
                                .await
                                .map_err(StoreError::Database)?
                                .ok_or(StoreError::ResourceNotFound)?;
                                if policy.get::<String, _>("project_id") != project
                                    || policy.get::<String, _>("state") != "active"
                                {
                                    return Err(StoreError::OwnershipConflict);
                                }
                            }
                            let mut default_value = None;
                            for policy_id in &requested {
                                let value = sqlx::query_scalar::<_, String>(
                                    "SELECT unmatched_action FROM canonical_reusable_network_policies WHERE id=?",
                                )
                                .bind(policy_id.to_string())
                                .fetch_one(&mut *connection)
                                .await
                                .map_err(StoreError::Database)?;
                                if let Some(previous) = &default_value {
                                    if previous != &value {
                                        return Err(StoreError::PolicyCompositionConflict);
                                    }
                                } else {
                                    default_value = Some(value);
                                }
                            }
                            let mut deleting = Vec::new();
                            for attachment in &existing {
                                if attachment.state == "active"
                                    && !requested.contains(&attachment.policy_id)
                                {
                                    sqlx::query("UPDATE canonical_policy_attachments SET state='deleting', generation=generation+1 WHERE id=? AND state='active' AND generation=?")
                                        .bind(attachment.id.to_string())
                                        .bind(checked_generation(attachment.generation)?)
                                        .execute(&mut *connection)
                                        .await
                                        .map_err(StoreError::Database)?;
                                    deleting.push(CanonicalPolicyAttachmentRecord {
                                        state: "deleting".to_owned(),
                                        generation: attachment.generation.saturating_add(1),
                                        ..attachment.clone()
                                    });
                                } else if attachment.state == "deleting"
                                    && requested.contains(&attachment.policy_id)
                                {
                                    return Err(StoreError::OwnershipConflict);
                                }
                            }
                            for policy_id in &requested {
                                if existing.iter().any(|attachment| {
                                    attachment.policy_id == *policy_id && attachment.state == "active"
                                }) {
                                    continue;
                                }
                                let attachment = CanonicalPolicyAttachmentRecord {
                                    id: Uuid::now_v7(),
                                    policy_id: *policy_id,
                                    endpoint_id: *endpoint,
                                    project_id: project.to_owned(),
                                    state: "active".to_owned(),
                                    generation: 1,
                                };
                                sqlx::query("INSERT INTO canonical_policy_attachments (id,policy_id,endpoint_id,project_id,state,generation) VALUES (?,?,?,?,?,?)")
                                    .bind(attachment.id.to_string())
                                    .bind(attachment.policy_id.to_string())
                                    .bind(attachment.endpoint_id.to_string())
                                    .bind(project)
                                    .bind("active")
                                    .bind(1_i64)
                                    .execute(&mut *connection)
                                    .await
                                    .map_err(map_canonical_insert_error)?;
                            }
                            Ok(deleting)
                        }
                        .await;
                    crate::SqliteStore::commit_or_rollback(&mut connection, outcome).await
                }
                Err(error) => Err(StoreError::Database(error)),
            };
            match outcome {
                Ok(deleting) => return Ok(deleting),
                Err(StoreError::Database(error))
                    if crate::is_sqlite_busy(&error)
                        && attempt + 1 < crate::SQLITE_BUSY_MAX_ATTEMPTS =>
                {
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the loop returns on the final attempt")
    }
    pub async fn begin_policy_attachment_deletion(
        &self,
        project: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<CanonicalPolicyAttachmentRecord, StoreError> {
        let result = sqlx::query("UPDATE canonical_policy_attachments SET state='deleting', generation=generation+1 WHERE id=? AND project_id=? AND state='active' AND generation=?")
            .bind(id.to_string()).bind(project).bind(checked_generation(expected)?).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_policy_attachment(project, id).await? {
                Some(attachment) if attachment.generation != expected => {
                    Err(StoreError::StaleGeneration)
                }
                Some(_) => Err(StoreError::Corrupt(
                    "policy attachment is not active".into(),
                )),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        self.get_policy_attachment(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }
    pub async fn finalize_policy_attachment_deletion(
        &self,
        project: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM canonical_policy_attachments WHERE id=? AND project_id=? AND state='deleting' AND generation=?")
            .bind(id.to_string()).bind(project).bind(checked_generation(expected)?).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        match self.get_policy_attachment(project, id).await? {
            Some(attachment) if attachment.generation != expected => {
                Err(StoreError::StaleGeneration)
            }
            Some(_) => Err(StoreError::Corrupt(
                "policy attachment is not deletion-reserved".into(),
            )),
            None => Err(StoreError::ResourceNotFound),
        }
    }
    pub async fn delete_policy_attachment(
        &self,
        project: &str,
        id: &Uuid,
    ) -> Result<(), StoreError> {
        let current = self
            .get_policy_attachment(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        let reserved = self
            .begin_policy_attachment_deletion(project, id, current.generation)
            .await?;
        self.finalize_policy_attachment_deletion(project, id, reserved.generation)
            .await
    }

    pub async fn upsert_policy_realization(
        &self,
        r: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError> {
        if r.endpoint_id.is_nil()
            || r.project_id.trim().is_empty()
            || r.desired_fingerprint.is_empty()
            || r.desired_generation == 0
            || !matches!(
                r.state.as_str(),
                "pending" | "applying" | "realized" | "failed" | "unknown"
            )
        {
            return Err(StoreError::Corrupt("invalid policy realization".into()));
        }
        sqlx::query("INSERT INTO canonical_policy_realizations (endpoint_id, project_id, attempt_id, desired_fingerprint, desired_generation, observed_fingerprint, observed_generation, state, provider_resource_id, last_outcome) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(endpoint_id) DO UPDATE SET project_id=excluded.project_id, attempt_id=excluded.attempt_id, desired_fingerprint=excluded.desired_fingerprint, desired_generation=excluded.desired_generation, observed_fingerprint=excluded.observed_fingerprint, observed_generation=excluded.observed_generation, state=excluded.state, provider_resource_id=excluded.provider_resource_id, last_outcome=excluded.last_outcome")
            .bind(r.endpoint_id.to_string()).bind(&r.project_id).bind(r.attempt_id.to_string()).bind(&r.desired_fingerprint).bind(checked_generation(r.desired_generation)?)
            .bind(&r.observed_fingerprint).bind(r.observed_generation.map(checked_generation).transpose()?).bind(&r.state).bind(&r.provider_resource_id).bind(&r.last_outcome)
            .execute(&self.pool).await.map_err(StoreError::Database).map(|_| ())
    }
    pub async fn get_policy_realization(
        &self,
        project: &str,
        endpoint: &Uuid,
    ) -> Result<Option<CanonicalPolicyRealizationRecord>, StoreError> {
        sqlx::query(&format!("SELECT {REALIZATION_COLUMNS} FROM canonical_policy_realizations WHERE endpoint_id=? AND project_id=?"))
            .bind(endpoint.to_string()).bind(project).fetch_optional(&self.pool).await.map_err(StoreError::Database)?.as_ref().map(sqlite_realization).transpose()
    }
    pub async fn list_policy_realizations(
        &self,
        project: &str,
    ) -> Result<Vec<CanonicalPolicyRealizationRecord>, StoreError> {
        let rows = sqlx::query(&format!("SELECT {REALIZATION_COLUMNS} FROM canonical_policy_realizations WHERE project_id=? ORDER BY endpoint_id")).bind(project).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.iter().map(sqlite_realization).collect()
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn set_policy_realization_outcome(
        &self,
        project: &str,
        endpoint: &Uuid,
        expected: &str,
        expected_attempt_id: &Uuid,
        state: &str,
        observed: Option<&str>,
        observed_generation: Option<u64>,
        provider_resource_id: Option<&str>,
        last_outcome: Option<&str>,
    ) -> Result<(), StoreError> {
        if !matches!(
            state,
            "pending" | "applying" | "realized" | "failed" | "unknown"
        ) {
            return Err(StoreError::Corrupt(
                "invalid policy realization state".into(),
            ));
        }
        let result = sqlx::query("UPDATE canonical_policy_realizations SET observed_fingerprint=?, observed_generation=?, state=?, provider_resource_id=?, last_outcome=? WHERE endpoint_id=? AND project_id=? AND desired_fingerprint=? AND attempt_id=?")
            .bind(observed).bind(observed_generation.map(checked_generation).transpose()?).bind(state).bind(provider_resource_id).bind(last_outcome)
            .bind(endpoint.to_string()).bind(project).bind(expected).bind(expected_attempt_id.to_string()).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(StoreError::StaleGeneration)
        }
    }

    pub async fn requeue_policy_realization(
        &self,
        expected_attempt_id: &Uuid,
        r: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError> {
        let result = sqlx::query("UPDATE canonical_policy_realizations SET attempt_id=?, desired_fingerprint=?, desired_generation=?, observed_fingerprint=?, observed_generation=?, state=?, provider_resource_id=?, last_outcome=? WHERE endpoint_id=? AND project_id=? AND attempt_id=?")
            .bind(r.attempt_id.to_string()).bind(&r.desired_fingerprint).bind(checked_generation(r.desired_generation)?)
            .bind(&r.observed_fingerprint).bind(r.observed_generation.map(checked_generation).transpose()?).bind(&r.state).bind(&r.provider_resource_id).bind(&r.last_outcome)
            .bind(r.endpoint_id.to_string()).bind(&r.project_id).bind(expected_attempt_id.to_string()).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(StoreError::StaleGeneration)
        }
    }
}

#[async_trait]
impl CanonicalPolicyRepository for crate::SqliteStore {
    async fn insert_reusable_policy(
        &self,
        p: &CanonicalReusableNetworkPolicyRecord,
    ) -> Result<(), StoreError> {
        self.insert_reusable_policy(p).await
    }
    async fn get_reusable_policy(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Option<CanonicalReusableNetworkPolicyRecord>, StoreError> {
        self.get_reusable_policy(p, i).await
    }
    async fn list_reusable_policies(
        &self,
        p: &str,
    ) -> Result<Vec<CanonicalReusableNetworkPolicyRecord>, StoreError> {
        self.list_reusable_policies(p).await
    }
    async fn update_reusable_policy(
        &self,
        p: &CanonicalReusableNetworkPolicyRecord,
        g: u64,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
        self.update_reusable_policy(p, g).await
    }
    async fn transition_reusable_policy_state(
        &self,
        p: &str,
        i: &Uuid,
        g: u64,
        s: &str,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
        self.transition_reusable_policy_state(p, i, g, s).await
    }
    async fn delete_reusable_policy(&self, p: &str, i: &Uuid) -> Result<(), StoreError> {
        self.delete_reusable_policy(p, i).await
    }
    async fn insert_policy_rule(
        &self,
        r: &CanonicalNetworkPolicyRuleRecord,
    ) -> Result<(), StoreError> {
        self.insert_policy_rule(r).await
    }
    async fn get_policy_rule(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Option<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        self.get_policy_rule(p, i).await
    }
    async fn list_policy_rules(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        self.list_policy_rules(p, i).await
    }
    async fn list_deleting_policy_rules(
        &self,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        self.list_deleting_policy_rules().await
    }
    async fn begin_policy_rule_deletion(
        &self,
        p: &str,
        i: &Uuid,
        g: u64,
    ) -> Result<CanonicalNetworkPolicyRuleRecord, StoreError> {
        self.begin_policy_rule_deletion(p, i, g).await
    }
    async fn finalize_policy_rule_deletion(
        &self,
        p: &str,
        i: &Uuid,
        g: u64,
    ) -> Result<(), StoreError> {
        self.finalize_policy_rule_deletion(p, i, g).await
    }
    async fn delete_policy_rule(&self, p: &str, i: &Uuid) -> Result<(), StoreError> {
        self.delete_policy_rule(p, i).await
    }
    async fn insert_policy_attachment(
        &self,
        a: &CanonicalPolicyAttachmentRecord,
    ) -> Result<(), StoreError> {
        self.insert_policy_attachment(a).await
    }
    async fn get_policy_attachment(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Option<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.get_policy_attachment(p, i).await
    }
    async fn list_policy_attachments(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.list_policy_attachments(p, i).await
    }
    async fn list_endpoint_policy_attachments(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.list_endpoint_policy_attachments(p, i).await
    }
    async fn list_deleting_policy_attachments(
        &self,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.list_deleting_policy_attachments().await
    }
    async fn replace_policy_attachment_set(
        &self,
        p: &str,
        i: &Uuid,
        policy_ids: &[Uuid],
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.replace_policy_attachment_set(p, i, policy_ids).await
    }
    async fn begin_policy_attachment_deletion(
        &self,
        p: &str,
        i: &Uuid,
        g: u64,
    ) -> Result<CanonicalPolicyAttachmentRecord, StoreError> {
        self.begin_policy_attachment_deletion(p, i, g).await
    }
    async fn finalize_policy_attachment_deletion(
        &self,
        p: &str,
        i: &Uuid,
        g: u64,
    ) -> Result<(), StoreError> {
        self.finalize_policy_attachment_deletion(p, i, g).await
    }
    async fn delete_policy_attachment(&self, p: &str, i: &Uuid) -> Result<(), StoreError> {
        self.delete_policy_attachment(p, i).await
    }
    async fn upsert_policy_realization(
        &self,
        r: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError> {
        self.upsert_policy_realization(r).await
    }
    async fn get_policy_realization(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Option<CanonicalPolicyRealizationRecord>, StoreError> {
        self.get_policy_realization(p, i).await
    }
    async fn list_policy_realizations(
        &self,
        p: &str,
    ) -> Result<Vec<CanonicalPolicyRealizationRecord>, StoreError> {
        self.list_policy_realizations(p).await
    }
    async fn set_policy_realization_outcome(
        &self,
        p: &str,
        e: &Uuid,
        f: &str,
        a: &Uuid,
        s: &str,
        o: Option<&str>,
        g: Option<u64>,
        r: Option<&str>,
        l: Option<&str>,
    ) -> Result<(), StoreError> {
        self.set_policy_realization_outcome(p, e, f, a, s, o, g, r, l)
            .await
    }
    async fn requeue_policy_realization(
        &self,
        a: &Uuid,
        r: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError> {
        self.requeue_policy_realization(a, r).await
    }
}

fn pg_policy(
    row: &sqlx::postgres::PgRow,
) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
    Ok(CanonicalReusableNetworkPolicyRecord {
        id: parse_uuid(row.get("id"))?,
        project_id: row.get("project_id"),
        name: row.get("name"),
        description: row.get("description"),
        stateful_mode: row.get("stateful_mode"),
        unmatched_action: row.get("unmatched_action"),
        generation: u64::try_from(row.get::<i64, _>("generation"))
            .map_err(|_| StoreError::Corrupt("negative policy generation".into()))?,
        state: row.get("state"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}
fn pg_rule(row: &sqlx::postgres::PgRow) -> Result<CanonicalNetworkPolicyRuleRecord, StoreError> {
    Ok(CanonicalNetworkPolicyRuleRecord {
        id: parse_uuid(row.get("id"))?,
        policy_id: parse_uuid(row.get("policy_id"))?,
        project_id: row.get("project_id"),
        direction: row.get("direction"),
        address_family: row.get("address_family"),
        protocol: row.get("protocol"),
        port_min: row
            .get::<Option<i32>, _>("port_min")
            .map(|v| u16::try_from(v).map_err(|_| StoreError::Corrupt("invalid rule port".into())))
            .transpose()?,
        port_max: row
            .get::<Option<i32>, _>("port_max")
            .map(|v| u16::try_from(v).map_err(|_| StoreError::Corrupt("invalid rule port".into())))
            .transpose()?,
        remote_selector: row.get("remote_selector"),
        action: row.get("action"),
        state: row.get("state"),
        generation: u64::try_from(row.get::<i64, _>("generation"))
            .map_err(|_| StoreError::Corrupt("negative rule generation".into()))?,
        enforcement_key: row.get("enforcement_key"),
    })
}
fn pg_attachment(
    row: &sqlx::postgres::PgRow,
) -> Result<CanonicalPolicyAttachmentRecord, StoreError> {
    Ok(CanonicalPolicyAttachmentRecord {
        id: parse_uuid(row.get("id"))?,
        policy_id: parse_uuid(row.get("policy_id"))?,
        endpoint_id: parse_uuid(row.get("endpoint_id"))?,
        project_id: row.get("project_id"),
        state: row.get("state"),
        generation: u64::try_from(row.get::<i64, _>("generation"))
            .map_err(|_| StoreError::Corrupt("negative attachment generation".into()))?,
    })
}

fn pg_realization(
    row: &sqlx::postgres::PgRow,
) -> Result<CanonicalPolicyRealizationRecord, StoreError> {
    Ok(CanonicalPolicyRealizationRecord {
        endpoint_id: parse_uuid(row.get("endpoint_id"))?,
        project_id: row.get("project_id"),
        attempt_id: parse_uuid(row.get("attempt_id"))?,
        desired_fingerprint: row.get("desired_fingerprint"),
        desired_generation: u64::try_from(row.get::<i64, _>("desired_generation"))
            .map_err(|_| StoreError::Corrupt("negative desired policy generation".into()))?,
        observed_fingerprint: row.get("observed_fingerprint"),
        observed_generation: row
            .get::<Option<i64>, _>("observed_generation")
            .map(u64::try_from)
            .transpose()
            .map_err(|_| StoreError::Corrupt("negative observed policy generation".into()))?,
        state: row.get("state"),
        provider_resource_id: row.get("provider_resource_id"),
        last_outcome: row.get("last_outcome"),
    })
}

impl crate::PostgresStore {
    pub async fn insert_reusable_policy(
        &self,
        p: &CanonicalReusableNetworkPolicyRecord,
    ) -> Result<(), StoreError> {
        let g = validate_policy(p)?;
        validate_policy_insert_state(&p.state)?;
        sqlx::query("INSERT INTO canonical_reusable_network_policies (id,project_id,name,description,stateful_mode,unmatched_action,generation,state,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(p.id.to_string()).bind(&p.project_id).bind(&p.name).bind(&p.description).bind(&p.stateful_mode).bind(&p.unmatched_action).bind(g).bind(&p.state).bind(&p.created_at).bind(&p.updated_at).execute(&self.pool).await.map_err(map_canonical_insert_error).map(|_|())
    }
    pub async fn get_reusable_policy(
        &self,
        project: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalReusableNetworkPolicyRecord>, StoreError> {
        sqlx::query(&format!("SELECT {POLICY_COLUMNS} FROM canonical_reusable_network_policies WHERE id=$1 AND project_id=$2")).bind(id.to_string()).bind(project).fetch_optional(&self.pool).await.map_err(StoreError::Database)?.as_ref().map(pg_policy).transpose()
    }
    pub async fn list_reusable_policies(
        &self,
        project: &str,
    ) -> Result<Vec<CanonicalReusableNetworkPolicyRecord>, StoreError> {
        let r=sqlx::query(&format!("SELECT {POLICY_COLUMNS} FROM canonical_reusable_network_policies WHERE project_id=$1 ORDER BY id")).bind(project).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        r.iter().map(pg_policy).collect()
    }
    pub async fn update_reusable_policy(
        &self,
        p: &CanonicalReusableNetworkPolicyRecord,
        expected: u64,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
        let g = validate_policy(p)?;
        if p.generation != expected.saturating_add(1) {
            return Err(StoreError::Corrupt(
                "policy update generation must increment by one".into(),
            ));
        }
        let current = self
            .get_reusable_policy(&p.project_id, &p.id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        if current.state != p.state {
            return Err(StoreError::StaleGeneration);
        }
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let current_state: Option<String> = sqlx::query_scalar("SELECT state FROM canonical_reusable_network_policies WHERE id=$1 AND project_id=$2 FOR UPDATE")
            .bind(p.id.to_string())
            .bind(&p.project_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        if current_state.as_deref() != Some(p.state.as_str()) {
            return Err(if current_state.is_some() {
                StoreError::StaleGeneration
            } else {
                StoreError::ResourceNotFound
            });
        }
        sqlx::query("SELECT e.id FROM canonical_endpoints e JOIN canonical_policy_attachments a ON a.endpoint_id=e.id WHERE a.policy_id=$1 AND a.state='active' ORDER BY e.id FOR UPDATE OF e")
            .bind(p.id.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let incompatible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM canonical_policy_attachments a JOIN canonical_policy_attachments other ON other.endpoint_id=a.endpoint_id AND other.policy_id<>a.policy_id AND other.state='active' JOIN canonical_reusable_network_policies other_policy ON other_policy.id=other.policy_id WHERE a.policy_id=$1 AND a.state='active' AND other_policy.unmatched_action<>$2")
            .bind(p.id.to_string()).bind(&p.unmatched_action).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
        if incompatible != 0 {
            return Err(StoreError::PolicyCompositionConflict);
        }
        let r=sqlx::query("UPDATE canonical_reusable_network_policies SET name=$1,description=$2,stateful_mode=$3,unmatched_action=$4,generation=$5,updated_at=$6 WHERE id=$7 AND project_id=$8 AND generation=$9 AND state=$10").bind(&p.name).bind(&p.description).bind(&p.stateful_mode).bind(&p.unmatched_action).bind(g).bind(&p.updated_at).bind(p.id.to_string()).bind(&p.project_id).bind(checked_generation(expected)?).bind(&p.state).execute(&mut *tx).await.map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)?;
        if r.rows_affected() == 0 {
            return match self.get_reusable_policy(&p.project_id, &p.id).await? {
                Some(_) => Err(StoreError::StaleGeneration),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        self.get_reusable_policy(&p.project_id, &p.id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }
    pub async fn transition_reusable_policy_state(
        &self,
        project: &str,
        id: &Uuid,
        expected: u64,
        state: &str,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
        validate_canonical_state(state)?;
        let query = match state {
            "active" => {
                "UPDATE canonical_reusable_network_policies SET state=$1, generation=generation+1, updated_at=updated_at WHERE id=$2 AND project_id=$3 AND generation=$4 AND state='requested'"
            }
            "deleting" => {
                "UPDATE canonical_reusable_network_policies SET state=$1, generation=generation+1, updated_at=updated_at WHERE id=$2 AND project_id=$3 AND generation=$4 AND state IN ('requested','active','error') AND NOT EXISTS (SELECT 1 FROM canonical_network_policy_rules WHERE policy_id=$2 AND state IN ('requested','active','deleting')) AND NOT EXISTS (SELECT 1 FROM canonical_policy_attachments WHERE policy_id=$2 AND state IN ('requested','active','deleting'))"
            }
            "deleted" => {
                "UPDATE canonical_reusable_network_policies SET state=$1, generation=generation+1, updated_at=updated_at WHERE id=$2 AND project_id=$3 AND generation=$4 AND state='deleting' AND NOT EXISTS (SELECT 1 FROM canonical_network_policy_rules WHERE policy_id=$2 AND state IN ('requested','active','deleting')) AND NOT EXISTS (SELECT 1 FROM canonical_policy_attachments WHERE policy_id=$2 AND state IN ('requested','active','deleting'))"
            }
            "error" => {
                "UPDATE canonical_reusable_network_policies SET state=$1, generation=generation+1, updated_at=updated_at WHERE id=$2 AND project_id=$3 AND generation=$4 AND state IN ('requested','active','deleting')"
            }
            "requested" => {
                "UPDATE canonical_reusable_network_policies SET state=$1, generation=generation+1, updated_at=updated_at WHERE id=$2 AND project_id=$3 AND generation=$4 AND state='__invalid_requested_transition__'"
            }
            _ => unreachable!(),
        };
        let result = sqlx::query(query)
            .bind(state)
            .bind(id.to_string())
            .bind(project)
            .bind(checked_generation(expected)?)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            if matches!(state, "deleting" | "deleted")
                && let Some(current) = self.get_reusable_policy(project, id).await?
            {
                if current.generation != expected {
                    return Err(StoreError::StaleGeneration);
                }
                let children: i64 = sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM canonical_network_policy_rules WHERE policy_id=$1 AND state IN ('requested','active','deleting')) + (SELECT COUNT(*) FROM canonical_policy_attachments WHERE policy_id=$1 AND state IN ('requested','active','deleting'))")
                    .bind(id.to_string()).fetch_one(&self.pool).await.map_err(StoreError::Database)?;
                if children > 0 {
                    return Err(StoreError::NetworkInUse);
                }
            }
            return match self.get_reusable_policy(project, id).await? {
                Some(_) => Err(StoreError::StaleGeneration),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        self.get_reusable_policy(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }
    pub async fn delete_reusable_policy(&self, project: &str, id: &Uuid) -> Result<(), StoreError> {
        let current = self
            .get_reusable_policy(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        let reserved = if current.state == "deleting" {
            current
        } else {
            self.transition_reusable_policy_state(project, id, current.generation, "deleting")
                .await?
        };
        let result = sqlx::query("DELETE FROM canonical_reusable_network_policies WHERE id=$1 AND project_id=$2 AND state='deleting' AND generation=$3 AND NOT EXISTS (SELECT 1 FROM canonical_network_policy_rules WHERE policy_id=$1 AND state IN ('requested','active','deleting')) AND NOT EXISTS (SELECT 1 FROM canonical_policy_attachments WHERE policy_id=$1 AND state IN ('requested','active','deleting'))")
            .bind(id.to_string())
            .bind(project)
            .bind(checked_generation(reserved.generation)?)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            match self.get_reusable_policy(project, id).await? {
                Some(policy) if policy.generation != reserved.generation => {
                    Err(StoreError::StaleGeneration)
                }
                Some(_) => Err(StoreError::NetworkInUse),
                None => Err(StoreError::ResourceNotFound),
            }
        }
    }
    pub async fn insert_policy_rule(
        &self,
        r: &CanonicalNetworkPolicyRuleRecord,
    ) -> Result<(), StoreError> {
        let generation = validate_rule(r)?;
        validate_child_insert_state(&r.state)?;
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let p = sqlx::query(
            "SELECT project_id,state,unmatched_action FROM canonical_reusable_network_policies WHERE id=$1 FOR UPDATE",
        )
        .bind(r.policy_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        .ok_or(StoreError::ResourceNotFound)?;
        if p.get::<String, _>("project_id") != r.project_id
            || p.get::<String, _>("state") != "active"
        {
            return Err(StoreError::OwnershipConflict);
        }
        sqlx::query("INSERT INTO canonical_network_policy_rules (id,policy_id,project_id,direction,address_family,protocol,port_min,port_max,remote_selector,action,state,generation,enforcement_key) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CAST($9 AS cidr),$10,$11,$12,$13)").bind(r.id.to_string()).bind(r.policy_id.to_string()).bind(&r.project_id).bind(&r.direction).bind(&r.address_family).bind(&r.protocol).bind(r.port_min.map(i32::from)).bind(r.port_max.map(i32::from)).bind(&r.remote_selector).bind(&r.action).bind(&r.state).bind(generation).bind(&r.enforcement_key).execute(&mut *tx).await.map_err(map_canonical_insert_error)?;
        tx.commit().await.map_err(StoreError::Database)
    }
    pub async fn get_policy_rule(
        &self,
        project: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        sqlx::query("SELECT id,policy_id,project_id,direction,address_family,protocol,port_min,port_max,remote_selector::text AS remote_selector,action,state,generation,enforcement_key FROM canonical_network_policy_rules WHERE id=$1 AND project_id=$2").bind(id.to_string()).bind(project).fetch_optional(&self.pool).await.map_err(StoreError::Database)?.as_ref().map(pg_rule).transpose()
    }
    pub async fn list_policy_rules(
        &self,
        project: &str,
        policy: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        let r=sqlx::query("SELECT id,policy_id,project_id,direction,address_family,protocol,port_min,port_max,remote_selector::text AS remote_selector,action,state,generation,enforcement_key FROM canonical_network_policy_rules WHERE policy_id=$1 AND project_id=$2 ORDER BY id").bind(policy.to_string()).bind(project).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        r.iter().map(pg_rule).collect()
    }
    pub async fn list_deleting_policy_rules(
        &self,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        let r = sqlx::query("SELECT id,policy_id,project_id,direction,address_family,protocol,port_min,port_max,remote_selector::text AS remote_selector,action,state,generation,enforcement_key FROM canonical_network_policy_rules WHERE state='deleting' ORDER BY project_id,id")
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        r.iter().map(pg_rule).collect()
    }
    pub async fn begin_policy_rule_deletion(
        &self,
        project: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<CanonicalNetworkPolicyRuleRecord, StoreError> {
        let result = sqlx::query("UPDATE canonical_network_policy_rules SET state='deleting', generation=generation+1 WHERE id=$1 AND project_id=$2 AND state='active' AND generation=$3")
            .bind(id.to_string()).bind(project).bind(checked_generation(expected)?).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_policy_rule(project, id).await? {
                Some(rule) if rule.generation != expected => Err(StoreError::StaleGeneration),
                Some(_) => Err(StoreError::Corrupt("policy rule is not active".into())),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        self.get_policy_rule(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }
    pub async fn finalize_policy_rule_deletion(
        &self,
        project: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM canonical_network_policy_rules WHERE id=$1 AND project_id=$2 AND state='deleting' AND generation=$3")
            .bind(id.to_string()).bind(project).bind(checked_generation(expected)?).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        match self.get_policy_rule(project, id).await? {
            Some(rule) if rule.generation != expected => Err(StoreError::StaleGeneration),
            Some(_) => Err(StoreError::Corrupt(
                "policy rule is not deletion-reserved".into(),
            )),
            None => Err(StoreError::ResourceNotFound),
        }
    }
    pub async fn delete_policy_rule(&self, project: &str, id: &Uuid) -> Result<(), StoreError> {
        let current = self
            .get_policy_rule(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        let reserved = self
            .begin_policy_rule_deletion(project, id, current.generation)
            .await?;
        self.finalize_policy_rule_deletion(project, id, reserved.generation)
            .await
    }
    pub async fn insert_policy_attachment(
        &self,
        a: &CanonicalPolicyAttachmentRecord,
    ) -> Result<(), StoreError> {
        let generation = validate_attachment(a)?;
        validate_child_insert_state(&a.state)?;
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let p = sqlx::query(
            "SELECT project_id,state,unmatched_action FROM canonical_reusable_network_policies WHERE id=$1 FOR UPDATE",
        )
        .bind(a.policy_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        .ok_or(StoreError::ResourceNotFound)?;
        if p.get::<String, _>("project_id") != a.project_id
            || p.get::<String, _>("state") != "active"
        {
            return Err(StoreError::OwnershipConflict);
        }
        let e = sqlx::query("SELECT project_id FROM canonical_endpoints WHERE id=$1 FOR UPDATE")
            .bind(a.endpoint_id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?;
        if e.get::<String, _>("project_id") != a.project_id {
            return Err(StoreError::OwnershipConflict);
        }
        let incompatible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM canonical_policy_attachments a JOIN canonical_reusable_network_policies existing ON existing.id=a.policy_id WHERE a.endpoint_id=$1 AND a.state='active' AND existing.unmatched_action <> $2")
            .bind(a.endpoint_id.to_string())
            .bind(p.get::<String, _>("unmatched_action"))
            .fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
        if incompatible != 0 {
            return Err(StoreError::PolicyCompositionConflict);
        }
        sqlx::query("INSERT INTO canonical_policy_attachments (id,policy_id,endpoint_id,project_id,state,generation) VALUES ($1,$2,$3,$4,$5,$6)").bind(a.id.to_string()).bind(a.policy_id.to_string()).bind(a.endpoint_id.to_string()).bind(&a.project_id).bind(&a.state).bind(generation).execute(&mut *tx).await.map_err(map_canonical_insert_error)?;
        tx.commit().await.map_err(StoreError::Database)
    }
    pub async fn get_policy_attachment(
        &self,
        project: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalPolicyAttachmentRecord>, StoreError> {
        sqlx::query(&format!("SELECT {ATTACHMENT_COLUMNS} FROM canonical_policy_attachments WHERE id=$1 AND project_id=$2")).bind(id.to_string()).bind(project).fetch_optional(&self.pool).await.map_err(StoreError::Database)?.as_ref().map(pg_attachment).transpose()
    }
    pub async fn list_policy_attachments(
        &self,
        project: &str,
        policy: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        let r=sqlx::query(&format!("SELECT {ATTACHMENT_COLUMNS} FROM canonical_policy_attachments WHERE policy_id=$1 AND project_id=$2 ORDER BY id")).bind(policy.to_string()).bind(project).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        r.iter().map(pg_attachment).collect()
    }
    pub async fn list_endpoint_policy_attachments(
        &self,
        project: &str,
        endpoint: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        let r=sqlx::query(&format!("SELECT {ATTACHMENT_COLUMNS} FROM canonical_policy_attachments WHERE endpoint_id=$1 AND project_id=$2 ORDER BY id")).bind(endpoint.to_string()).bind(project).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        r.iter().map(pg_attachment).collect()
    }
    pub async fn list_deleting_policy_attachments(
        &self,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        let r = sqlx::query(&format!(
            "SELECT {ATTACHMENT_COLUMNS} FROM canonical_policy_attachments WHERE state='deleting' ORDER BY project_id,id"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        r.iter().map(pg_attachment).collect()
    }
    pub async fn replace_policy_attachment_set(
        &self,
        project: &str,
        endpoint: &Uuid,
        policy_ids: &[Uuid],
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let endpoint_row =
            sqlx::query("SELECT project_id FROM canonical_endpoints WHERE id=$1 FOR UPDATE")
                .bind(endpoint.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?
                .ok_or(StoreError::ResourceNotFound)?;
        if endpoint_row.get::<String, _>("project_id") != project {
            return Err(StoreError::OwnershipConflict);
        }
        let existing = sqlx::query(&format!(
            "SELECT {ATTACHMENT_COLUMNS} FROM canonical_policy_attachments WHERE endpoint_id=$1 AND project_id=$2 ORDER BY id"
        ))
        .bind(endpoint.to_string())
        .bind(project)
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        let existing = existing
            .iter()
            .map(pg_attachment)
            .collect::<Result<Vec<_>, _>>()?;
        let requested = policy_ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let mut default_value = None;
        for policy_id in &requested {
            let policy = sqlx::query("SELECT project_id,state,unmatched_action FROM canonical_reusable_network_policies WHERE id=$1 FOR UPDATE")
                .bind(policy_id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?
                .ok_or(StoreError::ResourceNotFound)?;
            if policy.get::<String, _>("project_id") != project
                || policy.get::<String, _>("state") != "active"
            {
                return Err(StoreError::OwnershipConflict);
            }
            let value = policy.get::<String, _>("unmatched_action");
            if let Some(previous) = &default_value {
                if previous != &value {
                    return Err(StoreError::PolicyCompositionConflict);
                }
            } else {
                default_value = Some(value);
            }
        }
        let mut deleting = Vec::new();
        for attachment in &existing {
            if attachment.state == "active" && !requested.contains(&attachment.policy_id) {
                sqlx::query("UPDATE canonical_policy_attachments SET state='deleting', generation=generation+1 WHERE id=$1 AND state='active' AND generation=$2")
                    .bind(attachment.id.to_string())
                    .bind(checked_generation(attachment.generation)?)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                deleting.push(CanonicalPolicyAttachmentRecord {
                    state: "deleting".to_owned(),
                    generation: attachment.generation.saturating_add(1),
                    ..attachment.clone()
                });
            } else if attachment.state == "deleting" && requested.contains(&attachment.policy_id) {
                return Err(StoreError::OwnershipConflict);
            }
        }
        for policy_id in requested {
            if existing
                .iter()
                .any(|attachment| attachment.policy_id == policy_id && attachment.state == "active")
            {
                continue;
            }
            let attachment = CanonicalPolicyAttachmentRecord {
                id: Uuid::now_v7(),
                policy_id,
                endpoint_id: *endpoint,
                project_id: project.to_owned(),
                state: "active".to_owned(),
                generation: 1,
            };
            sqlx::query("INSERT INTO canonical_policy_attachments (id,policy_id,endpoint_id,project_id,state,generation) VALUES ($1,$2,$3,$4,$5,$6)")
                .bind(attachment.id.to_string())
                .bind(attachment.policy_id.to_string())
                .bind(attachment.endpoint_id.to_string())
                .bind(project)
                .bind("active")
                .bind(1_i32)
                .execute(&mut *tx)
                .await
                .map_err(map_canonical_insert_error)?;
        }
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(deleting)
    }
    pub async fn begin_policy_attachment_deletion(
        &self,
        project: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<CanonicalPolicyAttachmentRecord, StoreError> {
        let result = sqlx::query("UPDATE canonical_policy_attachments SET state='deleting', generation=generation+1 WHERE id=$1 AND project_id=$2 AND state='active' AND generation=$3")
            .bind(id.to_string()).bind(project).bind(checked_generation(expected)?).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_policy_attachment(project, id).await? {
                Some(attachment) if attachment.generation != expected => {
                    Err(StoreError::StaleGeneration)
                }
                Some(_) => Err(StoreError::Corrupt(
                    "policy attachment is not active".into(),
                )),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        self.get_policy_attachment(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }
    pub async fn finalize_policy_attachment_deletion(
        &self,
        project: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM canonical_policy_attachments WHERE id=$1 AND project_id=$2 AND state='deleting' AND generation=$3")
            .bind(id.to_string()).bind(project).bind(checked_generation(expected)?).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        match self.get_policy_attachment(project, id).await? {
            Some(attachment) if attachment.generation != expected => {
                Err(StoreError::StaleGeneration)
            }
            Some(_) => Err(StoreError::Corrupt(
                "policy attachment is not deletion-reserved".into(),
            )),
            None => Err(StoreError::ResourceNotFound),
        }
    }
    pub async fn delete_policy_attachment(
        &self,
        project: &str,
        id: &Uuid,
    ) -> Result<(), StoreError> {
        let current = self
            .get_policy_attachment(project, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        let reserved = self
            .begin_policy_attachment_deletion(project, id, current.generation)
            .await?;
        self.finalize_policy_attachment_deletion(project, id, reserved.generation)
            .await
    }

    pub async fn upsert_policy_realization(
        &self,
        r: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError> {
        if r.endpoint_id.is_nil()
            || r.project_id.trim().is_empty()
            || r.desired_fingerprint.is_empty()
            || r.desired_generation == 0
            || !matches!(
                r.state.as_str(),
                "pending" | "applying" | "realized" | "failed" | "unknown"
            )
        {
            return Err(StoreError::Corrupt("invalid policy realization".into()));
        }
        sqlx::query("INSERT INTO canonical_policy_realizations (endpoint_id, project_id, attempt_id, desired_fingerprint, desired_generation, observed_fingerprint, observed_generation, state, provider_resource_id, last_outcome) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT(endpoint_id) DO UPDATE SET project_id=excluded.project_id, attempt_id=excluded.attempt_id, desired_fingerprint=excluded.desired_fingerprint, desired_generation=excluded.desired_generation, observed_fingerprint=excluded.observed_fingerprint, observed_generation=excluded.observed_generation, state=excluded.state, provider_resource_id=excluded.provider_resource_id, last_outcome=excluded.last_outcome")
            .bind(r.endpoint_id.to_string()).bind(&r.project_id).bind(r.attempt_id.to_string()).bind(&r.desired_fingerprint).bind(checked_generation(r.desired_generation)?)
            .bind(&r.observed_fingerprint).bind(r.observed_generation.map(checked_generation).transpose()?).bind(&r.state).bind(&r.provider_resource_id).bind(&r.last_outcome)
            .execute(&self.pool).await.map_err(StoreError::Database).map(|_| ())
    }
    pub async fn get_policy_realization(
        &self,
        project: &str,
        endpoint: &Uuid,
    ) -> Result<Option<CanonicalPolicyRealizationRecord>, StoreError> {
        sqlx::query(&format!("SELECT {REALIZATION_COLUMNS} FROM canonical_policy_realizations WHERE endpoint_id=$1 AND project_id=$2"))
            .bind(endpoint.to_string()).bind(project).fetch_optional(&self.pool).await.map_err(StoreError::Database)?.as_ref().map(pg_realization).transpose()
    }
    pub async fn list_policy_realizations(
        &self,
        project: &str,
    ) -> Result<Vec<CanonicalPolicyRealizationRecord>, StoreError> {
        let rows = sqlx::query(&format!("SELECT {REALIZATION_COLUMNS} FROM canonical_policy_realizations WHERE project_id=$1 ORDER BY endpoint_id")).bind(project).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.iter().map(pg_realization).collect()
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn set_policy_realization_outcome(
        &self,
        project: &str,
        endpoint: &Uuid,
        expected: &str,
        expected_attempt_id: &Uuid,
        state: &str,
        observed: Option<&str>,
        observed_generation: Option<u64>,
        provider_resource_id: Option<&str>,
        last_outcome: Option<&str>,
    ) -> Result<(), StoreError> {
        if !matches!(
            state,
            "pending" | "applying" | "realized" | "failed" | "unknown"
        ) {
            return Err(StoreError::Corrupt(
                "invalid policy realization state".into(),
            ));
        }
        let result = sqlx::query("UPDATE canonical_policy_realizations SET observed_fingerprint=$1, observed_generation=$2, state=$3, provider_resource_id=$4, last_outcome=$5 WHERE endpoint_id=$6 AND project_id=$7 AND desired_fingerprint=$8 AND attempt_id=$9")
            .bind(observed).bind(observed_generation.map(checked_generation).transpose()?).bind(state).bind(provider_resource_id).bind(last_outcome)
            .bind(endpoint.to_string()).bind(project).bind(expected).bind(expected_attempt_id.to_string()).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(StoreError::StaleGeneration)
        }
    }

    pub async fn requeue_policy_realization(
        &self,
        expected_attempt_id: &Uuid,
        r: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError> {
        let result = sqlx::query("UPDATE canonical_policy_realizations SET attempt_id=$1, desired_fingerprint=$2, desired_generation=$3, observed_fingerprint=$4, observed_generation=$5, state=$6, provider_resource_id=$7, last_outcome=$8 WHERE endpoint_id=$9 AND project_id=$10 AND attempt_id=$11")
            .bind(r.attempt_id.to_string()).bind(&r.desired_fingerprint).bind(checked_generation(r.desired_generation)?)
            .bind(&r.observed_fingerprint).bind(r.observed_generation.map(checked_generation).transpose()?).bind(&r.state).bind(&r.provider_resource_id).bind(&r.last_outcome)
            .bind(r.endpoint_id.to_string()).bind(&r.project_id).bind(expected_attempt_id.to_string()).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(StoreError::StaleGeneration)
        }
    }
}

#[async_trait]
impl CanonicalPolicyRepository for crate::PostgresStore {
    async fn insert_reusable_policy(
        &self,
        p: &CanonicalReusableNetworkPolicyRecord,
    ) -> Result<(), StoreError> {
        self.insert_reusable_policy(p).await
    }
    async fn get_reusable_policy(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Option<CanonicalReusableNetworkPolicyRecord>, StoreError> {
        self.get_reusable_policy(p, i).await
    }
    async fn list_reusable_policies(
        &self,
        p: &str,
    ) -> Result<Vec<CanonicalReusableNetworkPolicyRecord>, StoreError> {
        self.list_reusable_policies(p).await
    }
    async fn update_reusable_policy(
        &self,
        p: &CanonicalReusableNetworkPolicyRecord,
        g: u64,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
        self.update_reusable_policy(p, g).await
    }
    async fn transition_reusable_policy_state(
        &self,
        p: &str,
        i: &Uuid,
        g: u64,
        s: &str,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
        self.transition_reusable_policy_state(p, i, g, s).await
    }
    async fn delete_reusable_policy(&self, p: &str, i: &Uuid) -> Result<(), StoreError> {
        self.delete_reusable_policy(p, i).await
    }
    async fn insert_policy_rule(
        &self,
        r: &CanonicalNetworkPolicyRuleRecord,
    ) -> Result<(), StoreError> {
        self.insert_policy_rule(r).await
    }
    async fn get_policy_rule(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Option<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        self.get_policy_rule(p, i).await
    }
    async fn list_policy_rules(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        self.list_policy_rules(p, i).await
    }
    async fn list_deleting_policy_rules(
        &self,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        self.list_deleting_policy_rules().await
    }
    async fn begin_policy_rule_deletion(
        &self,
        p: &str,
        i: &Uuid,
        g: u64,
    ) -> Result<CanonicalNetworkPolicyRuleRecord, StoreError> {
        self.begin_policy_rule_deletion(p, i, g).await
    }
    async fn finalize_policy_rule_deletion(
        &self,
        p: &str,
        i: &Uuid,
        g: u64,
    ) -> Result<(), StoreError> {
        self.finalize_policy_rule_deletion(p, i, g).await
    }
    async fn delete_policy_rule(&self, p: &str, i: &Uuid) -> Result<(), StoreError> {
        self.delete_policy_rule(p, i).await
    }
    async fn insert_policy_attachment(
        &self,
        a: &CanonicalPolicyAttachmentRecord,
    ) -> Result<(), StoreError> {
        self.insert_policy_attachment(a).await
    }
    async fn get_policy_attachment(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Option<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.get_policy_attachment(p, i).await
    }
    async fn list_policy_attachments(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.list_policy_attachments(p, i).await
    }
    async fn list_endpoint_policy_attachments(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.list_endpoint_policy_attachments(p, i).await
    }
    async fn list_deleting_policy_attachments(
        &self,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.list_deleting_policy_attachments().await
    }
    async fn replace_policy_attachment_set(
        &self,
        p: &str,
        i: &Uuid,
        policy_ids: &[Uuid],
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.replace_policy_attachment_set(p, i, policy_ids).await
    }
    async fn begin_policy_attachment_deletion(
        &self,
        p: &str,
        i: &Uuid,
        g: u64,
    ) -> Result<CanonicalPolicyAttachmentRecord, StoreError> {
        self.begin_policy_attachment_deletion(p, i, g).await
    }
    async fn finalize_policy_attachment_deletion(
        &self,
        p: &str,
        i: &Uuid,
        g: u64,
    ) -> Result<(), StoreError> {
        self.finalize_policy_attachment_deletion(p, i, g).await
    }
    async fn delete_policy_attachment(&self, p: &str, i: &Uuid) -> Result<(), StoreError> {
        self.delete_policy_attachment(p, i).await
    }
    async fn upsert_policy_realization(
        &self,
        r: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError> {
        self.upsert_policy_realization(r).await
    }
    async fn get_policy_realization(
        &self,
        p: &str,
        i: &Uuid,
    ) -> Result<Option<CanonicalPolicyRealizationRecord>, StoreError> {
        self.get_policy_realization(p, i).await
    }
    async fn list_policy_realizations(
        &self,
        p: &str,
    ) -> Result<Vec<CanonicalPolicyRealizationRecord>, StoreError> {
        self.list_policy_realizations(p).await
    }
    async fn set_policy_realization_outcome(
        &self,
        p: &str,
        e: &Uuid,
        f: &str,
        a: &Uuid,
        s: &str,
        o: Option<&str>,
        g: Option<u64>,
        r: Option<&str>,
        l: Option<&str>,
    ) -> Result<(), StoreError> {
        self.set_policy_realization_outcome(p, e, f, a, s, o, g, r, l)
            .await
    }
    async fn requeue_policy_realization(
        &self,
        a: &Uuid,
        r: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError> {
        self.requeue_policy_realization(a, r).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteStore;

    fn policy(id: Uuid, action: &str) -> CanonicalReusableNetworkPolicyRecord {
        CanonicalReusableNetworkPolicyRecord {
            id,
            project_id: "project-a".into(),
            name: "policy".into(),
            description: "test".into(),
            stateful_mode: "Stateful".into(),
            unmatched_action: action.into(),
            generation: 1,
            state: "active".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn rule(id: Uuid, policy_id: Uuid) -> CanonicalNetworkPolicyRuleRecord {
        let mut r = CanonicalNetworkPolicyRuleRecord {
            id,
            policy_id,
            project_id: "project-a".into(),
            direction: "Ingress".into(),
            address_family: "Ipv4".into(),
            protocol: "Tcp".into(),
            port_min: Some(443),
            port_max: Some(443),
            remote_selector: Some("198.51.100.0/24".into()),
            action: "Allow".into(),
            state: "active".into(),
            generation: 1,
            enforcement_key: String::new(),
        };
        r.enforcement_key = format!(
            "{}|{}|{}|443-443|198.51.100.0/24|{}",
            r.direction, r.address_family, r.protocol, r.action
        );
        r
    }

    async fn endpoint_fixture(store: &SqliteStore, endpoint: Uuid) -> Result<(), StoreError> {
        let network = Uuid::from_u128(10);
        let realm = Uuid::from_u128(11);
        sqlx::query("INSERT INTO canonical_networks (id,project_id,name,generation,state) VALUES (?,?,?,?,?)").bind(network.to_string()).bind("project-a").bind("network").bind(1_i64).bind("active").execute(&store.pool).await.map_err(StoreError::Database)?;
        sqlx::query("INSERT INTO canonical_address_realms (id,network_id,project_id,prefix,overlapping_prefixes,generation,state) VALUES (?,?,?,?,?,?,?)").bind(realm.to_string()).bind(network.to_string()).bind("project-a").bind("10.0.0.0/24").bind(0_i64).bind(1_i64).bind("active").execute(&store.pool).await.map_err(StoreError::Database)?;
        sqlx::query("INSERT INTO canonical_endpoints (id,realm_id,project_id,fixed_ip,mac,generation,state) VALUES (?,?,?,?,?,?,?)").bind(endpoint.to_string()).bind(realm.to_string()).bind("project-a").bind("10.0.0.10").bind("02:00:00:00:00:10").bind(1_i64).bind("active").execute(&store.pool).await.map_err(StoreError::Database)?;
        Ok(())
    }

    #[tokio::test]
    async fn detached_policy_rules_and_attachment_survive_reopen() -> Result<(), StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let policy_id = Uuid::from_u128(1);
        let rule_id = Uuid::from_u128(2);
        let endpoint_id = Uuid::from_u128(3);
        let attachment_id = Uuid::from_u128(4);
        store
            .insert_reusable_policy(&policy(policy_id, "Deny"))
            .await?;
        assert!(
            store
                .list_policy_attachments("project-a", &policy_id)
                .await?
                .is_empty()
        );
        store.insert_policy_rule(&rule(rule_id, policy_id)).await?;
        endpoint_fixture(&store, endpoint_id).await?;
        let attachment = CanonicalPolicyAttachmentRecord {
            id: attachment_id,
            policy_id,
            endpoint_id,
            project_id: "project-a".into(),
            state: "active".into(),
            generation: 1,
        };
        store.insert_policy_attachment(&attachment).await?;
        let loaded_policy = store
            .get_reusable_policy("project-a", &policy_id)
            .await?
            .ok_or(StoreError::Corrupt("policy missing after insert".into()))?;
        assert_eq!(loaded_policy.unmatched_action, "Deny");
        assert_eq!(
            store
                .get_policy_rule("project-a", &rule_id)
                .await?
                .ok_or(StoreError::Corrupt("rule missing after insert".into()))?
                .id,
            rule_id
        );
        assert_eq!(
            store
                .get_policy_attachment("project-a", &attachment_id)
                .await?
                .ok_or(StoreError::Corrupt(
                    "attachment missing after insert".into()
                ))?
                .id,
            attachment_id
        );
        assert!(matches!(
            store.delete_reusable_policy("project-a", &policy_id).await,
            Err(StoreError::NetworkInUse)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn endpoint_realization_truth_round_trips_and_is_overwritable() -> Result<(), StoreError>
    {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let endpoint = Uuid::from_u128(31);
        endpoint_fixture(&store, endpoint).await?;
        let first = CanonicalPolicyRealizationRecord {
            endpoint_id: endpoint,
            project_id: "project-a".into(),
            attempt_id: Uuid::from_u128(301),
            desired_fingerprint: "sha256:first".into(),
            desired_generation: 2,
            observed_fingerprint: None,
            observed_generation: None,
            state: "unknown".into(),
            provider_resource_id: None,
            last_outcome: Some("timeout".into()),
        };
        store.upsert_policy_realization(&first).await?;
        assert_eq!(
            store.get_policy_realization("project-a", &endpoint).await?,
            Some(first.clone())
        );
        let realized = CanonicalPolicyRealizationRecord {
            observed_fingerprint: Some(first.desired_fingerprint.clone()),
            observed_generation: Some(first.desired_generation),
            state: "realized".into(),
            last_outcome: Some("observed".into()),
            ..first
        };
        store.upsert_policy_realization(&realized).await?;
        assert_eq!(
            store.list_policy_realizations("project-a").await?.first(),
            Some(&realized)
        );
        Ok(())
    }

    #[tokio::test]
    async fn realization_outcome_is_fenced_by_attempt_id() -> Result<(), StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let endpoint = Uuid::from_u128(32);
        endpoint_fixture(&store, endpoint).await?;
        let first = CanonicalPolicyRealizationRecord {
            endpoint_id: endpoint,
            project_id: "project-a".into(),
            attempt_id: Uuid::from_u128(303),
            desired_fingerprint: "sha256:same-desired".into(),
            desired_generation: 2,
            observed_fingerprint: None,
            observed_generation: None,
            state: "applying".into(),
            provider_resource_id: None,
            last_outcome: None,
        };
        store.upsert_policy_realization(&first).await?;
        let second = CanonicalPolicyRealizationRecord {
            attempt_id: Uuid::from_u128(304),
            ..first.clone()
        };
        store.upsert_policy_realization(&second).await?;
        assert!(matches!(
            store
                .set_policy_realization_outcome(
                    "project-a",
                    &endpoint,
                    &first.desired_fingerprint,
                    &first.attempt_id,
                    "realized",
                    Some(&first.desired_fingerprint),
                    Some(first.desired_generation),
                    None,
                    Some("late worker"),
                )
                .await,
            Err(StoreError::StaleGeneration)
        ));
        let Some(current) = store.get_policy_realization("project-a", &endpoint).await? else {
            return Err(StoreError::Corrupt("realization disappeared".into()));
        };
        assert_eq!(current.attempt_id, second.attempt_id);
        assert_eq!(current.state, "applying");
        Ok(())
    }

    #[tokio::test]
    async fn active_semantic_duplicates_and_mixed_defaults_are_rejected() -> Result<(), StoreError>
    {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let policy_id = Uuid::from_u128(20);
        store
            .insert_reusable_policy(&policy(policy_id, "Allow"))
            .await?;
        store
            .insert_policy_rule(&rule(Uuid::from_u128(21), policy_id))
            .await?;
        assert!(matches!(
            store
                .insert_policy_rule(&rule(Uuid::from_u128(22), policy_id))
                .await,
            Err(StoreError::ResourceAlreadyExists)
        ));
        endpoint_fixture(&store, Uuid::from_u128(23)).await?;
        store
            .insert_policy_attachment(&CanonicalPolicyAttachmentRecord {
                id: Uuid::from_u128(24),
                policy_id,
                endpoint_id: Uuid::from_u128(23),
                project_id: "project-a".into(),
                state: "active".into(),
                generation: 1,
            })
            .await?;
        let other = Uuid::from_u128(25);
        store.insert_reusable_policy(&policy(other, "Deny")).await?;
        assert!(matches!(
            store
                .insert_policy_attachment(&CanonicalPolicyAttachmentRecord {
                    id: Uuid::from_u128(26),
                    policy_id: other,
                    endpoint_id: Uuid::from_u128(23),
                    project_id: "project-a".into(),
                    state: "active".into(),
                    generation: 1
                })
                .await,
            Err(StoreError::PolicyCompositionConflict)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn durable_uniqueness_wins_for_concurrent_rule_and_attachment_creates()
    -> Result<(), StoreError> {
        let path = std::env::temp_dir().join(format!("o3k-policy-{}.sqlite", Uuid::now_v7()));
        let store = SqliteStore::connect_file(&path).await?;
        let policy_id = Uuid::from_u128(30);
        store
            .insert_reusable_policy(&policy(policy_id, "Allow"))
            .await?;
        endpoint_fixture(&store, Uuid::from_u128(31)).await?;
        let first = rule(Uuid::from_u128(32), policy_id);
        let mut second = first.clone();
        second.id = Uuid::from_u128(33);
        let (a, b) = tokio::join!(
            store.insert_policy_rule(&first),
            store.insert_policy_rule(&second)
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert!(matches!(
            &a,
            Ok(()) | Err(StoreError::ResourceAlreadyExists)
        ));
        assert!(matches!(
            &b,
            Ok(()) | Err(StoreError::ResourceAlreadyExists)
        ));
        assert!(
            a.is_ok() ^ b.is_ok(),
            "exactly one rule create must win: {a:?}, {b:?}"
        );
        let attachment_a = CanonicalPolicyAttachmentRecord {
            id: Uuid::from_u128(34),
            policy_id,
            endpoint_id: Uuid::from_u128(31),
            project_id: "project-a".into(),
            state: "active".into(),
            generation: 1,
        };
        let mut attachment_b = attachment_a.clone();
        attachment_b.id = Uuid::from_u128(35);
        let (a, b) = tokio::join!(
            store.insert_policy_attachment(&attachment_a),
            store.insert_policy_attachment(&attachment_b)
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert!(matches!(
            &a,
            Ok(()) | Err(StoreError::ResourceAlreadyExists)
        ));
        assert!(matches!(
            &b,
            Ok(()) | Err(StoreError::ResourceAlreadyExists)
        ));
        assert!(
            a.is_ok() ^ b.is_ok(),
            "exactly one attachment create must win: {a:?}, {b:?}"
        );
        assert_eq!(
            store
                .list_endpoint_policy_attachments("project-a", &Uuid::from_u128(31))
                .await?
                .len(),
            1
        );
        drop(store);
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_writer_contention_waits_before_rule_validation() -> Result<(), StoreError> {
        let path =
            std::env::temp_dir().join(format!("o3k-policy-contention-{}.sqlite", Uuid::now_v7()));
        let store = SqliteStore::connect_file(&path).await?;
        let policy_id = Uuid::from_u128(36);
        store
            .insert_reusable_policy(&policy(policy_id, "Allow"))
            .await?;

        let mut holder = store.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *holder)
            .await
            .map_err(StoreError::Database)?;

        let contender_rule = rule(Uuid::from_u128(37), policy_id);
        let contender = store.insert_policy_rule(&contender_rule);
        let release = async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            sqlx::query("ROLLBACK")
                .execute(&mut *holder)
                .await
                .map_err(StoreError::Database)
        };
        let (result, released) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(contender, release)
        })
        .await
        .map_err(|_| StoreError::Database(sqlx::Error::PoolTimedOut))?;
        released?;
        result
    }

    #[tokio::test]
    async fn child_deletion_is_generation_fenced_and_survives_reopen() -> Result<(), StoreError> {
        let path =
            std::env::temp_dir().join(format!("o3k-policy-delete-{}.sqlite", Uuid::now_v7()));
        let store = SqliteStore::connect_file(&path).await?;
        let policy_id = Uuid::from_u128(40);
        let rule_id = Uuid::from_u128(41);
        let endpoint_id = Uuid::from_u128(42);
        let attachment_id = Uuid::from_u128(43);
        store
            .insert_reusable_policy(&policy(policy_id, "Allow"))
            .await?;
        store.insert_policy_rule(&rule(rule_id, policy_id)).await?;
        endpoint_fixture(&store, endpoint_id).await?;
        store
            .insert_policy_attachment(&CanonicalPolicyAttachmentRecord {
                id: attachment_id,
                policy_id,
                endpoint_id,
                project_id: "project-a".into(),
                state: "active".into(),
                generation: 1,
            })
            .await?;

        let deleting_rule = store
            .begin_policy_rule_deletion("project-a", &rule_id, 1)
            .await?;
        assert_eq!(deleting_rule.state, "deleting");
        assert_eq!(deleting_rule.generation, 2);
        assert!(matches!(
            store
                .begin_policy_rule_deletion("project-a", &rule_id, 1)
                .await,
            Err(StoreError::StaleGeneration)
        ));
        drop(store);

        let reopened = SqliteStore::connect_file(&path).await?;
        let reopened_rule = reopened
            .get_policy_rule("project-a", &rule_id)
            .await?
            .ok_or(StoreError::Corrupt("rule missing after reopen".into()))?;
        assert_eq!(reopened_rule.state, "deleting");
        assert!(matches!(
            reopened
                .finalize_policy_rule_deletion("project-a", &rule_id, 1)
                .await,
            Err(StoreError::StaleGeneration)
        ));
        reopened
            .finalize_policy_rule_deletion("project-a", &rule_id, 2)
            .await?;

        let deleting_attachment = reopened
            .begin_policy_attachment_deletion("project-a", &attachment_id, 1)
            .await?;
        assert_eq!(deleting_attachment.state, "deleting");
        assert_eq!(deleting_attachment.generation, 2);
        assert!(matches!(
            reopened
                .finalize_policy_attachment_deletion("project-a", &attachment_id, 1)
                .await,
            Err(StoreError::StaleGeneration)
        ));
        reopened
            .finalize_policy_attachment_deletion("project-a", &attachment_id, 2)
            .await?;
        assert!(
            reopened
                .get_policy_rule("project-a", &rule_id)
                .await?
                .is_none()
        );
        assert!(
            reopened
                .get_policy_attachment("project-a", &attachment_id)
                .await?
                .is_none()
        );
        std::fs::remove_file(path).map_err(|error| StoreError::Corrupt(error.to_string()))?;
        Ok(())
    }

    #[tokio::test]
    async fn deleting_policy_children_are_restart_inventory() -> Result<(), StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let policy_id = Uuid::from_u128(50);
        let rule_id = Uuid::from_u128(51);
        let endpoint_id = Uuid::from_u128(52);
        let attachment_id = Uuid::from_u128(53);
        store
            .insert_reusable_policy(&policy(policy_id, "Allow"))
            .await?;
        store.insert_policy_rule(&rule(rule_id, policy_id)).await?;
        endpoint_fixture(&store, endpoint_id).await?;
        store
            .insert_policy_attachment(&CanonicalPolicyAttachmentRecord {
                id: attachment_id,
                policy_id,
                endpoint_id,
                project_id: "project-a".into(),
                state: "active".into(),
                generation: 1,
            })
            .await?;

        store
            .begin_policy_rule_deletion("project-a", &rule_id, 1)
            .await?;
        store
            .begin_policy_attachment_deletion("project-a", &attachment_id, 1)
            .await?;
        let rules = store.list_deleting_policy_rules().await?;
        let attachments = store.list_deleting_policy_attachments().await?;
        assert_eq!(
            rules.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![rule_id]
        );
        assert_eq!(
            attachments.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![attachment_id]
        );
        assert_eq!(attachments[0].endpoint_id, endpoint_id);
        assert_eq!(attachments[0].policy_id, policy_id);
        Ok(())
    }

    #[tokio::test]
    async fn deleting_policy_fences_new_children() -> Result<(), StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let policy_id = Uuid::from_u128(50);
        store
            .insert_reusable_policy(&policy(policy_id, "Allow"))
            .await?;
        let updated = store
            .transition_reusable_policy_state("project-a", &policy_id, 1, "deleting")
            .await?;
        assert_eq!(updated.generation, 2);
        assert!(matches!(
            store
                .insert_policy_rule(&rule(Uuid::from_u128(51), policy_id))
                .await,
            Err(StoreError::OwnershipConflict)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn policy_state_changes_use_the_lifecycle_transition_path() -> Result<(), StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let policy_id = Uuid::from_u128(60);
        store
            .insert_reusable_policy(&policy(policy_id, "Allow"))
            .await?;
        store
            .insert_policy_rule(&rule(Uuid::from_u128(61), policy_id))
            .await?;

        let mut attempted_update = policy(policy_id, "Allow");
        attempted_update.generation = 2;
        attempted_update.state = "deleting".into();
        assert!(matches!(
            store.update_reusable_policy(&attempted_update, 1).await,
            Err(StoreError::StaleGeneration)
        ));
        assert!(matches!(
            store
                .transition_reusable_policy_state("project-a", &policy_id, 1, "deleted")
                .await,
            Err(StoreError::NetworkInUse)
        ));
        assert!(matches!(
            store
                .transition_reusable_policy_state("project-a", &policy_id, 1, "requested")
                .await,
            Err(StoreError::StaleGeneration)
        ));
        assert!(matches!(
            store
                .insert_policy_rule(&CanonicalNetworkPolicyRuleRecord {
                    id: Uuid::from_u128(62),
                    policy_id,
                    state: "deleted".into(),
                    ..rule(Uuid::from_u128(62), policy_id)
                })
                .await,
            Err(StoreError::Corrupt(_))
        ));
        let mut invalid_policy = policy(Uuid::from_u128(63), "Allow");
        invalid_policy.state = "deleted".into();
        assert!(matches!(
            store.insert_reusable_policy(&invalid_policy).await,
            Err(StoreError::Corrupt(_))
        ));

        let error_policy_id = Uuid::from_u128(64);
        let error_policy = policy(error_policy_id, "Allow");
        store.insert_reusable_policy(&error_policy).await?;
        store
            .transition_reusable_policy_state("project-a", &error_policy_id, 1, "error")
            .await?;
        store
            .transition_reusable_policy_state("project-a", &error_policy_id, 2, "deleting")
            .await?;
        store
            .delete_reusable_policy("project-a", &error_policy_id)
            .await?;
        Ok(())
    }
}
