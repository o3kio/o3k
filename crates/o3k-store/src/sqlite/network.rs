use super::{
    SqliteStore,
    helpers::{
        allocation_bounds, canonical_endpoint_from_row, canonical_network_from_row,
        canonical_policy_from_row, canonical_pool_from_row, canonical_realm_from_row,
        checked_generation, map_canonical_insert_error, network_allocation_from_row,
        network_from_row, network_intent_from_row, parse_ipv4_prefix, parse_uuid, port_from_row,
        security_group_binding_from_row, security_group_from_row, security_group_rule_from_row,
        subnet_from_row, validate_canonical_state, validate_ipv4_cidr, validate_network_intent,
        validate_network_intent_transition, validate_network_intent_update,
    },
};
use async_trait::async_trait;
use sqlx::Row;
use std::net::Ipv4Addr;
use std::time::Duration;
use uuid::Uuid;

use crate::{
    CanonicalAddressPoolRecord, CanonicalAddressRealmRecord, CanonicalEndpointRecord,
    CanonicalL3GatewayAttachmentRecord, CanonicalL3GatewayRecord, CanonicalNetworkPolicyRecord,
    CanonicalNetworkRecord, CanonicalRealmBindingRecord, FabricHostTransportIdentityRecord,
    NetworkAddressAllocationRecord, NetworkIntentRecord, NetworkRecord, NetworkRepository,
    PortRecord, SQLITE_BUSY_MAX_ATTEMPTS, SecurityGroupBindingRecord, SecurityGroupRecord,
    SecurityGroupRuleRecord, StoreError, SubnetRecord, is_sqlite_busy, legacy_policy_records,
};

impl SqliteStore {
    async fn read_fabric_host_identity(
        &self,
        host_id: &str,
    ) -> Result<Option<FabricHostTransportIdentityRecord>, StoreError> {
        let row = sqlx::query("SELECT host_id,agent_id,public_key,underlay_endpoint,fabric_transport_ip,provider_version,fabric_generation,underlay_mtu,fabric_mtu,administrative_state FROM canonical_fabric_host_transport_identities WHERE host_id=?")
            .bind(host_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        row.map(|row| {
            let generation: i64 = row
                .try_get("fabric_generation")
                .map_err(StoreError::Database)?;
            let underlay_mtu: i64 = row.try_get("underlay_mtu").map_err(StoreError::Database)?;
            let fabric_mtu: i64 = row.try_get("fabric_mtu").map_err(StoreError::Database)?;
            Ok(FabricHostTransportIdentityRecord {
                host_id: row.try_get("host_id").map_err(StoreError::Database)?,
                agent_id: row.try_get("agent_id").map_err(StoreError::Database)?,
                public_key: row.try_get("public_key").map_err(StoreError::Database)?,
                underlay_endpoint: row
                    .try_get("underlay_endpoint")
                    .map_err(StoreError::Database)?,
                fabric_transport_ip: row
                    .try_get::<String, _>("fabric_transport_ip")
                    .map_err(StoreError::Database)?
                    .parse()
                    .map_err(|_| {
                        StoreError::Corrupt("invalid Fabric transport address".to_owned())
                    })?,
                provider_version: row
                    .try_get("provider_version")
                    .map_err(StoreError::Database)?,
                fabric_generation: u64::try_from(generation)
                    .map_err(|_| StoreError::Corrupt("invalid Fabric generation".to_owned()))?,
                underlay_mtu: u16::try_from(underlay_mtu)
                    .map_err(|_| StoreError::Corrupt("invalid underlay MTU".to_owned()))?,
                fabric_mtu: u16::try_from(fabric_mtu)
                    .map_err(|_| StoreError::Corrupt("invalid Fabric MTU".to_owned()))?,
                administrative_state: row
                    .try_get("administrative_state")
                    .map_err(StoreError::Database)?,
            })
        })
        .transpose()
    }

    async fn read_all_fabric_host_identities(
        &self,
    ) -> Result<Vec<FabricHostTransportIdentityRecord>, StoreError> {
        let rows = sqlx::query("SELECT host_id,agent_id,public_key,underlay_endpoint,fabric_transport_ip,provider_version,fabric_generation,underlay_mtu,fabric_mtu,administrative_state FROM canonical_fabric_host_transport_identities ORDER BY host_id")
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        let mut identities = Vec::with_capacity(rows.len());
        for row in rows {
            let host_id: String = row.try_get("host_id").map_err(StoreError::Database)?;
            identities.push(
                self.read_fabric_host_identity(&host_id)
                    .await?
                    .ok_or_else(|| {
                        StoreError::Corrupt(
                            "Fabric host identity disappeared during read".to_owned(),
                        )
                    })?,
            );
        }
        Ok(identities)
    }

    async fn write_fabric_host_identity(
        &self,
        identity: &FabricHostTransportIdentityRecord,
        expected_generation: Option<u64>,
    ) -> Result<FabricHostTransportIdentityRecord, StoreError> {
        crate::validate_fabric_host_identity(identity)?;
        let current = self.read_fabric_host_identity(&identity.host_id).await?;
        match (current, expected_generation) {
            (None, None) => {
                sqlx::query("INSERT INTO canonical_fabric_host_transport_identities(host_id,agent_id,public_key,underlay_endpoint,fabric_transport_ip,provider_version,fabric_generation,underlay_mtu,fabric_mtu,administrative_state) VALUES(?,?,?,?,?,?,?,?,?,?)")
                    .bind(&identity.host_id).bind(&identity.agent_id).bind(&identity.public_key).bind(&identity.underlay_endpoint).bind(identity.fabric_transport_ip.to_string()).bind(&identity.provider_version).bind(checked_generation(identity.fabric_generation)?).bind(i64::from(identity.underlay_mtu)).bind(i64::from(identity.fabric_mtu)).bind(&identity.administrative_state)
                    .execute(&self.pool).await.map_err(map_canonical_insert_error)?;
            }
            (Some(current), Some(expected))
                if current == *identity && current.fabric_generation == expected =>
            {
                return Ok(current);
            }
            (Some(current), Some(expected))
                if current.fabric_generation == expected
                    && identity.fabric_generation == expected.saturating_add(1) =>
            {
                let result = sqlx::query("UPDATE canonical_fabric_host_transport_identities SET agent_id=?,public_key=?,underlay_endpoint=?,fabric_transport_ip=?,provider_version=?,fabric_generation=?,underlay_mtu=?,fabric_mtu=?,administrative_state=? WHERE host_id=? AND fabric_generation=?")
                    .bind(&identity.agent_id).bind(&identity.public_key).bind(&identity.underlay_endpoint).bind(identity.fabric_transport_ip.to_string()).bind(&identity.provider_version).bind(checked_generation(identity.fabric_generation)?).bind(i64::from(identity.underlay_mtu)).bind(i64::from(identity.fabric_mtu)).bind(&identity.administrative_state).bind(&identity.host_id).bind(checked_generation(expected)?)
                    .execute(&self.pool).await.map_err(map_canonical_insert_error)?;
                if result.rows_affected() != 1 {
                    return Err(StoreError::StaleGeneration);
                }
            }
            (None, Some(_)) | (Some(_), None) => return Err(StoreError::StaleGeneration),
            (Some(_), Some(_)) => return Err(StoreError::StaleGeneration),
        }
        self.read_fabric_host_identity(&identity.host_id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }

    pub async fn allocate_network_address(
        &self,
        realm_id: &Uuid,
        project_id: &str,
        endpoint_id: &Uuid,
        operation_id: &str,
        prefix: &str,
    ) -> Result<NetworkAddressAllocationRecord, StoreError> {
        if project_id.trim().is_empty() || operation_id.trim().is_empty() {
            return Err(StoreError::Corrupt(
                "network address allocation has empty identity".to_owned(),
            ));
        }
        let (network, prefix_len) = parse_ipv4_prefix(prefix)?;
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;

        let existing = sqlx::query(
            "SELECT realm_id, project_id, endpoint_id, operation_id, address
             FROM network_address_allocations WHERE endpoint_id = ? OR operation_id = ?",
        )
        .bind(endpoint_id.to_string())
        .bind(operation_id)
        .fetch_optional(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        if let Some(row) = existing {
            let existing_realm: String = row.get("realm_id");
            let existing_project: String = row.get("project_id");
            let existing_endpoint: String = row.get("endpoint_id");
            let existing_operation: String = row.get("operation_id");
            if existing_realm == realm_id.to_string()
                && existing_project == project_id
                && existing_endpoint == endpoint_id.to_string()
                && existing_operation == operation_id
            {
                let allocation = network_allocation_from_row(&row)?;
                sqlx::query("COMMIT")
                    .execute(&mut *connection)
                    .await
                    .map_err(StoreError::Database)?;
                return Ok(allocation);
            }
            let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
            return Err(StoreError::NetworkAddressConflict);
        }

        let occupied =
            sqlx::query("SELECT address FROM network_address_allocations WHERE realm_id = ?")
                .bind(realm_id.to_string())
                .fetch_all(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
        let occupied: std::collections::HashSet<Ipv4Addr> = occupied
            .iter()
            .map(|row| {
                row.get::<String, _>("address").parse().map_err(|_| {
                    StoreError::Corrupt("invalid allocated network address".to_owned())
                })
            })
            .collect::<Result<_, StoreError>>()?;
        let (first, last) = allocation_bounds(network, prefix_len);
        let address = (first..=last)
            .map(Ipv4Addr::from)
            .find(|candidate| !occupied.contains(candidate))
            .ok_or(StoreError::NetworkAddressExhausted)?;
        sqlx::query(
            "INSERT INTO network_address_allocations (realm_id, project_id, endpoint_id, operation_id, address)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(realm_id.to_string())
        .bind(project_id)
        .bind(endpoint_id.to_string())
        .bind(operation_id)
        .bind(address.to_string())
        .execute(&mut *connection)
        .await
        .map_err(|error| match error {
            sqlx::Error::Database(database) if database.is_unique_violation() => {
                StoreError::NetworkAddressConflict
            }
            other => StoreError::Database(other),
        })?;
        sqlx::query("COMMIT")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        Ok(NetworkAddressAllocationRecord {
            realm_id: *realm_id,
            project_id: project_id.to_owned(),
            endpoint_id: *endpoint_id,
            operation_id: operation_id.to_owned(),
            address,
        })
    }

    pub async fn release_network_address(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM network_address_allocations WHERE project_id = ? AND endpoint_id = ?",
        )
        .bind(project_id)
        .bind(endpoint_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn insert_network_intent(
        &self,
        intent: &NetworkIntentRecord,
    ) -> Result<(), StoreError> {
        validate_network_intent(intent)?;
        let generation = i64::try_from(intent.generation).map_err(|_| {
            StoreError::Corrupt("network intent generation exceeds SQLite range".to_owned())
        })?;
        let result = sqlx::query(
            "INSERT INTO network_intents (id, project_id, generation, payload, plan_fingerprint_sha256, status)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(intent.id.to_string())
        .bind(&intent.project_id)
        .bind(generation)
        .bind(&intent.payload)
        .bind(&intent.plan_fingerprint_sha256)
        .bind(&intent.status)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                match self
                    .get_network_intent(&intent.project_id, &intent.id)
                    .await?
                {
                    Some(existing) if existing == *intent => Ok(()),
                    _ => Err(StoreError::ResourceAlreadyExists),
                }
            }
            Err(error) => Err(StoreError::Database(error)),
        }
    }

    pub async fn list_network_intents(
        &self,
        project_id: &str,
    ) -> Result<Vec<NetworkIntentRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, project_id, generation, payload, plan_fingerprint_sha256, status
             FROM network_intents WHERE project_id = ? ORDER BY id",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(network_intent_from_row).collect()
    }

    pub async fn get_network_intent(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkIntentRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, project_id, generation, payload, plan_fingerprint_sha256, status
             FROM network_intents WHERE id = ? AND project_id = ?",
        )
        .bind(id.to_string())
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(network_intent_from_row).transpose()
    }

    pub async fn update_network_intent(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        payload: &str,
        plan_fingerprint_sha256: Option<&str>,
        status: &str,
    ) -> Result<NetworkIntentRecord, StoreError> {
        validate_network_intent_update(project_id, payload, status)?;
        let existing = self
            .get_network_intent(project_id, id)
            .await?
            .ok_or(StoreError::NetworkIntentNotFound)?;
        validate_network_intent_transition(&existing.status, status)?;
        let expected = i64::try_from(expected_generation).map_err(|_| {
            StoreError::Corrupt("network intent generation exceeds SQLite range".to_owned())
        })?;
        let result = sqlx::query(
            "UPDATE network_intents
             SET generation = generation + 1, payload = ?, plan_fingerprint_sha256 = ?, status = ?, updated_at = CURRENT_TIMESTAMP
             WHERE id = ? AND project_id = ? AND generation = ?",
        )
        .bind(payload)
        .bind(plan_fingerprint_sha256)
        .bind(status)
        .bind(id.to_string())
        .bind(project_id)
        .bind(expected)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_network_intent(project_id, id).await? {
                Some(_) => Err(StoreError::StaleGeneration),
                None => Err(StoreError::NetworkIntentNotFound),
            };
        }
        self.get_network_intent(project_id, id)
            .await?
            .ok_or(StoreError::Corrupt(
                "updated network intent disappeared".to_owned(),
            ))
    }

    pub async fn insert_network(&self, network: &NetworkRecord) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO network_networks (id, name, project_id, status) VALUES (?, ?, ?, ?)",
        )
        .bind(network.id.to_string())
        .bind(&network.name)
        .bind(&network.project_id)
        .bind(&network.status)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                Err(StoreError::ResourceAlreadyExists)
            }
            Err(error) => Err(StoreError::Database(error)),
        }
    }

    // Lists are ordered by rowid so insertion order is preserved; this is
    // deliberate and conformance-asserted.
    pub async fn list_networks(&self, project_id: &str) -> Result<Vec<NetworkRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, name, project_id, status FROM network_networks WHERE project_id = ? ORDER BY rowid",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(network_from_row).collect()
    }

    pub async fn get_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, name, project_id, status FROM network_networks WHERE id = ? AND project_id = ?",
        )
        .bind(id.to_string())
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(network_from_row).transpose()
    }

    pub async fn insert_canonical_network(
        &self,
        network: &CanonicalNetworkRecord,
    ) -> Result<(), StoreError> {
        validate_canonical_state(&network.state)?;
        let generation = checked_generation(network.generation)?;
        sqlx::query(
            "INSERT INTO canonical_networks (id, project_id, name, admin_state_up, generation, state) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(network.id.to_string())
        .bind(&network.project_id)
        .bind(&network.name)
        .bind(network.admin_state_up)
        .bind(generation)
        .bind(&network.state)
        .execute(&self.pool)
        .await
        .map_err(map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn get_canonical_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalNetworkRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, project_id, name, admin_state_up, generation, state FROM canonical_networks WHERE id = ? AND project_id = ?",
        )
        .bind(id.to_string())
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(canonical_network_from_row).transpose()
    }

    pub async fn list_canonical_networks(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalNetworkRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, project_id, name, admin_state_up, generation, state FROM canonical_networks WHERE project_id = ? ORDER BY id",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_network_from_row).collect()
    }

    pub async fn update_canonical_network(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        name: &str,
        admin_state_up: bool,
    ) -> Result<CanonicalNetworkRecord, StoreError> {
        if name.trim().is_empty() {
            return Err(StoreError::ResourceNotFound);
        }
        if sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM canonical_networks WHERE project_id = ? AND name = ? AND id <> ?",
        )
        .bind(project_id)
        .bind(name)
        .bind(id.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)?
            != 0
        {
            return Err(StoreError::ResourceAlreadyExists);
        }
        let mut transaction = self.pool.begin().await.map_err(StoreError::Database)?;
        let result = sqlx::query(
            "UPDATE canonical_networks SET name = ?, admin_state_up = ?, generation = generation + 1 WHERE id = ? AND project_id = ? AND generation = ? AND state = 'active'",
        )
        .bind(name)
        .bind(admin_state_up)
        .bind(id.to_string())
        .bind(project_id)
        .bind(checked_generation(expected_generation)?)
        .execute(&mut *transaction)
        .await
        .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            transaction.rollback().await.map_err(StoreError::Database)?;
            return match self.get_canonical_network(project_id, id).await? {
                Some(_) => Err(StoreError::StaleGeneration),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        sqlx::query("UPDATE network_networks SET name = ? WHERE id = ? AND project_id = ?")
            .bind(name)
            .bind(id.to_string())
            .bind(project_id)
            .execute(&mut *transaction)
            .await
            .map_err(StoreError::Database)?;
        transaction.commit().await.map_err(StoreError::Database)?;
        self.get_canonical_network(project_id, id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }

    pub async fn delete_canonical_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "DELETE FROM canonical_networks WHERE id = ? AND project_id = ? AND NOT EXISTS (SELECT 1 FROM canonical_address_realms WHERE network_id = canonical_networks.id)",
        )
        .bind(network_id.to_string())
        .bind(project_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_canonical_network(project_id, network_id).await? {
                Some(_) => Err(StoreError::NetworkInUse),
                None => Err(StoreError::NetworkNotFound),
            };
        }
        Ok(())
    }

    pub async fn insert_canonical_realm(
        &self,
        realm: &CanonicalAddressRealmRecord,
    ) -> Result<(), StoreError> {
        validate_canonical_state(&realm.state)?;
        let generation = checked_generation(realm.generation)?;
        let network = self
            .get_canonical_network_by_id(&realm.network_id)
            .await?
            .ok_or(StoreError::NetworkNotFound)?;
        if network.project_id != realm.project_id {
            return Err(StoreError::OwnershipConflict);
        }
        sqlx::query(
            "INSERT INTO canonical_address_realms (id, network_id, project_id, prefix, overlapping_prefixes, generation, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(realm.id.to_string())
        .bind(realm.network_id.to_string())
        .bind(&realm.project_id)
        .bind(&realm.prefix)
        .bind(realm.overlapping_prefixes)
        .bind(generation)
        .bind(&realm.state)
        .execute(&self.pool)
        .await
        .map_err(map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn get_canonical_realm(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalAddressRealmRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, network_id, project_id, prefix, overlapping_prefixes, generation, state FROM canonical_address_realms WHERE id = ? AND project_id = ?",
        )
        .bind(id.to_string())
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(canonical_realm_from_row).transpose()
    }

    pub async fn list_canonical_realms(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, network_id, project_id, prefix, overlapping_prefixes, generation, state FROM canonical_address_realms WHERE project_id = ? AND network_id = ? ORDER BY id",
        )
        .bind(project_id)
        .bind(network_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_realm_from_row).collect()
    }

    pub async fn list_active_canonical_realms(
        &self,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, network_id, project_id, prefix, overlapping_prefixes, generation, state FROM canonical_address_realms WHERE state = 'active' ORDER BY project_id, network_id, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_realm_from_row).collect()
    }

    pub async fn insert_canonical_pool(
        &self,
        pool: &CanonicalAddressPoolRecord,
    ) -> Result<(), StoreError> {
        validate_canonical_state(&pool.state)?;
        let generation = checked_generation(pool.generation)?;
        let realm = self
            .get_canonical_realm_by_id(&pool.realm_id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        if realm.project_id != pool.project_id {
            return Err(StoreError::OwnershipConflict);
        }
        sqlx::query(
            "INSERT INTO canonical_address_pools (id, realm_id, project_id, prefix, gateway, first_usable, last_usable, generation, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(pool.id.to_string())
        .bind(pool.realm_id.to_string())
        .bind(&pool.project_id)
        .bind(&pool.prefix)
        .bind(pool.gateway.map(|value| value.to_string()))
        .bind(pool.first_usable.to_string())
        .bind(pool.last_usable.to_string())
        .bind(generation)
        .bind(&pool.state)
        .execute(&self.pool)
        .await
        .map_err(map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn insert_subnet_bundle(
        &self,
        realm: &CanonicalAddressRealmRecord,
        pool: &CanonicalAddressPoolRecord,
        subnet: &SubnetRecord,
    ) -> Result<(), StoreError> {
        validate_canonical_state(&realm.state)?;
        validate_canonical_state(&pool.state)?;
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query("UPDATE canonical_networks SET generation = generation WHERE id = ? AND project_id = ? AND state = 'active'")
            .bind(realm.network_id.to_string())
            .bind(&realm.project_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let owner: Option<String> = sqlx::query_scalar(
            "SELECT project_id FROM canonical_networks WHERE id = ? AND state = 'active'",
        )
        .bind(realm.network_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if owner.as_deref() != Some(realm.project_id.as_str())
            || realm.project_id != pool.project_id
            || realm.project_id != subnet.project_id
            || realm.id != subnet.id
        {
            return Err(StoreError::OwnershipConflict);
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM canonical_address_realms WHERE network_id = ? AND project_id = ? AND state = 'active'",
        )
        .bind(realm.network_id.to_string())
        .bind(&realm.project_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if count != 0 {
            return Err(StoreError::NetworkInUse);
        }
        sqlx::query("INSERT INTO canonical_address_realms (id, network_id, project_id, prefix, overlapping_prefixes, generation, state) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(realm.id.to_string()).bind(realm.network_id.to_string()).bind(&realm.project_id).bind(&realm.prefix).bind(realm.overlapping_prefixes).bind(checked_generation(realm.generation)?).bind(&realm.state)
            .execute(&mut *tx).await.map_err(map_canonical_insert_error)?;
        sqlx::query("INSERT INTO canonical_address_pools (id, realm_id, project_id, prefix, gateway, first_usable, last_usable, generation, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(pool.id.to_string()).bind(pool.realm_id.to_string()).bind(&pool.project_id).bind(&pool.prefix).bind(pool.gateway.map(|v| v.to_string())).bind(pool.first_usable.to_string()).bind(pool.last_usable.to_string()).bind(checked_generation(pool.generation)?).bind(&pool.state)
            .execute(&mut *tx).await.map_err(map_canonical_insert_error)?;
        sqlx::query("INSERT INTO network_subnets (id, network_id, name, project_id, cidr, gateway_ip, allocation_start, allocation_end, ip_version, enable_dhcp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(subnet.id.to_string()).bind(subnet.network_id.to_string()).bind(&subnet.name).bind(&subnet.project_id).bind(&subnet.cidr).bind(subnet.gateway_ip.to_string()).bind(subnet.allocation_start.to_string()).bind(subnet.allocation_end.to_string()).bind(i64::from(subnet.ip_version)).bind(subnet.enable_dhcp)
            .execute(&mut *tx).await.map_err(map_canonical_insert_error)?;
        tx.commit().await.map_err(StoreError::Database)
    }

    pub async fn list_canonical_pools(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressPoolRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, realm_id, project_id, prefix, gateway, first_usable, last_usable, generation, state FROM canonical_address_pools WHERE project_id = ? AND realm_id = ? ORDER BY id",
        )
        .bind(project_id)
        .bind(realm_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_pool_from_row).collect()
    }

    pub async fn delete_canonical_pool(
        &self,
        project_id: &str,
        pool_id: &Uuid,
    ) -> Result<(), StoreError> {
        let result =
            sqlx::query("DELETE FROM canonical_address_pools WHERE id = ? AND project_id = ?")
                .bind(pool_id.to_string())
                .bind(project_id)
                .execute(&self.pool)
                .await
                .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::ResourceNotFound);
        }
        Ok(())
    }

    pub async fn update_canonical_pool(
        &self,
        project_id: &str,
        pool_id: &Uuid,
        expected_generation: u64,
        gateway: Option<Ipv4Addr>,
    ) -> Result<CanonicalAddressPoolRecord, StoreError> {
        let result = sqlx::query(
            "UPDATE canonical_address_pools SET gateway = ?, generation = generation + 1 WHERE id = ? AND project_id = ? AND generation = ? AND state = 'active'",
        )
        .bind(gateway.map(|value| value.to_string()))
        .bind(pool_id.to_string())
        .bind(project_id)
        .bind(checked_generation(expected_generation)?)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::StaleGeneration);
        }
        let row = sqlx::query("SELECT id, realm_id, project_id, prefix, gateway, first_usable, last_usable, generation, state FROM canonical_address_pools WHERE id = ? AND project_id = ?")
            .bind(pool_id.to_string())
            .bind(project_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?;
        canonical_pool_from_row(&row)
    }

    pub async fn insert_canonical_endpoint(
        &self,
        endpoint: &CanonicalEndpointRecord,
    ) -> Result<(), StoreError> {
        validate_canonical_state(&endpoint.state)?;
        let generation = checked_generation(endpoint.generation)?;
        let realm = self
            .get_canonical_realm_by_id(&endpoint.realm_id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        if realm.project_id != endpoint.project_id {
            return Err(StoreError::OwnershipConflict);
        }
        sqlx::query(
            "INSERT INTO canonical_endpoints (id, realm_id, project_id, fixed_ip, mac, generation, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(endpoint.id.to_string())
        .bind(endpoint.realm_id.to_string())
        .bind(&endpoint.project_id)
        .bind(endpoint.fixed_ip.to_string())
        .bind(&endpoint.mac)
        .bind(generation)
        .bind(&endpoint.state)
        .execute(&self.pool)
        .await
        .map_err(map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn insert_canonical_endpoint_and_port(
        &self,
        endpoint: &CanonicalEndpointRecord,
        port: &PortRecord,
    ) -> Result<(), StoreError> {
        validate_canonical_state(&endpoint.state)?;
        let generation = checked_generation(endpoint.generation)?;
        let subnet_id = port.subnet_id.ok_or(StoreError::ResourceNotFound)?;
        if endpoint.id != port.id
            || endpoint.realm_id != subnet_id
            || endpoint.project_id != port.project_id
        {
            return Err(StoreError::OwnershipConflict);
        }
        let mut tx = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<(), StoreError> = async {
            let realm = sqlx::query(
            "SELECT network_id, project_id FROM canonical_address_realms WHERE id = ? AND state = 'active'",
            )
            .bind(endpoint.realm_id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?;
            if realm.get::<String, _>("project_id") != endpoint.project_id
                || realm.get::<String, _>("network_id") != port.network_id.to_string()
            {
                return Err(StoreError::OwnershipConflict);
            }
            sqlx::query(
            "INSERT INTO canonical_endpoints (id, realm_id, project_id, fixed_ip, mac, generation, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(endpoint.id.to_string())
            .bind(endpoint.realm_id.to_string())
            .bind(&endpoint.project_id)
            .bind(endpoint.fixed_ip.to_string())
            .bind(&endpoint.mac)
            .bind(generation)
            .bind(&endpoint.state)
            .execute(&mut *tx)
            .await
            .map_err(map_canonical_insert_error)?;
            sqlx::query(
            "INSERT INTO network_ports (id, network_id, subnet_id, project_id, name, mac_address, fixed_ip, status, binding_host, binding_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(port.id.to_string())
            .bind(port.network_id.to_string())
            .bind(Some(subnet_id.to_string()))
            .bind(&port.project_id)
            .bind(&port.name)
            .bind(&port.mac_address)
            .bind(port.fixed_ip.to_string())
            .bind(&port.status)
            .bind(&port.binding_host)
            .bind(&port.binding_state)
            .execute(&mut *tx)
            .await
            .map_err(map_canonical_insert_error)?;
            Ok(())
        }
        .await;
        SqliteStore::commit_or_rollback(&mut tx, outcome).await
    }

    pub async fn list_canonical_endpoints(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalEndpointRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, realm_id, project_id, fixed_ip, mac, generation, state FROM canonical_endpoints WHERE project_id = ? AND realm_id = ? ORDER BY id",
        )
        .bind(project_id)
        .bind(realm_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_endpoint_from_row).collect()
    }

    pub async fn get_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<Option<CanonicalEndpointRecord>, StoreError> {
        let row = sqlx::query("SELECT id, realm_id, project_id, fixed_ip, mac, generation, state FROM canonical_endpoints WHERE id = ? AND project_id = ?")
            .bind(endpoint_id.to_string()).bind(project_id).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        row.as_ref().map(canonical_endpoint_from_row).transpose()
    }

    pub async fn delete_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM canonical_network_policies WHERE endpoint_id = ? AND project_id = ?",
        )
        .bind(endpoint_id.to_string())
        .bind(project_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let result = sqlx::query("DELETE FROM canonical_endpoints WHERE id = ? AND project_id = ?")
            .bind(endpoint_id.to_string())
            .bind(project_id)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::ResourceNotFound);
        }
        Ok(())
    }

    pub async fn delete_canonical_endpoint_and_port(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<(), StoreError> = async {
            sqlx::query(
                "DELETE FROM canonical_network_policies WHERE endpoint_id = ? AND project_id = ?",
            )
            .bind(endpoint_id.to_string())
            .bind(project_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
            let result =
                sqlx::query("DELETE FROM canonical_endpoints WHERE id = ? AND project_id = ?")
                    .bind(endpoint_id.to_string())
                    .bind(project_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
            if result.rows_affected() == 0 {
                return Err(StoreError::ResourceNotFound);
            }
            sqlx::query("DELETE FROM network_ports WHERE id = ? AND project_id = ?")
                .bind(endpoint_id.to_string())
                .bind(project_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
            Ok(())
        }
        .await;
        SqliteStore::commit_or_rollback(&mut tx, outcome).await
    }

    pub async fn upsert_canonical_policy(
        &self,
        policy: &CanonicalNetworkPolicyRecord,
    ) -> Result<(), StoreError> {
        let endpoint_project: String =
            sqlx::query_scalar("SELECT project_id FROM canonical_endpoints WHERE id = ?")
                .bind(policy.endpoint_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?
                .ok_or(StoreError::ResourceNotFound)?;
        if endpoint_project != policy.project_id {
            return Err(StoreError::OwnershipConflict);
        }
        checked_generation(policy.generation)?;
        sqlx::query(
            "INSERT INTO canonical_network_policies (id, project_id, endpoint_id, direction, protocol, port_min, port_max, source, destination, action, generation, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET project_id=excluded.project_id, endpoint_id=excluded.endpoint_id, direction=excluded.direction, protocol=excluded.protocol, port_min=excluded.port_min, port_max=excluded.port_max, source=excluded.source, destination=excluded.destination, action=excluded.action, generation=excluded.generation, state=excluded.state",
        )
        .bind(policy.id.to_string())
        .bind(&policy.project_id)
        .bind(policy.endpoint_id.to_string())
        .bind(&policy.direction)
        .bind(&policy.protocol)
        .bind(policy.port_min.map(i64::from))
        .bind(policy.port_max.map(i64::from))
        .bind(&policy.source)
        .bind(&policy.destination)
        .bind(&policy.action)
        .bind(policy.generation as i64)
        .bind(&policy.state)
        .execute(&self.pool)
        .await
        .map_err(map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn list_canonical_policies(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT p.id, p.project_id, p.endpoint_id, p.direction, p.protocol, p.port_min, p.port_max, p.source, p.destination, p.action, p.generation, p.state FROM canonical_network_policies p JOIN canonical_endpoints e ON e.id = p.endpoint_id JOIN canonical_address_realms r ON r.id = e.realm_id WHERE p.project_id = ? AND r.project_id = ? AND r.network_id = ? ORDER BY p.id",
        )
        .bind(project_id)
        .bind(project_id)
        .bind(network_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_policy_from_row).collect()
    }

    pub async fn delete_canonical_policy(
        &self,
        project_id: &str,
        policy_id: &Uuid,
    ) -> Result<(), StoreError> {
        let result =
            sqlx::query("DELETE FROM canonical_network_policies WHERE id = ? AND project_id = ?")
                .bind(policy_id.to_string())
                .bind(project_id)
                .execute(&self.pool)
                .await
                .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::ResourceNotFound);
        }
        Ok(())
    }

    pub async fn begin_canonical_realm_deletion(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalAddressRealmRecord, StoreError> {
        let result = sqlx::query(
            "UPDATE canonical_address_realms SET state = 'deleting', generation = generation + 1 WHERE id = ? AND project_id = ? AND generation = ? AND state = 'active' AND NOT EXISTS (SELECT 1 FROM canonical_address_pools WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_endpoints WHERE realm_id = canonical_address_realms.id)",
        )
        .bind(realm_id.to_string())
        .bind(project_id)
        .bind(checked_generation(expected_generation)?)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_canonical_realm(project_id, realm_id).await? {
                Some(realm) if realm.state == "deleting" => Ok(realm),
                Some(_) => Err(StoreError::NetworkInUse),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        self.get_canonical_realm(project_id, realm_id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }

    pub async fn advance_canonical_realm_generation(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalAddressRealmRecord, StoreError> {
        let updated = sqlx::query("UPDATE canonical_address_realms SET generation = generation + 1 WHERE id = ? AND project_id = ? AND generation = ? AND state = 'active'")
            .bind(realm_id.to_string())
            .bind(project_id)
            .bind(checked_generation(expected_generation)?)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::StaleGeneration);
        }
        self.get_canonical_realm(project_id, realm_id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }

    pub async fn finalize_canonical_realm_deletion(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "DELETE FROM canonical_address_realms WHERE id = ? AND project_id = ? AND generation = ? AND state = 'deleting' AND NOT EXISTS (SELECT 1 FROM canonical_address_pools WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_endpoints WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_network_policies p JOIN canonical_endpoints e ON e.id = p.endpoint_id WHERE e.realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_realm_encapsulation_bindings WHERE realm_id = canonical_address_realms.id)",
        )
        .bind(realm_id.to_string())
        .bind(project_id)
        .bind(checked_generation(expected_generation)?)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_canonical_realm(project_id, realm_id).await? {
                Some(_) => Err(StoreError::NetworkInUse),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        Ok(())
    }

    pub async fn insert_canonical_realm_binding(
        &self,
        binding: &CanonicalRealmBindingRecord,
    ) -> Result<(), StoreError> {
        let _realm = self
            .get_canonical_realm_by_id(&binding.realm_id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        validate_canonical_state(&binding.state)?;
        let generation = checked_generation(binding.binding_generation)?;
        let segment = checked_generation(binding.provider_segment_id)?;
        sqlx::query(
            "INSERT INTO canonical_realm_encapsulation_bindings (fabric_domain_id, realm_id, provider_kind, provider_segment_id, binding_generation, state) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&binding.fabric_domain_id)
        .bind(binding.realm_id.to_string())
        .bind(&binding.provider_kind)
        .bind(segment)
        .bind(generation)
        .bind(&binding.state)
        .execute(&self.pool)
        .await
        .map_err(map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn get_canonical_realm_binding(
        &self,
        fabric_domain_id: &str,
        realm_id: &Uuid,
    ) -> Result<Option<CanonicalRealmBindingRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT fabric_domain_id, realm_id, provider_kind, provider_segment_id, binding_generation, state FROM canonical_realm_encapsulation_bindings WHERE fabric_domain_id = ? AND realm_id = ?",
        )
        .bind(fabric_domain_id)
        .bind(realm_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.map(|row| {
            Ok(CanonicalRealmBindingRecord {
                fabric_domain_id: row.get("fabric_domain_id"),
                realm_id: parse_uuid(row.get("realm_id"))?,
                provider_kind: row.get("provider_kind"),
                provider_segment_id: u64::try_from(row.get::<i64, _>("provider_segment_id"))
                    .map_err(|_| StoreError::Corrupt("negative provider segment".into()))?,
                binding_generation: u64::try_from(row.get::<i64, _>("binding_generation"))
                    .map_err(|_| StoreError::Corrupt("negative binding generation".into()))?,
                state: row.get("state"),
            })
        })
        .transpose()
    }

    pub async fn list_canonical_realm_bindings(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalRealmBindingRecord>, StoreError> {
        let rows = sqlx::query("SELECT fabric_domain_id, realm_id, provider_kind, provider_segment_id, binding_generation, state FROM canonical_realm_encapsulation_bindings WHERE realm_id = ? ORDER BY fabric_domain_id")
            .bind(realm_id.to_string()).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.into_iter()
            .map(|row| {
                Ok(CanonicalRealmBindingRecord {
                    fabric_domain_id: row.get("fabric_domain_id"),
                    realm_id: parse_uuid(row.get("realm_id"))?,
                    provider_kind: row.get("provider_kind"),
                    provider_segment_id: u64::try_from(row.get::<i64, _>("provider_segment_id"))
                        .map_err(|_| StoreError::Corrupt("negative provider segment".into()))?,
                    binding_generation: u64::try_from(row.get::<i64, _>("binding_generation"))
                        .map_err(|_| StoreError::Corrupt("negative binding generation".into()))?,
                    state: row.get("state"),
                })
            })
            .collect()
    }

    pub async fn delete_canonical_realm_binding(
        &self,
        binding: &CanonicalRealmBindingRecord,
        expected_realm_generation: u64,
    ) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM canonical_realm_encapsulation_bindings WHERE fabric_domain_id = ? AND realm_id = ? AND provider_kind = ? AND provider_segment_id = ? AND binding_generation = ? AND binding_generation < ?")
            .bind(&binding.fabric_domain_id).bind(binding.realm_id.to_string()).bind(&binding.provider_kind)
            .bind(checked_generation(binding.provider_segment_id)?).bind(checked_generation(binding.binding_generation)?)
            .bind(checked_generation(expected_realm_generation)?).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::StaleGeneration);
        }
        Ok(())
    }

    pub async fn delete_canonical_realm(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "DELETE FROM canonical_address_realms WHERE id = ? AND project_id = ? AND NOT EXISTS (SELECT 1 FROM canonical_address_pools WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_endpoints WHERE realm_id = canonical_address_realms.id)",
        )
        .bind(realm_id.to_string())
        .bind(project_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_canonical_realm(project_id, realm_id).await? {
                Some(_) => Err(StoreError::NetworkInUse),
                None => Err(StoreError::ResourceNotFound),
            };
        }
        Ok(())
    }

    async fn get_canonical_network_by_id(
        &self,
        id: &Uuid,
    ) -> Result<Option<CanonicalNetworkRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, project_id, name, admin_state_up, generation, state FROM canonical_networks WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(canonical_network_from_row).transpose()
    }

    async fn get_canonical_realm_by_id(
        &self,
        id: &Uuid,
    ) -> Result<Option<CanonicalAddressRealmRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, network_id, project_id, prefix, overlapping_prefixes, generation, state FROM canonical_address_realms WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(canonical_realm_from_row).transpose()
    }

    /// Materializes the accepted canonical Network/Realm relations from the
    /// legacy durable rows. This is a data migration, not a compatibility
    /// write path: legacy rows are compared against any usable canonical
    /// intent metadata and contradictions fail closed.
    pub async fn backfill_canonical_network_state(&self) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let intents = sqlx::query(
            "SELECT id, project_id, generation, payload, status FROM network_intents ORDER BY id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        for intent in &intents {
            let id_text: String = intent.get("id");
            let Ok(id) = Uuid::parse_str(&id_text) else {
                continue;
            };
            let project_id: String = intent.get("project_id");
            let generation: i64 = intent.get("generation");
            let generation = u64::try_from(generation)
                .map_err(|_| StoreError::Corrupt("negative network intent generation".into()))?;
            let state: String = intent.get("status");
            validate_canonical_state(&state)?;
            sqlx::query(
                "INSERT INTO canonical_networks (id, project_id, name, generation, state) VALUES (?, ?, '', ?, ?) ON CONFLICT(id) DO NOTHING",
            )
            .bind(id.to_string())
            .bind(&project_id)
            .bind(checked_generation(generation)?)
            .bind(&state)
            .execute(&mut *tx)
            .await
            .map_err(map_canonical_insert_error)?;
            let row = sqlx::query(
                "SELECT project_id, name, generation, state FROM canonical_networks WHERE id = ?",
            )
            .bind(id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
            let existing_project: String = row.get("project_id");
            if existing_project != project_id {
                return Err(StoreError::OwnershipConflict);
            }
            let existing_generation: i64 = row.get("generation");
            let existing_state: String = row.get("state");
            if existing_generation != i64::try_from(generation).unwrap_or_default()
                || existing_state != state
            {
                return Err(StoreError::Corrupt(
                    "canonical network contradicts network intent".into(),
                ));
            }
            let payload: serde_json::Value =
                serde_json::from_str(intent.get("payload")).map_err(|error| {
                    StoreError::Corrupt(format!("invalid network intent JSON: {error}"))
                })?;
            if let Some(payload_id) = payload.get("id").and_then(serde_json::Value::as_str)
                && payload_id != id_text
            {
                return Err(StoreError::Corrupt(
                    "network intent payload identity contradicts its row".into(),
                ));
            }
        }

        let networks = sqlx::query("SELECT id, name, project_id FROM network_networks ORDER BY id")
            .fetch_all(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        for network in &networks {
            let id: String = network.get("id");
            let name: String = network.get("name");
            let project_id: String = network.get("project_id");
            sqlx::query(
                "INSERT INTO canonical_networks (id, project_id, name, generation, state) VALUES (?, ?, ?, 1, 'active') ON CONFLICT(id) DO NOTHING",
            )
            .bind(&id)
            .bind(&project_id)
            .bind(&name)
            .execute(&mut *tx)
            .await
            .map_err(map_canonical_insert_error)?;
            let canonical: (String, String) =
                sqlx::query_as("SELECT project_id, name FROM canonical_networks WHERE id = ?")
                    .bind(&id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
            if canonical.0 != project_id || (canonical.1 != name && !canonical.1.is_empty()) {
                return Err(StoreError::OwnershipConflict);
            }
            if canonical.1.is_empty() {
                sqlx::query("UPDATE canonical_networks SET name = ? WHERE id = ?")
                    .bind(&name)
                    .bind(&id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
            }
        }

        let subnets = sqlx::query(
            "SELECT id, network_id, project_id, cidr, gateway_ip, allocation_start, allocation_end FROM network_subnets ORDER BY id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        for subnet in &subnets {
            let id: String = subnet.get("id");
            let network_id: String = subnet.get("network_id");
            let project_id: String = subnet.get("project_id");
            let cidr: String = subnet.get("cidr");
            validate_ipv4_cidr(&cidr)?;
            let network_project: String =
                sqlx::query_scalar("SELECT project_id FROM canonical_networks WHERE id = ?")
                    .bind(&network_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?
                    .ok_or(StoreError::NetworkNotFound)?;
            if network_project != project_id {
                return Err(StoreError::OwnershipConflict);
            }
            sqlx::query(
                "INSERT INTO canonical_address_realms (id, network_id, project_id, prefix, overlapping_prefixes, generation, state) VALUES (?, ?, ?, ?, 0, 1, 'active') ON CONFLICT(id) DO NOTHING",
            )
            .bind(&id)
            .bind(&network_id)
            .bind(&project_id)
            .bind(&cidr)
            .execute(&mut *tx)
            .await
            .map_err(map_canonical_insert_error)?;
            let realm: (String, String, String) = sqlx::query_as(
                "SELECT network_id, project_id, prefix FROM canonical_address_realms WHERE id = ?",
            )
            .bind(&id)
            .fetch_one(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
            if realm.0 != network_id || realm.1 != project_id || realm.2 != cidr {
                return Err(StoreError::Corrupt(
                    "canonical realm contradicts legacy subnet state".into(),
                ));
            }
            let gateway: String = subnet.get("gateway_ip");
            let first_usable: String = subnet.get("allocation_start");
            let last_usable: String = subnet.get("allocation_end");
            let pool_id = id.clone();
            sqlx::query(
                "INSERT INTO canonical_address_pools (id, realm_id, project_id, prefix, gateway, first_usable, last_usable, generation, state) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'active') ON CONFLICT(id) DO NOTHING",
            )
            .bind(&pool_id)
            .bind(&id)
            .bind(&project_id)
            .bind(&cidr)
            .bind(&gateway)
            .bind(&first_usable)
            .bind(&last_usable)
            .execute(&mut *tx)
            .await
            .map_err(map_canonical_insert_error)?;
        }

        for intent in &intents {
            let payload: serde_json::Value =
                serde_json::from_str(intent.get("payload")).map_err(|error| {
                    StoreError::Corrupt(format!("invalid network intent JSON: {error}"))
                })?;
            if let Some(realm_id) = payload
                .get("realm")
                .and_then(|realm| realm.get("id"))
                .and_then(serde_json::Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
            {
                let realm_exists: Option<String> =
                    sqlx::query_scalar("SELECT id FROM canonical_address_realms WHERE id = ?")
                        .bind(realm_id.to_string())
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                if realm_exists.is_none() {
                    return Err(StoreError::Corrupt(
                        "network intent realm has no durable canonical owner".into(),
                    ));
                }
            }
        }

        let ports = sqlx::query(
            "SELECT id, subnet_id, project_id, fixed_ip, mac_address FROM network_ports ORDER BY id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        for port in &ports {
            let id: String = port.get("id");
            let subnet_id: Option<String> = port.get("subnet_id");
            let realm_id = subnet_id.ok_or_else(|| {
                StoreError::Corrupt("legacy endpoint has no explicit subnet owner".into())
            })?;
            let project_id: String = port.get("project_id");
            let realm_project: String =
                sqlx::query_scalar("SELECT project_id FROM canonical_address_realms WHERE id = ?")
                    .bind(&realm_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?
                    .ok_or(StoreError::ResourceNotFound)?;
            if realm_project != project_id {
                return Err(StoreError::OwnershipConflict);
            }
            let fixed_ip: String = port.get("fixed_ip");
            fixed_ip
                .parse::<Ipv4Addr>()
                .map_err(|_| StoreError::Corrupt("invalid legacy endpoint IP".into()))?;
            sqlx::query(
                "INSERT INTO canonical_endpoints (id, realm_id, project_id, fixed_ip, mac, generation, state) VALUES (?, ?, ?, ?, ?, 1, 'active') ON CONFLICT(id) DO NOTHING",
            )
            .bind(&id)
            .bind(&realm_id)
            .bind(&project_id)
            .bind(&fixed_ip)
            .bind(port.get::<String, _>("mac_address"))
            .execute(&mut *tx)
            .await
            .map_err(map_canonical_insert_error)?;
        }
        for intent in &intents {
            let project_id: String = intent.get("project_id");
            for policy in legacy_policy_records(intent.get("payload"), &project_id)? {
                let endpoint_project: Option<String> =
                    sqlx::query_scalar("SELECT project_id FROM canonical_endpoints WHERE id = ?")
                        .bind(policy.endpoint_id.to_string())
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                if endpoint_project.as_deref() != Some(project_id.as_str()) {
                    return Err(StoreError::OwnershipConflict);
                }
                sqlx::query(
                    "INSERT INTO canonical_network_policies (id, project_id, endpoint_id, direction, protocol, port_min, port_max, source, destination, action, generation, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
                )
                .bind(policy.id.to_string())
                .bind(&policy.project_id)
                .bind(policy.endpoint_id.to_string())
                .bind(&policy.direction)
                .bind(&policy.protocol)
                .bind(policy.port_min.map(i64::from))
                .bind(policy.port_max.map(i64::from))
                .bind(&policy.source)
                .bind(&policy.destination)
                .bind(&policy.action)
                .bind(policy.generation as i64)
                .bind(&policy.state)
                .execute(&mut *tx)
                .await
                .map_err(map_canonical_insert_error)?;
            }
        }
        tx.commit().await.map_err(StoreError::Database)
    }

    pub async fn delete_network(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM network_networks WHERE id = ? AND project_id = ? AND NOT EXISTS (SELECT 1 FROM network_subnets WHERE network_id = network_networks.id) AND NOT EXISTS (SELECT 1 FROM network_ports WHERE network_id = network_networks.id)")
            .bind(id.to_string())
            .bind(project_id)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_network(project_id, id).await? {
                Some(_) => Err(StoreError::NetworkInUse),
                None => Err(StoreError::NetworkNotFound),
            };
        }
        Ok(())
    }

    pub async fn insert_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO network_subnets (id, network_id, name, project_id, cidr, gateway_ip, allocation_start, allocation_end, ip_version, enable_dhcp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(subnet.id.to_string())
        .bind(subnet.network_id.to_string())
        .bind(&subnet.name)
        .bind(&subnet.project_id)
        .bind(&subnet.cidr)
        .bind(subnet.gateway_ip.to_string())
        .bind(subnet.allocation_start.to_string())
        .bind(subnet.allocation_end.to_string())
        .bind(i64::from(subnet.ip_version))
        .bind(subnet.enable_dhcp)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                Err(StoreError::ResourceAlreadyExists)
            }
            Err(error) => Err(StoreError::Database(error)),
        }
    }

    pub async fn list_subnets(&self, project_id: &str) -> Result<Vec<SubnetRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, network_id, name, project_id, cidr, gateway_ip, allocation_start, allocation_end, ip_version, enable_dhcp FROM network_subnets WHERE project_id = ? ORDER BY id",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(subnet_from_row).collect()
    }

    pub async fn list_subnets_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<SubnetRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, network_id, name, project_id, cidr, gateway_ip, allocation_start, allocation_end, ip_version, enable_dhcp FROM network_subnets WHERE project_id = ? AND network_id = ? ORDER BY id",
        )
        .bind(project_id)
        .bind(network_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(subnet_from_row).collect()
    }

    pub async fn get_subnet(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SubnetRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, network_id, name, project_id, cidr, gateway_ip, allocation_start, allocation_end, ip_version, enable_dhcp FROM network_subnets WHERE id = ? AND project_id = ?",
        )
        .bind(id.to_string())
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(subnet_from_row).transpose()
    }

    pub async fn delete_subnet(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        let mut backoff = Duration::from_millis(10);
        for attempt in 0..SQLITE_BUSY_MAX_ATTEMPTS {
            let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
            let began = sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut *connection)
                .await;
            let outcome = match began {
                Ok(_) => {
                    let outcome: Result<(), StoreError> = async {
                        let result = sqlx::query("DELETE FROM network_subnets WHERE id = ? AND project_id = ? AND NOT EXISTS (SELECT 1 FROM network_ports WHERE network_id = network_subnets.network_id)")
                            .bind(id.to_string())
                            .bind(project_id)
                            .execute(&mut *connection)
                            .await
                            .map_err(StoreError::Database)?;
                        if result.rows_affected() == 0 {
                            let exists: Option<String> = sqlx::query_scalar(
                                "SELECT id FROM network_subnets WHERE id = ? AND project_id = ?",
                            )
                            .bind(id.to_string())
                            .bind(project_id)
                            .fetch_optional(&mut *connection)
                            .await
                            .map_err(StoreError::Database)?;
                            return Err(if exists.is_some() {
                                StoreError::NetworkInUse
                            } else {
                                StoreError::NetworkNotFound
                            });
                        }
                        Ok(())
                    }
                    .await;
                    SqliteStore::commit_or_rollback(&mut connection, outcome).await
                }
                Err(error) => Err(StoreError::Database(error)),
            };
            match outcome {
                Ok(()) => return Ok(()),
                Err(StoreError::Database(error))
                    if is_sqlite_busy(&error) && attempt + 1 < SQLITE_BUSY_MAX_ATTEMPTS =>
                {
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the loop returns on the final attempt")
    }

    pub async fn update_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE network_subnets SET name = ?, gateway_ip = ?, allocation_start = ?, allocation_end = ?, ip_version = ?, enable_dhcp = ? WHERE id = ? AND project_id = ?",
        )
        .bind(&subnet.name)
        .bind(subnet.gateway_ip.to_string())
        .bind(subnet.allocation_start.to_string())
        .bind(subnet.allocation_end.to_string())
        .bind(i64::from(subnet.ip_version))
        .bind(subnet.enable_dhcp)
        .bind(subnet.id.to_string())
        .bind(&subnet.project_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NetworkNotFound);
        }
        Ok(())
    }

    pub async fn delete_subnet_bundle(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let endpoints: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM canonical_endpoints WHERE realm_id = ? AND project_id = ?",
        )
        .bind(id.to_string())
        .bind(project_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if endpoints != 0 {
            return Err(StoreError::NetworkInUse);
        }
        let realm: Option<String> = sqlx::query_scalar(
            "SELECT id FROM canonical_address_realms WHERE id = ? AND project_id = ?",
        )
        .bind(id.to_string())
        .bind(project_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if realm.is_some() {
            sqlx::query(
                "DELETE FROM canonical_address_pools WHERE realm_id = ? AND project_id = ?",
            )
            .bind(id.to_string())
            .bind(project_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
            let result = sqlx::query("DELETE FROM canonical_address_realms WHERE id = ? AND project_id = ? AND NOT EXISTS (SELECT 1 FROM canonical_address_pools WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_endpoints WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_realm_encapsulation_bindings WHERE realm_id = canonical_address_realms.id)")
                .bind(id.to_string()).bind(project_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
            if result.rows_affected() == 0 {
                return Err(StoreError::NetworkInUse);
            }
        }
        sqlx::query("DELETE FROM network_subnets WHERE id = ? AND project_id = ?")
            .bind(id.to_string())
            .bind(project_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)
    }

    pub async fn update_subnet_bundle(
        &self,
        subnet: &SubnetRecord,
        pool_id: &Uuid,
        expected_pool_generation: u64,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let pool = sqlx::query("UPDATE canonical_address_pools SET gateway = ?, generation = generation + 1 WHERE id = ? AND project_id = ? AND generation = ? AND state = 'active'")
            .bind(subnet.gateway_ip.to_string())
            .bind(pool_id.to_string())
            .bind(&subnet.project_id)
            .bind(checked_generation(expected_pool_generation)?)
            .execute(&mut *tx).await.map_err(StoreError::Database)?;
        if pool.rows_affected() == 0 {
            return Err(StoreError::StaleGeneration);
        }
        let metadata = sqlx::query("UPDATE network_subnets SET name = ?, gateway_ip = ?, allocation_start = ?, allocation_end = ?, ip_version = ?, enable_dhcp = ? WHERE id = ? AND project_id = ?")
            .bind(&subnet.name).bind(subnet.gateway_ip.to_string()).bind(subnet.allocation_start.to_string()).bind(subnet.allocation_end.to_string()).bind(i64::from(subnet.ip_version)).bind(subnet.enable_dhcp).bind(subnet.id.to_string()).bind(&subnet.project_id)
            .execute(&mut *tx).await.map_err(StoreError::Database)?;
        if metadata.rows_affected() == 0 {
            return Err(StoreError::ResourceNotFound);
        }
        tx.commit().await.map_err(StoreError::Database)
    }

    pub async fn insert_port(&self, port: &PortRecord) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO network_ports (id, network_id, subnet_id, project_id, name, mac_address, fixed_ip, status, binding_host, binding_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(port.id.to_string())
        .bind(port.network_id.to_string())
        .bind(port.subnet_id.map(|value| value.to_string()))
        .bind(&port.project_id)
        .bind(&port.name)
        .bind(port.mac_address.to_ascii_lowercase())
        .bind(port.fixed_ip.to_string())
        .bind(&port.status)
        .bind(&port.binding_host)
        .bind(&port.binding_state)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                Err(StoreError::ResourceAlreadyExists)
            }
            Err(error) => Err(StoreError::Database(error)),
        }
    }

    pub async fn list_ports(&self, project_id: &str) -> Result<Vec<PortRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, network_id, subnet_id, project_id, name, mac_address, fixed_ip, status, binding_host, binding_state, binding_generation FROM network_ports WHERE project_id = ? ORDER BY rowid",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(port_from_row).collect()
    }

    pub async fn list_ports_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<PortRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, network_id, subnet_id, project_id, name, mac_address, fixed_ip, status, binding_host, binding_state, binding_generation FROM network_ports WHERE project_id = ? AND network_id = ? ORDER BY rowid",
        )
        .bind(project_id)
        .bind(network_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(port_from_row).collect()
    }

    pub async fn get_port(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<PortRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, network_id, subnet_id, project_id, name, mac_address, fixed_ip, status, binding_host, binding_state, binding_generation FROM network_ports WHERE id = ? AND project_id = ?",
        )
        .bind(id.to_string())
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(port_from_row).transpose()
    }

    pub async fn get_port_by_id(&self, id: &Uuid) -> Result<Option<PortRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, network_id, subnet_id, project_id, name, mac_address, fixed_ip, status, binding_host, binding_state, binding_generation FROM network_ports WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(port_from_row).transpose()
    }

    pub async fn delete_port(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM network_security_group_bindings WHERE project_id = ? AND endpoint_id = ?",
        )
        .bind(project_id)
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let result = sqlx::query("DELETE FROM network_ports WHERE id = ? AND project_id = ?")
            .bind(id.to_string())
            .bind(project_id)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            Err(StoreError::NetworkNotFound)
        } else {
            Ok(())
        }
    }

    pub async fn update_port_binding(
        &self,
        project_id: &str,
        id: &Uuid,
        binding_host: Option<&str>,
        binding_state: Option<&str>,
    ) -> Result<PortRecord, StoreError> {
        let result = sqlx::query(
            "UPDATE network_ports SET binding_generation = CASE WHEN binding_host IS NOT ? THEN binding_generation + 1 ELSE binding_generation END, binding_host = ?, binding_state = ? WHERE id = ? AND project_id = ?",
        )
        .bind(binding_host)
        .bind(binding_host)
        .bind(binding_state)
        .bind(id.to_string())
        .bind(project_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NetworkNotFound);
        }
        self.get_port(project_id, id)
            .await?
            .ok_or(StoreError::Corrupt("updated port is missing".to_owned()))
    }

    pub async fn update_port_name(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
    ) -> Result<PortRecord, StoreError> {
        let result =
            sqlx::query("UPDATE network_ports SET name = ? WHERE id = ? AND project_id = ?")
                .bind(name)
                .bind(id.to_string())
                .bind(project_id)
                .execute(&self.pool)
                .await
                .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NetworkNotFound);
        }
        self.get_port(project_id, id)
            .await?
            .ok_or(StoreError::NetworkNotFound)
    }

    pub async fn insert_security_group(
        &self,
        group: &SecurityGroupRecord,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO network_security_groups (id, project_id, name, description) VALUES (?, ?, ?, ?)")
            .bind(group.id.to_string()).bind(&group.project_id).bind(&group.name).bind(&group.description)
            .execute(&self.pool).await.map(|_| ()).map_err(|error| match error {
                sqlx::Error::Database(db) if db.is_unique_violation() => StoreError::ResourceAlreadyExists,
                other => StoreError::Database(other),
            })
    }

    pub async fn list_security_groups(
        &self,
        project_id: &str,
    ) -> Result<Vec<SecurityGroupRecord>, StoreError> {
        let rows = sqlx::query("SELECT id, project_id, name, description FROM network_security_groups WHERE project_id = ? ORDER BY id")
            .bind(project_id).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.iter().map(security_group_from_row).collect()
    }

    pub async fn get_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRecord>, StoreError> {
        let row = sqlx::query("SELECT id, project_id, name, description FROM network_security_groups WHERE project_id = ? AND id = ?")
            .bind(project_id).bind(id.to_string()).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        row.as_ref().map(security_group_from_row).transpose()
    }

    pub async fn update_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
        description: &str,
    ) -> Result<SecurityGroupRecord, StoreError> {
        let result = sqlx::query("UPDATE network_security_groups SET name = ?, description = ? WHERE project_id = ? AND id = ?")
            .bind(name).bind(description).bind(project_id).bind(id.to_string()).execute(&self.pool).await.map_err(|error| match error {
                sqlx::Error::Database(db) if db.is_unique_violation() => StoreError::ResourceAlreadyExists,
                other => StoreError::Database(other),
            })?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NetworkNotFound);
        }
        self.get_security_group(project_id, id)
            .await?
            .ok_or(StoreError::NetworkNotFound)
    }

    pub async fn delete_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM network_security_groups WHERE project_id = ? AND id = ? AND NOT EXISTS (SELECT 1 FROM network_security_group_rules WHERE security_group_id = ?) AND NOT EXISTS (SELECT 1 FROM network_security_group_bindings WHERE security_group_id = ?)")
            .bind(project_id).bind(id.to_string()).bind(id.to_string()).bind(id.to_string()).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() != 0 {
            return Ok(());
        }
        match self.get_security_group(project_id, id).await? {
            Some(_) => Err(StoreError::NetworkInUse),
            None => Err(StoreError::NetworkNotFound),
        }
    }

    pub async fn insert_security_group_rule(
        &self,
        rule: &SecurityGroupRuleRecord,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO network_security_group_rules (id, security_group_id, project_id, direction, protocol, port_min, port_max, remote_ip_prefix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(rule.id.to_string()).bind(rule.security_group_id.to_string()).bind(&rule.project_id).bind(&rule.direction).bind(&rule.protocol)
            .bind(rule.port_min.map(i64::from)).bind(rule.port_max.map(i64::from)).bind(&rule.remote_ip_prefix)
            .execute(&self.pool).await.map(|_| ()).map_err(|error| match error {
                sqlx::Error::Database(db) if db.is_unique_violation() => StoreError::ResourceAlreadyExists,
                other => StoreError::Database(other),
            })
    }

    pub async fn list_security_group_rules(
        &self,
        project_id: &str,
        group_id: &Uuid,
    ) -> Result<Vec<SecurityGroupRuleRecord>, StoreError> {
        let rows = sqlx::query("SELECT id, security_group_id, project_id, direction, protocol, port_min, port_max, remote_ip_prefix FROM network_security_group_rules WHERE project_id = ? AND security_group_id = ? ORDER BY id")
            .bind(project_id).bind(group_id.to_string()).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.iter().map(security_group_rule_from_row).collect()
    }

    pub async fn get_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRuleRecord>, StoreError> {
        let row = sqlx::query("SELECT id, security_group_id, project_id, direction, protocol, port_min, port_max, remote_ip_prefix FROM network_security_group_rules WHERE project_id = ? AND id = ?")
            .bind(project_id).bind(id.to_string()).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        row.as_ref().map(security_group_rule_from_row).transpose()
    }

    pub async fn delete_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<(), StoreError> {
        let result =
            sqlx::query("DELETE FROM network_security_group_rules WHERE project_id = ? AND id = ?")
                .bind(project_id)
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            Err(StoreError::NetworkNotFound)
        } else {
            Ok(())
        }
    }

    pub async fn list_security_group_bindings(
        &self,
        project_id: &str,
        endpoint_id: Option<&Uuid>,
    ) -> Result<Vec<SecurityGroupBindingRecord>, StoreError> {
        let (sql, endpoint) = match endpoint_id {
            Some(id) => (
                "SELECT project_id, endpoint_id, security_group_id FROM network_security_group_bindings WHERE project_id = ? AND endpoint_id = ? ORDER BY security_group_id",
                Some(id.to_string()),
            ),
            None => (
                "SELECT project_id, endpoint_id, security_group_id FROM network_security_group_bindings WHERE project_id = ? ORDER BY endpoint_id, security_group_id",
                None,
            ),
        };
        let mut query = sqlx::query(sql).bind(project_id);
        if let Some(endpoint) = endpoint {
            query = query.bind(endpoint);
        }
        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        rows.iter().map(security_group_binding_from_row).collect()
    }

    pub async fn replace_security_group_bindings(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
        group_ids: &[Uuid],
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query(
            "DELETE FROM network_security_group_bindings WHERE project_id = ? AND endpoint_id = ?",
        )
        .bind(project_id)
        .bind(endpoint_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        for group_id in group_ids {
            sqlx::query("INSERT INTO network_security_group_bindings (project_id, endpoint_id, security_group_id) VALUES (?, ?, ?)").bind(project_id).bind(endpoint_id.to_string()).bind(group_id.to_string()).execute(&mut *tx).await.map_err(StoreError::Database)?;
        }
        tx.commit().await.map_err(StoreError::Database)
    }
}

impl SqliteStore {
    pub async fn insert_canonical_l3_gateway(
        &self,
        g: &CanonicalL3GatewayRecord,
    ) -> Result<(), StoreError> {
        validate_canonical_state(&g.state)?;
        checked_generation(g.generation)?;
        sqlx::query("INSERT INTO canonical_l3_gateways (id,project_id,name,external_realm_id,enable_snat,generation,state) VALUES (?,?,?,?,?,?,?)")
            .bind(g.id.to_string()).bind(&g.project_id).bind(&g.name)
            .bind(g.external_realm_id.map(|v| v.to_string())).bind(g.enable_snat)
            .bind(g.generation as i64).bind(&g.state).execute(&self.pool).await
            .map_err(map_canonical_insert_error).map(|_| ())
    }
    pub async fn get_canonical_l3_gateway(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayRecord>, StoreError> {
        let row = sqlx::query("SELECT id,project_id,name,external_realm_id,enable_snat,generation,state FROM canonical_l3_gateways WHERE id=? AND project_id=?").bind(id.to_string()).bind(project_id).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        row.as_ref()
            .map(|r| {
                Ok(CanonicalL3GatewayRecord {
                    id: r
                        .try_get::<String, _>("id")
                        .map_err(StoreError::Database)?
                        .parse()
                        .map_err(StoreError::InvalidUuid)?,
                    project_id: r.try_get("project_id").map_err(StoreError::Database)?,
                    name: r.try_get("name").map_err(StoreError::Database)?,
                    external_realm_id: r
                        .try_get::<Option<String>, _>("external_realm_id")
                        .map_err(StoreError::Database)?
                        .map(|v| v.parse().map_err(StoreError::InvalidUuid))
                        .transpose()?,
                    enable_snat: r.try_get("enable_snat").map_err(StoreError::Database)?,
                    generation: checked_generation(
                        r.try_get::<i64, _>("generation")
                            .map_err(StoreError::Database)? as u64,
                    )? as u64,
                    state: r.try_get("state").map_err(StoreError::Database)?,
                })
            })
            .transpose()
    }
    pub async fn list_canonical_l3_gateways(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError> {
        let rows =
            sqlx::query("SELECT id FROM canonical_l3_gateways WHERE project_id=? ORDER BY id")
                .bind(project_id)
                .fetch_all(&self.pool)
                .await
                .map_err(StoreError::Database)?;
        let mut out = Vec::new();
        for r in rows {
            let id: Uuid = r
                .try_get::<String, _>("id")
                .map_err(StoreError::Database)?
                .parse()
                .map_err(StoreError::InvalidUuid)?;
            out.push(
                self.get_canonical_l3_gateway(project_id, &id)
                    .await?
                    .ok_or_else(|| StoreError::Corrupt("gateway disappeared".into()))?,
            );
        }
        Ok(out)
    }
    pub async fn list_canonical_l3_gateways_by_state(
        &self,
        state: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, project_id FROM canonical_l3_gateways WHERE state=? ORDER BY project_id,id",
        )
        .bind(state)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let mut out = Vec::new();
        for row in rows {
            let id: Uuid = row
                .try_get::<String, _>("id")
                .map_err(StoreError::Database)?
                .parse()
                .map_err(StoreError::InvalidUuid)?;
            let project: String = row.try_get("project_id").map_err(StoreError::Database)?;
            out.push(
                self.get_canonical_l3_gateway(&project, &id)
                    .await?
                    .ok_or_else(|| StoreError::Corrupt("gateway disappeared".into()))?,
            );
        }
        Ok(out)
    }
    pub async fn update_canonical_l3_gateway(
        &self,
        project_id: &str,
        id: &Uuid,
        expected: u64,
        name: &str,
        external: Option<Uuid>,
        snat: bool,
    ) -> Result<CanonicalL3GatewayRecord, StoreError> {
        let n=sqlx::query("UPDATE canonical_l3_gateways SET name=?,external_realm_id=?,enable_snat=?,generation=generation+1 WHERE id=? AND project_id=? AND generation=? AND state='active'").bind(name).bind(external.map(|v|v.to_string())).bind(snat).bind(id.to_string()).bind(project_id).bind(expected as i64).execute(&self.pool).await.map_err(StoreError::Database)?;
        if n.rows_affected() == 0 {
            return Err(
                if self
                    .get_canonical_l3_gateway(project_id, id)
                    .await?
                    .is_some()
                {
                    StoreError::StaleGeneration
                } else {
                    StoreError::ResourceNotFound
                },
            );
        }
        self.get_canonical_l3_gateway(project_id, id)
            .await?
            .ok_or_else(|| StoreError::Corrupt("gateway disappeared".into()))
    }
    async fn classify_l3_gateway_deletion_failure(
        &self,
        p: &str,
        id: &Uuid,
        expected: u64,
        required_state: &str,
    ) -> Result<StoreError, StoreError> {
        let row =
            sqlx::query("SELECT project_id,generation,state FROM canonical_l3_gateways WHERE id=?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?;
        let Some(row) = row else {
            return Ok(StoreError::OwnershipConflict);
        };
        let owner: String = row.try_get("project_id").map_err(StoreError::Database)?;
        if owner != p {
            return Ok(StoreError::OwnershipConflict);
        }
        let generation = checked_generation(
            row.try_get::<i64, _>("generation")
                .map_err(StoreError::Database)? as u64,
        )? as u64;
        if generation != expected {
            return Ok(StoreError::StaleGeneration);
        }
        let state: String = row.try_get("state").map_err(StoreError::Database)?;
        if state != required_state {
            return Ok(StoreError::OwnershipConflict);
        }
        Ok(StoreError::NetworkInUse)
    }
    pub async fn begin_canonical_l3_gateway_deletion(
        &self,
        p: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<CanonicalL3GatewayRecord, StoreError> {
        let n=sqlx::query("UPDATE canonical_l3_gateways SET state='deleting',generation=generation+1 WHERE id=? AND project_id=? AND generation=? AND state='active' AND NOT EXISTS (SELECT 1 FROM canonical_l3_gateway_attachments WHERE gateway_id=? AND state IN ('active','deleting'))").bind(id.to_string()).bind(p).bind(expected as i64).bind(id.to_string()).execute(&self.pool).await.map_err(StoreError::Database)?;
        if n.rows_affected() == 0 {
            return Err(self
                .classify_l3_gateway_deletion_failure(p, id, expected, "active")
                .await?);
        }
        self.get_canonical_l3_gateway(p, id)
            .await?
            .ok_or_else(|| StoreError::Corrupt("gateway disappeared".into()))
    }
    pub async fn finalize_canonical_l3_gateway_deletion(
        &self,
        p: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<(), StoreError> {
        let n=sqlx::query("DELETE FROM canonical_l3_gateways WHERE id=? AND project_id=? AND generation=? AND state='deleting' AND NOT EXISTS (SELECT 1 FROM canonical_l3_gateway_attachments WHERE gateway_id=? AND state IN ('active','deleting'))").bind(id.to_string()).bind(p).bind(expected as i64).bind(id.to_string()).execute(&self.pool).await.map_err(StoreError::Database)?;
        if n.rows_affected() == 0 {
            Err(self
                .classify_l3_gateway_deletion_failure(p, id, expected, "deleting")
                .await?)
        } else {
            Ok(())
        }
    }
    pub async fn insert_canonical_l3_gateway_attachment(
        &self,
        a: &CanonicalL3GatewayAttachmentRecord,
    ) -> Result<(), StoreError> {
        validate_canonical_state(&a.state)?;
        checked_generation(a.generation)?;
        sqlx::query("INSERT INTO canonical_l3_gateway_attachments (id,gateway_id,realm_id,project_id,generation,state) VALUES (?,?,?,?,?,?)").bind(a.id.to_string()).bind(a.gateway_id.to_string()).bind(a.realm_id.to_string()).bind(&a.project_id).bind(a.generation as i64).bind(&a.state).execute(&self.pool).await.map_err(map_canonical_insert_error).map(|_|())
    }
    pub async fn get_canonical_l3_gateway_attachment(
        &self,
        p: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        let row=sqlx::query("SELECT id,gateway_id,realm_id,project_id,generation,state FROM canonical_l3_gateway_attachments WHERE id=? AND project_id=?").bind(id.to_string()).bind(p).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        row.as_ref()
            .map(|r| {
                Ok(CanonicalL3GatewayAttachmentRecord {
                    id: r
                        .try_get::<String, _>("id")
                        .map_err(StoreError::Database)?
                        .parse()
                        .map_err(StoreError::InvalidUuid)?,
                    gateway_id: r
                        .try_get::<String, _>("gateway_id")
                        .map_err(StoreError::Database)?
                        .parse()
                        .map_err(StoreError::InvalidUuid)?,
                    realm_id: r
                        .try_get::<String, _>("realm_id")
                        .map_err(StoreError::Database)?
                        .parse()
                        .map_err(StoreError::InvalidUuid)?,
                    project_id: r.try_get("project_id").map_err(StoreError::Database)?,
                    generation: checked_generation(
                        r.try_get::<i64, _>("generation")
                            .map_err(StoreError::Database)? as u64,
                    )? as u64,
                    state: r.try_get("state").map_err(StoreError::Database)?,
                })
            })
            .transpose()
    }
    pub async fn list_canonical_l3_gateway_attachments(
        &self,
        p: &str,
        g: &Uuid,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        let rows=sqlx::query("SELECT id FROM canonical_l3_gateway_attachments WHERE project_id=? AND gateway_id=? ORDER BY id").bind(p).bind(g.to_string()).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        let mut out = Vec::new();
        for r in rows {
            let id: Uuid = r
                .try_get::<String, _>("id")
                .map_err(StoreError::Database)?
                .parse()
                .map_err(StoreError::InvalidUuid)?;
            out.push(
                self.get_canonical_l3_gateway_attachment(p, &id)
                    .await?
                    .ok_or_else(|| StoreError::Corrupt("attachment disappeared".into()))?,
            )
        }
        Ok(out)
    }
    pub async fn list_canonical_l3_gateway_attachments_by_state(
        &self,
        state: &str,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, project_id FROM canonical_l3_gateway_attachments WHERE state=? ORDER BY project_id,id",
        )
        .bind(state)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let mut out = Vec::new();
        for row in rows {
            let id: Uuid = row
                .try_get::<String, _>("id")
                .map_err(StoreError::Database)?
                .parse()
                .map_err(StoreError::InvalidUuid)?;
            let project: String = row.try_get("project_id").map_err(StoreError::Database)?;
            out.push(
                self.get_canonical_l3_gateway_attachment(&project, &id)
                    .await?
                    .ok_or_else(|| StoreError::Corrupt("attachment disappeared".into()))?,
            );
        }
        Ok(out)
    }
    pub async fn list_canonical_realm_l3_gateway_attachments(
        &self,
        p: &str,
        r: &Uuid,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        let rows=sqlx::query("SELECT id FROM canonical_l3_gateway_attachments WHERE project_id=? AND realm_id=? ORDER BY id").bind(p).bind(r.to_string()).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        let mut out = Vec::new();
        for row in rows {
            let id: Uuid = row
                .try_get::<String, _>("id")
                .map_err(StoreError::Database)?
                .parse()
                .map_err(StoreError::InvalidUuid)?;
            out.push(
                self.get_canonical_l3_gateway_attachment(p, &id)
                    .await?
                    .ok_or_else(|| StoreError::Corrupt("attachment disappeared".into()))?,
            )
        }
        Ok(out)
    }
    pub async fn begin_canonical_l3_gateway_attachment_deletion(
        &self,
        p: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<CanonicalL3GatewayAttachmentRecord, StoreError> {
        let n=sqlx::query("UPDATE canonical_l3_gateway_attachments SET state='deleting',generation=generation+1 WHERE id=? AND project_id=? AND generation=? AND state='active'").bind(id.to_string()).bind(p).bind(expected as i64).execute(&self.pool).await.map_err(StoreError::Database)?;
        if n.rows_affected() == 0 {
            return Err(StoreError::StaleGeneration);
        }
        self.get_canonical_l3_gateway_attachment(p, id)
            .await?
            .ok_or_else(|| StoreError::Corrupt("attachment disappeared".into()))
    }
    pub async fn finalize_canonical_l3_gateway_attachment_deletion(
        &self,
        p: &str,
        id: &Uuid,
        expected: u64,
    ) -> Result<(), StoreError> {
        let n=sqlx::query("DELETE FROM canonical_l3_gateway_attachments WHERE id=? AND project_id=? AND generation=? AND state='deleting'").bind(id.to_string()).bind(p).bind(expected as i64).execute(&self.pool).await.map_err(StoreError::Database)?;
        if n.rows_affected() == 0 {
            Err(StoreError::StaleGeneration)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl NetworkRepository for SqliteStore {
    async fn get_fabric_host_identity(
        &self,
        host_id: &str,
    ) -> Result<Option<FabricHostTransportIdentityRecord>, StoreError> {
        self.read_fabric_host_identity(host_id).await
    }

    async fn list_fabric_host_identities(
        &self,
    ) -> Result<Vec<FabricHostTransportIdentityRecord>, StoreError> {
        self.read_all_fabric_host_identities().await
    }

    async fn upsert_fabric_host_identity(
        &self,
        identity: &FabricHostTransportIdentityRecord,
        expected_generation: Option<u64>,
    ) -> Result<FabricHostTransportIdentityRecord, StoreError> {
        self.write_fabric_host_identity(identity, expected_generation)
            .await
    }

    async fn get_canonical_owner(
        &self,
        resource_name: &str,
        id: &Uuid,
    ) -> Result<Option<String>, StoreError> {
        let table = match resource_name {
            "network" => "canonical_networks",
            "address_realm" => "canonical_address_realms",
            "address_pool" => "canonical_address_pools",
            "endpoint" => "canonical_endpoints",
            "l3_gateway" => "canonical_l3_gateways",
            "l3_gateway_attachment" => "canonical_l3_gateway_attachments",
            _ => {
                return Err(StoreError::Corrupt(
                    "unknown canonical resource type".into(),
                ));
            }
        };
        let query = format!("SELECT project_id FROM {table} WHERE id = ?");
        sqlx::query_scalar(&query)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)
    }
    async fn insert_canonical_network(
        &self,
        network: &CanonicalNetworkRecord,
    ) -> Result<(), StoreError> {
        self.insert_canonical_network(network).await
    }
    async fn get_canonical_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalNetworkRecord>, StoreError> {
        self.get_canonical_network(project_id, id).await
    }
    async fn list_canonical_networks(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalNetworkRecord>, StoreError> {
        self.list_canonical_networks(project_id).await
    }
    async fn update_canonical_network(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        name: &str,
        admin_state_up: bool,
    ) -> Result<CanonicalNetworkRecord, StoreError> {
        self.update_canonical_network(project_id, id, expected_generation, name, admin_state_up)
            .await
    }
    async fn insert_canonical_l3_gateway(
        &self,
        g: &CanonicalL3GatewayRecord,
    ) -> Result<(), StoreError> {
        self.insert_canonical_l3_gateway(g).await
    }
    async fn get_canonical_l3_gateway(
        &self,
        p: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayRecord>, StoreError> {
        self.get_canonical_l3_gateway(p, id).await
    }
    async fn list_canonical_l3_gateways(
        &self,
        p: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError> {
        self.list_canonical_l3_gateways(p).await
    }
    async fn list_canonical_l3_gateways_by_state(
        &self,
        state: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError> {
        self.list_canonical_l3_gateways_by_state(state).await
    }
    async fn update_canonical_l3_gateway(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
        n: &str,
        x: Option<Uuid>,
        s: bool,
    ) -> Result<CanonicalL3GatewayRecord, StoreError> {
        self.update_canonical_l3_gateway(p, id, e, n, x, s).await
    }
    async fn begin_canonical_l3_gateway_deletion(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
    ) -> Result<CanonicalL3GatewayRecord, StoreError> {
        self.begin_canonical_l3_gateway_deletion(p, id, e).await
    }
    async fn finalize_canonical_l3_gateway_deletion(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
    ) -> Result<(), StoreError> {
        self.finalize_canonical_l3_gateway_deletion(p, id, e).await
    }
    async fn insert_canonical_l3_gateway_attachment(
        &self,
        a: &CanonicalL3GatewayAttachmentRecord,
    ) -> Result<(), StoreError> {
        self.insert_canonical_l3_gateway_attachment(a).await
    }
    async fn get_canonical_l3_gateway_attachment(
        &self,
        p: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        self.get_canonical_l3_gateway_attachment(p, id).await
    }
    async fn list_canonical_l3_gateway_attachments(
        &self,
        p: &str,
        g: &Uuid,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        self.list_canonical_l3_gateway_attachments(p, g).await
    }
    async fn list_canonical_l3_gateway_attachments_by_state(
        &self,
        state: &str,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        self.list_canonical_l3_gateway_attachments_by_state(state)
            .await
    }
    async fn list_canonical_realm_l3_gateway_attachments(
        &self,
        p: &str,
        r: &Uuid,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        self.list_canonical_realm_l3_gateway_attachments(p, r).await
    }
    async fn begin_canonical_l3_gateway_attachment_deletion(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
    ) -> Result<CanonicalL3GatewayAttachmentRecord, StoreError> {
        self.begin_canonical_l3_gateway_attachment_deletion(p, id, e)
            .await
    }
    async fn finalize_canonical_l3_gateway_attachment_deletion(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
    ) -> Result<(), StoreError> {
        self.finalize_canonical_l3_gateway_attachment_deletion(p, id, e)
            .await
    }
    async fn insert_canonical_realm(
        &self,
        realm: &CanonicalAddressRealmRecord,
    ) -> Result<(), StoreError> {
        self.insert_canonical_realm(realm).await
    }
    async fn get_canonical_realm(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalAddressRealmRecord>, StoreError> {
        self.get_canonical_realm(project_id, id).await
    }
    async fn list_canonical_realms(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError> {
        self.list_canonical_realms(project_id, network_id).await
    }

    async fn list_active_canonical_realms(
        &self,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError> {
        self.list_active_canonical_realms().await
    }
    async fn insert_canonical_pool(
        &self,
        pool: &CanonicalAddressPoolRecord,
    ) -> Result<(), StoreError> {
        self.insert_canonical_pool(pool).await
    }
    async fn insert_subnet_bundle(
        &self,
        realm: &CanonicalAddressRealmRecord,
        pool: &CanonicalAddressPoolRecord,
        subnet: &SubnetRecord,
    ) -> Result<(), StoreError> {
        self.insert_subnet_bundle(realm, pool, subnet).await
    }
    async fn list_canonical_pools(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressPoolRecord>, StoreError> {
        self.list_canonical_pools(project_id, realm_id).await
    }
    async fn delete_canonical_pool(
        &self,
        project_id: &str,
        pool_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.delete_canonical_pool(project_id, pool_id).await
    }
    async fn update_canonical_pool(
        &self,
        project_id: &str,
        pool_id: &Uuid,
        expected_generation: u64,
        gateway: Option<Ipv4Addr>,
    ) -> Result<CanonicalAddressPoolRecord, StoreError> {
        self.update_canonical_pool(project_id, pool_id, expected_generation, gateway)
            .await
    }
    async fn insert_canonical_endpoint(
        &self,
        endpoint: &CanonicalEndpointRecord,
    ) -> Result<(), StoreError> {
        self.insert_canonical_endpoint(endpoint).await
    }
    async fn insert_canonical_endpoint_and_port(
        &self,
        endpoint: &CanonicalEndpointRecord,
        port: &PortRecord,
    ) -> Result<(), StoreError> {
        self.insert_canonical_endpoint_and_port(endpoint, port)
            .await
    }
    async fn list_canonical_endpoints(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalEndpointRecord>, StoreError> {
        self.list_canonical_endpoints(project_id, realm_id).await
    }
    async fn get_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<Option<CanonicalEndpointRecord>, StoreError> {
        self.get_canonical_endpoint(project_id, endpoint_id).await
    }
    async fn delete_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.delete_canonical_endpoint(project_id, endpoint_id)
            .await
    }
    async fn delete_canonical_endpoint_and_port(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.delete_canonical_endpoint_and_port(project_id, endpoint_id)
            .await
    }
    async fn upsert_canonical_policy(
        &self,
        policy: &CanonicalNetworkPolicyRecord,
    ) -> Result<(), StoreError> {
        self.upsert_canonical_policy(policy).await
    }
    async fn list_canonical_policies(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRecord>, StoreError> {
        self.list_canonical_policies(project_id, network_id).await
    }
    async fn delete_canonical_policy(
        &self,
        project_id: &str,
        policy_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.delete_canonical_policy(project_id, policy_id).await
    }
    async fn begin_canonical_realm_deletion(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalAddressRealmRecord, StoreError> {
        self.begin_canonical_realm_deletion(project_id, realm_id, expected_generation)
            .await
    }
    async fn advance_canonical_realm_generation(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalAddressRealmRecord, StoreError> {
        self.advance_canonical_realm_generation(project_id, realm_id, expected_generation)
            .await
    }
    async fn finalize_canonical_realm_deletion(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError> {
        self.finalize_canonical_realm_deletion(project_id, realm_id, expected_generation)
            .await
    }
    async fn list_canonical_realm_bindings(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalRealmBindingRecord>, StoreError> {
        self.list_canonical_realm_bindings(realm_id).await
    }
    async fn insert_canonical_realm_binding(
        &self,
        binding: &CanonicalRealmBindingRecord,
    ) -> Result<(), StoreError> {
        self.insert_canonical_realm_binding(binding).await
    }
    async fn get_canonical_realm_binding(
        &self,
        fabric_domain_id: &str,
        realm_id: &Uuid,
    ) -> Result<Option<CanonicalRealmBindingRecord>, StoreError> {
        self.get_canonical_realm_binding(fabric_domain_id, realm_id)
            .await
    }
    async fn delete_canonical_realm_binding(
        &self,
        binding: &CanonicalRealmBindingRecord,
        expected_realm_generation: u64,
    ) -> Result<(), StoreError> {
        self.delete_canonical_realm_binding(binding, expected_realm_generation)
            .await
    }
    async fn delete_canonical_realm(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.delete_canonical_realm(project_id, realm_id).await
    }
    async fn delete_canonical_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.delete_canonical_network(project_id, network_id).await
    }
    async fn backfill_canonical_network_state(&self) -> Result<(), StoreError> {
        self.backfill_canonical_network_state().await
    }
    async fn allocate_network_address(
        &self,
        realm_id: &Uuid,
        project_id: &str,
        endpoint_id: &Uuid,
        operation_id: &str,
        prefix: &str,
    ) -> Result<NetworkAddressAllocationRecord, StoreError> {
        self.allocate_network_address(realm_id, project_id, endpoint_id, operation_id, prefix)
            .await
    }

    async fn release_network_address(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.release_network_address(project_id, endpoint_id).await
    }

    async fn insert_network_intent(&self, intent: &NetworkIntentRecord) -> Result<(), StoreError> {
        self.insert_network_intent(intent).await
    }

    async fn list_network_intents(
        &self,
        project_id: &str,
    ) -> Result<Vec<NetworkIntentRecord>, StoreError> {
        self.list_network_intents(project_id).await
    }

    async fn get_network_intent(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkIntentRecord>, StoreError> {
        self.get_network_intent(project_id, id).await
    }

    async fn update_network_intent(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        payload: &str,
        plan_fingerprint_sha256: Option<&str>,
        status: &str,
    ) -> Result<NetworkIntentRecord, StoreError> {
        self.update_network_intent(
            project_id,
            id,
            expected_generation,
            payload,
            plan_fingerprint_sha256,
            status,
        )
        .await
    }

    async fn insert_network(&self, network: &NetworkRecord) -> Result<(), StoreError> {
        self.insert_network(network).await
    }

    async fn list_networks(&self, project_id: &str) -> Result<Vec<NetworkRecord>, StoreError> {
        self.list_networks(project_id).await
    }

    async fn get_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkRecord>, StoreError> {
        self.get_network(project_id, id).await
    }

    async fn delete_network(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.delete_network(project_id, id).await
    }

    async fn insert_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError> {
        self.insert_subnet(subnet).await
    }

    async fn list_subnets(&self, project_id: &str) -> Result<Vec<SubnetRecord>, StoreError> {
        self.list_subnets(project_id).await
    }

    async fn list_subnets_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<SubnetRecord>, StoreError> {
        self.list_subnets_for_network(project_id, network_id).await
    }

    async fn get_subnet(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SubnetRecord>, StoreError> {
        self.get_subnet(project_id, id).await
    }

    async fn delete_subnet(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.delete_subnet(project_id, id).await
    }
    async fn update_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError> {
        self.update_subnet(subnet).await
    }
    async fn delete_subnet_bundle(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.delete_subnet_bundle(project_id, id).await
    }
    async fn update_subnet_bundle(
        &self,
        subnet: &SubnetRecord,
        pool_id: &Uuid,
        expected_pool_generation: u64,
    ) -> Result<(), StoreError> {
        self.update_subnet_bundle(subnet, pool_id, expected_pool_generation)
            .await
    }

    async fn insert_port(&self, port: &PortRecord) -> Result<(), StoreError> {
        self.insert_port(port).await
    }

    async fn list_ports(&self, project_id: &str) -> Result<Vec<PortRecord>, StoreError> {
        self.list_ports(project_id).await
    }

    async fn list_ports_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<PortRecord>, StoreError> {
        self.list_ports_for_network(project_id, network_id).await
    }

    async fn get_port(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<PortRecord>, StoreError> {
        self.get_port(project_id, id).await
    }

    async fn get_port_by_id(&self, id: &Uuid) -> Result<Option<PortRecord>, StoreError> {
        self.get_port_by_id(id).await
    }

    async fn delete_port(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.delete_port(project_id, id).await
    }

    async fn update_port_binding(
        &self,
        project_id: &str,
        id: &Uuid,
        binding_host: Option<&str>,
        binding_state: Option<&str>,
    ) -> Result<PortRecord, StoreError> {
        self.update_port_binding(project_id, id, binding_host, binding_state)
            .await
    }
    async fn update_port_name(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
    ) -> Result<PortRecord, StoreError> {
        self.update_port_name(project_id, id, name).await
    }

    async fn insert_security_group(&self, group: &SecurityGroupRecord) -> Result<(), StoreError> {
        self.insert_security_group(group).await
    }
    async fn list_security_groups(
        &self,
        project_id: &str,
    ) -> Result<Vec<SecurityGroupRecord>, StoreError> {
        self.list_security_groups(project_id).await
    }
    async fn get_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRecord>, StoreError> {
        self.get_security_group(project_id, id).await
    }
    async fn update_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
        description: &str,
    ) -> Result<SecurityGroupRecord, StoreError> {
        self.update_security_group(project_id, id, name, description)
            .await
    }
    async fn delete_security_group(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.delete_security_group(project_id, id).await
    }
    async fn insert_security_group_rule(
        &self,
        rule: &SecurityGroupRuleRecord,
    ) -> Result<(), StoreError> {
        self.insert_security_group_rule(rule).await
    }
    async fn list_security_group_rules(
        &self,
        project_id: &str,
        group_id: &Uuid,
    ) -> Result<Vec<SecurityGroupRuleRecord>, StoreError> {
        self.list_security_group_rules(project_id, group_id).await
    }
    async fn get_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRuleRecord>, StoreError> {
        self.get_security_group_rule(project_id, id).await
    }
    async fn delete_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<(), StoreError> {
        self.delete_security_group_rule(project_id, id).await
    }
    async fn list_security_group_bindings(
        &self,
        project_id: &str,
        endpoint_id: Option<&Uuid>,
    ) -> Result<Vec<SecurityGroupBindingRecord>, StoreError> {
        self.list_security_group_bindings(project_id, endpoint_id)
            .await
    }
    async fn replace_security_group_bindings(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
        group_ids: &[Uuid],
    ) -> Result<(), StoreError> {
        self.replace_security_group_bindings(project_id, endpoint_id, group_ids)
            .await
    }
}
