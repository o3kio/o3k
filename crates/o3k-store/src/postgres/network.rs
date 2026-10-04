use async_trait::async_trait;
use sqlx::Row;
use std::net::Ipv4Addr;
use uuid::Uuid;

use crate::{
    CanonicalAddressPoolRecord, CanonicalAddressRealmRecord, CanonicalEndpointRecord,
    CanonicalL3GatewayAttachmentRecord, CanonicalL3GatewayRecord, CanonicalNetworkPolicyRecord,
    CanonicalNetworkRecord, CanonicalRealmBindingRecord, FabricHostTransportIdentityRecord,
    NetworkAddressAllocationRecord, NetworkIntentRecord, NetworkRecord, NetworkRepository,
    PortRecord, SecurityGroupBindingRecord, SecurityGroupRecord, SecurityGroupRuleRecord,
    StoreError, SubnetRecord,
};

use super::{
    PostgresStore,
    helpers::{
        allocation_bounds, canonical_endpoint_from_pg_row, canonical_network_from_pg_row,
        canonical_policy_from_pg_row, canonical_pool_from_pg_row, canonical_realm_from_pg_row,
        map_pg_error, parse_pg_ipv4_prefix, parse_pg_network, parse_pg_network_allocation,
        parse_pg_network_intent, parse_pg_port, parse_pg_subnet,
        pg_security_group_binding_from_row, pg_security_group_from_row,
        pg_security_group_rule_from_row, validate_network_intent,
    },
};

impl PostgresStore {
    async fn read_fabric_host_identity(
        &self,
        host_id: &str,
    ) -> Result<Option<FabricHostTransportIdentityRecord>, StoreError> {
        let row = sqlx::query("SELECT host_id,agent_id,public_key,underlay_endpoint,host(fabric_transport_ip) AS fabric_transport_ip,provider_version,fabric_generation,underlay_mtu,fabric_mtu,administrative_state FROM canonical_fabric_host_transport_identities WHERE host_id=$1")
            .bind(host_id).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        row.map(|row| {
            let generation: i64 = row
                .try_get("fabric_generation")
                .map_err(StoreError::Database)?;
            let underlay_mtu: i32 = row.try_get("underlay_mtu").map_err(StoreError::Database)?;
            let fabric_mtu: i32 = row.try_get("fabric_mtu").map_err(StoreError::Database)?;
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

    async fn write_fabric_host_identity(
        &self,
        identity: &FabricHostTransportIdentityRecord,
        expected_generation: Option<u64>,
    ) -> Result<FabricHostTransportIdentityRecord, StoreError> {
        crate::validate_fabric_host_identity(identity)?;
        let current = self.read_fabric_host_identity(&identity.host_id).await?;
        match (current, expected_generation) {
            (None, None) => {
                sqlx::query("INSERT INTO canonical_fabric_host_transport_identities(host_id,agent_id,public_key,underlay_endpoint,fabric_transport_ip,provider_version,fabric_generation,underlay_mtu,fabric_mtu,administrative_state) VALUES($1,$2,$3,$4,$5::inet,$6,$7,$8,$9,$10)")
                    .bind(&identity.host_id).bind(&identity.agent_id).bind(&identity.public_key).bind(&identity.underlay_endpoint).bind(identity.fabric_transport_ip.to_string()).bind(&identity.provider_version).bind(crate::checked_generation(identity.fabric_generation)?).bind(i32::from(identity.underlay_mtu)).bind(i32::from(identity.fabric_mtu)).bind(&identity.administrative_state)
                    .execute(&self.pool).await.map_err(crate::map_canonical_insert_error)?;
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
                let updated = sqlx::query("UPDATE canonical_fabric_host_transport_identities SET agent_id=$1,public_key=$2,underlay_endpoint=$3,fabric_transport_ip=$4::inet,provider_version=$5,fabric_generation=$6,underlay_mtu=$7,fabric_mtu=$8,administrative_state=$9 WHERE host_id=$10 AND fabric_generation=$11")
                    .bind(&identity.agent_id).bind(&identity.public_key).bind(&identity.underlay_endpoint).bind(identity.fabric_transport_ip.to_string()).bind(&identity.provider_version).bind(crate::checked_generation(identity.fabric_generation)?).bind(i32::from(identity.underlay_mtu)).bind(i32::from(identity.fabric_mtu)).bind(&identity.administrative_state).bind(&identity.host_id).bind(crate::checked_generation(expected)?)
                    .execute(&self.pool).await.map_err(crate::map_canonical_insert_error)?;
                if updated.rows_affected() != 1 {
                    return Err(StoreError::StaleGeneration);
                }
            }
            (None, Some(_)) | (Some(_), None) | (Some(_), Some(_)) => {
                return Err(StoreError::StaleGeneration);
            }
        }
        self.read_fabric_host_identity(&identity.host_id)
            .await?
            .ok_or(StoreError::ResourceNotFound)
    }

    pub async fn get_fabric_host_identity(
        &self,
        host_id: &str,
    ) -> Result<Option<FabricHostTransportIdentityRecord>, StoreError> {
        self.read_fabric_host_identity(host_id).await
    }

    pub async fn list_fabric_host_identities(
        &self,
    ) -> Result<Vec<FabricHostTransportIdentityRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT host_id FROM canonical_fabric_host_transport_identities ORDER BY host_id",
        )
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

    pub async fn upsert_fabric_host_identity(
        &self,
        identity: &FabricHostTransportIdentityRecord,
        expected_generation: Option<u64>,
    ) -> Result<FabricHostTransportIdentityRecord, StoreError> {
        self.write_fabric_host_identity(identity, expected_generation)
            .await
    }

    pub async fn insert_canonical_l3_gateway(
        &self,
        g: &CanonicalL3GatewayRecord,
    ) -> Result<(), StoreError> {
        crate::validate_canonical_state(&g.state)?;
        crate::checked_generation(g.generation)?;
        sqlx::query("INSERT INTO canonical_l3_gateways (id,project_id,name,external_realm_id,enable_snat,generation,state) VALUES ($1,$2,$3,$4,$5,$6,$7)").bind(g.id).bind(&g.project_id).bind(&g.name).bind(g.external_realm_id.map(|value| value.to_string())).bind(g.enable_snat).bind(g.generation as i64).bind(&g.state).execute(&self.pool).await.map_err(crate::map_canonical_insert_error).map(|_|())
    }
    pub async fn get_canonical_l3_gateway(
        &self,
        p: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayRecord>, StoreError> {
        let r=sqlx::query("SELECT id,project_id,name,external_realm_id,enable_snat,generation,state FROM canonical_l3_gateways WHERE id=$1 AND project_id=$2").bind(id).bind(p).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        r.map(|x| {
            Ok(CanonicalL3GatewayRecord {
                id: x.try_get("id").map_err(StoreError::Database)?,
                project_id: x.try_get("project_id").map_err(StoreError::Database)?,
                name: x.try_get("name").map_err(StoreError::Database)?,
                external_realm_id: x
                    .try_get::<Option<String>, _>("external_realm_id")
                    .map_err(StoreError::Database)?
                    .map(|value| value.parse().map_err(StoreError::InvalidUuid))
                    .transpose()?,
                enable_snat: x.try_get("enable_snat").map_err(StoreError::Database)?,
                generation: crate::checked_generation(
                    x.try_get::<i64, _>("generation")
                        .map_err(StoreError::Database)? as u64,
                )? as u64,
                state: x.try_get("state").map_err(StoreError::Database)?,
            })
        })
        .transpose()
    }
    pub async fn list_canonical_l3_gateways(
        &self,
        p: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError> {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM canonical_l3_gateways WHERE project_id=$1 ORDER BY id",
        )
        .bind(p)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let mut out = Vec::new();
        for id in ids {
            out.push(
                self.get_canonical_l3_gateway(p, &id)
                    .await?
                    .ok_or_else(|| StoreError::Corrupt("gateway disappeared".into()))?,
            )
        }
        Ok(out)
    }
    pub async fn list_canonical_l3_gateways_by_state(
        &self,
        state: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, project_id FROM canonical_l3_gateways WHERE state=$1 ORDER BY project_id,id",
        )
        .bind(state)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let mut out = Vec::new();
        for row in rows {
            let id: Uuid = row.try_get("id").map_err(StoreError::Database)?;
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
        p: &str,
        id: &Uuid,
        e: u64,
        n: &str,
        x: Option<Uuid>,
        s: bool,
    ) -> Result<CanonicalL3GatewayRecord, StoreError> {
        let r=sqlx::query("UPDATE canonical_l3_gateways SET name=$1,external_realm_id=$2,enable_snat=$3,generation=generation+1 WHERE id=$4 AND project_id=$5 AND generation=$6 AND state='active'").bind(n).bind(x.map(|value| value.to_string())).bind(s).bind(id).bind(p).bind(e as i64).execute(&self.pool).await.map_err(StoreError::Database)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::StaleGeneration);
        }
        self.get_canonical_l3_gateway(p, id)
            .await?
            .ok_or_else(|| StoreError::Corrupt("gateway disappeared".into()))
    }
    async fn classify_l3_gateway_deletion_failure(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
        required_state: &str,
    ) -> Result<StoreError, StoreError> {
        let r = sqlx::query(
            "SELECT project_id,generation,state FROM canonical_l3_gateways WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let Some(r) = r else {
            return Ok(StoreError::OwnershipConflict);
        };
        let owner: String = r.try_get("project_id").map_err(StoreError::Database)?;
        if owner != p {
            return Ok(StoreError::OwnershipConflict);
        }
        let generation = crate::checked_generation(
            r.try_get::<i64, _>("generation")
                .map_err(StoreError::Database)? as u64,
        )? as u64;
        if generation != e {
            return Ok(StoreError::StaleGeneration);
        }
        let state: String = r.try_get("state").map_err(StoreError::Database)?;
        if state != required_state {
            return Ok(StoreError::OwnershipConflict);
        }
        Ok(StoreError::NetworkInUse)
    }
    pub async fn begin_canonical_l3_gateway_deletion(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
    ) -> Result<CanonicalL3GatewayRecord, StoreError> {
        let r=sqlx::query("UPDATE canonical_l3_gateways SET state='deleting',generation=generation+1 WHERE id=$1 AND project_id=$2 AND generation=$3 AND state='active' AND NOT EXISTS (SELECT 1 FROM canonical_l3_gateway_attachments WHERE gateway_id=$1 AND state IN ('active','deleting'))").bind(id).bind(p).bind(e as i64).execute(&self.pool).await.map_err(StoreError::Database)?;
        if r.rows_affected() == 0 {
            return Err(self
                .classify_l3_gateway_deletion_failure(p, id, e, "active")
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
        e: u64,
    ) -> Result<(), StoreError> {
        let r=sqlx::query("DELETE FROM canonical_l3_gateways WHERE id=$1 AND project_id=$2 AND generation=$3 AND state='deleting' AND NOT EXISTS (SELECT 1 FROM canonical_l3_gateway_attachments WHERE gateway_id=$1 AND state IN ('active','deleting'))").bind(id).bind(p).bind(e as i64).execute(&self.pool).await.map_err(StoreError::Database)?;
        if r.rows_affected() == 0 {
            Err(self
                .classify_l3_gateway_deletion_failure(p, id, e, "deleting")
                .await?)
        } else {
            Ok(())
        }
    }
    pub async fn insert_canonical_l3_gateway_attachment(
        &self,
        a: &CanonicalL3GatewayAttachmentRecord,
    ) -> Result<(), StoreError> {
        crate::validate_canonical_state(&a.state)?;
        crate::checked_generation(a.generation)?;
        sqlx::query("INSERT INTO canonical_l3_gateway_attachments (id,gateway_id,realm_id,project_id,generation,state) VALUES ($1,$2,$3,$4,$5,$6)").bind(a.id).bind(a.gateway_id).bind(a.realm_id.to_string()).bind(&a.project_id).bind(a.generation as i64).bind(&a.state).execute(&self.pool).await.map_err(crate::map_canonical_insert_error).map(|_|())
    }
    pub async fn get_canonical_l3_gateway_attachment(
        &self,
        p: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        let r=sqlx::query("SELECT id,gateway_id,realm_id,project_id,generation,state FROM canonical_l3_gateway_attachments WHERE id=$1 AND project_id=$2").bind(id).bind(p).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        r.map(|x| {
            Ok(CanonicalL3GatewayAttachmentRecord {
                id: x.try_get("id").map_err(StoreError::Database)?,
                gateway_id: x.try_get("gateway_id").map_err(StoreError::Database)?,
                realm_id: x
                    .try_get::<String, _>("realm_id")
                    .map_err(StoreError::Database)?
                    .parse()
                    .map_err(StoreError::InvalidUuid)?,
                project_id: x.try_get("project_id").map_err(StoreError::Database)?,
                generation: crate::checked_generation(
                    x.try_get::<i64, _>("generation")
                        .map_err(StoreError::Database)? as u64,
                )? as u64,
                state: x.try_get("state").map_err(StoreError::Database)?,
            })
        })
        .transpose()
    }
    pub async fn list_canonical_l3_gateway_attachments(
        &self,
        p: &str,
        g: &Uuid,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM canonical_l3_gateway_attachments WHERE project_id=$1 AND gateway_id=$2 ORDER BY id").bind(p).bind(g).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        let mut out = Vec::new();
        for id in ids {
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
            "SELECT id, project_id FROM canonical_l3_gateway_attachments WHERE state=$1 ORDER BY project_id,id",
        )
        .bind(state)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let mut out = Vec::new();
        for row in rows {
            let id: Uuid = row.try_get("id").map_err(StoreError::Database)?;
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
        let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM canonical_l3_gateway_attachments WHERE project_id=$1 AND realm_id=$2 ORDER BY id").bind(p).bind(r).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        let mut out = Vec::new();
        for id in ids {
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
        e: u64,
    ) -> Result<CanonicalL3GatewayAttachmentRecord, StoreError> {
        let r=sqlx::query("UPDATE canonical_l3_gateway_attachments SET state='deleting',generation=generation+1 WHERE id=$1 AND project_id=$2 AND generation=$3 AND state='active'").bind(id).bind(p).bind(e as i64).execute(&self.pool).await.map_err(StoreError::Database)?;
        if r.rows_affected() == 0 {
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
        e: u64,
    ) -> Result<(), StoreError> {
        let r=sqlx::query("DELETE FROM canonical_l3_gateway_attachments WHERE id=$1 AND project_id=$2 AND generation=$3 AND state='deleting'").bind(id).bind(p).bind(e as i64).execute(&self.pool).await.map_err(StoreError::Database)?;
        if r.rows_affected() == 0 {
            Err(StoreError::StaleGeneration)
        } else {
            Ok(())
        }
    }
    pub async fn insert_canonical_network(
        &self,
        network: &CanonicalNetworkRecord,
    ) -> Result<(), StoreError> {
        crate::validate_canonical_state(&network.state)?;
        sqlx::query(
            "INSERT INTO canonical_networks (id, project_id, name, admin_state_up, generation, state) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(network.id.to_string())
        .bind(&network.project_id)
        .bind(&network.name)
        .bind(network.admin_state_up)
        .bind(crate::checked_generation(network.generation)?)
        .bind(&network.state)
        .execute(&self.pool)
        .await
        .map_err(crate::map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn get_canonical_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalNetworkRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, project_id, name, admin_state_up, generation, state FROM canonical_networks WHERE id = $1 AND project_id = $2",
        )
        .bind(id.to_string())
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(canonical_network_from_pg_row).transpose()
    }

    pub async fn list_canonical_networks(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalNetworkRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, project_id, name, admin_state_up, generation, state FROM canonical_networks WHERE project_id = $1 ORDER BY id",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_network_from_pg_row).collect()
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
            "SELECT COUNT(*) FROM canonical_networks WHERE project_id = $1 AND name = $2 AND id <> $3",
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
            "UPDATE canonical_networks SET name = $1, admin_state_up = $2, generation = generation + 1 WHERE id = $3 AND project_id = $4 AND generation = $5 AND state = 'active'",
        )
        .bind(name)
        .bind(admin_state_up)
        .bind(id.to_string())
        .bind(project_id)
        .bind(crate::checked_generation(expected_generation)?)
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
        sqlx::query("UPDATE network_networks SET name = $1 WHERE id = $2 AND project_id = $3")
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
            "DELETE FROM canonical_networks WHERE id = $1 AND project_id = $2 AND NOT EXISTS (SELECT 1 FROM canonical_address_realms WHERE network_id = canonical_networks.id)",
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
        crate::validate_canonical_state(&realm.state)?;
        let network = sqlx::query("SELECT project_id FROM canonical_networks WHERE id = $1")
            .bind(realm.network_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::NetworkNotFound)?;
        if network.get::<String, _>("project_id") != realm.project_id {
            return Err(StoreError::OwnershipConflict);
        }
        sqlx::query(
            "INSERT INTO canonical_address_realms (id, network_id, project_id, prefix, overlapping_prefixes, generation, state) VALUES ($1, $2, $3, $4::cidr, $5, $6, $7)",
        )
        .bind(realm.id.to_string())
        .bind(realm.network_id.to_string())
        .bind(&realm.project_id)
        .bind(&realm.prefix)
        .bind(realm.overlapping_prefixes)
        .bind(crate::checked_generation(realm.generation)?)
        .bind(&realm.state)
        .execute(&self.pool)
        .await
        .map_err(crate::map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn list_canonical_realms(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, network_id, project_id, prefix::text AS prefix, overlapping_prefixes, generation, state FROM canonical_address_realms WHERE project_id = $1 AND network_id = $2 ORDER BY id",
        )
        .bind(project_id)
        .bind(network_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_realm_from_pg_row).collect()
    }

    pub async fn list_active_canonical_realms(
        &self,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, network_id, project_id, prefix::text AS prefix, overlapping_prefixes, generation, state FROM canonical_address_realms WHERE state = 'active' ORDER BY project_id, network_id, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_realm_from_pg_row).collect()
    }

    pub async fn get_canonical_realm(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalAddressRealmRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, network_id, project_id, prefix::text AS prefix, overlapping_prefixes, generation, state FROM canonical_address_realms WHERE project_id = $1 AND id = $2",
        )
        .bind(project_id)
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(canonical_realm_from_pg_row).transpose()
    }

    pub async fn delete_canonical_realm(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "DELETE FROM canonical_address_realms WHERE id = $1 AND project_id = $2 AND NOT EXISTS (SELECT 1 FROM canonical_address_pools WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_endpoints WHERE realm_id = canonical_address_realms.id)",
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

    pub async fn insert_canonical_pool(
        &self,
        pool: &CanonicalAddressPoolRecord,
    ) -> Result<(), StoreError> {
        crate::validate_canonical_state(&pool.state)?;
        let realm = sqlx::query("SELECT project_id FROM canonical_address_realms WHERE id = $1")
            .bind(pool.realm_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?;
        if realm.get::<String, _>("project_id") != pool.project_id {
            return Err(StoreError::OwnershipConflict);
        }
        sqlx::query(
            "INSERT INTO canonical_address_pools (id, realm_id, project_id, prefix, gateway, first_usable, last_usable, generation, state) VALUES ($1, $2, $3, $4::cidr, $5::inet, $6::inet, $7::inet, $8, $9)",
        )
        .bind(pool.id.to_string())
        .bind(pool.realm_id.to_string())
        .bind(&pool.project_id)
        .bind(&pool.prefix)
        .bind(pool.gateway.map(|value| value.to_string()))
        .bind(pool.first_usable.to_string())
        .bind(pool.last_usable.to_string())
        .bind(crate::checked_generation(pool.generation)?)
        .bind(&pool.state)
        .execute(&self.pool)
        .await
        .map_err(crate::map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn insert_subnet_bundle(
        &self,
        realm: &CanonicalAddressRealmRecord,
        pool: &CanonicalAddressPoolRecord,
        subnet: &SubnetRecord,
    ) -> Result<(), StoreError> {
        crate::validate_canonical_state(&realm.state)?;
        crate::validate_canonical_state(&pool.state)?;
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let owner: Option<String> = sqlx::query_scalar("SELECT project_id FROM canonical_networks WHERE id = $1 AND state = 'active' FOR UPDATE")
            .bind(realm.network_id.to_string()).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
        if owner.as_deref() != Some(realm.project_id.as_str())
            || realm.project_id != pool.project_id
            || realm.project_id != subnet.project_id
            || realm.id != subnet.id
        {
            return Err(StoreError::OwnershipConflict);
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM canonical_address_realms WHERE network_id = $1 AND project_id = $2 AND state = 'active'")
            .bind(realm.network_id.to_string()).bind(&realm.project_id).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
        if count != 0 {
            return Err(StoreError::NetworkInUse);
        }
        sqlx::query("INSERT INTO canonical_address_realms (id, network_id, project_id, prefix, overlapping_prefixes, generation, state) VALUES ($1, $2, $3, $4::cidr, $5, $6, $7)")
            .bind(realm.id.to_string()).bind(realm.network_id.to_string()).bind(&realm.project_id).bind(&realm.prefix).bind(realm.overlapping_prefixes).bind(crate::checked_generation(realm.generation)?).bind(&realm.state).execute(&mut *tx).await.map_err(crate::map_canonical_insert_error)?;
        sqlx::query("INSERT INTO canonical_address_pools (id, realm_id, project_id, prefix, gateway, first_usable, last_usable, generation, state) VALUES ($1, $2, $3, $4::cidr, $5::inet, $6::inet, $7::inet, $8, $9)")
            .bind(pool.id.to_string()).bind(pool.realm_id.to_string()).bind(&pool.project_id).bind(&pool.prefix).bind(pool.gateway.map(|v| v.to_string())).bind(pool.first_usable.to_string()).bind(pool.last_usable.to_string()).bind(crate::checked_generation(pool.generation)?).bind(&pool.state).execute(&mut *tx).await.map_err(crate::map_canonical_insert_error)?;
        sqlx::query("INSERT INTO network_subnets (id, network_id, name, project_id, cidr, gateway_ip, allocation_start, allocation_end, ip_version, enable_dhcp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)")
            .bind(subnet.id.to_string()).bind(subnet.network_id.to_string()).bind(&subnet.name).bind(&subnet.project_id).bind(&subnet.cidr).bind(subnet.gateway_ip.to_string()).bind(subnet.allocation_start.to_string()).bind(subnet.allocation_end.to_string()).bind(i16::from(subnet.ip_version)).bind(subnet.enable_dhcp).execute(&mut *tx).await.map_err(crate::map_canonical_insert_error)?;
        tx.commit().await.map_err(StoreError::Database)
    }

    pub async fn list_canonical_pools(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressPoolRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, realm_id, project_id, prefix::text AS prefix, gateway::text AS gateway, first_usable::text AS first_usable, last_usable::text AS last_usable, generation, state FROM canonical_address_pools WHERE project_id = $1 AND realm_id = $2 ORDER BY id",
        )
        .bind(project_id)
        .bind(realm_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_pool_from_pg_row).collect()
    }

    pub async fn delete_canonical_pool(
        &self,
        project_id: &str,
        pool_id: &Uuid,
    ) -> Result<(), StoreError> {
        let result =
            sqlx::query("DELETE FROM canonical_address_pools WHERE id = $1 AND project_id = $2")
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
            "UPDATE canonical_address_pools SET gateway = $1::inet, generation = generation + 1 WHERE id = $2 AND project_id = $3 AND generation = $4 AND state = 'active'",
        )
        .bind(gateway.map(|value| value.to_string()))
        .bind(pool_id.to_string())
        .bind(project_id)
        .bind(crate::checked_generation(expected_generation)?)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::StaleGeneration);
        }
        let row = sqlx::query("SELECT id, realm_id, project_id, prefix::text AS prefix, gateway::text AS gateway, first_usable::text AS first_usable, last_usable::text AS last_usable, generation, state FROM canonical_address_pools WHERE id = $1 AND project_id = $2")
            .bind(pool_id.to_string())
            .bind(project_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?;
        canonical_pool_from_pg_row(&row)
    }

    pub async fn insert_canonical_endpoint(
        &self,
        endpoint: &CanonicalEndpointRecord,
    ) -> Result<(), StoreError> {
        crate::validate_canonical_state(&endpoint.state)?;
        let realm = sqlx::query("SELECT project_id FROM canonical_address_realms WHERE id = $1")
            .bind(endpoint.realm_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?;
        if realm.get::<String, _>("project_id") != endpoint.project_id {
            return Err(StoreError::OwnershipConflict);
        }
        sqlx::query(
            "INSERT INTO canonical_endpoints (id, realm_id, project_id, fixed_ip, mac, generation, state) VALUES ($1, $2, $3, $4::inet, $5, $6, $7)",
        )
        .bind(endpoint.id.to_string())
        .bind(endpoint.realm_id.to_string())
        .bind(&endpoint.project_id)
        .bind(endpoint.fixed_ip.to_string())
        .bind(&endpoint.mac)
        .bind(crate::checked_generation(endpoint.generation)?)
        .bind(&endpoint.state)
        .execute(&self.pool)
        .await
        .map_err(crate::map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn insert_canonical_endpoint_and_port(
        &self,
        endpoint: &CanonicalEndpointRecord,
        port: &PortRecord,
    ) -> Result<(), StoreError> {
        crate::validate_canonical_state(&endpoint.state)?;
        let subnet_id = port.subnet_id.ok_or(StoreError::ResourceNotFound)?;
        if endpoint.id != port.id
            || endpoint.realm_id != subnet_id
            || endpoint.project_id != port.project_id
        {
            return Err(StoreError::OwnershipConflict);
        }
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let realm = sqlx::query(
            "SELECT network_id, project_id FROM canonical_address_realms WHERE id = $1 AND state = 'active'",
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
            "INSERT INTO canonical_endpoints (id, realm_id, project_id, fixed_ip, mac, generation, state) VALUES ($1, $2, $3, $4::inet, $5, $6, $7)",
        )
        .bind(endpoint.id.to_string())
        .bind(endpoint.realm_id.to_string())
        .bind(&endpoint.project_id)
        .bind(endpoint.fixed_ip.to_string())
        .bind(&endpoint.mac)
        .bind(crate::checked_generation(endpoint.generation)?)
        .bind(&endpoint.state)
        .execute(&mut *tx)
        .await
        .map_err(crate::map_canonical_insert_error)?;
        sqlx::query(
            "INSERT INTO network_ports (id, network_id, subnet_id, project_id, name, mac_address, fixed_ip, status, binding_host, binding_state) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(port.id.to_string())
        .bind(port.network_id.to_string())
        .bind(subnet_id.to_string())
        .bind(&port.project_id)
        .bind(&port.name)
        .bind(&port.mac_address)
        .bind(port.fixed_ip.to_string())
        .bind(&port.status)
        .bind(&port.binding_host)
        .bind(&port.binding_state)
        .execute(&mut *tx)
        .await
        .map_err(crate::map_canonical_insert_error)?;
        tx.commit().await.map_err(StoreError::Database)
    }

    pub async fn list_canonical_endpoints(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalEndpointRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, realm_id, project_id, fixed_ip::text AS fixed_ip, mac, generation, state FROM canonical_endpoints WHERE project_id = $1 AND realm_id = $2 ORDER BY id",
        )
        .bind(project_id)
        .bind(realm_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_endpoint_from_pg_row).collect()
    }

    pub async fn get_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<Option<CanonicalEndpointRecord>, StoreError> {
        let row = sqlx::query("SELECT id, realm_id, project_id, fixed_ip::text AS fixed_ip, mac, generation, state FROM canonical_endpoints WHERE id = $1 AND project_id = $2")
            .bind(endpoint_id.to_string()).bind(project_id).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        row.as_ref().map(canonical_endpoint_from_pg_row).transpose()
    }

    pub async fn delete_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM canonical_network_policies WHERE endpoint_id = $1 AND project_id = $2",
        )
        .bind(endpoint_id.to_string())
        .bind(project_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let result =
            sqlx::query("DELETE FROM canonical_endpoints WHERE id = $1 AND project_id = $2")
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
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query(
            "DELETE FROM canonical_network_policies WHERE endpoint_id = $1 AND project_id = $2",
        )
        .bind(endpoint_id.to_string())
        .bind(project_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        let result =
            sqlx::query("DELETE FROM canonical_endpoints WHERE id = $1 AND project_id = $2")
                .bind(endpoint_id.to_string())
                .bind(project_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::ResourceNotFound);
        }
        sqlx::query("DELETE FROM network_ports WHERE id = $1 AND project_id = $2")
            .bind(endpoint_id.to_string())
            .bind(project_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)
    }

    pub async fn upsert_canonical_policy(
        &self,
        policy: &CanonicalNetworkPolicyRecord,
    ) -> Result<(), StoreError> {
        let endpoint_project: String =
            sqlx::query_scalar("SELECT project_id FROM canonical_endpoints WHERE id = $1")
                .bind(policy.endpoint_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?
                .ok_or(StoreError::ResourceNotFound)?;
        if endpoint_project != policy.project_id {
            return Err(StoreError::OwnershipConflict);
        }
        crate::checked_generation(policy.generation)?;
        sqlx::query(
            "INSERT INTO canonical_network_policies (id, project_id, endpoint_id, direction, protocol, port_min, port_max, source, destination, action, generation, state) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::cidr, $9::cidr, $10, $11, $12) ON CONFLICT(id) DO UPDATE SET project_id=excluded.project_id, endpoint_id=excluded.endpoint_id, direction=excluded.direction, protocol=excluded.protocol, port_min=excluded.port_min, port_max=excluded.port_max, source=excluded.source, destination=excluded.destination, action=excluded.action, generation=excluded.generation, state=excluded.state",
        )
        .bind(policy.id.to_string())
        .bind(&policy.project_id)
        .bind(policy.endpoint_id.to_string())
        .bind(&policy.direction)
        .bind(&policy.protocol)
        .bind(policy.port_min.map(i32::from))
        .bind(policy.port_max.map(i32::from))
        .bind(&policy.source)
        .bind(&policy.destination)
        .bind(&policy.action)
        .bind(crate::checked_generation(policy.generation)?)
        .bind(&policy.state)
        .execute(&self.pool)
        .await
        .map_err(crate::map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn list_canonical_policies(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT p.id, p.project_id, p.endpoint_id, p.direction, p.protocol, p.port_min, p.port_max, p.source::text AS source, p.destination::text AS destination, p.action, p.generation, p.state FROM canonical_network_policies p JOIN canonical_endpoints e ON e.id = p.endpoint_id JOIN canonical_address_realms r ON r.id = e.realm_id WHERE p.project_id = $1 AND r.project_id = $1 AND r.network_id = $2 ORDER BY p.id",
        )
        .bind(project_id)
        .bind(network_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(canonical_policy_from_pg_row).collect()
    }

    pub async fn delete_canonical_policy(
        &self,
        project_id: &str,
        policy_id: &Uuid,
    ) -> Result<(), StoreError> {
        let result =
            sqlx::query("DELETE FROM canonical_network_policies WHERE id = $1 AND project_id = $2")
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
            "UPDATE canonical_address_realms SET state = 'deleting', generation = generation + 1 WHERE id = $1 AND project_id = $2 AND generation = $3 AND state = 'active' AND NOT EXISTS (SELECT 1 FROM canonical_address_pools WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_endpoints WHERE realm_id = canonical_address_realms.id)",
        )
        .bind(realm_id.to_string())
        .bind(project_id)
        .bind(crate::checked_generation(expected_generation)?)
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
        let updated = sqlx::query("UPDATE canonical_address_realms SET generation = generation + 1 WHERE id = $1 AND project_id = $2 AND generation = $3 AND state = 'active'")
            .bind(realm_id.to_string())
            .bind(project_id)
            .bind(crate::checked_generation(expected_generation)?)
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
            "DELETE FROM canonical_address_realms WHERE id = $1 AND project_id = $2 AND generation = $3 AND state = 'deleting' AND NOT EXISTS (SELECT 1 FROM canonical_address_pools WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_endpoints WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_network_policies p JOIN canonical_endpoints e ON e.id = p.endpoint_id WHERE e.realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_realm_encapsulation_bindings WHERE realm_id = canonical_address_realms.id)",
        )
        .bind(realm_id.to_string())
        .bind(project_id)
        .bind(crate::checked_generation(expected_generation)?)
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
        let realm = sqlx::query("SELECT 1 FROM canonical_address_realms WHERE id = $1")
            .bind(binding.realm_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        if realm.is_none() {
            return Err(StoreError::ResourceNotFound);
        }
        crate::validate_canonical_state(&binding.state)?;
        sqlx::query(
            "INSERT INTO canonical_realm_encapsulation_bindings (fabric_domain_id, realm_id, provider_kind, provider_segment_id, binding_generation, state) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&binding.fabric_domain_id)
        .bind(binding.realm_id.to_string())
        .bind(&binding.provider_kind)
        .bind(crate::checked_generation(binding.provider_segment_id)?)
        .bind(crate::checked_generation(binding.binding_generation)?)
        .bind(&binding.state)
        .execute(&self.pool)
        .await
        .map_err(crate::map_canonical_insert_error)
        .map(|_| ())
    }

    pub async fn get_canonical_realm_binding(
        &self,
        fabric_domain_id: &str,
        realm_id: &Uuid,
    ) -> Result<Option<CanonicalRealmBindingRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT fabric_domain_id, realm_id, provider_kind, provider_segment_id, binding_generation, state FROM canonical_realm_encapsulation_bindings WHERE fabric_domain_id = $1 AND realm_id = $2",
        )
        .bind(fabric_domain_id)
        .bind(realm_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.map(|row| {
            Ok(CanonicalRealmBindingRecord {
                fabric_domain_id: row.get("fabric_domain_id"),
                realm_id: Uuid::parse_str(row.get::<&str, _>("realm_id"))
                    .map_err(StoreError::InvalidUuid)?,
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
        let rows = sqlx::query("SELECT fabric_domain_id, realm_id, provider_kind, provider_segment_id, binding_generation, state FROM canonical_realm_encapsulation_bindings WHERE realm_id = $1 ORDER BY fabric_domain_id")
            .bind(realm_id.to_string()).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.into_iter()
            .map(|row| {
                Ok(CanonicalRealmBindingRecord {
                    fabric_domain_id: row.get("fabric_domain_id"),
                    realm_id: Uuid::parse_str(row.get::<&str, _>("realm_id"))
                        .map_err(StoreError::InvalidUuid)?,
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
        let result = sqlx::query("DELETE FROM canonical_realm_encapsulation_bindings WHERE fabric_domain_id = $1 AND realm_id = $2 AND provider_kind = $3 AND provider_segment_id = $4 AND binding_generation = $5 AND binding_generation < $6")
            .bind(&binding.fabric_domain_id).bind(binding.realm_id.to_string()).bind(&binding.provider_kind)
            .bind(crate::checked_generation(binding.provider_segment_id)?).bind(crate::checked_generation(binding.binding_generation)?)
            .bind(crate::checked_generation(expected_realm_generation)?).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::StaleGeneration);
        }
        Ok(())
    }

    async fn backfill_canonical_network_state(&self) -> Result<(), StoreError> {
        // PostgreSQL uses the same legacy-source audit and identity-preserving
        // materialization as SQLite. The transaction makes retry after a
        // failed validation safe and prevents partially inserted relations.
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let intents = sqlx::query(
            "SELECT id, project_id, generation, payload, status FROM network_intents ORDER BY id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        for intent in &intents {
            let id_text: String = intent.get("id");
            if Uuid::parse_str(&id_text).is_err() {
                continue;
            }
            let generation: i64 = intent.get("generation");
            let generation = u64::try_from(generation)
                .map_err(|_| StoreError::Corrupt("negative network intent generation".into()))?;
            let state: String = intent.get("status");
            crate::validate_canonical_state(&state)?;
            sqlx::query(
                "INSERT INTO canonical_networks (id, project_id, name, generation, state) VALUES ($1, $2, '', $3, $4) ON CONFLICT(id) DO NOTHING",
            )
            .bind(&id_text)
            .bind(intent.get::<String, _>("project_id"))
            .bind(crate::checked_generation(generation)?)
            .bind(&state)
            .execute(&mut *tx)
            .await
            .map_err(crate::map_canonical_insert_error)?;
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
            sqlx::query(
                "INSERT INTO canonical_networks (id, project_id, name, generation, state) VALUES ($1, $2, $3, 1, 'active') ON CONFLICT(id) DO NOTHING",
            )
            .bind(network.get::<String, _>("id"))
            .bind(network.get::<String, _>("project_id"))
            .bind(network.get::<String, _>("name"))
            .execute(&mut *tx)
            .await
            .map_err(crate::map_canonical_insert_error)?;
            let canonical: (String, String) =
                sqlx::query_as("SELECT project_id, name FROM canonical_networks WHERE id = $1")
                    .bind(network.get::<String, _>("id"))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
            if canonical.0 != network.get::<String, _>("project_id")
                || (canonical.1 != network.get::<String, _>("name") && !canonical.1.is_empty())
            {
                return Err(StoreError::OwnershipConflict);
            }
            if canonical.1.is_empty() {
                sqlx::query("UPDATE canonical_networks SET name = $1 WHERE id = $2")
                    .bind(network.get::<String, _>("name"))
                    .bind(network.get::<String, _>("id"))
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
            }
        }
        let subnets = sqlx::query(
            "SELECT id, network_id, project_id, cidr::text AS cidr, gateway_ip::text AS gateway_ip, allocation_start::text AS allocation_start, allocation_end::text AS allocation_end FROM network_subnets ORDER BY id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        for subnet in &subnets {
            let network_id: String = subnet.get("network_id");
            let project_id: String = subnet.get("project_id");
            let network_project: String =
                sqlx::query_scalar("SELECT project_id FROM canonical_networks WHERE id = $1")
                    .bind(&network_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?
                    .ok_or(StoreError::NetworkNotFound)?;
            if network_project != project_id {
                return Err(StoreError::OwnershipConflict);
            }
            let id: String = subnet.get("id");
            let prefix: String = subnet.get("cidr");
            crate::validate_ipv4_cidr(&prefix)?;
            sqlx::query(
                "INSERT INTO canonical_address_realms (id, network_id, project_id, prefix, overlapping_prefixes, generation, state) VALUES ($1, $2, $3, $4::cidr, false, 1, 'active') ON CONFLICT(id) DO NOTHING",
            )
            .bind(&id)
            .bind(&network_id)
            .bind(&project_id)
            .bind(&prefix)
            .execute(&mut *tx)
            .await
            .map_err(crate::map_canonical_insert_error)?;
            sqlx::query(
                "INSERT INTO canonical_address_pools (id, realm_id, project_id, prefix, gateway, first_usable, last_usable, generation, state) VALUES ($1, $2, $3, $4::cidr, $5::inet, $6::inet, $7::inet, 1, 'active') ON CONFLICT(id) DO NOTHING",
            )
            .bind(&id)
            .bind(&id)
            .bind(&project_id)
            .bind(&prefix)
            .bind(subnet.get::<String, _>("gateway_ip"))
            .bind(subnet.get::<String, _>("allocation_start"))
            .bind(subnet.get::<String, _>("allocation_end"))
            .execute(&mut *tx)
            .await
            .map_err(crate::map_canonical_insert_error)?;
        }
        let ports = sqlx::query(
            "SELECT id, subnet_id, project_id, fixed_ip::text AS fixed_ip, mac_address FROM network_ports ORDER BY id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        for port in &ports {
            let realm_id: String = port.get::<Option<String>, _>("subnet_id").ok_or_else(|| {
                StoreError::Corrupt("legacy endpoint has no explicit subnet owner".into())
            })?;
            let project_id: String = port.get("project_id");
            let realm_project: String =
                sqlx::query_scalar("SELECT project_id FROM canonical_address_realms WHERE id = $1")
                    .bind(&realm_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?
                    .ok_or(StoreError::ResourceNotFound)?;
            if realm_project != project_id {
                return Err(StoreError::OwnershipConflict);
            }
            sqlx::query(
                "INSERT INTO canonical_endpoints (id, realm_id, project_id, fixed_ip, mac, generation, state) VALUES ($1, $2, $3, $4::inet, $5, 1, 'active') ON CONFLICT(id) DO NOTHING",
            )
            .bind(port.get::<String, _>("id"))
            .bind(&realm_id)
            .bind(&project_id)
            .bind(port.get::<String, _>("fixed_ip"))
            .bind(port.get::<String, _>("mac_address"))
            .execute(&mut *tx)
            .await
            .map_err(crate::map_canonical_insert_error)?;
        }
        for intent in &intents {
            let project_id: String = intent.get("project_id");
            for policy in crate::legacy_policy_records(intent.get("payload"), &project_id)? {
                let endpoint_project: Option<String> =
                    sqlx::query_scalar("SELECT project_id FROM canonical_endpoints WHERE id = $1")
                        .bind(policy.endpoint_id.to_string())
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                if endpoint_project.as_deref() != Some(project_id.as_str()) {
                    return Err(StoreError::OwnershipConflict);
                }
                sqlx::query(
                    "INSERT INTO canonical_network_policies (id, project_id, endpoint_id, direction, protocol, port_min, port_max, source, destination, action, generation, state) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::cidr, $9::cidr, $10, $11, $12) ON CONFLICT(id) DO NOTHING",
                )
                .bind(policy.id.to_string())
                .bind(&policy.project_id)
                .bind(policy.endpoint_id.to_string())
                .bind(&policy.direction)
                .bind(&policy.protocol)
                .bind(policy.port_min.map(i32::from))
                .bind(policy.port_max.map(i32::from))
                .bind(&policy.source)
                .bind(&policy.destination)
                .bind(&policy.action)
                .bind(crate::checked_generation(policy.generation)?)
                .bind(&policy.state)
                .execute(&mut *tx)
                .await
                .map_err(crate::map_canonical_insert_error)?;
            }
        }
        tx.commit().await.map_err(StoreError::Database)
    }
}

#[async_trait]
impl NetworkRepository for PostgresStore {
    async fn get_fabric_host_identity(
        &self,
        host_id: &str,
    ) -> Result<Option<FabricHostTransportIdentityRecord>, StoreError> {
        PostgresStore::get_fabric_host_identity(self, host_id).await
    }

    async fn list_fabric_host_identities(
        &self,
    ) -> Result<Vec<FabricHostTransportIdentityRecord>, StoreError> {
        PostgresStore::list_fabric_host_identities(self).await
    }

    async fn upsert_fabric_host_identity(
        &self,
        identity: &FabricHostTransportIdentityRecord,
        expected_generation: Option<u64>,
    ) -> Result<FabricHostTransportIdentityRecord, StoreError> {
        PostgresStore::upsert_fabric_host_identity(self, identity, expected_generation).await
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
        let query = format!("SELECT project_id FROM {table} WHERE id = $1");
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
        if project_id.trim().is_empty() || operation_id.trim().is_empty() {
            return Err(StoreError::Corrupt(
                "network address allocation has empty identity".to_owned(),
            ));
        }
        let (network, prefix_len) = parse_pg_ipv4_prefix(prefix)?;
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(realm_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let existing = sqlx::query(
            "SELECT realm_id, project_id, endpoint_id, operation_id, address::text AS address
             FROM network_address_allocations WHERE endpoint_id = $1 OR operation_id = $2
             FOR UPDATE",
        )
        .bind(endpoint_id.to_string())
        .bind(operation_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if let Some(row) = existing {
            let allocation = parse_pg_network_allocation(&row)?;
            if allocation.realm_id == *realm_id
                && allocation.project_id == project_id
                && allocation.endpoint_id == *endpoint_id
                && allocation.operation_id == operation_id
            {
                tx.commit().await.map_err(StoreError::Database)?;
                return Ok(allocation);
            }
            return Err(StoreError::NetworkAddressConflict);
        }
        let occupied = sqlx::query(
            "SELECT address::text AS address FROM network_address_allocations WHERE realm_id = $1",
        )
        .bind(realm_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        let occupied: std::collections::HashSet<std::net::Ipv4Addr> = occupied
            .iter()
            .map(|row| {
                row.get::<String, _>("address")
                    .split('/')
                    .next()
                    .ok_or_else(|| {
                        StoreError::Corrupt("invalid allocated network address".to_owned())
                    })?
                    .parse()
                    .map_err(|_| {
                        StoreError::Corrupt("invalid allocated network address".to_owned())
                    })
            })
            .collect::<Result<_, StoreError>>()?;
        let (first, last) = allocation_bounds(network, prefix_len);
        let address = (first..=last)
            .map(std::net::Ipv4Addr::from)
            .find(|candidate| !occupied.contains(candidate))
            .ok_or(StoreError::NetworkAddressExhausted)?;
        sqlx::query(
            "INSERT INTO network_address_allocations (realm_id, project_id, endpoint_id, operation_id, address)
             VALUES ($1, $2, $3, $4, $5::inet)",
        )
        .bind(realm_id.to_string())
        .bind(project_id)
        .bind(endpoint_id.to_string())
        .bind(operation_id)
        .bind(address.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|error| match error {
            sqlx::Error::Database(database) if database.is_unique_violation() => {
                StoreError::NetworkAddressConflict
            }
            other => StoreError::Database(other),
        })?;
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(NetworkAddressAllocationRecord {
            realm_id: *realm_id,
            project_id: project_id.to_owned(),
            endpoint_id: *endpoint_id,
            operation_id: operation_id.to_owned(),
            address,
        })
    }

    async fn release_network_address(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM network_address_allocations WHERE project_id = $1 AND endpoint_id = $2",
        )
        .bind(project_id)
        .bind(endpoint_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    async fn insert_network_intent(&self, intent: &NetworkIntentRecord) -> Result<(), StoreError> {
        validate_network_intent(intent)?;
        let generation = i64::try_from(intent.generation).map_err(|_| {
            StoreError::Corrupt("network intent generation exceeds PostgreSQL range".to_owned())
        })?;
        let result = sqlx::query(
            "INSERT INTO network_intents (id, project_id, generation, payload, plan_fingerprint_sha256, status)
             VALUES ($1, $2, $3, $4, $5, $6)",
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
            Err(error) => Err(map_pg_error(error)),
        }
    }

    async fn list_network_intents(
        &self,
        project_id: &str,
    ) -> Result<Vec<NetworkIntentRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, project_id, generation, payload, plan_fingerprint_sha256, status
             FROM network_intents WHERE project_id = $1 ORDER BY id",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(parse_pg_network_intent).collect()
    }

    async fn get_network_intent(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkIntentRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, project_id, generation, payload, plan_fingerprint_sha256, status
             FROM network_intents WHERE id = $1 AND project_id = $2",
        )
        .bind(id.to_string())
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.as_ref().map(parse_pg_network_intent).transpose()
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
        crate::validate_network_intent_update(project_id, payload, status)?;
        let existing = self
            .get_network_intent(project_id, id)
            .await?
            .ok_or(StoreError::NetworkIntentNotFound)?;
        crate::validate_network_intent_transition(&existing.status, status)?;
        let expected = i64::try_from(expected_generation).map_err(|_| {
            StoreError::Corrupt("network intent generation exceeds PostgreSQL range".to_owned())
        })?;
        let result = sqlx::query(
            "UPDATE network_intents
             SET generation = generation + 1, payload = $1, plan_fingerprint_sha256 = $2, status = $3, updated_at = NOW()
             WHERE id = $4 AND project_id = $5 AND generation = $6",
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

    async fn insert_network(&self, network: &NetworkRecord) -> Result<(), StoreError> {
        let id_str = network.id.to_string();
        sqlx::query(
            "INSERT INTO network_networks (id, name, project_id, status)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&id_str)
        .bind(&network.name)
        .bind(&network.project_id)
        .bind(&network.status)
        .execute(&self.pool)
        .await
        .map_err(map_pg_error)?;
        Ok(())
    }

    async fn list_networks(&self, project_id: &str) -> Result<Vec<NetworkRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM network_networks
             WHERE project_id = $1 AND status != 'deleted'
             ORDER BY id",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        rows.iter().map(parse_pg_network).collect()
    }

    async fn get_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkRecord>, StoreError> {
        let id_str = id.to_string();
        let row = sqlx::query(
            "SELECT * FROM network_networks
             WHERE id = $1 AND project_id = $2 AND status != 'deleted'",
        )
        .bind(&id_str)
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        row.map(|r| parse_pg_network(&r)).transpose()
    }

    async fn delete_network(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        let id_str = id.to_string();
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let subnet_count: i64 =
            sqlx::query("SELECT COUNT(*) FROM network_subnets WHERE network_id = $1")
                .bind(&id_str)
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?
                .get(0);

        if subnet_count > 0 {
            return Err(StoreError::NetworkInUse);
        }

        // The canonical row is the durable deletion record. Remove the
        // compatibility projection as well so its unique (project, name)
        // constraint cannot prevent a later recreation with the same name.
        let res = sqlx::query(
            "DELETE FROM network_networks
             WHERE id = $1 AND project_id = $2 AND status != 'deleted'",
        )
        .bind(&id_str)
        .bind(project_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        if res.rows_affected() == 0 {
            return Err(StoreError::NetworkNotFound);
        }

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(())
    }

    async fn insert_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError> {
        let id_str = subnet.id.to_string();
        let net_id_str = subnet.network_id.to_string();

        sqlx::query(
            "INSERT INTO network_subnets (id, network_id, name, project_id, cidr, gateway_ip, allocation_start, allocation_end, ip_version, enable_dhcp)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&id_str)
        .bind(&net_id_str)
        .bind(&subnet.name)
        .bind(&subnet.project_id)
        .bind(&subnet.cidr)
        .bind(subnet.gateway_ip.to_string())
        .bind(subnet.allocation_start.to_string())
        .bind(subnet.allocation_end.to_string())
        .bind(i16::from(subnet.ip_version))
        .bind(subnet.enable_dhcp)
        .execute(&self.pool)
        .await
        .map_err(map_pg_error)?;
        Ok(())
    }

    async fn list_subnets(&self, project_id: &str) -> Result<Vec<SubnetRecord>, StoreError> {
        let rows = sqlx::query("SELECT * FROM network_subnets WHERE project_id = $1 ORDER BY id")
            .bind(project_id)
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        rows.iter().map(parse_pg_subnet).collect()
    }

    async fn list_subnets_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<SubnetRecord>, StoreError> {
        let net_id_str = network_id.to_string();
        let rows = sqlx::query(
            "SELECT * FROM network_subnets WHERE project_id = $1 AND network_id = $2 ORDER BY id",
        )
        .bind(project_id)
        .bind(&net_id_str)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        rows.iter().map(parse_pg_subnet).collect()
    }

    async fn get_subnet(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SubnetRecord>, StoreError> {
        let id_str = id.to_string();
        let row = sqlx::query("SELECT * FROM network_subnets WHERE id = $1 AND project_id = $2")
            .bind(&id_str)
            .bind(project_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        row.map(|r| parse_pg_subnet(&r)).transpose()
    }

    async fn delete_subnet(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        let id_str = id.to_string();
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let port_count: i64 =
            sqlx::query("SELECT COUNT(*) FROM network_ports WHERE subnet_id = $1")
                .bind(&id_str)
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?
                .get(0);

        if port_count > 0 {
            return Err(StoreError::NetworkInUse);
        }

        let res = sqlx::query("DELETE FROM network_subnets WHERE id = $1 AND project_id = $2")
            .bind(&id_str)
            .bind(project_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;

        if res.rows_affected() == 0 {
            return Err(StoreError::NetworkNotFound);
        }

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(())
    }

    async fn update_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE network_subnets SET name = $1, gateway_ip = $2, allocation_start = $3, allocation_end = $4, ip_version = $5, enable_dhcp = $6 WHERE id = $7 AND project_id = $8",
        )
        .bind(&subnet.name)
        .bind(subnet.gateway_ip.to_string())
        .bind(subnet.allocation_start.to_string())
        .bind(subnet.allocation_end.to_string())
        .bind(i16::from(subnet.ip_version))
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

    async fn delete_subnet_bundle(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let endpoints: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM canonical_endpoints WHERE realm_id = $1 AND project_id = $2",
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
            "SELECT id FROM canonical_address_realms WHERE id = $1 AND project_id = $2 FOR UPDATE",
        )
        .bind(id.to_string())
        .bind(project_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if realm.is_some() {
            sqlx::query(
                "DELETE FROM canonical_address_pools WHERE realm_id = $1 AND project_id = $2",
            )
            .bind(id.to_string())
            .bind(project_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
            let result = sqlx::query("DELETE FROM canonical_address_realms WHERE id = $1 AND project_id = $2 AND NOT EXISTS (SELECT 1 FROM canonical_address_pools WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_endpoints WHERE realm_id = canonical_address_realms.id) AND NOT EXISTS (SELECT 1 FROM canonical_realm_encapsulation_bindings WHERE realm_id = canonical_address_realms.id)")
                .bind(id.to_string()).bind(project_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
            if result.rows_affected() == 0 {
                return Err(StoreError::NetworkInUse);
            }
        }
        sqlx::query("DELETE FROM network_subnets WHERE id = $1 AND project_id = $2")
            .bind(id.to_string())
            .bind(project_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)
    }

    async fn update_subnet_bundle(
        &self,
        subnet: &SubnetRecord,
        pool_id: &Uuid,
        expected_pool_generation: u64,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let pool = sqlx::query("UPDATE canonical_address_pools SET gateway = $1::inet, generation = generation + 1 WHERE id = $2 AND project_id = $3 AND generation = $4 AND state = 'active'")
            .bind(subnet.gateway_ip.to_string()).bind(pool_id.to_string()).bind(&subnet.project_id).bind(crate::checked_generation(expected_pool_generation)?).execute(&mut *tx).await.map_err(StoreError::Database)?;
        if pool.rows_affected() == 0 {
            return Err(StoreError::StaleGeneration);
        }
        let metadata = sqlx::query("UPDATE network_subnets SET name = $1, gateway_ip = $2, allocation_start = $3, allocation_end = $4, ip_version = $5, enable_dhcp = $6 WHERE id = $7 AND project_id = $8")
            .bind(&subnet.name).bind(subnet.gateway_ip.to_string()).bind(subnet.allocation_start.to_string()).bind(subnet.allocation_end.to_string()).bind(i16::from(subnet.ip_version)).bind(subnet.enable_dhcp).bind(subnet.id.to_string()).bind(&subnet.project_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        if metadata.rows_affected() == 0 {
            return Err(StoreError::ResourceNotFound);
        }
        tx.commit().await.map_err(StoreError::Database)
    }

    async fn insert_port(&self, port: &PortRecord) -> Result<(), StoreError> {
        let id_str = port.id.to_string();
        let net_id_str = port.network_id.to_string();
        let sub_id_str = port.subnet_id.map(|id| id.to_string());

        sqlx::query(
            "INSERT INTO network_ports (id, network_id, subnet_id, project_id, name, mac_address, fixed_ip, status, binding_host, binding_state)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&id_str)
        .bind(&net_id_str)
        .bind(sub_id_str.as_deref())
        .bind(&port.project_id)
        .bind(&port.name)
        .bind(&port.mac_address)
        .bind(port.fixed_ip.to_string())
        .bind(&port.status)
        .bind(&port.binding_host)
        .bind(&port.binding_state)
        .execute(&self.pool)
        .await
        .map_err(map_pg_error)?;
        Ok(())
    }

    async fn list_ports(&self, project_id: &str) -> Result<Vec<PortRecord>, StoreError> {
        let rows = sqlx::query("SELECT * FROM network_ports WHERE project_id = $1 ORDER BY id")
            .bind(project_id)
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        rows.iter().map(parse_pg_port).collect()
    }

    async fn list_ports_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<PortRecord>, StoreError> {
        let net_id_str = network_id.to_string();
        let rows = sqlx::query(
            "SELECT * FROM network_ports WHERE project_id = $1 AND network_id = $2 ORDER BY id",
        )
        .bind(project_id)
        .bind(&net_id_str)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        rows.iter().map(parse_pg_port).collect()
    }

    async fn get_port(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<PortRecord>, StoreError> {
        let id_str = id.to_string();
        let row = sqlx::query("SELECT * FROM network_ports WHERE id = $1 AND project_id = $2")
            .bind(&id_str)
            .bind(project_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        row.map(|r| parse_pg_port(&r)).transpose()
    }

    async fn get_port_by_id(&self, id: &Uuid) -> Result<Option<PortRecord>, StoreError> {
        let id_str = id.to_string();
        let row = sqlx::query("SELECT * FROM network_ports WHERE id = $1")
            .bind(&id_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        row.map(|r| parse_pg_port(&r)).transpose()
    }

    async fn delete_port(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        let id_str = id.to_string();
        sqlx::query("DELETE FROM network_security_group_bindings WHERE project_id = $1 AND endpoint_id = $2")
            .bind(project_id)
            .bind(&id_str)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        let res = sqlx::query("DELETE FROM network_ports WHERE id = $1 AND project_id = $2")
            .bind(&id_str)
            .bind(project_id)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        if res.rows_affected() == 0 {
            return Err(StoreError::NetworkNotFound);
        }
        Ok(())
    }

    async fn update_port_binding(
        &self,
        project_id: &str,
        id: &Uuid,
        binding_host: Option<&str>,
        binding_state: Option<&str>,
    ) -> Result<PortRecord, StoreError> {
        let id_str = id.to_string();
        let res = sqlx::query(
            "UPDATE network_ports
             SET binding_generation = CASE WHEN $1 IS NOT NULL AND binding_host IS DISTINCT FROM $1 THEN binding_generation + 1 ELSE binding_generation END,
                 binding_host = COALESCE($1, binding_host),
                 binding_state = COALESCE($2, binding_state)
             WHERE id = $3 AND project_id = $4",
        )
        .bind(binding_host)
        .bind(binding_state)
        .bind(&id_str)
        .bind(project_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        if res.rows_affected() == 0 {
            return Err(StoreError::NetworkNotFound);
        }

        self.get_port(project_id, id)
            .await?
            .ok_or(StoreError::NetworkNotFound)
    }

    async fn update_port_name(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
    ) -> Result<PortRecord, StoreError> {
        let id_str = id.to_string();
        let res =
            sqlx::query("UPDATE network_ports SET name = $1 WHERE id = $2 AND project_id = $3")
                .bind(name)
                .bind(&id_str)
                .bind(project_id)
                .execute(&self.pool)
                .await
                .map_err(StoreError::Database)?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NetworkNotFound);
        }
        self.get_port(project_id, id)
            .await?
            .ok_or(StoreError::NetworkNotFound)
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

impl PostgresStore {
    pub async fn insert_security_group(
        &self,
        group: &SecurityGroupRecord,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO network_security_groups (id, project_id, name, description) VALUES ($1, $2, $3, $4)").bind(group.id.to_string()).bind(&group.project_id).bind(&group.name).bind(&group.description).execute(&self.pool).await.map(|_| ()).map_err(map_pg_error)
    }
    pub async fn list_security_groups(
        &self,
        project_id: &str,
    ) -> Result<Vec<SecurityGroupRecord>, StoreError> {
        let rows = sqlx::query("SELECT id, project_id, name, description FROM network_security_groups WHERE project_id = $1 ORDER BY id").bind(project_id).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.iter().map(pg_security_group_from_row).collect()
    }
    pub async fn get_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRecord>, StoreError> {
        let row = sqlx::query("SELECT id, project_id, name, description FROM network_security_groups WHERE project_id = $1 AND id = $2").bind(project_id).bind(id.to_string()).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        row.as_ref().map(pg_security_group_from_row).transpose()
    }
    pub async fn update_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
        description: &str,
    ) -> Result<SecurityGroupRecord, StoreError> {
        let result = sqlx::query("UPDATE network_security_groups SET name = $1, description = $2 WHERE project_id = $3 AND id = $4").bind(name).bind(description).bind(project_id).bind(id.to_string()).execute(&self.pool).await.map_err(map_pg_error)?;
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
        let result = sqlx::query("DELETE FROM network_security_groups WHERE project_id = $1 AND id = $2 AND NOT EXISTS (SELECT 1 FROM network_security_group_rules WHERE security_group_id = $2) AND NOT EXISTS (SELECT 1 FROM network_security_group_bindings WHERE security_group_id = $2)").bind(project_id).bind(id.to_string()).execute(&self.pool).await.map_err(StoreError::Database)?;
        if result.rows_affected() != 0 {
            Ok(())
        } else {
            match self.get_security_group(project_id, id).await? {
                Some(_) => Err(StoreError::NetworkInUse),
                None => Err(StoreError::NetworkNotFound),
            }
        }
    }
    pub async fn insert_security_group_rule(
        &self,
        rule: &SecurityGroupRuleRecord,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO network_security_group_rules (id, security_group_id, project_id, direction, protocol, port_min, port_max, remote_ip_prefix) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet)").bind(rule.id.to_string()).bind(rule.security_group_id.to_string()).bind(&rule.project_id).bind(&rule.direction).bind(&rule.protocol).bind(rule.port_min.map(i32::from)).bind(rule.port_max.map(i32::from)).bind(&rule.remote_ip_prefix).execute(&self.pool).await.map(|_| ()).map_err(map_pg_error)
    }
    pub async fn list_security_group_rules(
        &self,
        project_id: &str,
        group_id: &Uuid,
    ) -> Result<Vec<SecurityGroupRuleRecord>, StoreError> {
        let rows = sqlx::query("SELECT id, security_group_id, project_id, direction, protocol, port_min, port_max, remote_ip_prefix::text AS remote_ip_prefix FROM network_security_group_rules WHERE project_id = $1 AND security_group_id = $2 ORDER BY id").bind(project_id).bind(group_id.to_string()).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.iter().map(pg_security_group_rule_from_row).collect()
    }
    pub async fn get_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRuleRecord>, StoreError> {
        let row = sqlx::query("SELECT id, security_group_id, project_id, direction, protocol, port_min, port_max, remote_ip_prefix::text AS remote_ip_prefix FROM network_security_group_rules WHERE project_id = $1 AND id = $2").bind(project_id).bind(id.to_string()).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        row.as_ref()
            .map(pg_security_group_rule_from_row)
            .transpose()
    }
    pub async fn delete_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "DELETE FROM network_security_group_rules WHERE project_id = $1 AND id = $2",
        )
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
                "SELECT project_id, endpoint_id, security_group_id FROM network_security_group_bindings WHERE project_id = $1 AND endpoint_id = $2 ORDER BY security_group_id",
                Some(id.to_string()),
            ),
            None => (
                "SELECT project_id, endpoint_id, security_group_id FROM network_security_group_bindings WHERE project_id = $1 ORDER BY endpoint_id, security_group_id",
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
        rows.iter()
            .map(pg_security_group_binding_from_row)
            .collect()
    }
    pub async fn replace_security_group_bindings(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
        group_ids: &[Uuid],
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query("DELETE FROM network_security_group_bindings WHERE project_id = $1 AND endpoint_id = $2").bind(project_id).bind(endpoint_id.to_string()).execute(&mut *tx).await.map_err(StoreError::Database)?;
        for group_id in group_ids {
            sqlx::query("INSERT INTO network_security_group_bindings (project_id, endpoint_id, security_group_id) VALUES ($1, $2, $3)").bind(project_id).bind(endpoint_id.to_string()).bind(group_id.to_string()).execute(&mut *tx).await.map_err(map_pg_error)?;
        }
        tx.commit().await.map_err(StoreError::Database)
    }
}
