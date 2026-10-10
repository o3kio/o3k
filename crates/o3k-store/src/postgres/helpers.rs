use std::net::Ipv4Addr;

use o3k_kernel::{LimitKey, ResourceAmount};
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

use crate::{
    CanonicalAddressPoolRecord, CanonicalAddressRealmRecord, CanonicalEndpointRecord,
    CanonicalNetworkPolicyRecord, CanonicalNetworkRecord, CanonicalOperationRecord,
    IdempotencyReservationRequest, ImageMetadataRecord, ImageOverlayState,
    NetworkAddressAllocationRecord, NetworkIntentRecord, NetworkRecord, OperationRecord,
    OperationState, PortRecord, ResourceRecord, ResourceRelationshipRecord,
    SecurityGroupBindingRecord, SecurityGroupRecord, SecurityGroupRuleRecord, StoreError,
    SubnetRecord, VolumeAttachmentRecord, validate_canonical_idempotent_operation_identity,
};

pub(crate) fn relationship_from_pg_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ResourceRelationshipRecord, StoreError> {
    Ok(ResourceRelationshipRecord {
        parent_resource_id: Uuid::parse_str(
            &row.try_get::<String, _>("parent_resource_id")
                .map_err(StoreError::Database)?,
        )
        .map_err(StoreError::InvalidUuid)?,
        parent_resource_type: row
            .try_get("parent_resource_type")
            .map_err(StoreError::Database)?,
        slot: row.try_get("slot").map_err(StoreError::Database)?,
        expected_child_resource_type: row
            .try_get("expected_child_resource_type")
            .map_err(StoreError::Database)?,
        child_resource_id: row
            .try_get::<Option<String>, _>("child_resource_id")
            .map_err(StoreError::Database)?
            .map(|id| Uuid::parse_str(&id).map_err(StoreError::InvalidUuid))
            .transpose()?,
        ownership: row.try_get("ownership").map_err(StoreError::Database)?,
        parent_operation_id: Uuid::parse_str(
            &row.try_get::<String, _>("parent_operation_id")
                .map_err(StoreError::Database)?,
        )
        .map_err(StoreError::InvalidUuid)?,
        child_operation_id: row
            .try_get::<Option<String>, _>("child_operation_id")
            .map_err(StoreError::Database)?
            .map(|id| Uuid::parse_str(&id).map_err(StoreError::InvalidUuid))
            .transpose()?,
        owner_scope: row.try_get("owner_scope").map_err(StoreError::Database)?,
        state: row.try_get("state").map_err(StoreError::Database)?,
        fingerprint: row.try_get("fingerprint").map_err(StoreError::Database)?,
    })
}

pub(crate) fn map_pg_error(error: sqlx::Error) -> StoreError {
    match &error {
        sqlx::Error::Database(db_err) if db_err.code().as_deref() == Some("23505") => {
            StoreError::ResourceAlreadyExists
        }
        _ => StoreError::Database(error),
    }
}

pub(crate) fn parse_uuid(s: &str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(s).map_err(StoreError::InvalidUuid)
}

pub(crate) fn row_to_resource(row: &PgRow) -> Result<ResourceRecord, StoreError> {
    let id_str: String = row.get("id");
    let id = parse_uuid(&id_str)?;
    let generation: i64 = row.get("generation");
    let observed_generation: i64 = row.get("observed_generation");
    Ok(ResourceRecord {
        id,
        kind: row.get("kind"),
        project_id: row.get("project_id"),
        generation,
        observed_generation,
        desired_state: row.get("desired_state"),
        observed_state: row.get("observed_state"),
        provider_id: row.get("provider_id"),
    })
}

pub(crate) fn row_to_operation(row: &PgRow) -> Result<OperationRecord, StoreError> {
    let id_str: String = row.get("id");
    let id = parse_uuid(&id_str)?;
    let resource_id_str: String = row.get("resource_id");
    let resource_id = parse_uuid(&resource_id_str)?;
    let state_str: String = row.get("state");
    let state = OperationState::parse(&state_str)?;

    Ok(OperationRecord {
        id,
        resource_id,
        kind: row.get("kind"),
        state,
        provider_operation_id: row.get("provider_operation_id"),
        error_category: row.get("error_category"),
        error_message: row.get("error_message"),
    })
}

pub(crate) fn validate_image_overlay_transition(
    current: ImageOverlayState,
    next: ImageOverlayState,
) -> Result<(), StoreError> {
    if current == next {
        return Ok(());
    }
    match (current, next) {
        (ImageOverlayState::Pending, ImageOverlayState::Materializing) => Ok(()),
        (ImageOverlayState::Materializing, ImageOverlayState::Ready) => Ok(()),
        (ImageOverlayState::Ready, ImageOverlayState::Deleting) => Ok(()),
        (ImageOverlayState::Deleting, ImageOverlayState::Deleted) => Ok(()),
        (ImageOverlayState::Pending, ImageOverlayState::Failed) => Ok(()),
        (ImageOverlayState::Materializing, ImageOverlayState::Failed) => Ok(()),
        (ImageOverlayState::Ready, ImageOverlayState::Failed) => Ok(()),
        (ImageOverlayState::Deleting, ImageOverlayState::Failed) => Ok(()),
        (ImageOverlayState::Failed, ImageOverlayState::Deleting) => Ok(()),
        (ImageOverlayState::Failed, ImageOverlayState::Deleted) => Ok(()),
        _ => Err(StoreError::ImageOverlayConflict(format!(
            "invalid image overlay state transition from {current:?} to {next:?}"
        ))),
    }
}

pub(crate) async fn validate_existing_canonical_reservation(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operation_id: Uuid,
    request: &IdempotencyReservationRequest,
) -> Result<(), StoreError> {
    let durable_row = sqlx::query("SELECT * FROM operations WHERE id=$1")
        .bind(operation_id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(StoreError::Database)?
        .ok_or_else(|| {
            StoreError::Corrupt("idempotency reservation references missing operation".into())
        })?;
    let durable = row_to_operation(&durable_row)?;
    let metadata = sqlx::query("SELECT * FROM canonical_operation_metadata WHERE operation_id=$1")
        .bind(operation_id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(StoreError::Database)?
        .ok_or_else(|| {
            StoreError::Corrupt(
                "idempotency reservation references operation without canonical metadata".into(),
            )
        })?;
    let canonical = CanonicalOperationRecord {
        id: operation_id,
        service: metadata.try_get("service").map_err(StoreError::Database)?,
        action: metadata.try_get("action").map_err(StoreError::Database)?,
        actor: metadata.try_get("actor").map_err(StoreError::Database)?,
        owner_scope: metadata
            .try_get("owner_scope")
            .map_err(StoreError::Database)?,
        resource_type: metadata
            .try_get("resource_type")
            .map_err(StoreError::Database)?,
        resource_id: metadata
            .try_get("resource_id")
            .map_err(StoreError::Database)?,
        state: durable.state,
        attempt: u32::try_from(
            metadata
                .try_get::<i32, _>("attempt")
                .map_err(StoreError::Database)?,
        )
        .map_err(|_| StoreError::Corrupt("invalid operation attempt".into()))?,
        created_at: metadata
            .try_get("created_at")
            .map_err(StoreError::Database)?,
        started_at: metadata
            .try_get("started_at")
            .map_err(StoreError::Database)?,
        finished_at: metadata
            .try_get("finished_at")
            .map_err(StoreError::Database)?,
        error: metadata.try_get("error").map_err(StoreError::Database)?,
        request_id: metadata
            .try_get("request_id")
            .map_err(StoreError::Database)?,
    };
    let mut winning_request = request.clone();
    winning_request.operation_id = operation_id;
    validate_canonical_idempotent_operation_identity(&durable, &canonical, &winning_request)?;

    let resource_owner: String = sqlx::query("SELECT project_id FROM resources WHERE id=$1")
        .bind(durable.resource_id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(StoreError::Database)?
        .ok_or_else(|| {
            StoreError::Corrupt("canonical operation references missing resource".into())
        })?
        .try_get("project_id")
        .map_err(StoreError::Database)?;
    if resource_owner != canonical.owner_scope {
        return Err(StoreError::Corrupt(
            "canonical operation resource and owner scopes differ".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn postgres_existing_acceptance(
    pool: &sqlx::PgPool,
    request: &IdempotencyReservationRequest,
) -> Result<Option<crate::CanonicalAcceptanceOutcome>, StoreError> {
    let Some(row) = sqlx::query("SELECT fingerprint,operation_id FROM idempotency_reservations WHERE owner_scope=$1 AND action=$2 AND idempotency_key=$3")
        .bind(&request.owner_scope).bind(&request.action).bind(&request.key)
        .fetch_optional(pool).await.map_err(StoreError::Database)? else { return Ok(None); };
    if row
        .try_get::<String, _>("fingerprint")
        .map_err(StoreError::Database)?
        != request.fingerprint
    {
        return Ok(Some(crate::CanonicalAcceptanceOutcome::Conflict));
    }
    let operation_id = Uuid::parse_str(
        &row.try_get::<String, _>("operation_id")
            .map_err(StoreError::Database)?,
    )
    .map_err(StoreError::InvalidUuid)?;
    let durable = row_to_operation(
        &sqlx::query("SELECT * FROM operations WHERE id=$1")
            .bind(operation_id.to_string())
            .fetch_one(pool)
            .await
            .map_err(StoreError::Database)?,
    )?;
    let metadata = sqlx::query("SELECT * FROM canonical_operation_metadata WHERE operation_id=$1")
        .bind(operation_id.to_string())
        .fetch_one(pool)
        .await
        .map_err(StoreError::Database)?;
    let canonical = CanonicalOperationRecord {
        id: operation_id,
        service: metadata.try_get("service").map_err(StoreError::Database)?,
        action: metadata.try_get("action").map_err(StoreError::Database)?,
        actor: metadata.try_get("actor").map_err(StoreError::Database)?,
        owner_scope: metadata
            .try_get("owner_scope")
            .map_err(StoreError::Database)?,
        resource_type: metadata
            .try_get("resource_type")
            .map_err(StoreError::Database)?,
        resource_id: metadata
            .try_get("resource_id")
            .map_err(StoreError::Database)?,
        state: durable.state,
        attempt: u32::try_from(
            metadata
                .try_get::<i32, _>("attempt")
                .map_err(StoreError::Database)?,
        )
        .map_err(|_| StoreError::Corrupt("invalid operation attempt".into()))?,
        created_at: metadata
            .try_get("created_at")
            .map_err(StoreError::Database)?,
        started_at: metadata
            .try_get("started_at")
            .map_err(StoreError::Database)?,
        finished_at: metadata
            .try_get("finished_at")
            .map_err(StoreError::Database)?,
        error: metadata.try_get("error").map_err(StoreError::Database)?,
        request_id: metadata
            .try_get("request_id")
            .map_err(StoreError::Database)?,
    };
    let resource = row_to_resource(
        &sqlx::query("SELECT * FROM resources WHERE id=$1")
            .bind(durable.resource_id.to_string())
            .fetch_one(pool)
            .await
            .map_err(StoreError::Database)?,
    )?;
    let mut replay = request.clone();
    replay.operation_id = operation_id;
    crate::validate_canonical_resource_acceptance(&resource, &durable, &canonical, &replay)?;
    Ok(Some(
        crate::CanonicalAcceptanceOutcome::ExistingEquivalent {
            operation_id,
            resource_id: resource.id,
        },
    ))
}

pub(crate) async fn postgres_existing_acceptance_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &IdempotencyReservationRequest,
) -> Result<Option<crate::CanonicalAcceptanceOutcome>, StoreError> {
    let Some(row) = sqlx::query("SELECT fingerprint,operation_id FROM idempotency_reservations WHERE owner_scope=$1 AND action=$2 AND idempotency_key=$3")
        .bind(&request.owner_scope).bind(&request.action).bind(&request.key)
        .fetch_optional(&mut **tx).await.map_err(StoreError::Database)? else { return Ok(None); };
    if row
        .try_get::<String, _>("fingerprint")
        .map_err(StoreError::Database)?
        != request.fingerprint
    {
        return Ok(Some(crate::CanonicalAcceptanceOutcome::Conflict));
    }
    let operation_id = Uuid::parse_str(
        &row.try_get::<String, _>("operation_id")
            .map_err(StoreError::Database)?,
    )
    .map_err(StoreError::InvalidUuid)?;
    validate_existing_canonical_reservation(tx, operation_id, request).await?;
    let resource_id = Uuid::parse_str(
        &sqlx::query("SELECT resource_id FROM operations WHERE id=$1")
            .bind(operation_id.to_string())
            .fetch_one(&mut **tx)
            .await
            .map_err(StoreError::Database)?
            .try_get::<String, _>("resource_id")
            .map_err(StoreError::Database)?,
    )
    .map_err(StoreError::InvalidUuid)?;
    Ok(Some(
        crate::CanonicalAcceptanceOutcome::ExistingEquivalent {
            operation_id,
            resource_id,
        },
    ))
}

pub(crate) async fn insert_postgres_canonical_acceptance(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operation: &OperationRecord,
    canonical: &CanonicalOperationRecord,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO operations (id,resource_id,kind,state,provider_operation_id,error_category,error_message) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(operation.id.to_string()).bind(operation.resource_id.to_string()).bind(&operation.kind).bind(operation.state.as_str())
        .bind(&operation.provider_operation_id).bind(&operation.error_category).bind(&operation.error_message)
        .execute(&mut **tx).await.map_err(map_pg_error)?;
    sqlx::query("INSERT INTO canonical_operation_metadata (operation_id,service,action,actor,owner_scope,resource_type,resource_id,attempt,created_at,started_at,finished_at,error,request_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
        .bind(canonical.id.to_string()).bind(&canonical.service).bind(&canonical.action).bind(&canonical.actor).bind(&canonical.owner_scope)
        .bind(&canonical.resource_type).bind(&canonical.resource_id).bind(i32::try_from(canonical.attempt).map_err(|_| StoreError::Corrupt("operation attempt exceeds storage range".into()))?)
        .bind(&canonical.created_at).bind(&canonical.started_at).bind(&canonical.finished_at).bind(&canonical.error).bind(&canonical.request_id)
        .execute(&mut **tx).await.map_err(map_pg_error)?;
    Ok(())
}
pub(crate) fn parse_pg_volume_attachment(
    row: &PgRow,
) -> Result<VolumeAttachmentRecord, StoreError> {
    let id_str: String = row.get("id");
    let id = parse_uuid(&id_str)?;
    let srv_id_str: String = row.get("server_id");
    let server_id = parse_uuid(&srv_id_str)?;
    let vol_id_str: String = row.get("volume_id");
    let volume_id = parse_uuid(&vol_id_str)?;
    let op_id = row
        .get::<Option<String>, _>("operation_id")
        .as_deref()
        .map(parse_uuid)
        .transpose()?;
    let target_lun = row.get::<Option<i32>, _>("target_lun").map(|l| l as u32);
    let del_term: i32 = row.get("delete_on_termination");

    Ok(VolumeAttachmentRecord {
        id,
        server_id,
        volume_id,
        device: row.get("device"),
        tag: row.get("tag"),
        delete_on_termination: del_term != 0,
        created_at: row.get("created_at"),
        status: row.get("status"),
        operation_id: op_id,
        idempotency_key: row.get("idempotency_key"),
        cinder_attachment_id: row.get("cinder_attachment_id"),
        connector_host: row.get("connector_host"),
        connector_ip: row.get("connector_ip"),
        connector_initiator: row.get("connector_initiator"),
        driver_volume_type: row.get("driver_volume_type"),
        target_iqn: row.get("target_iqn"),
        target_portal: row.get("target_portal"),
        target_lun,
        connection_info_digest: row.get("connection_info_digest"),
        error: row.get("error"),
    })
}
pub(crate) fn parse_pg_image(row: &PgRow) -> Result<ImageMetadataRecord, StoreError> {
    let id_str: String = row.get("id");
    let id = parse_uuid(&id_str)?;

    Ok(ImageMetadataRecord {
        id,
        name: row.get("name"),
        project_id: row.get("project_id"),
        status: row.get("status"),
        visibility: row.get("visibility"),
        container_format: row.get("container_format"),
        disk_format: row.get("disk_format"),
        size: row.get("size"),
        checksum: row.get("checksum"),
    })
}
pub(crate) fn validate_network_intent(intent: &NetworkIntentRecord) -> Result<(), StoreError> {
    if intent.project_id.is_empty() || intent.payload.is_empty() || intent.status.is_empty() {
        return Err(StoreError::Corrupt(
            "network intent has empty required field".to_owned(),
        ));
    }
    if intent.generation == 0 {
        return Err(StoreError::Corrupt(
            "network intent generation must be positive".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn parse_pg_network_intent(row: &PgRow) -> Result<NetworkIntentRecord, StoreError> {
    let generation: i64 = row.get("generation");
    Ok(NetworkIntentRecord {
        id: parse_uuid(&row.get::<String, _>("id"))?,
        project_id: row.get("project_id"),
        generation: u64::try_from(generation)
            .map_err(|_| StoreError::Corrupt("negative network intent generation".to_owned()))?,
        payload: row.get("payload"),
        plan_fingerprint_sha256: row.get("plan_fingerprint_sha256"),
        status: row.get("status"),
    })
}

pub(crate) fn parse_pg_network(row: &PgRow) -> Result<NetworkRecord, StoreError> {
    let id_str: String = row.get("id");
    let id = parse_uuid(&id_str)?;
    Ok(NetworkRecord {
        id,
        name: row.get("name"),
        project_id: row.get("project_id"),
        status: row.get("status"),
    })
}

pub(crate) fn canonical_network_from_pg_row(
    row: &PgRow,
) -> Result<CanonicalNetworkRecord, StoreError> {
    let generation: i64 = row.get("generation");
    Ok(CanonicalNetworkRecord {
        id: Uuid::parse_str(row.get::<&str, _>("id")).map_err(StoreError::InvalidUuid)?,
        project_id: row.get("project_id"),
        name: row.get("name"),
        admin_state_up: row.get("admin_state_up"),
        generation: u64::try_from(generation)
            .map_err(|_| StoreError::Corrupt("negative canonical generation".into()))?,
        state: row.get("state"),
    })
}

pub(crate) fn canonical_realm_from_pg_row(
    row: &PgRow,
) -> Result<CanonicalAddressRealmRecord, StoreError> {
    let generation: i64 = row.get("generation");
    Ok(CanonicalAddressRealmRecord {
        id: Uuid::parse_str(row.get::<&str, _>("id")).map_err(StoreError::InvalidUuid)?,
        network_id: Uuid::parse_str(row.get::<&str, _>("network_id"))
            .map_err(StoreError::InvalidUuid)?,
        project_id: row.get("project_id"),
        prefix: row.get("prefix"),
        overlapping_prefixes: row.get("overlapping_prefixes"),
        generation: u64::try_from(generation)
            .map_err(|_| StoreError::Corrupt("negative canonical generation".into()))?,
        state: row.get("state"),
    })
}

pub(crate) fn canonical_pool_from_pg_row(
    row: &PgRow,
) -> Result<CanonicalAddressPoolRecord, StoreError> {
    let generation: i64 = row.get("generation");
    Ok(CanonicalAddressPoolRecord {
        id: Uuid::parse_str(row.get::<&str, _>("id")).map_err(StoreError::InvalidUuid)?,
        realm_id: Uuid::parse_str(row.get::<&str, _>("realm_id"))
            .map_err(StoreError::InvalidUuid)?,
        project_id: row.get("project_id"),
        prefix: row.get("prefix"),
        gateway: row
            .get::<Option<String>, _>("gateway")
            .map(|value| parse_pg_ipv4(&value))
            .transpose()
            .map_err(|_| StoreError::Corrupt("invalid canonical gateway".into()))?,
        first_usable: parse_pg_ipv4(&row.get::<String, _>("first_usable"))
            .map_err(|_| StoreError::Corrupt("invalid canonical pool start".into()))?,
        last_usable: parse_pg_ipv4(&row.get::<String, _>("last_usable"))
            .map_err(|_| StoreError::Corrupt("invalid canonical pool end".into()))?,
        generation: u64::try_from(generation)
            .map_err(|_| StoreError::Corrupt("negative canonical generation".into()))?,
        state: row.get("state"),
    })
}

pub(crate) fn canonical_endpoint_from_pg_row(
    row: &PgRow,
) -> Result<CanonicalEndpointRecord, StoreError> {
    let generation: i64 = row.get("generation");
    Ok(CanonicalEndpointRecord {
        id: Uuid::parse_str(row.get::<&str, _>("id")).map_err(StoreError::InvalidUuid)?,
        realm_id: Uuid::parse_str(row.get::<&str, _>("realm_id"))
            .map_err(StoreError::InvalidUuid)?,
        project_id: row.get("project_id"),
        fixed_ip: parse_pg_ipv4(&row.get::<String, _>("fixed_ip"))
            .map_err(|_| StoreError::Corrupt("invalid canonical endpoint IP".into()))?,
        mac: row.get("mac"),
        generation: u64::try_from(generation)
            .map_err(|_| StoreError::Corrupt("negative canonical generation".into()))?,
        state: row.get("state"),
    })
}

pub(crate) fn canonical_policy_from_pg_row(
    row: &PgRow,
) -> Result<CanonicalNetworkPolicyRecord, StoreError> {
    Ok(CanonicalNetworkPolicyRecord {
        id: parse_uuid(row.get("id"))?,
        project_id: row.get("project_id"),
        endpoint_id: parse_uuid(row.get("endpoint_id"))?,
        direction: row.get("direction"),
        protocol: row.get("protocol"),
        port_min: row
            .get::<Option<i32>, _>("port_min")
            .map(parse_port)
            .transpose()?,
        port_max: row
            .get::<Option<i32>, _>("port_max")
            .map(parse_port)
            .transpose()?,
        source: row.get("source"),
        destination: row.get("destination"),
        action: row.get("action"),
        generation: u64::try_from(row.get::<i64, _>("generation"))
            .map_err(|_| StoreError::Corrupt("invalid policy generation".into()))?,
        state: row.get("state"),
    })
}

pub(crate) fn parse_port(value: i32) -> Result<u16, StoreError> {
    u16::try_from(value).map_err(|_| StoreError::Corrupt("invalid policy port".into()))
}

pub(crate) fn parse_pg_ipv4(value: &str) -> Result<Ipv4Addr, std::net::AddrParseError> {
    value.split('/').next().unwrap_or(value).parse()
}

pub(crate) fn parse_pg_ipv4_prefix(value: &str) -> Result<(u32, u8), StoreError> {
    let (address, length) = value
        .split_once('/')
        .ok_or_else(|| StoreError::Corrupt("network prefix is missing length".to_owned()))?;
    let address = address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| StoreError::Corrupt("network prefix has invalid address".to_owned()))?;
    let prefix_len = length
        .parse::<u8>()
        .map_err(|_| StoreError::Corrupt("network prefix has invalid length".to_owned()))?;
    if !(1..=30).contains(&prefix_len) {
        return Err(StoreError::Corrupt(
            "network allocation prefix must leave usable addresses".to_owned(),
        ));
    }
    let mask = u32::MAX << (32 - prefix_len);
    let network = u32::from(address) & mask;
    if network != u32::from(address) {
        return Err(StoreError::Corrupt(
            "network prefix is not canonical".to_owned(),
        ));
    }
    Ok((network, prefix_len))
}

pub(crate) fn allocation_bounds(network: u32, prefix_len: u8) -> (u32, u32) {
    let size = 1u32 << (32 - prefix_len);
    (network + 1, network + size - 2)
}

pub(crate) fn parse_pg_network_allocation(
    row: &PgRow,
) -> Result<NetworkAddressAllocationRecord, StoreError> {
    Ok(NetworkAddressAllocationRecord {
        realm_id: parse_uuid(&row.get::<String, _>("realm_id"))?,
        project_id: row.get("project_id"),
        endpoint_id: parse_uuid(&row.get::<String, _>("endpoint_id"))?,
        operation_id: row.get("operation_id"),
        address: row
            .get::<String, _>("address")
            .split('/')
            .next()
            .ok_or_else(|| StoreError::Corrupt("invalid allocated network address".to_owned()))?
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid allocated network address".to_owned()))?,
    })
}

pub(crate) fn parse_pg_subnet(row: &PgRow) -> Result<SubnetRecord, StoreError> {
    let id_str: String = row.get("id");
    let id = parse_uuid(&id_str)?;
    let net_id_str: String = row.get("network_id");
    let network_id = parse_uuid(&net_id_str)?;
    let gateway_ip: String = row.get("gateway_ip");
    let alloc_start: String = row.get("allocation_start");
    let alloc_end: String = row.get("allocation_end");

    Ok(SubnetRecord {
        id,
        network_id,
        name: row.get("name"),
        project_id: row.get("project_id"),
        cidr: row.get("cidr"),
        gateway_ip: gateway_ip
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid IPv4 address in durable state".to_owned()))?,
        allocation_start: alloc_start
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid IPv4 address in durable state".to_owned()))?,
        allocation_end: alloc_end
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid IPv4 address in durable state".to_owned()))?,
        ip_version: row.get::<i16, _>("ip_version") as u8,
        enable_dhcp: row.get("enable_dhcp"),
    })
}

pub(crate) fn pg_security_group_from_row(row: &PgRow) -> Result<SecurityGroupRecord, StoreError> {
    Ok(SecurityGroupRecord {
        id: parse_uuid(row.get("id"))?,
        project_id: row.get("project_id"),
        name: row.get("name"),
        description: row.get("description"),
    })
}

pub(crate) fn pg_security_group_rule_from_row(
    row: &PgRow,
) -> Result<SecurityGroupRuleRecord, StoreError> {
    let port_min = row
        .get::<Option<i32>, _>("port_min")
        .map(u16::try_from)
        .transpose()
        .map_err(|_| StoreError::Corrupt("security-group port is out of range".to_owned()))?;
    let port_max = row
        .get::<Option<i32>, _>("port_max")
        .map(u16::try_from)
        .transpose()
        .map_err(|_| StoreError::Corrupt("security-group port is out of range".to_owned()))?;
    Ok(SecurityGroupRuleRecord {
        id: parse_uuid(row.get("id"))?,
        security_group_id: parse_uuid(row.get("security_group_id"))?,
        project_id: row.get("project_id"),
        direction: row.get("direction"),
        protocol: row.get("protocol"),
        port_min,
        port_max,
        remote_ip_prefix: row.get("remote_ip_prefix"),
    })
}

pub(crate) fn pg_security_group_binding_from_row(
    row: &PgRow,
) -> Result<SecurityGroupBindingRecord, StoreError> {
    Ok(SecurityGroupBindingRecord {
        project_id: row.get("project_id"),
        endpoint_id: parse_uuid(row.get("endpoint_id"))?,
        security_group_id: parse_uuid(row.get("security_group_id"))?,
    })
}

pub(crate) fn parse_pg_port(row: &PgRow) -> Result<PortRecord, StoreError> {
    let id_str: String = row.get("id");
    let id = parse_uuid(&id_str)?;
    let net_id_str: String = row.get("network_id");
    let network_id = parse_uuid(&net_id_str)?;
    let sub_id = row
        .get::<Option<String>, _>("subnet_id")
        .as_deref()
        .map(parse_uuid)
        .transpose()?;
    let fixed_ip: String = row.get("fixed_ip");

    Ok(PortRecord {
        id,
        network_id,
        subnet_id: sub_id,
        project_id: row.get("project_id"),
        name: row.get("name"),
        mac_address: row.get("mac_address"),
        fixed_ip: fixed_ip
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid IPv4 address in durable state".to_owned()))?,
        status: row.get("status"),
        binding_host: row.get("binding_host"),
        binding_state: row.get("binding_state"),
        binding_generation: u64::try_from(row.get::<i64, _>("binding_generation"))
            .map_err(|_| StoreError::Corrupt("negative port binding generation".to_owned()))?,
    })
}
pub(crate) fn amounts_match(a: &[ResourceAmount], b: &[ResourceAmount]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut a_sorted: Vec<(&LimitKey, u64)> =
        a.iter().map(|item| (&item.key, item.amount)).collect();
    let mut b_sorted: Vec<(&LimitKey, u64)> =
        b.iter().map(|item| (&item.key, item.amount)).collect();
    a_sorted.sort();
    b_sorted.sort();
    a_sorted == b_sorted
}
pub(crate) fn parse_pg_non_negative_u64(val: i64, context: &str) -> Result<u64, StoreError> {
    if val < 0 {
        return Err(StoreError::Corrupt(format!(
            "malformed negative count/amount {val} for {context} in durable storage"
        )));
    }
    u64::try_from(val).map_err(|_| {
        StoreError::Corrupt(format!(
            "count/amount {val} for {context} exceeds maximum supported 64-bit integer"
        ))
    })
}
