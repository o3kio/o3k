use super::helpers::deterministic_port_mac;
use super::*;
use crate::{
    AttachmentPlanInput, NetworkPlanError, compile_attachment_plan,
    compile_attachment_plan_with_defaults,
};
use o3k_domain::{NetworkPlanIntent, NetworkProtocol, PolicyAction, PolicyDirection, PolicyIntent};
use o3k_kernel::{AuditOutcome, AuthContext, LimitKey, LimitValue, OwnershipScope, ScopeId};
use o3k_store::DurableStore;
use std::{
    collections::HashSet,
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

fn auth(project_id: &str) -> AuthContext {
    AuthContext::new(
        o3k_kernel::Principal::User(o3k_kernel::UserPrincipal::new(
            o3k_kernel::PrincipalId::new_unchecked("test-user"),
            "test-user",
            Some("default".to_string()),
        )),
        o3k_kernel::OwnershipScope::project(
            o3k_kernel::ScopeId::new_unchecked(project_id),
            Some(project_id.to_string()),
            Some("default".to_string()),
        ),
        vec!["admin".to_string()],
        1000,
        5000,
        uuid::Uuid::now_v7().to_string(),
        uuid::Uuid::now_v7().to_string(),
        None,
    )
}

fn root(label: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/o3k-network-{label}-{}", std::process::id()))
}

#[test]
fn canonical_endpoint_status_projects_from_durable_binding_state() {
    let cases = [
        (None, "ACTIVE"),
        (Some("binding"), "BUILD"),
        (Some("bound"), "ACTIVE"),
        (Some("down"), "DOWN"),
        (Some("error"), "ERROR"),
    ];
    for (binding_state, expected) in cases {
        assert!(matches!(
            super::port::project_neutron_port_status("active", binding_state),
            Ok(status) if status == expected
        ));
    }
    assert!(matches!(
        super::port::project_neutron_port_status("active", Some("unknown")),
        Err(NetworkError::CorruptBindingState)
    ));
}

#[tokio::test]
async fn canonical_service_reconstructs_zero_and_multiple_realms()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("canonical-runtime");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_canonical_network_for_project("project-a", "canonical".to_owned())
        .await?;
    let empty = service
        .reconstruct_canonical_network("project-a", network.id)
        .await?;
    assert!(empty.realms.is_empty());

    let realm_a = service
        .create_canonical_realm_for_project("project-a", network.id, "10.0.0.0/24".to_owned(), true)
        .await?;
    let realm_b = service
        .create_canonical_realm_for_project("project-a", network.id, "10.0.0.0/24".to_owned(), true)
        .await?;
    let realm_c = service
        .create_canonical_realm_for_project(
            "project-a",
            network.id,
            "10.1.0.0/24".to_owned(),
            false,
        )
        .await?;
    let pool = service
        .create_canonical_pool_for_project(
            "project-a",
            realm_a.id,
            "10.0.0.0/24".to_owned(),
            Some("10.0.0.1".parse()?),
            "10.0.0.2".parse()?,
            "10.0.0.254".parse()?,
        )
        .await?;
    let endpoint_a = service
        .create_canonical_endpoint_for_project(
            "project-a",
            realm_a.id,
            "10.0.0.10".parse()?,
            "02:00:00:00:00:10".to_owned(),
        )
        .await?;
    let endpoint_b = service
        .create_canonical_endpoint_for_project(
            "project-a",
            realm_b.id,
            "10.0.0.10".parse()?,
            "02:00:00:00:00:11".to_owned(),
        )
        .await?;
    assert_eq!(endpoint_a.fixed_ip, endpoint_b.fixed_ip);
    assert!(matches!(
        service
            .create_canonical_endpoint_for_project(
                "project-a",
                realm_a.id,
                endpoint_a.fixed_ip,
                "02:00:00:00:00:12".to_owned()
            )
            .await,
        Err(NetworkError::Conflict)
    ));
    assert!(matches!(
        service
            .delete_canonical_realm_for_project("project-a", realm_a.id)
            .await,
        Err(NetworkError::Conflict)
    ));
    drop(service);
    drop(store);

    let reopened_store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let reopened = NetworkService::open_for_test(&path, reopened_store.clone()).await?;
    let snapshot = reopened
        .reconstruct_canonical_network("project-a", network.id)
        .await?;
    assert_eq!(snapshot.network.id, network.id);
    assert_eq!(snapshot.realms.len(), 3);
    assert_eq!(snapshot.pools[&realm_a.id], vec![pool]);
    assert_eq!(snapshot.endpoints[&realm_a.id], vec![endpoint_a]);
    reopened
        .delete_canonical_realm_for_project("project-a", realm_c.id)
        .await?;
    assert_eq!(
        reopened
            .reconstruct_canonical_network("project-a", network.id)
            .await?
            .realms
            .len(),
        2
    );
    assert!(matches!(
        reopened
            .delete_canonical_network_for_project("project-a", network.id)
            .await,
        Err(NetworkError::Conflict)
    ));
    drop(reopened);
    drop(reopened_store);
    fs::remove_dir_all(path)?;
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{sqlite_path}-wal"));
    let _ = fs::remove_file(format!("{sqlite_path}-shm"));
    Ok(())
}

#[tokio::test]
async fn network_rename_updates_projection_and_reopens_with_new_name()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("rename-restart");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let identity = auth("project-a");
    let network = service
        .create_network(&identity, "before".to_owned())
        .await?;
    let renamed = service
        .update_network(&identity, network.id, Some("after".to_owned()), Some(false))
        .await?;
    assert_eq!(renamed.id, network.id);
    assert_eq!(renamed.name, "after");
    let canonical = store
        .get_canonical_network("project-a", &network.id)
        .await?
        .ok_or("canonical network after rename")?;
    assert!(!canonical.admin_state_up);
    assert_eq!(
        store
            .get_network("project-a", &network.id)
            .await?
            .map(|n| n.name),
        Some("after".to_owned())
    );

    drop(service);
    drop(store);
    let reopened_store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let reopened = NetworkService::open_for_test(&path, reopened_store.clone()).await?;
    let restored = reopened.get_network(&identity, network.id).await?;
    assert_eq!(restored.id, network.id);
    assert_eq!(restored.project_id, "project-a");
    assert_eq!(restored.name, "after");
    let restored_canonical = reopened_store
        .get_canonical_network("project-a", &network.id)
        .await?
        .ok_or("canonical network after restart")?;
    assert!(!restored_canonical.admin_state_up);
    assert_eq!(
        reopened_store
            .get_network("project-a", &network.id)
            .await?
            .map(|n| n.name),
        Some("after".to_owned())
    );
    assert!(
        reopened_store
            .get_network("project-a", &network.id)
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn canonical_reads_do_not_require_projection_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("canonical-reads");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_canonical_network_for_project("project-a", "canonical".to_owned())
        .await?;
    let realm = service
        .create_canonical_realm_for_project(
            "project-a",
            network.id,
            "10.20.0.0/24".to_owned(),
            false,
        )
        .await?;
    let _pool = service
        .create_canonical_pool_for_project(
            "project-a",
            realm.id,
            "10.20.0.0/24".to_owned(),
            Some("10.20.0.1".parse()?),
            "10.20.0.2".parse()?,
            "10.20.0.254".parse()?,
        )
        .await?;
    let endpoint = service
        .create_canonical_endpoint_for_project(
            "project-a",
            realm.id,
            "10.20.0.10".parse()?,
            "02:00:00:20:00:10".to_owned(),
        )
        .await?;

    let subnet = service
        .get_subnet_for_project("project-a", realm.id)
        .await?;
    assert_eq!(subnet.id, realm.id);
    assert_eq!(subnet.network_id, network.id);
    assert!(subnet.name.is_empty());

    let port = service
        .get_port_for_project("project-a", endpoint.id)
        .await?;
    assert_eq!(port.id, endpoint.id);
    assert_eq!(port.subnet_id, Some(realm.id));
    assert_eq!(port.fixed_ip, endpoint.fixed_ip);
    assert_eq!(port.mac_address, endpoint.mac);
    assert!(port.name.is_empty());

    drop(service);
    fs::remove_dir_all(path)?;
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{sqlite_path}-wal"));
    let _ = fs::remove_file(format!("{sqlite_path}-shm"));
    Ok(())
}

#[tokio::test]
async fn authenticated_canonical_entry_points_enforce_scope_and_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("canonical-auth");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let sink = Arc::new(o3k_kernel::MemoryAuditSink::new());
    let service = NetworkService::open_for_test(&path, store)
        .await?
        .with_required_audit_publisher(sink.clone());
    let network = service
        .create_canonical_network(&auth("project-a"), "authorized".to_owned())
        .await?;
    let realm = service
        .create_canonical_realm(
            &auth("project-a"),
            network.id,
            "10.30.0.0/24".to_owned(),
            false,
        )
        .await?;
    assert!(matches!(
        service
            .delete_canonical_realm(&auth("project-b"), realm.id)
            .await,
        Err(NetworkError::NotFound)
    ));
    let events = sink.events();
    assert!(events.iter().any(|event| {
        event.action.to_string() == "network:DeleteAddressRealm"
            && event.outcome == AuditOutcome::Denied
            && event.resource_id.is_none()
    }));
    Ok(())
}

#[tokio::test]
async fn authenticated_parent_actions_use_canonical_owner_and_audit_outcomes()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("canonical-auth-matrix");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let sink = Arc::new(o3k_kernel::MemoryAuditSink::new());
    let service = NetworkService::open_for_test(&path, store)
        .await?
        .with_required_audit_publisher(sink.clone());
    let network = service
        .create_canonical_network(&auth("project-a"), "matrix".to_owned())
        .await?;
    let realm = service
        .create_canonical_realm(
            &auth("project-a"),
            network.id,
            "10.32.0.0/24".to_owned(),
            false,
        )
        .await?;

    assert!(matches!(
        service
            .create_canonical_realm(
                &auth("project-b"),
                network.id,
                "10.33.0.0/24".to_owned(),
                false,
            )
            .await,
        Err(NetworkError::NotFound)
    ));
    assert!(matches!(
        service
            .create_canonical_pool(
                &auth("project-b"),
                realm.id,
                "10.32.0.0/24".to_owned(),
                Some("10.32.0.1".parse()?),
                "10.32.0.2".parse()?,
                "10.32.0.254".parse()?,
            )
            .await,
        Err(NetworkError::NotFound)
    ));
    assert!(matches!(
        service
            .create_canonical_endpoint(
                &auth("project-b"),
                realm.id,
                "10.32.0.10".parse()?,
                "02:00:00:32:00:10".to_owned(),
            )
            .await,
        Err(NetworkError::NotFound)
    ));

    let pool = service
        .create_canonical_pool(
            &auth("project-a"),
            realm.id,
            "10.32.0.0/24".to_owned(),
            Some("10.32.0.1".parse()?),
            "10.32.0.2".parse()?,
            "10.32.0.254".parse()?,
        )
        .await?;
    assert_eq!(
        service
            .list_canonical_pools(&auth("project-a"), realm.id)
            .await?
            .len(),
        1
    );
    assert!(matches!(
        service
            .list_canonical_pools(&auth("project-b"), realm.id)
            .await,
        Err(NetworkError::NotFound)
    ));
    let endpoint = service
        .create_canonical_endpoint(
            &auth("project-a"),
            realm.id,
            "10.32.0.10".parse()?,
            "02:00:00:32:00:10".to_owned(),
        )
        .await?;
    assert_eq!(
        service
            .get_canonical_realm(&auth("project-a"), realm.id)
            .await?
            .id,
        realm.id
    );
    assert_eq!(
        service
            .list_canonical_endpoints(&auth("project-a"), realm.id)
            .await?
            .len(),
        1
    );
    assert_eq!(
        service
            .get_canonical_endpoint(&auth("project-a"), endpoint.id)
            .await?
            .id,
        endpoint.id
    );
    assert!(matches!(
        service
            .get_canonical_endpoint(&auth("project-b"), endpoint.id)
            .await,
        Err(NetworkError::NotFound)
    ));
    assert!(matches!(
        service
            .create_canonical_network(&auth("project-a"), "matrix".to_owned())
            .await,
        Err(NetworkError::Conflict)
    ));

    let events = sink.events();
    let denied = events
        .iter()
        .filter(|event| event.outcome == AuditOutcome::Denied)
        .collect::<Vec<_>>();
    assert!(denied.len() >= 3);
    assert!(denied.iter().all(|event| {
        event
            .authorization_decision
            .as_ref()
            .is_some_and(|decision| decision.reason() == &o3k_kernel::DecisionReason::ScopeMismatch)
            && event
                .owner_scope
                .as_ref()
                .is_some_and(|scope| scope.id().as_str() == "project-a")
    }));
    assert!(events.iter().any(|event| {
        event.action.to_string() == "network:CreateNetwork" && event.outcome == AuditOutcome::Failed
    }));
    assert!(events.iter().any(|event| {
        event.action.to_string() == "network:CreateEndpoint"
            && event.outcome == AuditOutcome::Succeeded
    }));
    service
        .delete_canonical_endpoint(&auth("project-a"), endpoint.id)
        .await?;
    service
        .delete_canonical_pool(&auth("project-a"), pool.id)
        .await?;
    service
        .delete_canonical_realm(&auth("project-a"), realm.id)
        .await?;
    service
        .delete_canonical_network(&auth("project-a"), network.id)
        .await?;
    let final_events = sink.events();
    assert!(final_events.iter().any(|event| {
        event.action.to_string() == "network:DeleteNetwork"
            && event.outcome == AuditOutcome::Succeeded
    }));
    let _ = fs::remove_dir_all(path);
    let _ = fs::remove_file(sqlite_path);
    Ok(())
}

#[tokio::test]
async fn independent_services_preserve_canonical_endpoint_and_realm_races()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("canonical-races");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store_a = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let store_b = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service_a = NetworkService::open_for_test(&path, store_a).await?;
    let service_b = NetworkService::open_for_test(&path, store_b).await?;
    let network = service_a
        .create_canonical_network_for_project("project-a", "races".to_owned())
        .await?;
    let realm = service_a
        .create_canonical_realm_for_project(
            "project-a",
            network.id,
            "10.31.0.0/24".to_owned(),
            false,
        )
        .await?;
    let (left, right) = tokio::join!(
        service_a.create_canonical_endpoint_for_project(
            "project-a",
            realm.id,
            "10.31.0.10".parse()?,
            "02:00:00:00:31:10".to_owned(),
        ),
        service_b.create_canonical_endpoint_for_project(
            "project-a",
            realm.id,
            "10.31.0.10".parse()?,
            "02:00:00:00:31:11".to_owned(),
        )
    );
    assert_eq!(left.is_ok() as u8 + right.is_ok() as u8, 1);

    let delete = service_a.delete_canonical_realm_for_project("project-a", realm.id);
    let create = service_b.create_canonical_endpoint_for_project(
        "project-a",
        realm.id,
        "10.31.0.11".parse()?,
        "02:00:00:00:31:12".to_owned(),
    );
    let (delete_result, create_result) = tokio::join!(delete, create);
    if delete_result.is_ok() {
        assert!(create_result.is_err());
        assert!(
            service_a
                .reconstruct_canonical_network("project-a", network.id)
                .await?
                .realms
                .is_empty()
        );
    } else {
        assert!(create_result.is_ok());
        assert!(
            service_a
                .reconstruct_canonical_network("project-a", network.id)
                .await?
                .realms
                .iter()
                .any(|value| value.id == realm.id)
        );
    }
    let _ = fs::remove_dir_all(path);
    let _ = fs::remove_file(sqlite_path);
    Ok(())
}

#[tokio::test]
async fn independent_services_preserve_network_realm_races()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("canonical-network-realm-races");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store_a = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let store_b = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service_a = NetworkService::open_for_test(&path, store_a).await?;
    let service_b = NetworkService::open_for_test(&path, store_b).await?;
    let network = service_a
        .create_canonical_network_for_project("project-a", "parent-race".to_owned())
        .await?;

    let (first, second) = tokio::join!(
        service_a.create_canonical_realm_for_project(
            "project-a",
            network.id,
            "10.34.0.0/24".to_owned(),
            false,
        ),
        service_b.create_canonical_realm_for_project(
            "project-a",
            network.id,
            "10.35.0.0/24".to_owned(),
            false,
        )
    );
    let created = [first, second]
        .into_iter()
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    assert_eq!(created.len(), 2);
    let realms = service_a
        .reconstruct_canonical_network("project-a", network.id)
        .await?
        .realms;
    assert_eq!(realms.len(), 2);
    assert!(realms.iter().all(|realm| realm.network_id == network.id));

    let (delete, create) = tokio::join!(
        service_a.delete_canonical_network_for_project("project-a", network.id),
        service_b.create_canonical_realm_for_project(
            "project-a",
            network.id,
            "10.36.0.0/24".to_owned(),
            false,
        )
    );
    assert!(delete.is_err());
    assert!(create.is_ok());
    let snapshot = service_a
        .reconstruct_canonical_network("project-a", network.id)
        .await?;
    assert!(
        snapshot
            .realms
            .iter()
            .all(|realm| realm.network_id == snapshot.network.id)
    );
    let _ = fs::remove_dir_all(path);
    let _ = fs::remove_file(sqlite_path);
    Ok(())
}

#[tokio::test]
async fn realm_deletion_is_fenced_when_provider_binding_remains()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("realm-deletion-fence");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_canonical_network_for_project("project-a", "fenced".to_owned())
        .await?;
    let realm = service
        .create_canonical_realm_for_project(
            "project-a",
            network.id,
            "10.30.0.0/24".to_owned(),
            false,
        )
        .await?;
    store
        .insert_canonical_realm_binding(&o3k_store::CanonicalRealmBindingRecord {
            fabric_domain_id: "fabric-a".to_owned(),
            realm_id: realm.id,
            provider_kind: "geneve".to_owned(),
            provider_segment_id: 300,
            binding_generation: 1,
            state: "active".to_owned(),
        })
        .await?;

    assert!(matches!(
        service
            .delete_canonical_realm_for_project("project-a", realm.id)
            .await,
        Err(NetworkError::Conflict)
    ));
    let deleting = store
        .get_canonical_realm("project-a", &realm.id)
        .await?
        .ok_or("realm disappeared during fenced deletion")?;
    assert_eq!(deleting.state, "deleting");
    assert!(matches!(
        service
            .create_canonical_endpoint_for_project(
                "project-a",
                realm.id,
                "10.30.0.10".parse()?,
                "02:00:00:30:00:10".to_owned(),
            )
            .await,
        Err(NetworkError::InvalidRequest) | Err(NetworkError::Conflict)
    ));
    assert!(matches!(
        service
            .delete_canonical_realm_for_project("project-a", realm.id)
            .await,
        Err(NetworkError::Conflict)
    ));
    assert!(
        service
            .get_canonical_network_for_project("project-a", network.id)
            .await
            .is_ok()
    );
    let _ = fs::remove_dir_all(path);
    let _ = fs::remove_file(sqlite_path);
    Ok(())
}

#[tokio::test]
async fn realm_cleanup_unknown_outcome_replays_and_finalizes_after_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("realm-cleanup-recovery");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_canonical_network_for_project("project-a", "recovery".to_owned())
        .await?;
    let realm = service
        .create_canonical_realm_for_project(
            "project-a",
            network.id,
            "10.31.0.0/24".to_owned(),
            false,
        )
        .await?;
    let binding = o3k_store::CanonicalRealmBindingRecord {
        fabric_domain_id: "fabric-a".to_owned(),
        realm_id: realm.id,
        provider_kind: "geneve".to_owned(),
        provider_segment_id: 301,
        binding_generation: 1,
        state: "active".to_owned(),
    };
    store.insert_canonical_realm_binding(&binding).await?;

    assert!(matches!(
        service
            .delete_canonical_realm_for_project("project-a", realm.id)
            .await,
        Err(NetworkError::Conflict)
    ));
    let first = service
        .begin_canonical_realm_deletion_for_project("project-a", realm.id)
        .await?;
    let operation_id = match first {
        RealmCleanupProgress::AwaitingObservation { operation_id, .. } => operation_id,
        _ => return Err("unexpected replay progress".into()),
    };
    let unknown = service
        .observe_canonical_realm_cleanup_for_project(
            "project-a",
            realm.id,
            vec![RealmCleanupObservation::Unknown {
                binding: binding.clone(),
                reason: "provider response lost".to_owned(),
            }],
        )
        .await?;
    assert!(matches!(
        unknown,
        RealmCleanupProgress::AwaitingObservation { .. }
    ));
    assert_eq!(
        store.get_canonical_operation(operation_id).await?.state,
        o3k_store::OperationState::UnknownOutcome
    );

    drop(service);
    let reopened_store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let reopened = NetworkService::open_for_test(&path, reopened_store.clone()).await?;
    let replay = reopened
        .begin_canonical_realm_deletion_for_project("project-a", realm.id)
        .await?;
    assert!(matches!(
        replay,
        RealmCleanupProgress::AwaitingObservation { operation_id: id, .. } if id == operation_id
    ));
    let present = reopened
        .observe_canonical_realm_cleanup_for_project(
            "project-a",
            realm.id,
            vec![RealmCleanupObservation::Present(binding.clone())],
        )
        .await?;
    assert!(matches!(
        present,
        RealmCleanupProgress::AwaitingObservation { .. }
    ));
    let removed = reopened
        .observe_canonical_realm_cleanup_for_project(
            "project-a",
            realm.id,
            vec![RealmCleanupObservation::Absent(binding)],
        )
        .await?;
    assert_eq!(removed, RealmCleanupProgress::Removed { operation_id });
    assert!(
        reopened
            .get_canonical_network_for_project("project-a", network.id)
            .await
            .is_ok()
    );
    assert!(matches!(
        reopened
            .reconstruct_canonical_network("project-a", network.id)
            .await,
        Ok(snapshot) if snapshot.realms.is_empty()
    ));
    let _ = fs::remove_dir_all(path);
    let _ = fs::remove_file(sqlite_path);
    Ok(())
}

#[tokio::test]
async fn realm_deletion_rejects_gateway_dependents_and_cannot_be_reattached()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("realm-delete-gateway-dependent");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_canonical_network_for_project("project-a", "net".to_owned())
        .await?;
    let realm = service
        .create_canonical_realm_for_project(
            "project-a",
            network.id,
            "192.0.2.0/24".to_owned(),
            false,
        )
        .await?;
    let gateway = service
        .create_l3_gateway_for_project("project-a", "edge".to_owned(), None, true)
        .await?;
    let attachment = service
        .attach_l3_gateway_realm("project-a", &gateway.id, &realm.id)
        .await?;

    assert!(matches!(
        service
            .begin_canonical_realm_deletion_for_project("project-a", realm.id)
            .await,
        Err(NetworkError::Conflict)
    ));
    assert!(matches!(
        store
            .begin_canonical_realm_deletion("project-a", &realm.id, realm.generation)
            .await,
        Err(o3k_store::StoreError::NetworkInUse)
    ));
    assert_eq!(
        service
            .get_canonical_realm_for_project("project-a", realm.id)
            .await?
            .state,
        "active"
    );

    // The attachment remains a deletion dependency until its own lifecycle
    // proves detachment and removes the relation.
    let deleting_attachment = service
        .detach_l3_gateway_realm("project-a", &attachment.id, attachment.generation)
        .await?;
    service
        .finalize_l3_gateway_realm_detachment_for_project(
            "project-a",
            &attachment.id,
            deleting_attachment.generation,
        )
        .await?;
    let deletion = service
        .begin_canonical_realm_deletion_for_project("project-a", realm.id)
        .await?;
    assert!(matches!(deletion, RealmCleanupProgress::Deleting { .. }));
    assert!(matches!(
        service
            .attach_l3_gateway_realm("project-a", &gateway.id, &realm.id)
            .await,
        Err(NetworkError::Conflict)
    ));
    let _ = fs::remove_dir_all(path);
    Ok(())
}

#[tokio::test]
async fn allocation_is_deterministic_collision_safe_and_restartable()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("allocation");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_network(&auth("project-a"), "flat".to_owned())
        .await?;
    let subnet = service
        .create_subnet(
            &auth("project-a"),
            network.id,
            "lab".to_owned(),
            "192.0.2.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let first = service
        .create_port(&auth("project-a"), network.id, "one".to_owned())
        .await?;
    let second = service
        .create_port(&auth("project-a"), network.id, "two".to_owned())
        .await?;
    assert_ne!(first.fixed_ip, second.fixed_ip);
    assert_ne!(first.mac_address, second.mac_address);
    assert_eq!(first.mac_address, deterministic_port_mac(first.id));
    assert_eq!(first.fixed_ip, subnet.allocation_start);
    drop(service);
    drop(store);
    let reopened_store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let reopened = NetworkService::open_for_test(&path, reopened_store.clone()).await?;
    assert_eq!(
        reopened.get_port(&auth("project-a"), first.id).await?,
        first
    );
    reopened.delete_port(&auth("project-a"), first.id).await?;
    let replacement = reopened
        .create_port(&auth("project-a"), network.id, "replacement".to_owned())
        .await?;
    assert_eq!(replacement.fixed_ip, first.fixed_ip);
    assert!(!fs::read_dir(&path)?.flatten().any(|entry| {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        name.contains("metadata.tmp-") || name.contains("metadata.json")
    }));
    drop(reopened);
    drop(reopened_store);
    fs::remove_dir_all(path)?;
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{sqlite_path}-wal"));
    let _ = fs::remove_file(format!("{sqlite_path}-shm"));
    Ok(())
}

#[tokio::test]
async fn caller_supplied_port_identity_is_stable_and_conflicts_on_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("stable-port-id");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store).await?;
    let network = service
        .create_network(&auth("project-a"), "stable".to_owned())
        .await?;
    service
        .create_subnet(
            &auth("project-a"),
            network.id,
            "stable-subnet".to_owned(),
            "192.0.2.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let id = Uuid::new_v5(&Uuid::NAMESPACE_OID, b"native:stable-port");
    // A compatibility/TestLab port owns the first pool address. Stable native
    // identity must not imply a fixed address; allocation advances safely.
    let occupied = service
        .create_port(&auth("project-a"), network.id, "occupied".to_owned())
        .await?;
    let first = service
        .create_port_for_project_with_stable_id(
            "project-a",
            id,
            network.id,
            "native-server-endpoint".to_owned(),
        )
        .await?;
    assert_eq!(first.id, id);
    assert_ne!(first.fixed_ip, occupied.fixed_ip);
    assert!(matches!(
        service
            .create_port_for_project_with_stable_id(
                "project-a",
                id,
                network.id,
                "native-server-endpoint".to_owned(),
            )
            .await,
        Err(NetworkError::Conflict)
    ));
    assert_eq!(service.get_port(&auth("project-a"), id).await?, first);
    let _ = fs::remove_dir_all(path);
    Ok(())
}

#[tokio::test]
async fn concurrent_stable_native_ports_keep_identity_and_address_unique()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("o3k-network-stable-race-{}", Uuid::now_v7()));
    let sqlite_path = path.with_extension("sqlite");
    fs::create_dir_all(&path)?;
    let setup_store = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
    let setup = NetworkService::open_for_test(&path, setup_store).await?;
    let network = setup
        .create_network(&auth("project-a"), "stable-race".to_owned())
        .await?;
    setup
        .create_subnet(
            &auth("project-a"),
            network.id,
            "stable-race-subnet".to_owned(),
            "192.0.2.0/27".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    drop(setup);

    let service_a = NetworkService::open_for_test(
        &path,
        Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?),
    )
    .await?;
    let service_b = NetworkService::open_for_test(
        &path,
        Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?),
    )
    .await?;
    let mut handles = Vec::new();
    for index in 0..8 {
        let service = if index % 2 == 0 {
            service_a.clone()
        } else {
            service_b.clone()
        };
        let id = Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            format!("native:stable:{index}").as_bytes(),
        );
        handles.push(tokio::spawn(async move {
            service
                .create_port_for_project_with_stable_id(
                    "project-a",
                    id,
                    network.id,
                    format!("native-{index}"),
                )
                .await
        }));
    }
    let mut ports = Vec::new();
    for handle in handles {
        ports.push(handle.await??);
    }
    let ids: HashSet<Uuid> = ports.iter().map(|port| port.id).collect();
    let ips: HashSet<Ipv4Addr> = ports.iter().map(|port| port.fixed_ip).collect();
    let macs: HashSet<String> = ports
        .iter()
        .map(|port| port.mac_address.to_ascii_lowercase())
        .collect();
    assert_eq!(ports.len(), ids.len());
    assert_eq!(ports.len(), ips.len());
    assert_eq!(ports.len(), macs.len());
    drop(service_a);
    drop(service_b);
    fs::remove_dir_all(path)?;
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{}-wal", sqlite_path.display()));
    let _ = fs::remove_file(format!("{}-shm", sqlite_path.display()));
    Ok(())
}

#[tokio::test]
async fn legacy_metadata_file_is_imported_once_and_never_read_again()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("legacy-import");
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path)?;
    let network_id = Uuid::now_v7();
    let subnet_id = Uuid::now_v7();
    let port_with_mac = Uuid::now_v7();
    let port_without_mac = Uuid::now_v7();
    let port_without_subnet = Uuid::now_v7();
    let legacy = serde_json::json!({
        "networks": [{
            "id": network_id,
            "name": "flat",
            "project_id": "project-a",
            "status": "ACTIVE"
        }],
        "subnets": [{
            "id": subnet_id,
            "network_id": network_id,
            "name": "lab",
            "project_id": "project-a",
            "cidr": "192.0.2.0/29",
            "gateway_ip": "192.0.2.1",
            "allocation_start": "192.0.2.2",
            "allocation_end": "192.0.2.14"
        }],
        "ports": [
            {
                "id": port_with_mac,
                "network_id": network_id,
                "subnet_id": subnet_id,
                "project_id": "project-a",
                "name": "with-mac",
                "mac_address": "02:00:00:00:00:99",
                "fixed_ip": "192.0.2.2",
                "status": "ACTIVE"
            },
            {
                "id": port_without_mac,
                "network_id": network_id,
                "subnet_id": subnet_id,
                "project_id": "project-a",
                "name": "no-mac",
                "fixed_ip": "192.0.2.3",
                "status": "ACTIVE"
            },
            {
                "id": port_without_subnet,
                "network_id": network_id,
                "project_id": "project-a",
                "name": "no-subnet",
                "mac_address": "02:00:00:00:00:98",
                "fixed_ip": "192.0.2.4",
                "status": "ACTIVE"
            }
        ]
    });
    fs::write(path.join("metadata.json"), serde_json::to_vec(&legacy)?)?;
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    assert_eq!(service.list_networks(&auth("project-a")).await?.len(), 1);
    assert_eq!(service.list_subnets(&auth("project-a")).await?.len(), 1);
    assert_eq!(service.list_ports(&auth("project-a")).await?.len(), 3);
    let network = service.get_network(&auth("project-a"), network_id).await?;
    assert_eq!(network.id, network_id);
    let subnet = service.get_subnet(&auth("project-a"), subnet_id).await?;
    assert_eq!(subnet.id, subnet_id);
    let first = service.get_port(&auth("project-a"), port_with_mac).await?;
    assert_eq!(first.mac_address, "02:00:00:00:00:99");
    assert_eq!(first.subnet_id, Some(subnet_id));
    let migrated_mac = service
        .get_port(&auth("project-a"), port_without_mac)
        .await?;
    assert_eq!(
        migrated_mac.mac_address,
        deterministic_port_mac(port_without_mac)
    );
    assert_eq!(migrated_mac.subnet_id, Some(subnet_id));
    let migrated_subnet = service
        .get_port(&auth("project-a"), port_without_subnet)
        .await?;
    assert_eq!(migrated_subnet.subnet_id, Some(subnet_id));
    assert_eq!(migrated_subnet.mac_address, "02:00:00:00:00:98");
    assert!(!path.join("metadata.json").exists());
    assert!(path.join("metadata.json.imported").exists());
    let second = NetworkService::open_for_test(&path, store).await?;
    assert_eq!(second.list_networks(&auth("project-a")).await?.len(), 1);
    assert_eq!(second.list_subnets(&auth("project-a")).await?.len(), 1);
    assert_eq!(second.list_ports(&auth("project-a")).await?.len(), 3);
    drop(second);
    fs::remove_dir_all(path)?;

    let corrupt_path = root("legacy-import-corrupt");
    let _ = fs::remove_dir_all(&corrupt_path);
    fs::create_dir_all(&corrupt_path)?;
    fs::write(corrupt_path.join("metadata.json"), b"not-json")?;
    let corrupt_store = Arc::new(o3k_store::testkit::open_memory().await?);
    assert!(matches!(
        NetworkService::open_for_test(&corrupt_path, corrupt_store).await,
        Err(NetworkError::CorruptMetadata(_))
    ));
    assert!(corrupt_path.join("metadata.json").exists());
    fs::remove_dir_all(corrupt_path)?;

    let duplicate_path = root("legacy-import-duplicate-mac");
    let _ = fs::remove_dir_all(&duplicate_path);
    fs::create_dir_all(&duplicate_path)?;
    let duplicated = serde_json::json!({
        "networks": [],
        "subnets": [],
        "ports": [
            {
                "id": Uuid::now_v7(),
                "network_id": Uuid::now_v7(),
                "project_id": "project-a",
                "name": "one",
                "mac_address": "02:00:00:00:00:01",
                "fixed_ip": "192.0.2.2",
                "status": "ACTIVE"
            },
            {
                "id": Uuid::now_v7(),
                "network_id": Uuid::now_v7(),
                "project_id": "project-a",
                "name": "two",
                "mac_address": "02:00:00:00:00:01",
                "fixed_ip": "192.0.2.3",
                "status": "ACTIVE"
            }
        ]
    });
    fs::write(
        duplicate_path.join("metadata.json"),
        serde_json::to_vec(&duplicated)?,
    )?;
    let duplicate_store = Arc::new(o3k_store::testkit::open_memory().await?);
    assert!(matches!(
        NetworkService::open_for_test(&duplicate_path, duplicate_store).await,
        Err(NetworkError::Conflict)
    ));
    assert!(duplicate_path.join("metadata.json").exists());
    fs::remove_dir_all(duplicate_path)?;
    Ok(())
}

#[tokio::test]
async fn concurrent_port_creation_never_allocates_duplicate_ips_or_macs()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("o3k-network-concurrent-{}", Uuid::now_v7()));
    let sqlite_path = path.with_extension("sqlite");
    fs::create_dir_all(&path)?;
    let setup_store = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
    let setup = NetworkService::open_for_test(&path, setup_store.clone()).await?;
    let network = setup
        .create_network(&auth("project-a"), "flat".to_owned())
        .await?;
    let subnet = setup
        .create_subnet(
            &auth("project-a"),
            network.id,
            "lab".to_owned(),
            "192.0.2.0/28".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(subnet.cidr, "192.0.2.0/28");
    drop(setup);
    drop(setup_store);

    let store_a = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
    let store_b = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
    let service_a = NetworkService::open_for_test(&path, store_a).await?;
    let service_b = NetworkService::open_for_test(&path, store_b).await?;
    let mut handles = Vec::new();
    for index in 0..12 {
        let service = if index % 2 == 0 {
            service_a.clone()
        } else {
            service_b.clone()
        };
        let network_id = network.id;
        handles.push(tokio::spawn(async move {
            service
                .create_port(&auth("project-a"), network_id, format!("port-{index}"))
                .await
        }));
    }
    let mut ports = Vec::new();
    for handle in handles {
        match handle.await? {
            Ok(port) => ports.push(port),
            Err(NetworkError::PoolExhausted) => {}
            Err(error) => return Err(error.into()),
        }
    }
    assert_eq!(ports.len(), 12);
    let ips: HashSet<Ipv4Addr> = ports.iter().map(|port| port.fixed_ip).collect();
    let macs: HashSet<String> = ports
        .iter()
        .map(|port| port.mac_address.to_ascii_lowercase())
        .collect();
    assert_eq!(ports.len(), ips.len());
    assert_eq!(ports.len(), macs.len());
    drop(service_a);
    drop(service_b);
    fs::remove_dir_all(path)?;
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{}-wal", sqlite_path.display()));
    let _ = fs::remove_file(format!("{}-shm", sqlite_path.display()));
    Ok(())
}

#[tokio::test]
async fn concurrent_explicit_fixed_ip_creation_has_one_winner()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("o3k-network-explicit-race-{}", Uuid::now_v7()));
    let sqlite_path = path.with_extension("sqlite");
    fs::create_dir_all(&path)?;
    let setup_store = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
    let setup = NetworkService::open_for_test(&path, setup_store.clone()).await?;
    let network = setup
        .create_network(&auth("project-a"), "flat".to_owned())
        .await?;
    let subnet = setup
        .create_subnet(
            &auth("project-a"),
            network.id,
            "lab".to_owned(),
            "192.0.2.0/28".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    assert!(matches!(
        setup
            .create_port_with_fixed_ip(
                &auth("project-a"),
                network.id,
                "outside-pool".to_owned(),
                Some((subnet.id, Some(Ipv4Addr::new(203, 0, 113, 5)))),
            )
            .await,
        Err(NetworkError::InvalidRequest)
    ));
    assert!(matches!(
        setup
            .create_port_with_fixed_ip(
                &auth("project-a"),
                network.id,
                "o3k-server:project-a:spoof".to_owned(),
                Some((subnet.id, None)),
            )
            .await,
        Err(NetworkError::InvalidRequest)
    ));
    let server_port = setup
        .create_port_for_project(
            "project-a",
            network.id,
            "o3k-server:project-a:owned".to_owned(),
        )
        .await?;
    assert!(matches!(
        setup
            .update_port_name_for_project("project-a", server_port.id, "renamed".to_owned(),)
            .await,
        Err(NetworkError::Conflict)
    ));
    setup
        .delete_port_for_project("project-a", server_port.id)
        .await?;
    drop(setup);
    drop(setup_store);

    let service_a = NetworkService::open_for_test(
        &path,
        Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?),
    )
    .await?;
    let service_b = NetworkService::open_for_test(
        &path,
        Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?),
    )
    .await?;
    let fixed_ip = Ipv4Addr::new(192, 0, 2, 5);
    let first = tokio::spawn({
        let service = service_a.clone();
        async move {
            service
                .create_port_with_fixed_ip(
                    &auth("project-a"),
                    network.id,
                    "first".to_owned(),
                    Some((subnet.id, Some(fixed_ip))),
                )
                .await
        }
    });
    let second = tokio::spawn({
        let service = service_b.clone();
        async move {
            service
                .create_port_with_fixed_ip(
                    &auth("project-a"),
                    network.id,
                    "second".to_owned(),
                    Some((subnet.id, Some(fixed_ip))),
                )
                .await
        }
    });
    let outcomes = [first.await?, second.await?];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(NetworkError::Conflict)))
            .count(),
        1
    );
    drop(service_a);
    drop(service_b);
    fs::remove_dir_all(path)?;
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{}-wal", sqlite_path.display()));
    let _ = fs::remove_file(format!("{}-shm", sqlite_path.display()));
    Ok(())
}

#[tokio::test]
async fn concurrent_cross_instance_writers_conflict_deterministically_without_duplicates()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("o3k-network-multiwriter-{}", Uuid::now_v7()));
    let sqlite_path = path.with_extension("sqlite");
    fs::create_dir_all(&path)?;
    let store_a = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
    let store_b = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
    let service_a = NetworkService::open_for_test(&path, store_a).await?;
    let service_b = NetworkService::open_for_test(&path, store_b).await?;
    let auth_a = auth("project-a");
    let auth_b = auth("project-a");
    // Two writers create a network with the same name: exactly one wins.
    let (first, second) = tokio::join!(
        service_a.create_network(&auth_a, "flat".to_owned()),
        service_b.create_network(&auth_b, "flat".to_owned()),
    );
    assert_eq!([&first, &second].iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        [&first, &second]
            .iter()
            .filter(|r| matches!(r, Err(NetworkError::Conflict)))
            .count(),
        1
    );
    let network_id = first
        .or(second)
        .map_err(|_| "expected one network create to succeed")?
        .id;
    // Same cidr on the same network: exactly one subnet survives.
    let (subnet_first, subnet_second) = tokio::join!(
        service_a.create_subnet(
            &auth_a,
            network_id,
            "lab".to_owned(),
            "192.0.2.0/27".to_owned(),
            None,
            None,
            None,
        ),
        service_b.create_subnet(
            &auth_b,
            network_id,
            "lab".to_owned(),
            "192.0.2.0/27".to_owned(),
            None,
            None,
            None,
        ),
    );
    assert_eq!(
        [&subnet_first, &subnet_second]
            .iter()
            .filter(|r| r.is_ok())
            .count(),
        1
    );
    assert_eq!(
        [&subnet_first, &subnet_second]
            .iter()
            .filter(|r| matches!(r, Err(NetworkError::Conflict)))
            .count(),
        1
    );
    // 40 concurrent port creates across two writers over a 29-address
    // pool: every allocation is distinct and the pool is exhausted
    // deterministically.
    let mut handles = Vec::new();
    for index in 0..40 {
        let service = if index % 2 == 0 {
            service_a.clone()
        } else {
            service_b.clone()
        };
        handles.push(tokio::spawn(async move {
            service
                .create_port(&auth("project-a"), network_id, format!("port-{index}"))
                .await
        }));
    }
    let mut ports = Vec::new();
    let mut exhausted = 0;
    for handle in handles {
        match handle.await? {
            Ok(port) => ports.push(port),
            Err(NetworkError::PoolExhausted) => exhausted += 1,
            Err(error) => return Err(error.into()),
        }
    }
    assert_eq!(ports.len(), 29);
    assert_eq!(exhausted, 11);
    let ips: HashSet<Ipv4Addr> = ports.iter().map(|port| port.fixed_ip).collect();
    let macs: HashSet<String> = ports
        .iter()
        .map(|port| port.mac_address.to_ascii_lowercase())
        .collect();
    assert_eq!(ports.len(), ips.len());
    assert_eq!(ports.len(), macs.len());
    // Concurrent deletion of one port: exactly one writer wins.
    let (delete_first, delete_second) = tokio::join!(
        service_a.delete_port(&auth_a, ports[0].id),
        service_b.delete_port(&auth_b, ports[0].id),
    );
    assert_eq!(
        [&delete_first, &delete_second]
            .iter()
            .filter(|r| r.is_ok())
            .count(),
        1
    );
    assert_eq!(
        [&delete_first, &delete_second]
            .iter()
            .filter(|r| matches!(r, Err(NetworkError::NotFound)))
            .count(),
        1
    );
    drop(service_a);
    drop(service_b);
    fs::remove_dir_all(path)?;
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{}-wal", sqlite_path.display()));
    let _ = fs::remove_file(format!("{}-shm", sqlite_path.display()));
    Ok(())
}

#[tokio::test]
async fn binding_state_strings_round_trip_through_canonical_parsing() {
    for state in [
        PortBindingState::Binding,
        PortBindingState::Bound,
        PortBindingState::Down,
        PortBindingState::Error,
    ] {
        assert_eq!(PortBindingState::parse(state.as_str()), Some(state));
    }
    assert_eq!(PortBindingState::parse("unbound"), None);
    assert_eq!(PortBindingState::parse("banana"), None);
    assert_eq!(PortBindingState::parse(""), None);
}

#[tokio::test]
async fn binding_intent_and_observation_projection_are_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("binding");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_network(&auth("project-a"), "flat".to_owned())
        .await?;
    let _subnet = service
        .create_subnet(
            &auth("project-a"),
            network.id,
            "lab".to_owned(),
            "192.0.2.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let port = service
        .create_port(&auth("project-a"), network.id, "one".to_owned())
        .await?;
    let intended = service
        .record_binding_intent("project-a", port.id, "compute-1")
        .await?;
    assert_eq!(intended.binding_host.as_deref(), Some("compute-1"));
    assert_eq!(intended.binding_state.as_deref(), Some("binding"));
    let observed = service
        .project_binding_observation("project-a", port.id, "compute-1", "bound")
        .await?;
    assert_eq!(observed.binding_host.as_deref(), Some("compute-1"));
    assert_eq!(observed.binding_state.as_deref(), Some("bound"));
    assert!(matches!(
        service
            .project_binding_observation("project-a", port.id, "compute-1", "banana")
            .await,
        Err(NetworkError::InvalidRequest)
    ));
    // An idempotent dispatch replay of the same create must not downgrade
    // the completed `bound` observation back to `binding`.
    let replayed = service
        .record_binding_intent("project-a", port.id, "compute-1")
        .await?;
    assert_eq!(replayed.binding_state.as_deref(), Some("bound"));
    // A fresh dispatch after an observed failure resets to `binding`.
    let down = service
        .project_binding_observation("project-a", port.id, "compute-1", "down")
        .await?;
    assert_eq!(down.binding_state.as_deref(), Some("down"));
    let retried = service
        .record_binding_intent("project-a", port.id, "compute-1")
        .await?;
    assert_eq!(retried.binding_state.as_deref(), Some("binding"));
    assert!(matches!(
        service
            .project_binding_observation("project-a", port.id, "compute-2", "bound")
            .await,
        Err(NetworkError::Conflict)
    ));
    assert!(matches!(
        service
            .record_binding_intent("project-a", port.id, "compute-2")
            .await,
        Err(NetworkError::Conflict)
    ));
    assert!(matches!(
        service
            .project_binding_observation("project-a", Uuid::now_v7(), "compute-1", "bound")
            .await,
        Err(NetworkError::NotFound)
    ));
    assert!(matches!(
        service
            .record_binding_intent("project-a", port.id, "  ")
            .await,
        Err(NetworkError::InvalidRequest)
    ));
    let final_observed = service
        .project_binding_observation("project-a", port.id, "compute-1", "bound")
        .await?;
    assert_eq!(final_observed.binding_state.as_deref(), Some("bound"));
    drop(service);
    drop(store);
    let reopened_store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let reopened = NetworkService::open_for_test(&path, reopened_store.clone()).await?;
    let restored = reopened.get_port(&auth("project-a"), port.id).await?;
    assert_eq!(restored.binding_host.as_deref(), Some("compute-1"));
    assert_eq!(restored.binding_state.as_deref(), Some("bound"));
    drop(reopened);
    drop(reopened_store);
    fs::remove_dir_all(path)?;
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{sqlite_path}-wal"));
    let _ = fs::remove_file(format!("{sqlite_path}-shm"));
    Ok(())
}

#[tokio::test]
async fn delete_cleanup_and_ip_reuse_after_restart() -> Result<(), Box<dyn std::error::Error>> {
    let path = root("delete-reuse");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_network(&auth("project-a"), "flat".to_owned())
        .await?;
    let subnet = service
        .create_subnet(
            &auth("project-a"),
            network.id,
            "lab".to_owned(),
            "192.0.2.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let port = service
        .create_port(&auth("project-a"), network.id, "one".to_owned())
        .await?;
    service.delete_port(&auth("project-a"), port.id).await?;
    assert!(matches!(
        service.get_port(&auth("project-a"), port.id).await,
        Err(NetworkError::NotFound)
    ));
    drop(service);
    drop(store);
    let reopened_store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let reopened = NetworkService::open_for_test(&path, reopened_store.clone()).await?;
    let replacement = reopened
        .create_port(&auth("project-a"), network.id, "replacement".to_owned())
        .await?;
    assert_eq!(replacement.fixed_ip, port.fixed_ip);
    assert_ne!(replacement.mac_address, port.mac_address);
    reopened
        .delete_port(&auth("project-a"), replacement.id)
        .await?;
    reopened
        .delete_subnet(&auth("project-a"), subnet.id)
        .await?;
    reopened
        .delete_network(&auth("project-a"), network.id)
        .await?;
    assert!(matches!(
        reopened.get_network(&auth("project-a"), network.id).await,
        Err(NetworkError::NotFound)
    ));
    drop(reopened);
    drop(reopened_store);
    fs::remove_dir_all(path)?;
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{sqlite_path}-wal"));
    let _ = fs::remove_file(format!("{sqlite_path}-shm"));
    Ok(())
}

#[tokio::test]
async fn create_outcome_projection_and_unbind_are_durable_and_idempotent()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("create-outcome");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_network(&auth("project-a"), "flat".to_owned())
        .await?;
    let _subnet = service
        .create_subnet(
            &auth("project-a"),
            network.id,
            "lab".to_owned(),
            "192.0.2.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let port = service
        .create_port(&auth("project-a"), network.id, "one".to_owned())
        .await?;
    // Without a recorded intent the projection is rejected.
    assert!(matches!(
        service
            .project_create_outcome("project-a", port.id, PortBindingState::Bound)
            .await,
        Err(NetworkError::Conflict)
    ));
    service
        .record_binding_intent("project-a", port.id, "compute-1")
        .await?;
    // The observed state is set on the host recorded by the intent.
    let bound = service
        .project_create_outcome("project-a", port.id, PortBindingState::Bound)
        .await?;
    assert_eq!(bound.binding_host.as_deref(), Some("compute-1"));
    assert_eq!(bound.binding_state.as_deref(), Some("bound"));
    assert_eq!(
        service.get_port(&auth("project-a"), port.id).await?.status,
        "ACTIVE"
    );
    // A failed outcome after a fresh intent projects `error`.
    service
        .project_binding_observation("project-a", port.id, "compute-1", "down")
        .await?;
    service
        .record_binding_intent("project-a", port.id, "compute-1")
        .await?;
    let errored = service
        .project_create_outcome("project-a", port.id, PortBindingState::Error)
        .await?;
    assert_eq!(errored.binding_state.as_deref(), Some("error"));
    assert_eq!(
        service.get_port(&auth("project-a"), port.id).await?.status,
        "ERROR"
    );
    // Only terminal create outcomes are projectable.
    assert!(matches!(
        service
            .project_create_outcome("project-a", port.id, PortBindingState::Binding)
            .await,
        Err(NetworkError::InvalidRequest)
    ));
    assert!(matches!(
        service
            .project_create_outcome("project-a", Uuid::now_v7(), PortBindingState::Bound)
            .await,
        Err(NetworkError::NotFound)
    ));
    // During Fabric v3 withdrawal, the selected host is retained with a down
    // tombstone until all peer plans converge. A delayed create callback may
    // not resurrect that endpoint, including after controller restart.
    service
        .project_binding_observation("project-a", port.id, "compute-1", "down")
        .await?;
    assert!(matches!(
        service
            .project_create_outcome("project-a", port.id, PortBindingState::Bound)
            .await,
        Err(NetworkError::Conflict)
    ));
    // A new deliberate attachment intent, rather than a stale create callback,
    // reopens the same caller-owned endpoint.
    let endpoint_before_reattach = service
        .get_canonical_endpoint(&auth("project-a"), port.id)
        .await?;
    service
        .record_binding_intent("project-a", port.id, "compute-1")
        .await?;
    let binding = service.get_port(&auth("project-a"), port.id).await?;
    assert_eq!(binding.status, "BUILD");
    let reattached = service
        .project_create_outcome("project-a", port.id, PortBindingState::Bound)
        .await?;
    assert_eq!(
        service.get_port(&auth("project-a"), port.id).await?.status,
        "ACTIVE"
    );
    assert_eq!(reattached.id, port.id);
    assert_eq!(reattached.mac_address, port.mac_address);
    assert_eq!(reattached.fixed_ip, port.fixed_ip);
    let endpoint_after_reattach = service
        .get_canonical_endpoint(&auth("project-a"), port.id)
        .await?;
    assert_eq!(endpoint_after_reattach.state, "active");
    assert_eq!(
        endpoint_after_reattach.generation,
        endpoint_before_reattach.generation
    );
    // Unbind clears the binding idempotently and is durable.
    let unbound = service.unbind_port("project-a", port.id).await?;
    assert_eq!(unbound.binding_host, None);
    assert_eq!(unbound.binding_state.as_deref(), Some("down"));
    assert_eq!(
        service.get_port(&auth("project-a"), port.id).await?.status,
        "DOWN"
    );
    let again = service.unbind_port("project-a", port.id).await?;
    assert_eq!(again.binding_host, None);
    assert!(matches!(
        service.unbind_port("project-a", Uuid::now_v7()).await,
        Err(NetworkError::NotFound)
    ));
    drop(service);
    drop(store);
    let reopened_store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let reopened = NetworkService::open_for_test(&path, reopened_store.clone()).await?;
    let restored = reopened.get_port(&auth("project-a"), port.id).await?;
    assert_eq!(restored.binding_host, None);
    assert_eq!(restored.binding_state.as_deref(), Some("down"));
    assert_eq!(restored.status, "DOWN");
    drop(reopened);
    drop(reopened_store);
    fs::remove_dir_all(path)?;
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{sqlite_path}-wal"));
    let _ = fs::remove_file(format!("{sqlite_path}-shm"));
    Ok(())
}

#[tokio::test]
async fn invalid_cidr_exhaustion_and_project_isolation_are_enforced()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("validation");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store).await?;
    let network = service
        .create_network(&auth("project-a"), "flat".to_owned())
        .await?;
    assert!(matches!(
        service
            .create_subnet(
                &auth("project-a"),
                network.id,
                "bad".to_owned(),
                "192.0.2.1/31".to_owned(),
                None,
                None,
                None
            )
            .await,
        Err(NetworkError::InvalidRequest)
    ));
    let _ = service
        .create_subnet(
            &auth("project-a"),
            network.id,
            "tiny".to_owned(),
            "192.0.2.0/30".to_owned(),
            None,
            Some(Ipv4Addr::new(192, 0, 2, 2)),
            Some(Ipv4Addr::new(192, 0, 2, 2)),
        )
        .await?;
    let _ = service
        .create_port(&auth("project-a"), network.id, "one".to_owned())
        .await?;
    assert!(matches!(
        service
            .create_port(&auth("project-a"), network.id, "two".to_owned())
            .await,
        Err(NetworkError::PoolExhausted)
    ));
    assert!(matches!(
        service
            .create_subnet(
                &auth("project-a"),
                network.id,
                "gateway-overlap".to_owned(),
                "198.51.100.0/29".to_owned(),
                Some(Ipv4Addr::new(198, 51, 100, 3)),
                Some(Ipv4Addr::new(198, 51, 100, 2)),
                Some(Ipv4Addr::new(198, 51, 100, 4)),
            )
            .await,
        Err(NetworkError::InvalidRequest)
    ));
    assert!(matches!(
        service.get_network(&auth("project-b"), network.id).await,
        Err(NetworkError::NotFound)
    ));
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn exhausted_network_pool_preserves_state_and_allows_retry_after_release()
-> Result<(), Box<dyn std::error::Error>> {
    use o3k_store::QuotaRepository;

    let path = root("pool-exhaustion-retry");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let project_auth = auth("project-pool-pressure");
    let quota_scope =
        OwnershipScope::project(ScopeId::new_unchecked("project-pool-pressure"), None, None);
    let network = service
        .create_network(&project_auth, "small-pool".to_owned())
        .await?;
    let subnet = service
        .create_subnet(
            &project_auth,
            network.id,
            "single-address".to_owned(),
            "192.0.2.0/30".to_owned(),
            None,
            Some(Ipv4Addr::new(192, 0, 2, 2)),
            Some(Ipv4Addr::new(192, 0, 2, 2)),
        )
        .await?;
    let original = service
        .create_port(&project_auth, network.id, "original".to_owned())
        .await?;
    let ports_before = service.list_ports(&project_auth).await?;
    let canonical_before = service
        .list_canonical_endpoints(&project_auth, subnet.id)
        .await?;
    let quota_before = store
        .get_usage(&quota_scope, &LimitKey::network_ports())
        .await?
        .in_use;
    assert_eq!(ports_before.len(), 1);
    assert_eq!(canonical_before.len(), 1);
    assert_eq!(quota_before, 1);

    for name in ["exhausted-first", "exhausted-retry"] {
        assert!(matches!(
            service
                .create_port(&project_auth, network.id, name.to_owned())
                .await,
            Err(NetworkError::PoolExhausted)
        ));
        assert_eq!(
            service.list_ports(&project_auth).await?,
            ports_before,
            "failed allocation must leave the project's port projection unchanged"
        );
        assert_eq!(
            service
                .list_canonical_endpoints(&project_auth, subnet.id)
                .await?,
            canonical_before,
            "failed allocation must leave canonical endpoint state unchanged"
        );
        assert_eq!(
            store
                .get_usage(&quota_scope, &LimitKey::network_ports())
                .await?
                .in_use,
            quota_before,
            "failed allocation must release its quota reservation"
        );
    }

    service.delete_port(&project_auth, original.id).await?;
    assert!(
        service
            .list_canonical_endpoints(&project_auth, subnet.id)
            .await?
            .is_empty(),
        "deleting the owned port must remove its canonical endpoint"
    );
    assert_eq!(
        store
            .get_usage(&quota_scope, &LimitKey::network_ports())
            .await?
            .in_use,
        0,
        "deleting the owned port must release its quota"
    );
    let replacement = service
        .create_port(&project_auth, network.id, "replacement".to_owned())
        .await?;
    assert_eq!(replacement.fixed_ip, original.fixed_ip);
    assert_eq!(service.list_ports(&project_auth).await?.len(), 1);
    let canonical_after_retry = service
        .list_canonical_endpoints(&project_auth, subnet.id)
        .await?;
    assert_eq!(canonical_after_retry.len(), 1);
    assert_eq!(canonical_after_retry[0].id, replacement.id);
    assert_eq!(
        store
            .get_usage(&quota_scope, &LimitKey::network_ports())
            .await?
            .in_use,
        1
    );

    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn network_quota_enforcement_and_isolation() -> Result<(), Box<dyn std::error::Error>> {
    use o3k_store::QuotaRepository;

    let path = root("network-quota-isolation");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;

    let scope_a = OwnershipScope::project(ScopeId::new_unchecked("proj-a"), None, None);

    // Limit proj-a to 1 network
    store
        .set_limit(
            &scope_a,
            &LimitKey::network_networks(),
            LimitValue::Maximum(1),
        )
        .await?;

    let auth_a = auth("proj-a");
    let auth_b = auth("proj-b");

    // 1. First network for proj-a succeeds
    let net1 = service.create_network(&auth_a, "net-1".to_owned()).await?;
    assert_eq!(net1.name, "net-1");

    // 2. Second network for proj-a fails with QuotaExceeded
    let res2 = service.create_network(&auth_a, "net-2".to_owned()).await;
    assert!(matches!(res2, Err(NetworkError::QuotaExceeded { .. })));

    // 3. Proj-b can create network (isolation)
    let net_b = service.create_network(&auth_b, "net-b".to_owned()).await?;
    assert_eq!(net_b.name, "net-b");

    // 4. Deleting net1 frees quota for proj-a
    service.delete_network(&auth_a, net1.id).await?;

    let net2 = service.create_network(&auth_a, "net-2".to_owned()).await?;
    assert_eq!(net2.name, "net-2");

    let _ = fs::remove_dir_all(&path);
    Ok(())
}

#[tokio::test]
async fn network_subnet_and_port_quota_enforcement() -> Result<(), Box<dyn std::error::Error>> {
    use o3k_store::QuotaRepository;

    let path = root("network-subnets-ports-quota");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;

    let scope_a = OwnershipScope::project(ScopeId::new_unchecked("proj-sub-port"), None, None);
    let auth_a = auth("proj-sub-port");

    // 1. Set subnet limit = 1 and port limit = 1
    store
        .set_limit(
            &scope_a,
            &LimitKey::network_subnets(),
            LimitValue::Maximum(1),
        )
        .await?;
    store
        .set_limit(&scope_a, &LimitKey::network_ports(), LimitValue::Maximum(1))
        .await?;

    let net = service
        .create_network(&auth_a, "net-main".to_owned())
        .await?;

    // 2. Subnet creation: 1st succeeds, 2nd fails
    let sub1 = service
        .create_subnet(
            &auth_a,
            net.id,
            "sub-1".to_owned(),
            "10.0.0.0/24".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(sub1.network_id, net.id);

    let sub2_res = service
        .create_subnet(
            &auth_a,
            net.id,
            "sub-2".to_owned(),
            "10.0.1.0/24".to_owned(),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(sub2_res, Err(NetworkError::QuotaExceeded { .. })));

    // 3. Port creation: 1st succeeds, 2nd fails
    let port1 = service
        .create_port(&auth_a, net.id, "port-1".to_owned())
        .await?;
    assert_eq!(port1.network_id, net.id);

    let port2_res = service
        .create_port(&auth_a, net.id, "port-2".to_owned())
        .await;
    assert!(matches!(port2_res, Err(NetworkError::QuotaExceeded { .. })));

    // 4. Delete port1 and subnet1 -> frees quota
    service.delete_port(&auth_a, port1.id).await?;
    service.delete_subnet(&auth_a, sub1.id).await?;

    // 5. Subsequent creates succeed
    let sub2 = service
        .create_subnet(
            &auth_a,
            net.id,
            "sub-2".to_owned(),
            "10.0.1.0/24".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(sub2.network_id, net.id);

    let port2 = service
        .create_port(&auth_a, net.id, "port-2".to_owned())
        .await?;
    assert_eq!(port2.network_id, net.id);

    let _ = fs::remove_dir_all(&path);
    Ok(())
}

#[tokio::test]
async fn policy_intent_is_durable_generation_fenced_and_compiled()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("policy-intent");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let project = "project-a";
    let network = service
        .create_network(&auth(project), "policy-net".to_owned())
        .await?;
    service
        .create_subnet(
            &auth(project),
            network.id,
            "policy-subnet".to_owned(),
            "10.20.0.0/24".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let port = service
        .create_port(&auth(project), network.id, "policy-port".to_owned())
        .await?;
    let policy_id = Uuid::now_v7();
    let policy = PolicyIntent {
        id: policy_id,
        endpoint_id: port.id,
        direction: PolicyDirection::Ingress,
        protocol: NetworkProtocol::Tcp,
        ports: Some(o3k_domain::PortRange {
            start: 8080,
            end: 8080,
        }),
        source: Some(
            o3k_domain::Ipv4Prefix::new("198.51.100.0".parse()?, 24)
                .ok_or("invalid source prefix")?,
        ),
        destination: None,
        action: PolicyAction::Deny,
    };
    service
        .upsert_policy_for_project(project, network.id, policy.clone())
        .await?;
    assert_eq!(
        service
            .list_policies_for_project(project, network.id)
            .await?,
        vec![policy.clone()]
    );
    let canonical = store.list_canonical_policies(project, &network.id).await?;
    assert_eq!(canonical.len(), 1);
    assert_eq!(canonical[0].id, policy_id);
    let legacy = store.get_network_intent(project, &network.id).await?;
    assert!(!legacy.is_some_and(|record| record.payload.contains(&policy_id.to_string())));

    let compiled = compile_attachment_plan(AttachmentPlanInput {
        endpoint_id: port.id,
        realm_id: network.id,
        project_id: project,
        mac: &port.mac_address,
        fixed_ip: port.fixed_ip,
        subnet_cidr: "10.20.0.0/24",
        node_id: "network-agent-1",
        operation_id: Uuid::now_v7(),
        deadline_unix_ms: 1,
        public_address: None,
        external_realm_id: None,
        policies: vec![policy.clone()],
    })?;
    assert!(compiled.intents.iter().any(|intent| matches!(
        intent,
        NetworkPlanIntent::Policy(value) if value == &policy
    )));

    service
        .delete_policy_for_project(project, network.id, policy_id)
        .await?;
    assert!(
        service
            .list_policies_for_project(project, network.id)
            .await?
            .is_empty()
    );
    assert!(matches!(
        service
            .delete_policy_for_project("other-project", network.id, policy_id)
            .await,
        Err(NetworkError::NotFound)
    ));
    let _ = fs::remove_dir_all(&path);
    Ok(())
}

#[test]
fn attachment_plan_can_carry_operator_owned_routed_egress() -> Result<(), NetworkPlanError> {
    let endpoint_id = Uuid::from_u128(11);
    let external_realm_id = Uuid::from_u128(12);
    let plan = compile_attachment_plan(AttachmentPlanInput {
        endpoint_id,
        realm_id: Uuid::from_u128(13),
        project_id: "project-a",
        mac: "02:00:00:00:00:0b",
        fixed_ip: Ipv4Addr::new(10, 0, 0, 2),
        subnet_cidr: "10.0.0.0/24",
        node_id: "node-a",
        operation_id: Uuid::from_u128(14),
        deadline_unix_ms: 1,
        public_address: None,
        external_realm_id: Some(external_realm_id),
        policies: Vec::new(),
    })?;
    assert!(plan.intents.iter().any(|intent| matches!(
        intent,
        NetworkPlanIntent::Egress(o3k_domain::EgressIntent {
            external_realm_id: id,
            enabled: true,
            nat: true,
        }) if *id == external_realm_id
    )));
    assert!(plan
            .intents
            .iter()
            .any(|intent| matches!(intent, NetworkPlanIntent::EndpointAttachment { endpoint_id: id, .. } if *id == endpoint_id)));
    Ok(())
}

#[tokio::test]
async fn security_group_rules_project_to_endpoint_policy_and_enforce_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("security-groups");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_network(&auth("project-a"), "net".to_owned())
        .await?;
    service
        .create_subnet(
            &auth("project-a"),
            network.id,
            "subnet".to_owned(),
            "192.0.2.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let port = service
        .create_port(&auth("project-a"), network.id, "port".to_owned())
        .await?;
    let group = service
        .create_security_group_for_project("project-a", "web".to_owned(), String::new())
        .await?;
    let second_group = service
        .create_security_group_for_project("project-a", "api".to_owned(), String::new())
        .await?;
    let rule = service
        .create_security_group_rule_for_project(
            "project-a",
            group.id,
            "ingress".to_owned(),
            "tcp".to_owned(),
            Some(443),
            Some(443),
            Some("0.0.0.0/0".to_owned()),
        )
        .await?;
    let first_change = service
        .replace_security_group_bindings_for_project("project-a", port.id, vec![group.id])
        .await?;
    assert!(first_change.is_empty());
    let first_attachment = store
        .list_endpoint_policy_attachments("project-a", &port.id)
        .await?
        .into_iter()
        .find(|attachment| attachment.policy_id == group.id)
        .ok_or("initial attachment missing")?;
    let unchanged = service
        .replace_security_group_bindings_for_project("project-a", port.id, vec![group.id])
        .await?;
    assert!(unchanged.is_empty());
    let unchanged_attachment = store
        .list_endpoint_policy_attachments("project-a", &port.id)
        .await?
        .into_iter()
        .find(|attachment| attachment.policy_id == group.id)
        .ok_or("unchanged attachment missing")?;
    assert_eq!(unchanged_attachment.id, first_attachment.id);
    assert_eq!(unchanged_attachment.generation, first_attachment.generation);
    let added = service
        .replace_security_group_bindings_for_project(
            "project-a",
            port.id,
            vec![group.id, second_group.id],
        )
        .await?;
    assert!(added.is_empty());
    let attachments = store
        .list_endpoint_policy_attachments("project-a", &port.id)
        .await?;
    assert_eq!(attachments.len(), 2);
    assert_eq!(
        attachments
            .iter()
            .find(|attachment| attachment.policy_id == group.id)
            .map(|attachment| attachment.id),
        Some(first_attachment.id)
    );
    let updated_group = service
        .update_security_group_for_project(
            "project-a",
            group.id,
            "web-renamed".to_owned(),
            "updated".to_owned(),
        )
        .await?;
    assert_eq!(updated_group.name, "web-renamed");
    let canonical_group = store
        .get_reusable_policy("project-a", &group.id)
        .await?
        .ok_or("canonical security group missing")?;
    assert_eq!(canonical_group.generation, 2);
    assert_eq!(canonical_group.stateful_mode, "Stateful");
    assert_eq!(canonical_group.unmatched_action, "Deny");
    let defaults = service
        .policy_defaults_for_endpoint("project-a", port.id)
        .await?;
    assert_eq!(defaults.len(), 2);
    assert!(
        defaults
            .iter()
            .all(|default| default.endpoint_id == port.id)
    );
    assert!(
        defaults
            .iter()
            .all(|default| default.unmatched_action == PolicyAction::Deny)
    );
    let default_plan = compile_attachment_plan_with_defaults(
        AttachmentPlanInput {
            endpoint_id: port.id,
            realm_id: network.id,
            project_id: "project-a",
            mac: &port.mac_address,
            fixed_ip: port.fixed_ip,
            subnet_cidr: "192.0.2.0/29",
            node_id: "network-agent-1",
            operation_id: Uuid::now_v7(),
            deadline_unix_ms: 1,
            public_address: None,
            external_realm_id: None,
            policies: Vec::new(),
        },
        defaults,
    )?;
    assert!(default_plan.intents.iter().any(|intent| matches!(
        intent,
        NetworkPlanIntent::PolicyDefault(default)
            if default.policy_id == group.id
                && default.unmatched_action == PolicyAction::Deny
    )));
    let canonical_rules = store.list_policy_rules("project-a", &group.id).await?;
    assert_eq!(canonical_rules.len(), 1);
    assert_eq!(canonical_rules[0].id, rule.id);
    let canonical_attachments = store
        .list_endpoint_policy_attachments("project-a", &port.id)
        .await?;
    assert_eq!(canonical_attachments.len(), 2);
    assert!(
        canonical_attachments
            .iter()
            .any(|attachment| attachment.policy_id == group.id)
    );
    assert!(
        canonical_attachments
            .iter()
            .all(|attachment| attachment.id != attachment.policy_id)
    );
    let policies = service
        .list_policies_for_project("project-a", network.id)
        .await?;
    assert!(policies.iter().any(|policy| policy.id == rule.id
        && policy.endpoint_id == port.id
        && policy.action == PolicyAction::Allow));
    assert!(
        service
            .list_policies_for_project("project-b", network.id)
            .await
            .is_err()
    );
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{sqlite_path}-wal"));
    let _ = fs::remove_file(format!("{sqlite_path}-shm"));
    Ok(())
}

#[tokio::test]
async fn gateway_delete_reservation_reconstructs_a_generation_fenced_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("gateway-delete-reservation");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let gateway = service
        .create_l3_gateway_for_project("project-a", "edge".to_owned(), None, true)
        .await?;

    let deleting = service
        .delete_l3_gateway_for_project("project-a", &gateway.id, gateway.generation)
        .await?;
    assert_eq!(deleting.state, "deleting");
    assert_eq!(deleting.generation, gateway.generation + 1);
    assert_eq!(service.list_deleting_l3_gateways().await?.len(), 1);

    // A retry/restart can rebuild the exact removal target from the
    // durable reservation; it must not need the pre-delete row in memory.
    let snapshot = service
        .compile_l3_gateway_execution_plan_for_project("project-a", &gateway.id)
        .await?;
    assert_eq!(snapshot.gateway_id, gateway.id);
    assert_eq!(snapshot.gateway_generation, deleting.generation);
    assert!(snapshot.attachments.is_empty());
    assert_eq!(
        store
            .get_canonical_l3_gateway("project-a", &gateway.id)
            .await?
            .ok_or("gateway reservation disappeared")?
            .state,
        "deleting"
    );
    Ok(())
}

#[tokio::test]
async fn attachment_detach_reservation_is_gateway_scoped_and_not_finalized_implicitly()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("gateway-detach-reservation");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_canonical_network_for_project("project-a", "net".to_owned())
        .await?;
    let realm = service
        .create_canonical_realm_for_project(
            "project-a",
            network.id,
            "192.0.2.0/24".to_owned(),
            false,
        )
        .await?;
    let gateway = service
        .create_l3_gateway_for_project("project-a", "edge".to_owned(), None, true)
        .await?;
    let attachment = service
        .attach_l3_gateway_realm("project-a", &gateway.id, &realm.id)
        .await?;
    let deleting = service
        .detach_l3_gateway_realm("project-a", &attachment.id, attachment.generation)
        .await?;

    assert_eq!(deleting.state, "deleting");
    assert_eq!(deleting.generation, attachment.generation + 1);
    assert_eq!(
        service.list_deleting_l3_gateway_attachments().await?.len(),
        1
    );
    assert!(matches!(
        service
            .attach_l3_gateway_realm("project-a", &gateway.id, &realm.id)
            .await,
        Err(NetworkError::Conflict)
    ));

    // The relation remains present until an external provider observation
    // authorizes finalization, while the gateway snapshot excludes it.
    let snapshot = service
        .compile_l3_gateway_execution_plan_for_project("project-a", &gateway.id)
        .await?;
    assert_eq!(snapshot.gateway_id, gateway.id);
    assert!(snapshot.attachments.is_empty());
    let persisted = store
        .get_canonical_l3_gateway_attachment("project-a", &attachment.id)
        .await?
        .ok_or("attachment reservation disappeared")?;
    assert_eq!(persisted.state, "deleting");
    assert_eq!(persisted.generation, deleting.generation);

    service
        .finalize_l3_gateway_realm_detachment_for_project(
            "project-a",
            &attachment.id,
            deleting.generation,
        )
        .await?;
    assert!(
        store
            .get_canonical_l3_gateway_attachment("project-a", &attachment.id)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn gateway_delete_with_stale_generation_is_conflict_not_concealed()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("gateway-delete-stale-generation");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let gateway = service
        .create_l3_gateway_for_project("project-a", "edge".to_owned(), None, true)
        .await?;

    // A stale generation is a same-owner conflict and must surface as 409,
    // never as the 404 used to conceal foreign resources.
    let result = service
        .delete_l3_gateway_for_project("project-a", &gateway.id, gateway.generation + 1)
        .await;
    assert!(
        matches!(result, Err(NetworkError::Conflict)),
        "stale generation must surface as Conflict, got {result:?}"
    );
    assert!(
        !matches!(result, Err(NetworkError::NotFound)),
        "stale generation must not be concealed as NotFound"
    );

    // The gateway remains active after the rejected deletion.
    let persisted = store
        .get_canonical_l3_gateway("project-a", &gateway.id)
        .await?
        .ok_or("gateway disappeared after rejected deletion")?;
    assert_eq!(persisted.state, "active");
    assert_eq!(persisted.generation, gateway.generation);
    let _ = fs::remove_dir_all(&path);
    Ok(())
}

#[tokio::test]
async fn gateway_delete_with_active_attachments_is_conflict_not_concealed()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("gateway-delete-active-attachments");
    let _ = fs::remove_dir_all(&path);
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let network = service
        .create_canonical_network_for_project("project-a", "net".to_owned())
        .await?;
    let realm = service
        .create_canonical_realm_for_project(
            "project-a",
            network.id,
            "192.0.2.0/24".to_owned(),
            false,
        )
        .await?;
    let gateway = service
        .create_l3_gateway_for_project("project-a", "edge".to_owned(), None, true)
        .await?;
    service
        .attach_l3_gateway_realm("project-a", &gateway.id, &realm.id)
        .await?;

    // Deleting a gateway that still has active attachments is a same-owner
    // conflict and must surface as 409, never as the 404 used to conceal
    // foreign resources.
    let result = service
        .delete_l3_gateway_for_project("project-a", &gateway.id, gateway.generation)
        .await;
    assert!(
        matches!(result, Err(NetworkError::Conflict)),
        "active attachments must surface as Conflict, got {result:?}"
    );
    assert!(
        !matches!(result, Err(NetworkError::NotFound)),
        "active attachments must not be concealed as NotFound"
    );

    // The gateway and its attachment remain active after the rejected deletion.
    let persisted = store
        .get_canonical_l3_gateway("project-a", &gateway.id)
        .await?
        .ok_or("gateway disappeared after rejected deletion")?;
    assert_eq!(persisted.state, "active");
    assert_eq!(persisted.generation, gateway.generation);
    let attachments = store
        .list_canonical_l3_gateway_attachments("project-a", &gateway.id)
        .await?;
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].state, "active");
    let _ = fs::remove_dir_all(&path);
    Ok(())
}

/// The reserved server-owned endpoint identity is the discriminator a server
/// delete uses to decide whether an endpoint it references may be released
/// (#1034). A server attaching an endpoint is not the same as a server owning
/// it, so only the exact `o3k-server:<this-project>:<context>` shape counts.
#[test]
fn server_owned_endpoint_identity_requires_the_owning_project_and_a_context() {
    assert!(is_server_owned_endpoint_name(
        "project-a",
        "o3k-server:project-a:pp4-native"
    ));
    assert!(is_server_owned_endpoint_name(
        "project-a",
        "o3k-server:project-a:project-a:canonical:abc"
    ));
    assert_eq!(
        server_owned_endpoint_context("project-a", "o3k-server:project-a:ctx"),
        Some("ctx")
    );
    // Another project's endpoint, a bare prefix, and a context-less reserved
    // name are all *not* owned by this project.
    for name in [
        "o3k-server:project-b:server",
        "o3k-server:",
        "o3k-server:project-a:",
        "o3k-server:project-a",
        "tenant-port",
        "o3k-serverX:project-a:server",
    ] {
        assert!(
            !is_server_owned_endpoint_name("project-a", name),
            "{name} must not be treated as a server-owned endpoint of project-a"
        );
    }
}

/// The shared cleanup rule: only O3K server-owned endpoints of the addressed
/// project are released, user-supplied and foreign endpoints survive, an
/// absent endpoint is idempotent success, and the address plus the port quota
/// become reusable.
#[tokio::test]
async fn server_owned_endpoint_cleanup_is_ownership_filtered_and_frees_the_address()
-> Result<(), Box<dyn std::error::Error>> {
    use o3k_store::QuotaRepository;

    let path = root("server-owned-cleanup");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let auth_a = auth("project-a");
    let network = service.create_network(&auth_a, "flat".to_owned()).await?;
    service
        .create_subnet(
            &auth_a,
            network.id,
            "lab".to_owned(),
            "192.0.2.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let foreign_network = service
        .create_network(&auth("project-b"), "foreign".to_owned())
        .await?;
    service
        .create_subnet(
            &auth("project-b"),
            foreign_network.id,
            "foreign-lab".to_owned(),
            "198.51.100.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;

    let owned = service
        .create_port_for_project(
            "project-a",
            network.id,
            "o3k-server:project-a:server-one".to_owned(),
        )
        .await?;
    let supplied = service
        .create_port_for_project("project-a", network.id, "tenant-port".to_owned())
        .await?;
    let forged_owner = service
        .create_port_for_project(
            "project-a",
            network.id,
            "o3k-server:project-b:elsewhere".to_owned(),
        )
        .await?;
    let contextless = service
        .create_port_for_project("project-a", network.id, "o3k-server:project-a:".to_owned())
        .await?;
    let foreign = service
        .create_port_for_project(
            "project-b",
            foreign_network.id,
            "o3k-server:project-b:server-two".to_owned(),
        )
        .await?;

    let scope_a = OwnershipScope::project(ScopeId::new_unchecked("project-a"), None, None);
    let used_before = store
        .get_usage(&scope_a, &LimitKey::network_ports())
        .await?
        .in_use;

    let released = service
        .cleanup_server_owned_ports_for_project(
            "project-a",
            &[
                owned.id,
                supplied.id,
                forged_owner.id,
                contextless.id,
                foreign.id,
            ],
        )
        .await?;
    // The report is the observability contract for the #1035 orphan repair
    // sweep, so it must name exactly what happened: one owned endpoint
    // discovered and released, three present-but-not-owned endpoints
    // preserved, and one identifier with nothing to repair.
    assert_eq!(
        released,
        ServerOwnedEndpointRelease {
            discovered: 1,
            released: 1,
            preserved: 3,
            absent: 1,
        }
    );

    assert!(matches!(
        service.get_port_for_project("project-a", owned.id).await,
        Err(NetworkError::NotFound)
    ));
    for preserved in [supplied.id, forged_owner.id, contextless.id] {
        assert!(
            service
                .get_port_for_project("project-a", preserved)
                .await
                .is_ok(),
            "{preserved} must survive as a non-owned endpoint"
        );
    }
    assert!(
        service
            .get_port_for_project("project-b", foreign.id)
            .await
            .is_ok(),
        "a foreign project's endpoint must never be released"
    );
    // Only the released endpoint leaves the project's collection.
    let remaining = service.list_ports_for_project("project-a").await?;
    assert_eq!(remaining.len(), 3);
    assert_eq!(
        store
            .get_usage(&scope_a, &LimitKey::network_ports())
            .await?
            .in_use,
        used_before.saturating_sub(1),
        "releasing an endpoint must release its port quota"
    );
    // The address is reusable, and the endpoint surface really is gone.
    assert!(matches!(
        service.get_port(&auth_a, owned.id).await,
        Err(NetworkError::NotFound)
    ));
    let replacement = service
        .create_port_for_project("project-a", network.id, "replacement".to_owned())
        .await?;
    assert_eq!(replacement.fixed_ip, owned.fixed_ip);
    // Replaying the cleanup is idempotent: the released endpoint is gone and
    // the surviving endpoints are still untouched.
    let replayed = service
        .cleanup_server_owned_ports_for_project(
            "project-a",
            &[
                owned.id,
                supplied.id,
                forged_owner.id,
                contextless.id,
                foreign.id,
            ],
        )
        .await?;
    assert_eq!(
        replayed,
        ServerOwnedEndpointRelease {
            discovered: 0,
            released: 0,
            preserved: 3,
            absent: 2,
        },
        "a replayed release must discover nothing and release nothing"
    );
    assert!(
        service
            .get_port_for_project("project-a", supplied.id)
            .await
            .is_ok()
    );

    drop(service);
    drop(store);
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{sqlite_path}-wal"));
    let _ = fs::remove_file(format!("{sqlite_path}-shm"));
    Ok(())
}

/// The durable-binding fence on the compute release path (#1035): a sweep or
/// delete replay must never delete a server-owned endpoint a NEW live server
/// has explicitly re-attached, even when the sweep's `still_attached` scan did
/// not see it. A bound (or binding) endpoint is preserved and retried on the
/// next pass; only after an own unbind (`down`) is it actually released.
#[tokio::test]
async fn server_owned_endpoint_cleanup_preserves_a_bound_endpoint_until_unbound()
-> Result<(), Box<dyn std::error::Error>> {
    let path = root("server-owned-bound-fence");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let service = NetworkService::open_for_test(&path, store.clone()).await?;
    let auth_a = auth("project-a");
    let network = service.create_network(&auth_a, "flat".to_owned()).await?;
    service
        .create_subnet(
            &auth_a,
            network.id,
            "lab".to_owned(),
            "192.0.2.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let owned = service
        .create_port_for_project(
            "project-a",
            network.id,
            "o3k-server:project-a:server-one".to_owned(),
        )
        .await?;

    // An attaching server realizes the endpoint: host selected, then observed
    // bound. This is the durable state a NEW live server's attachment leaves.
    service
        .record_binding_intent("project-a", owned.id, "compute-1")
        .await?;
    service
        .project_binding_observation("project-a", owned.id, "compute-1", "bound")
        .await?;

    // The release path must refuse while the endpoint is still bound: the
    // endpoint stays, is counted preserved (not released, not a failure), and
    // no port quota is freed for reuse.
    let first = service
        .cleanup_server_owned_ports_for_project("project-a", &[owned.id])
        .await?;
    assert_eq!(
        first,
        ServerOwnedEndpointRelease {
            discovered: 1,
            released: 0,
            preserved: 1,
            absent: 0,
        }
    );
    let still_bound = service.get_port_for_project("project-a", owned.id).await?;
    assert_eq!(still_bound.binding_state.as_deref(), Some("bound"));
    assert!(
        service
            .get_port_for_project("project-a", owned.id)
            .await
            .is_ok(),
        "a bound endpoint must survive an orphan repair release"
    );

    // The owning server's own delete unbinds first (recording `down`); only
    // then may the release path delete it.
    service.unbind_port("project-a", owned.id).await?;
    let second = service
        .cleanup_server_owned_ports_for_project("project-a", &[owned.id])
        .await?;
    assert_eq!(
        second,
        ServerOwnedEndpointRelease {
            discovered: 1,
            released: 1,
            preserved: 0,
            absent: 0,
        }
    );
    assert!(matches!(
        service.get_port_for_project("project-a", owned.id).await,
        Err(NetworkError::NotFound)
    ));

    drop(service);
    drop(store);
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let _ = fs::remove_file(format!("{sqlite_path}-wal"));
    let _ = fs::remove_file(format!("{sqlite_path}-shm"));
    Ok(())
}
use o3k_kernel::{Reservation, ReservationId, ResourceAmount, Usage};
use o3k_store::{
    AgentCommandRecord, AgentCommandState, ArtifactTransferRecord, ArtifactTransferUpdate,
    AuditEventRecord, CanonicalAcceptanceOutcome, CanonicalAddressPoolRecord,
    CanonicalAddressRealmRecord, CanonicalEndpointRecord, CanonicalL3GatewayAttachmentRecord,
    CanonicalL3GatewayRecord, CanonicalNetworkPolicyRecord, CanonicalNetworkPolicyRuleRecord,
    CanonicalNetworkRecord, CanonicalOperationLifecycleUpdate, CanonicalOperationRecord,
    CanonicalPolicyAttachmentRecord, CanonicalPolicyRealizationRecord, CanonicalRealmBindingRecord,
    CanonicalReusableNetworkPolicyRecord, FabricHostTransportIdentityRecord,
    IdempotencyReservation, IdempotencyReservationRequest, ImageOverlayIdentity,
    ImageOverlayOwnershipRecord, ImageOverlayUpdate, LifecycleTerminalization,
    NetworkAddressAllocationRecord, NetworkIntentRecord, NetworkPlanWorkRecord,
    NetworkPlanWorkState, NetworkRecord, NetworkRepository, ObservationUpdate, OperationRecord,
    OperationState, PortRecord, ProviderReference, RepositoryPage, ResourceRecord,
    SecurityGroupBindingRecord, SecurityGroupRecord, SecurityGroupRuleRecord, StoreError,
    StoredIdempotencyReservation, SubnetRecord,
};

// ── Issue #1047: realm cleanup finalization must be one transaction ──────────

/// Delegating repository for the issue-#1047 crash boundary. Every method
/// passes through to the wrapped store except `finalize_realm_cleanup`, which
/// supports two modes:
///
/// - `fail_next_finalize()`: the NEXT finalization fails on a sabotaged realm
///   identity, so the REAL primitive fails with its genuine
///   `ResourceNotFound` error. This is the control-plane crash at the worst
///   possible moment — every provider side effect has already happened and
///   the durable finalization is about to commit — and the invariant under
///   test is that a failed finalization commits nothing (the transaction is
///   all-or-nothing).
/// - `arm_converged_assertion()`: after a delegated finalization the realm
///   row must be gone, the operation must be terminal, and an existing
///   projection must be `deleted`. A split commit would surface here
///   deterministically instead of needing a racy external observer.
struct RealmCleanupFaultStore {
    inner: Arc<dyn o3k_store::NetworkRepository>,
    fail_next: std::sync::Arc<std::sync::atomic::AtomicBool>,
    assert_converged: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RealmCleanupFaultStore {
    fn new(inner: Arc<dyn o3k_store::NetworkRepository>) -> Self {
        Self {
            inner,
            fail_next: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            assert_converged: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn fail_next_finalize(&self) {
        self.fail_next
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn arm_converged_assertion(&self) {
        self.assert_converged
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl o3k_store::DurableStore for RealmCleanupFaultStore {
    async fn insert_network_plan_work(
        &self,
        work: &NetworkPlanWorkRecord,
    ) -> Result<NetworkPlanWorkRecord, StoreError> {
        self.inner.insert_network_plan_work(work).await
    }

    async fn insert_network_plan_work_under_lease(
        &self,
        realm_work_key: &str,
        controller_id: &str,
        controller_epoch: &str,
        fencing_token: u64,
        work: &NetworkPlanWorkRecord,
    ) -> Result<NetworkPlanWorkRecord, StoreError> {
        self.inner
            .insert_network_plan_work_under_lease(
                realm_work_key,
                controller_id,
                controller_epoch,
                fencing_token,
                work,
            )
            .await
    }

    async fn get_network_plan_work(
        &self,
        command_id: &str,
    ) -> Result<NetworkPlanWorkRecord, StoreError> {
        self.inner.get_network_plan_work(command_id).await
    }

    async fn update_network_plan_work(
        &self,
        command_id: &str,
        expected_revision: u64,
        state: NetworkPlanWorkState,
        outcome: Option<&[u8]>,
    ) -> Result<NetworkPlanWorkRecord, StoreError> {
        self.inner
            .update_network_plan_work(command_id, expected_revision, state, outcome)
            .await
    }

    async fn update_network_plan_work_under_lease(
        &self,
        realm_work_key: &str,
        controller_id: &str,
        controller_epoch: &str,
        fencing_token: u64,
        command_id: &str,
        expected_revision: u64,
        state: NetworkPlanWorkState,
        outcome: Option<&[u8]>,
    ) -> Result<NetworkPlanWorkRecord, StoreError> {
        self.inner
            .update_network_plan_work_under_lease(
                realm_work_key,
                controller_id,
                controller_epoch,
                fencing_token,
                command_id,
                expected_revision,
                state,
                outcome,
            )
            .await
    }

    async fn supersede_network_plan_work_under_lease(
        &self,
        realm_work_key: &str,
        controller_id: &str,
        controller_epoch: &str,
        fencing_token: u64,
        old_command_id: &str,
        expected_old_revision: u64,
        successor: &NetworkPlanWorkRecord,
    ) -> Result<(NetworkPlanWorkRecord, NetworkPlanWorkRecord), StoreError> {
        self.inner
            .supersede_network_plan_work_under_lease(
                realm_work_key,
                controller_id,
                controller_epoch,
                fencing_token,
                old_command_id,
                expected_old_revision,
                successor,
            )
            .await
    }

    async fn list_unresolved_network_plan_work(
        &self,
    ) -> Result<Vec<NetworkPlanWorkRecord>, StoreError> {
        self.inner.list_unresolved_network_plan_work().await
    }

    async fn list_network_plan_work_history(
        &self,
    ) -> Result<Vec<NetworkPlanWorkRecord>, StoreError> {
        self.inner.list_network_plan_work_history().await
    }

    async fn insert_resource(&self, resource: &ResourceRecord) -> Result<(), StoreError> {
        self.inner.insert_resource(resource).await
    }

    async fn get_resource(&self, id: Uuid) -> Result<ResourceRecord, StoreError> {
        self.inner.get_resource(id).await
    }

    async fn list_resources(
        &self,
        project_id: &str,
        kind: &str,
    ) -> Result<Vec<ResourceRecord>, StoreError> {
        self.inner.list_resources(project_id, kind).await
    }

    async fn list_resources_for_reconciliation(
        &self,
        kind: &str,
    ) -> Result<Vec<ResourceRecord>, StoreError> {
        self.inner.list_resources_for_reconciliation(kind).await
    }

    async fn list_resources_page(
        &self,
        project_id: &str,
        kind: &str,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<RepositoryPage<ResourceRecord>, StoreError> {
        self.inner
            .list_resources_page(project_id, kind, after_id, limit)
            .await
    }

    async fn update_resource(
        &self,
        id: Uuid,
        expected_generation: i64,
        desired_state: &str,
        observed_state: &str,
        observed_generation: i64,
        provider_id: Option<&str>,
    ) -> Result<ResourceRecord, StoreError> {
        self.inner
            .update_resource(
                id,
                expected_generation,
                desired_state,
                observed_state,
                observed_generation,
                provider_id,
            )
            .await
    }

    async fn update_resource_and_complete_operation(
        &self,
        resource_id: Uuid,
        expected_generation: i64,
        desired_state: &str,
        observed_state: &str,
        observed_generation: i64,
        provider_id: Option<&str>,
        operation_id: Uuid,
        lifecycle: &CanonicalOperationLifecycleUpdate,
    ) -> Result<ResourceRecord, StoreError> {
        self.inner
            .update_resource_and_complete_operation(
                resource_id,
                expected_generation,
                desired_state,
                observed_state,
                observed_generation,
                provider_id,
                operation_id,
                lifecycle,
            )
            .await
    }

    async fn terminalize_lifecycle(
        &self,
        terminalization: &LifecycleTerminalization<'_>,
    ) -> Result<(OperationRecord, ResourceRecord), StoreError> {
        self.inner.terminalize_lifecycle(terminalization).await
    }

    async fn update_resource_from_observation(
        &self,
        id: Uuid,
        update: &ObservationUpdate<'_>,
    ) -> Result<ResourceRecord, StoreError> {
        self.inner
            .update_resource_from_observation(id, update)
            .await
    }

    async fn insert_operation(&self, operation: &OperationRecord) -> Result<(), StoreError> {
        self.inner.insert_operation(operation).await
    }

    async fn reserve_idempotent_operation(
        &self,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        self.inner.reserve_idempotent_operation(request).await
    }

    async fn get_idempotency_reservation(
        &self,
        owner_scope: &str,
        action: &str,
        key: &str,
    ) -> Result<Option<StoredIdempotencyReservation>, StoreError> {
        self.inner
            .get_idempotency_reservation(owner_scope, action, key)
            .await
    }

    async fn create_or_replay_idempotent_operation(
        &self,
        operation: &OperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        self.inner
            .create_or_replay_idempotent_operation(operation, request)
            .await
    }

    async fn create_or_replay_canonical_idempotent_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        self.inner
            .create_or_replay_canonical_idempotent_operation(operation, canonical, request)
            .await
    }

    async fn create_or_replay_canonical_scoped_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        self.inner
            .create_or_replay_canonical_scoped_operation(operation, canonical, request)
            .await
    }

    async fn create_or_replay_canonical_resource_operation(
        &self,
        resource: &ResourceRecord,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<CanonicalAcceptanceOutcome, StoreError> {
        self.inner
            .create_or_replay_canonical_resource_operation(
                resource,
                operation,
                canonical,
                request,
                expected_placement_allocation_id,
            )
            .await
    }

    async fn create_or_replay_canonical_lifecycle_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<CanonicalAcceptanceOutcome, StoreError> {
        self.inner
            .create_or_replay_canonical_lifecycle_operation(operation, canonical, request)
            .await
    }

    async fn get_operation(&self, id: Uuid) -> Result<OperationRecord, StoreError> {
        self.inner.get_operation(id).await
    }

    async fn get_canonical_operation(
        &self,
        id: Uuid,
    ) -> Result<CanonicalOperationRecord, StoreError> {
        self.inner.get_canonical_operation(id).await
    }

    async fn list_canonical_operations_page(
        &self,
        owner_scope: &str,
        after_id: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<CanonicalOperationRecord>, StoreError> {
        self.inner
            .list_canonical_operations_page(owner_scope, after_id, limit)
            .await
    }

    async fn update_canonical_operation_lifecycle(
        &self,
        id: Uuid,
        update: &CanonicalOperationLifecycleUpdate,
    ) -> Result<CanonicalOperationRecord, StoreError> {
        self.inner
            .update_canonical_operation_lifecycle(id, update)
            .await
    }

    async fn update_operation(
        &self,
        id: Uuid,
        state: OperationState,
        provider_operation_id: Option<&str>,
        error_category: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<OperationRecord, StoreError> {
        self.inner
            .update_operation(
                id,
                state,
                provider_operation_id,
                error_category,
                error_message,
            )
            .await
    }

    async fn list_non_terminal_lifecycle_operations(
        &self,
    ) -> Result<Vec<OperationRecord>, StoreError> {
        self.inner.list_non_terminal_lifecycle_operations().await
    }

    async fn attach_provider_reference(
        &self,
        reference: &ProviderReference,
    ) -> Result<(), StoreError> {
        self.inner.attach_provider_reference(reference).await
    }

    async fn get_provider_reference(
        &self,
        resource_id: Uuid,
        provider_name: &str,
    ) -> Result<ProviderReference, StoreError> {
        self.inner
            .get_provider_reference(resource_id, provider_name)
            .await
    }

    async fn insert_agent_command(
        &self,
        command: &AgentCommandRecord,
    ) -> Result<AgentCommandRecord, StoreError> {
        self.inner.insert_agent_command(command).await
    }

    async fn get_agent_command(&self, command_id: &str) -> Result<AgentCommandRecord, StoreError> {
        self.inner.get_agent_command(command_id).await
    }

    async fn get_agent_command_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<AgentCommandRecord, StoreError> {
        self.inner
            .get_agent_command_by_idempotency_key(idempotency_key)
            .await
    }

    async fn get_agent_command_by_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<AgentCommandRecord, StoreError> {
        self.inner
            .get_agent_command_by_operation(operation_id)
            .await
    }

    async fn update_agent_command(
        &self,
        command_id: &str,
        state: AgentCommandState,
        accepted_sequence: u64,
        last_sequence: u64,
        provider_operation_id: Option<&str>,
        provider_resource_id: Option<&str>,
    ) -> Result<AgentCommandRecord, StoreError> {
        self.inner
            .update_agent_command(
                command_id,
                state,
                accepted_sequence,
                last_sequence,
                provider_operation_id,
                provider_resource_id,
            )
            .await
    }

    async fn list_recoverable_agent_commands(&self) -> Result<Vec<AgentCommandRecord>, StoreError> {
        self.inner.list_recoverable_agent_commands().await
    }

    async fn insert_artifact_transfer(
        &self,
        transfer: &ArtifactTransferRecord,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        self.inner.insert_artifact_transfer(transfer).await
    }

    async fn get_artifact_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        self.inner.get_artifact_transfer(transfer_id).await
    }

    async fn rebind_artifact_transfer_epoch(
        &self,
        transfer_id: &str,
        expected_agent_epoch: &str,
        new_agent_epoch: &str,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        self.inner
            .rebind_artifact_transfer_epoch(transfer_id, expected_agent_epoch, new_agent_epoch)
            .await
    }

    async fn update_artifact_transfer(
        &self,
        transfer_id: &str,
        expected_agent_epoch: &str,
        update: ArtifactTransferUpdate,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        self.inner
            .update_artifact_transfer(transfer_id, expected_agent_epoch, update)
            .await
    }

    async fn list_recoverable_artifact_transfers(
        &self,
    ) -> Result<Vec<ArtifactTransferRecord>, StoreError> {
        self.inner.list_recoverable_artifact_transfers().await
    }

    async fn expire_transfers_of_terminal_operations(&self) -> Result<u64, StoreError> {
        self.inner.expire_transfers_of_terminal_operations().await
    }

    async fn insert_image_overlay(
        &self,
        overlay: &ImageOverlayOwnershipRecord,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        self.inner.insert_image_overlay(overlay).await
    }

    async fn get_image_overlay(
        &self,
        overlay_id: &str,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        self.inner.get_image_overlay(overlay_id).await
    }

    async fn update_image_overlay(
        &self,
        overlay_id: &str,
        expected_identity: &ImageOverlayIdentity,
        update: ImageOverlayUpdate,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        self.inner
            .update_image_overlay(overlay_id, expected_identity, update)
            .await
    }

    async fn list_image_overlays(
        &self,
        resource_id: Uuid,
    ) -> Result<Vec<ImageOverlayOwnershipRecord>, StoreError> {
        self.inner.list_image_overlays(resource_id).await
    }

    async fn count_image_overlay_references(
        &self,
        base_sha256: &str,
        base_format: &str,
    ) -> Result<u64, StoreError> {
        self.inner
            .count_image_overlay_references(base_sha256, base_format)
            .await
    }

    async fn delete_image_overlay(
        &self,
        overlay_id: &str,
        expected_identity: &ImageOverlayIdentity,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        self.inner
            .delete_image_overlay(overlay_id, expected_identity)
            .await
    }

    async fn increment_operation_retry(&self, operation_id: Uuid) -> Result<u8, StoreError> {
        self.inner.increment_operation_retry(operation_id).await
    }

    async fn insert_resource_and_operation(
        &self,
        resource: &ResourceRecord,
        operation: &OperationRecord,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<(), StoreError> {
        self.inner
            .insert_resource_and_operation(resource, operation, expected_placement_allocation_id)
            .await
    }

    async fn revive_resource_and_operation(
        &self,
        id: Uuid,
        expected_generation: i64,
        desired_state: &str,
        observed_state: &str,
        observed_generation: i64,
        provider_id: Option<&str>,
        operation: &OperationRecord,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<ResourceRecord, StoreError> {
        self.inner
            .revive_resource_and_operation(
                id,
                expected_generation,
                desired_state,
                observed_state,
                observed_generation,
                provider_id,
                operation,
                expected_placement_allocation_id,
            )
            .await
    }

    async fn readiness_check(&self) -> Result<(), StoreError> {
        self.inner.readiness_check().await
    }
}

#[async_trait::async_trait]
impl o3k_store::QuotaRepository for RealmCleanupFaultStore {
    async fn get_limit_state(
        &self,
        scope: &OwnershipScope,
        key: &LimitKey,
    ) -> Result<(LimitValue, u64), StoreError> {
        self.inner.get_limit_state(scope, key).await
    }

    async fn set_limit_if_generation(
        &self,
        scope: &OwnershipScope,
        key: &LimitKey,
        limit: LimitValue,
        expected_generation: u64,
    ) -> Result<u64, StoreError> {
        self.inner
            .set_limit_if_generation(scope, key, limit, expected_generation)
            .await
    }

    async fn set_limit_if_generation_with_audit(
        &self,
        scope: &OwnershipScope,
        key: &LimitKey,
        limit: LimitValue,
        expected_generation: u64,
        audit: &AuditEventRecord,
    ) -> Result<u64, StoreError> {
        self.inner
            .set_limit_if_generation_with_audit(scope, key, limit, expected_generation, audit)
            .await
    }

    async fn get_limit(
        &self,
        scope: &OwnershipScope,
        key: &LimitKey,
    ) -> Result<LimitValue, StoreError> {
        self.inner.get_limit(scope, key).await
    }

    async fn set_limit(
        &self,
        scope: &OwnershipScope,
        key: &LimitKey,
        limit: LimitValue,
    ) -> Result<(), StoreError> {
        self.inner.set_limit(scope, key, limit).await
    }

    async fn get_usage(&self, scope: &OwnershipScope, key: &LimitKey) -> Result<Usage, StoreError> {
        self.inner.get_usage(scope, key).await
    }

    async fn reserve_quota(
        &self,
        scope: &OwnershipScope,
        operation_id: &str,
        amounts: &[ResourceAmount],
    ) -> Result<Reservation, StoreError> {
        self.inner.reserve_quota(scope, operation_id, amounts).await
    }

    async fn commit_reservation(&self, reservation_id: &ReservationId) -> Result<(), StoreError> {
        self.inner.commit_reservation(reservation_id).await
    }

    async fn release_reservation(&self, reservation_id: &ReservationId) -> Result<(), StoreError> {
        self.inner.release_reservation(reservation_id).await
    }

    async fn release_reservation_for_operation(
        &self,
        operation_id: &str,
    ) -> Result<(), StoreError> {
        self.inner
            .release_reservation_for_operation(operation_id)
            .await
    }

    async fn get_reservation_for_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<Reservation>, StoreError> {
        self.inner.get_reservation_for_operation(operation_id).await
    }
}

#[async_trait::async_trait]
impl o3k_store::CanonicalPolicyRepository for RealmCleanupFaultStore {
    async fn insert_reusable_policy(
        &self,
        policy: &CanonicalReusableNetworkPolicyRecord,
    ) -> Result<(), StoreError> {
        self.inner.insert_reusable_policy(policy).await
    }

    async fn get_reusable_policy(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalReusableNetworkPolicyRecord>, StoreError> {
        self.inner.get_reusable_policy(project_id, id).await
    }

    async fn list_reusable_policies(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalReusableNetworkPolicyRecord>, StoreError> {
        self.inner.list_reusable_policies(project_id).await
    }

    async fn update_reusable_policy(
        &self,
        policy: &CanonicalReusableNetworkPolicyRecord,
        expected_generation: u64,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
        self.inner
            .update_reusable_policy(policy, expected_generation)
            .await
    }

    async fn transition_reusable_policy_state(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        state: &str,
    ) -> Result<CanonicalReusableNetworkPolicyRecord, StoreError> {
        self.inner
            .transition_reusable_policy_state(project_id, id, expected_generation, state)
            .await
    }

    async fn delete_reusable_policy(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.inner.delete_reusable_policy(project_id, id).await
    }

    async fn insert_policy_rule(
        &self,
        rule: &CanonicalNetworkPolicyRuleRecord,
    ) -> Result<(), StoreError> {
        self.inner.insert_policy_rule(rule).await
    }

    async fn get_policy_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        self.inner.get_policy_rule(project_id, id).await
    }

    async fn list_policy_rules(
        &self,
        project_id: &str,
        policy_id: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        self.inner.list_policy_rules(project_id, policy_id).await
    }

    async fn begin_policy_rule_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalNetworkPolicyRuleRecord, StoreError> {
        self.inner
            .begin_policy_rule_deletion(project_id, id, expected_generation)
            .await
    }

    async fn list_deleting_policy_rules(
        &self,
    ) -> Result<Vec<CanonicalNetworkPolicyRuleRecord>, StoreError> {
        self.inner.list_deleting_policy_rules().await
    }

    async fn finalize_policy_rule_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .finalize_policy_rule_deletion(project_id, id, expected_generation)
            .await
    }

    async fn delete_policy_rule(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.inner.delete_policy_rule(project_id, id).await
    }

    async fn insert_policy_attachment(
        &self,
        attachment: &CanonicalPolicyAttachmentRecord,
    ) -> Result<(), StoreError> {
        self.inner.insert_policy_attachment(attachment).await
    }

    async fn get_policy_attachment(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.inner.get_policy_attachment(project_id, id).await
    }

    async fn list_policy_attachments(
        &self,
        project_id: &str,
        policy_id: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.inner
            .list_policy_attachments(project_id, policy_id)
            .await
    }

    async fn list_endpoint_policy_attachments(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.inner
            .list_endpoint_policy_attachments(project_id, endpoint_id)
            .await
    }

    async fn replace_policy_attachment_set(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
        policy_ids: &[Uuid],
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.inner
            .replace_policy_attachment_set(project_id, endpoint_id, policy_ids)
            .await
    }

    async fn begin_policy_attachment_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalPolicyAttachmentRecord, StoreError> {
        self.inner
            .begin_policy_attachment_deletion(project_id, id, expected_generation)
            .await
    }

    async fn list_deleting_policy_attachments(
        &self,
    ) -> Result<Vec<CanonicalPolicyAttachmentRecord>, StoreError> {
        self.inner.list_deleting_policy_attachments().await
    }

    async fn finalize_policy_attachment_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .finalize_policy_attachment_deletion(project_id, id, expected_generation)
            .await
    }

    async fn delete_policy_attachment(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<(), StoreError> {
        self.inner.delete_policy_attachment(project_id, id).await
    }

    async fn upsert_policy_realization(
        &self,
        realization: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError> {
        self.inner.upsert_policy_realization(realization).await
    }

    async fn get_policy_realization(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<Option<CanonicalPolicyRealizationRecord>, StoreError> {
        self.inner
            .get_policy_realization(project_id, endpoint_id)
            .await
    }

    async fn list_policy_realizations(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalPolicyRealizationRecord>, StoreError> {
        self.inner.list_policy_realizations(project_id).await
    }

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
    ) -> Result<(), StoreError> {
        self.inner
            .set_policy_realization_outcome(
                project_id,
                endpoint_id,
                expected_fingerprint,
                expected_attempt_id,
                state,
                observed_fingerprint,
                observed_generation,
                provider_resource_id,
                last_outcome,
            )
            .await
    }

    async fn requeue_policy_realization(
        &self,
        expected_attempt_id: &Uuid,
        realization: &CanonicalPolicyRealizationRecord,
    ) -> Result<(), StoreError> {
        self.inner
            .requeue_policy_realization(expected_attempt_id, realization)
            .await
    }
}

#[async_trait::async_trait]
impl o3k_store::NetworkRepository for RealmCleanupFaultStore {
    async fn finalize_realm_cleanup(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
        operation_id: Uuid,
        lifecycle: &CanonicalOperationLifecycleUpdate,
    ) -> Result<(), StoreError> {
        if self
            .fail_next
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            // The simulated crash runs through the REAL primitive with a
            // sabotaged realm identity: a genuine store failure, and (because
            // the primitive is one transaction) provably no durable effect.
            return self
                .inner
                .finalize_realm_cleanup(
                    project_id,
                    &Uuid::now_v7(),
                    expected_generation,
                    operation_id,
                    lifecycle,
                )
                .await;
        }
        self.inner
            .finalize_realm_cleanup(
                project_id,
                realm_id,
                expected_generation,
                operation_id,
                lifecycle,
            )
            .await?;
        if self
            .assert_converged
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            // A split commit would surface here deterministically instead of
            // needing a racy external observer.
            let realm_row = self.inner.get_canonical_realm(project_id, realm_id).await;
            assert!(
                matches!(realm_row, Ok(None)),
                "finalize_realm_cleanup must remove the realm row, got {realm_row:?}"
            );
            let operation = self.inner.get_operation(operation_id).await;
            assert!(
                matches!(operation, Ok(ref op) if op.state == lifecycle.state),
                "finalize_realm_cleanup must leave the operation in the \
                 terminalized state, got {operation:?}"
            );
            if let Ok(resource) = self.inner.get_resource(*realm_id).await {
                assert_eq!(
                    resource.observed_state, "deleted",
                    "finalize_realm_cleanup must terminalize the projection"
                );
            }
        }
        Ok(())
    }
    async fn get_fabric_host_identity(
        &self,
        host_id: &str,
    ) -> Result<Option<FabricHostTransportIdentityRecord>, StoreError> {
        self.inner.get_fabric_host_identity(host_id).await
    }

    async fn list_fabric_host_identities(
        &self,
    ) -> Result<Vec<FabricHostTransportIdentityRecord>, StoreError> {
        self.inner.list_fabric_host_identities().await
    }

    async fn upsert_fabric_host_identity(
        &self,
        identity: &FabricHostTransportIdentityRecord,
        expected_generation: Option<u64>,
    ) -> Result<FabricHostTransportIdentityRecord, StoreError> {
        self.inner
            .upsert_fabric_host_identity(identity, expected_generation)
            .await
    }

    async fn get_canonical_owner(
        &self,
        resource_name: &str,
        id: &Uuid,
    ) -> Result<Option<String>, StoreError> {
        self.inner.get_canonical_owner(resource_name, id).await
    }

    async fn insert_canonical_network(
        &self,
        network: &CanonicalNetworkRecord,
    ) -> Result<(), StoreError> {
        self.inner.insert_canonical_network(network).await
    }

    async fn get_canonical_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalNetworkRecord>, StoreError> {
        self.inner.get_canonical_network(project_id, id).await
    }

    async fn list_canonical_networks(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalNetworkRecord>, StoreError> {
        self.inner.list_canonical_networks(project_id).await
    }

    async fn update_canonical_network(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        name: &str,
        admin_state_up: bool,
    ) -> Result<CanonicalNetworkRecord, StoreError> {
        self.inner
            .update_canonical_network(project_id, id, expected_generation, name, admin_state_up)
            .await
    }

    async fn insert_canonical_l3_gateway(
        &self,
        gateway: &CanonicalL3GatewayRecord,
    ) -> Result<(), StoreError> {
        self.inner.insert_canonical_l3_gateway(gateway).await
    }

    async fn get_canonical_l3_gateway(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayRecord>, StoreError> {
        self.inner.get_canonical_l3_gateway(project_id, id).await
    }

    async fn list_canonical_l3_gateways(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError> {
        self.inner.list_canonical_l3_gateways(project_id).await
    }

    async fn list_canonical_l3_gateways_by_state(
        &self,
        state: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError> {
        self.inner.list_canonical_l3_gateways_by_state(state).await
    }

    async fn update_canonical_l3_gateway(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        name: &str,
        external_realm_id: Option<Uuid>,
        enable_snat: bool,
    ) -> Result<CanonicalL3GatewayRecord, StoreError> {
        self.inner
            .update_canonical_l3_gateway(
                project_id,
                id,
                expected_generation,
                name,
                external_realm_id,
                enable_snat,
            )
            .await
    }

    async fn begin_canonical_l3_gateway_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalL3GatewayRecord, StoreError> {
        self.inner
            .begin_canonical_l3_gateway_deletion(project_id, id, expected_generation)
            .await
    }

    async fn finalize_canonical_l3_gateway_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .finalize_canonical_l3_gateway_deletion(project_id, id, expected_generation)
            .await
    }

    async fn insert_canonical_l3_gateway_attachment(
        &self,
        attachment: &CanonicalL3GatewayAttachmentRecord,
    ) -> Result<(), StoreError> {
        self.inner
            .insert_canonical_l3_gateway_attachment(attachment)
            .await
    }

    async fn get_canonical_l3_gateway_attachment(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        self.inner
            .get_canonical_l3_gateway_attachment(project_id, id)
            .await
    }

    async fn list_canonical_l3_gateway_attachments(
        &self,
        project_id: &str,
        gateway_id: &Uuid,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        self.inner
            .list_canonical_l3_gateway_attachments(project_id, gateway_id)
            .await
    }

    async fn list_canonical_l3_gateway_attachments_by_state(
        &self,
        state: &str,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        self.inner
            .list_canonical_l3_gateway_attachments_by_state(state)
            .await
    }

    async fn list_canonical_realm_l3_gateway_attachments(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        self.inner
            .list_canonical_realm_l3_gateway_attachments(project_id, realm_id)
            .await
    }

    async fn begin_canonical_l3_gateway_attachment_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalL3GatewayAttachmentRecord, StoreError> {
        self.inner
            .begin_canonical_l3_gateway_attachment_deletion(project_id, id, expected_generation)
            .await
    }

    async fn finalize_canonical_l3_gateway_attachment_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .finalize_canonical_l3_gateway_attachment_deletion(project_id, id, expected_generation)
            .await
    }

    async fn insert_canonical_realm(
        &self,
        realm: &CanonicalAddressRealmRecord,
    ) -> Result<(), StoreError> {
        self.inner.insert_canonical_realm(realm).await
    }

    async fn get_canonical_realm(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalAddressRealmRecord>, StoreError> {
        self.inner.get_canonical_realm(project_id, id).await
    }

    async fn list_canonical_realms(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError> {
        self.inner
            .list_canonical_realms(project_id, network_id)
            .await
    }

    async fn list_active_canonical_realms(
        &self,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError> {
        self.inner.list_active_canonical_realms().await
    }

    async fn list_deleting_canonical_realms(
        &self,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError> {
        self.inner.list_deleting_canonical_realms().await
    }

    async fn insert_canonical_pool(
        &self,
        pool: &CanonicalAddressPoolRecord,
    ) -> Result<(), StoreError> {
        self.inner.insert_canonical_pool(pool).await
    }

    async fn insert_subnet_bundle(
        &self,
        realm: &CanonicalAddressRealmRecord,
        pool: &CanonicalAddressPoolRecord,
        subnet: &SubnetRecord,
    ) -> Result<(), StoreError> {
        self.inner.insert_subnet_bundle(realm, pool, subnet).await
    }

    async fn list_canonical_pools(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressPoolRecord>, StoreError> {
        self.inner.list_canonical_pools(project_id, realm_id).await
    }

    async fn delete_canonical_pool(
        &self,
        project_id: &str,
        pool_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.inner.delete_canonical_pool(project_id, pool_id).await
    }

    async fn update_canonical_pool(
        &self,
        project_id: &str,
        pool_id: &Uuid,
        expected_generation: u64,
        gateway: Option<std::net::Ipv4Addr>,
    ) -> Result<CanonicalAddressPoolRecord, StoreError> {
        self.inner
            .update_canonical_pool(project_id, pool_id, expected_generation, gateway)
            .await
    }

    async fn insert_canonical_endpoint(
        &self,
        endpoint: &CanonicalEndpointRecord,
    ) -> Result<(), StoreError> {
        self.inner.insert_canonical_endpoint(endpoint).await
    }

    async fn insert_canonical_endpoint_and_port(
        &self,
        endpoint: &CanonicalEndpointRecord,
        port: &PortRecord,
    ) -> Result<(), StoreError> {
        self.inner
            .insert_canonical_endpoint_and_port(endpoint, port)
            .await
    }

    async fn list_canonical_endpoints(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalEndpointRecord>, StoreError> {
        self.inner
            .list_canonical_endpoints(project_id, realm_id)
            .await
    }

    async fn get_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<Option<CanonicalEndpointRecord>, StoreError> {
        self.inner
            .get_canonical_endpoint(project_id, endpoint_id)
            .await
    }

    async fn delete_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.inner
            .delete_canonical_endpoint(project_id, endpoint_id)
            .await
    }

    async fn delete_canonical_endpoint_and_port(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.inner
            .delete_canonical_endpoint_and_port(project_id, endpoint_id)
            .await
    }

    async fn upsert_canonical_policy(
        &self,
        policy: &CanonicalNetworkPolicyRecord,
    ) -> Result<(), StoreError> {
        self.inner.upsert_canonical_policy(policy).await
    }

    async fn list_canonical_policies(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRecord>, StoreError> {
        self.inner
            .list_canonical_policies(project_id, network_id)
            .await
    }

    async fn delete_canonical_policy(
        &self,
        project_id: &str,
        policy_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.inner
            .delete_canonical_policy(project_id, policy_id)
            .await
    }

    async fn begin_canonical_realm_deletion(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalAddressRealmRecord, StoreError> {
        self.inner
            .begin_canonical_realm_deletion(project_id, realm_id, expected_generation)
            .await
    }

    async fn advance_canonical_realm_generation(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalAddressRealmRecord, StoreError> {
        self.inner
            .advance_canonical_realm_generation(project_id, realm_id, expected_generation)
            .await
    }

    async fn list_canonical_realm_bindings(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalRealmBindingRecord>, StoreError> {
        self.inner.list_canonical_realm_bindings(realm_id).await
    }

    async fn insert_canonical_realm_binding(
        &self,
        binding: &CanonicalRealmBindingRecord,
    ) -> Result<(), StoreError> {
        self.inner.insert_canonical_realm_binding(binding).await
    }

    async fn get_canonical_realm_binding(
        &self,
        fabric_domain_id: &str,
        realm_id: &Uuid,
    ) -> Result<Option<CanonicalRealmBindingRecord>, StoreError> {
        self.inner
            .get_canonical_realm_binding(fabric_domain_id, realm_id)
            .await
    }

    async fn delete_canonical_realm_binding(
        &self,
        binding: &CanonicalRealmBindingRecord,
        expected_realm_generation: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .delete_canonical_realm_binding(binding, expected_realm_generation)
            .await
    }

    async fn delete_canonical_realm(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.inner
            .delete_canonical_realm(project_id, realm_id)
            .await
    }

    async fn delete_canonical_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.inner
            .delete_canonical_network(project_id, network_id)
            .await
    }

    async fn backfill_canonical_network_state(&self) -> Result<(), StoreError> {
        self.inner.backfill_canonical_network_state().await
    }

    async fn allocate_network_address(
        &self,
        realm_id: &Uuid,
        project_id: &str,
        endpoint_id: &Uuid,
        operation_id: &str,
        prefix: &str,
    ) -> Result<NetworkAddressAllocationRecord, StoreError> {
        self.inner
            .allocate_network_address(realm_id, project_id, endpoint_id, operation_id, prefix)
            .await
    }

    async fn release_network_address(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        self.inner
            .release_network_address(project_id, endpoint_id)
            .await
    }

    async fn insert_network_intent(&self, intent: &NetworkIntentRecord) -> Result<(), StoreError> {
        self.inner.insert_network_intent(intent).await
    }

    async fn list_network_intents(
        &self,
        project_id: &str,
    ) -> Result<Vec<NetworkIntentRecord>, StoreError> {
        self.inner.list_network_intents(project_id).await
    }

    async fn get_network_intent(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkIntentRecord>, StoreError> {
        self.inner.get_network_intent(project_id, id).await
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
        self.inner
            .update_network_intent(
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
        self.inner.insert_network(network).await
    }

    async fn list_networks(&self, project_id: &str) -> Result<Vec<NetworkRecord>, StoreError> {
        self.inner.list_networks(project_id).await
    }

    async fn get_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkRecord>, StoreError> {
        self.inner.get_network(project_id, id).await
    }

    async fn delete_network(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.inner.delete_network(project_id, id).await
    }

    async fn insert_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError> {
        self.inner.insert_subnet(subnet).await
    }

    async fn list_subnets(&self, project_id: &str) -> Result<Vec<SubnetRecord>, StoreError> {
        self.inner.list_subnets(project_id).await
    }

    async fn list_subnets_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<SubnetRecord>, StoreError> {
        self.inner
            .list_subnets_for_network(project_id, network_id)
            .await
    }

    async fn get_subnet(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SubnetRecord>, StoreError> {
        self.inner.get_subnet(project_id, id).await
    }

    async fn delete_subnet(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.inner.delete_subnet(project_id, id).await
    }

    async fn delete_subnet_bundle(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.inner.delete_subnet_bundle(project_id, id).await
    }

    async fn update_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError> {
        self.inner.update_subnet(subnet).await
    }

    async fn update_subnet_bundle(
        &self,
        subnet: &SubnetRecord,
        pool_id: &Uuid,
        expected_pool_generation: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .update_subnet_bundle(subnet, pool_id, expected_pool_generation)
            .await
    }

    async fn insert_port(&self, port: &PortRecord) -> Result<(), StoreError> {
        self.inner.insert_port(port).await
    }

    async fn list_ports(&self, project_id: &str) -> Result<Vec<PortRecord>, StoreError> {
        self.inner.list_ports(project_id).await
    }

    async fn list_ports_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<PortRecord>, StoreError> {
        self.inner
            .list_ports_for_network(project_id, network_id)
            .await
    }

    async fn get_port(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<PortRecord>, StoreError> {
        self.inner.get_port(project_id, id).await
    }

    async fn get_port_by_id(&self, id: &Uuid) -> Result<Option<PortRecord>, StoreError> {
        self.inner.get_port_by_id(id).await
    }

    async fn delete_port(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.inner.delete_port(project_id, id).await
    }

    async fn update_port_binding(
        &self,
        project_id: &str,
        id: &Uuid,
        binding_host: Option<&str>,
        binding_state: Option<&str>,
    ) -> Result<PortRecord, StoreError> {
        self.inner
            .update_port_binding(project_id, id, binding_host, binding_state)
            .await
    }

    async fn update_port_name(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
    ) -> Result<PortRecord, StoreError> {
        self.inner.update_port_name(project_id, id, name).await
    }

    async fn insert_security_group(&self, group: &SecurityGroupRecord) -> Result<(), StoreError> {
        self.inner.insert_security_group(group).await
    }

    async fn list_security_groups(
        &self,
        project_id: &str,
    ) -> Result<Vec<SecurityGroupRecord>, StoreError> {
        self.inner.list_security_groups(project_id).await
    }

    async fn get_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRecord>, StoreError> {
        self.inner.get_security_group(project_id, id).await
    }

    async fn update_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
        description: &str,
    ) -> Result<SecurityGroupRecord, StoreError> {
        self.inner
            .update_security_group(project_id, id, name, description)
            .await
    }

    async fn delete_security_group(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        self.inner.delete_security_group(project_id, id).await
    }

    async fn insert_security_group_rule(
        &self,
        rule: &SecurityGroupRuleRecord,
    ) -> Result<(), StoreError> {
        self.inner.insert_security_group_rule(rule).await
    }

    async fn list_security_group_rules(
        &self,
        project_id: &str,
        group_id: &Uuid,
    ) -> Result<Vec<SecurityGroupRuleRecord>, StoreError> {
        self.inner
            .list_security_group_rules(project_id, group_id)
            .await
    }

    async fn get_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRuleRecord>, StoreError> {
        self.inner.get_security_group_rule(project_id, id).await
    }

    async fn delete_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<(), StoreError> {
        self.inner.delete_security_group_rule(project_id, id).await
    }

    async fn list_security_group_bindings(
        &self,
        project_id: &str,
        endpoint_id: Option<&Uuid>,
    ) -> Result<Vec<SecurityGroupBindingRecord>, StoreError> {
        self.inner
            .list_security_group_bindings(project_id, endpoint_id)
            .await
    }

    async fn replace_security_group_bindings(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
        group_ids: &[Uuid],
    ) -> Result<(), StoreError> {
        self.inner
            .replace_security_group_bindings(project_id, endpoint_id, group_ids)
            .await
    }
}

/// Issue #1047: the realm DELETE, the `resources` DELETED tombstone, and the
/// canonical operation's Succeeded terminal update must commit in ONE
/// transaction. They used to be three separate durable writes with a
/// swallowed tombstone error, so a fault between them returned `Removed`
/// while stranding the projection in `deleting` forever — a state no repair
/// pass fixes. The atomic primitive must instead commit nothing on failure
/// and stay re-drivable, converge exactly once, and accept idempotent replay.
#[tokio::test]
async fn realm_cleanup_terminalization_is_atomic() -> Result<(), Box<dyn std::error::Error>> {
    let path = root("realm-cleanup-terminalization");
    let sqlite_path = format!("{}.sqlite", path.display());
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_file(&sqlite_path);
    let store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let fault = Arc::new(RealmCleanupFaultStore::new(store.clone()));
    fault.arm_converged_assertion();
    let service = NetworkService::open_for_test(&path, fault.clone()).await?;
    let network = service
        .create_canonical_network_for_project("project-a", "atomic".to_owned())
        .await?;
    let realm = service
        .create_canonical_realm_for_project(
            "project-a",
            network.id,
            "10.41.0.0/24".to_owned(),
            false,
        )
        .await?;
    let binding = o3k_store::CanonicalRealmBindingRecord {
        fabric_domain_id: "fabric-a".to_owned(),
        realm_id: realm.id,
        provider_kind: "geneve".to_owned(),
        provider_segment_id: 411,
        binding_generation: 1,
        state: "active".to_owned(),
    };
    store.insert_canonical_realm_binding(&binding).await?;
    assert!(matches!(
        service
            .delete_canonical_realm_for_project("project-a", realm.id)
            .await,
        Err(NetworkError::Conflict)
    ));
    let first = service
        .begin_canonical_realm_deletion_for_project("project-a", realm.id)
        .await?;
    let operation_id = match first {
        RealmCleanupProgress::AwaitingObservation { operation_id, .. } => operation_id,
        _ => return Err("unexpected replay progress".into()),
    };

    // The crash: the provider side effects happened (the binding and pool
    // removals committed), the finalization is about to fail.
    fault.fail_next_finalize();
    let crashed = service
        .observe_canonical_realm_cleanup_for_project(
            "project-a",
            realm.id,
            vec![RealmCleanupObservation::Absent(binding)],
        )
        .await;
    assert!(
        matches!(crashed, Err(NetworkError::NotFound)),
        "the injected finalization failure must propagate: {crashed:?}"
    );
    // Issue #1047 invariant after the crash: NONE of the three durable
    // writes is committed, exactly as if the finalization never ran, so the
    // cleanup stays re-drivable.
    let realm_after = store
        .get_canonical_realm("project-a", &realm.id)
        .await?
        .ok_or("realm must survive a failed finalization")?;
    assert_eq!(realm_after.state, "deleting");
    assert_eq!(
        store.get_canonical_operation(operation_id).await?.state,
        o3k_store::OperationState::Running
    );
    let resource = store.get_resource(realm.id).await?;
    assert_eq!(resource.desired_state, "deleting");
    assert_eq!(resource.observed_state, "deleting");

    // Re-drive converges once: the absent binding already proved the provider
    // cleanup, so the observation set is empty now.
    let removed = service
        .observe_canonical_realm_cleanup_for_project("project-a", realm.id, vec![])
        .await?;
    assert_eq!(removed, RealmCleanupProgress::Removed { operation_id });
    assert!(
        store
            .get_canonical_realm("project-a", &realm.id)
            .await?
            .is_none()
    );
    assert_eq!(
        store.get_canonical_operation(operation_id).await?.state,
        o3k_store::OperationState::Succeeded
    );
    let resource = store.get_resource(realm.id).await?;
    assert_eq!(resource.desired_state, "deleted");
    assert_eq!(
        resource.observed_state, "deleted",
        "the tombstone must commit atomically with the terminal operation"
    );

    // Idempotent replay: a second finalization neither errors nor re-applies.
    let canonical = store.get_canonical_operation(operation_id).await?;
    let replay_update = o3k_store::CanonicalOperationLifecycleUpdate::new(
        o3k_kernel::OperationState::Succeeded,
        canonical.attempt.saturating_add(1),
        canonical.started_at.clone(),
        Some(
            canonical
                .started_at
                .clone()
                .unwrap_or_else(|| canonical.created_at.clone()),
        ),
        None,
    )?;
    fault
        .finalize_realm_cleanup(
            "project-a",
            &realm.id,
            realm_after.generation,
            operation_id,
            &replay_update,
        )
        .await?;
    let resource = store.get_resource(realm.id).await?;
    assert_eq!(resource.observed_state, "deleted");

    // A restarted control plane must not need to repair anything: reopening
    // runs the recovery scan, and the projection must still be terminal.
    drop(service);
    let reopened_store = Arc::new(o3k_store::testkit::open_file(Path::new(&sqlite_path)).await?);
    let _reopened = NetworkService::open_for_test(&path, reopened_store.clone()).await?;
    let resource = reopened_store.get_resource(realm.id).await?;
    assert_eq!(resource.observed_state, "deleted");
    let _ = fs::remove_dir_all(path);
    let _ = fs::remove_file(sqlite_path);
    Ok(())
}
