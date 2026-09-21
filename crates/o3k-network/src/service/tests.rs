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
    // Unbind clears the binding idempotently and is durable.
    let unbound = service.unbind_port("project-a", port.id).await?;
    assert_eq!(unbound.binding_host, None);
    assert_eq!(unbound.binding_state.as_deref(), Some("down"));
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
