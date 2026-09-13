#[cfg(test)]
mod tests {
    use crate::*;
    use std::error::Error;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    #[tokio::test]
    async fn sqlite_scoped_operation_migration_preserves_populated_database()
    -> Result<(), Box<dyn Error>> {
        use sqlx::migrate::Migrator;
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
        use std::str::FromStr;

        let path = std::env::temp_dir().join(format!(
            "o3k-scoped-operation-upgrade-{}.sqlite",
            Uuid::now_v7()
        ));
        let url = format!("sqlite://{}", path.display());
        let options = SqliteConnectOptions::from_str(&url)?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        let migration_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut historical = Migrator::new(migration_path).await?;
        historical
            .migrations
            .to_mut()
            .retain(|migration| migration.version < 37);
        historical.run(&pool).await?;

        let generic_resource = Uuid::now_v7().to_string();
        let canonical_network = Uuid::now_v7().to_string();
        let generic_operation = Uuid::now_v7().to_string();
        let canonical_operation = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO resources (id, kind, project_id, generation, observed_generation, desired_state, observed_state) VALUES (?, 'server', 'project-a', 1, 0, 'requested', 'unknown')",
        )
        .bind(&generic_resource)
        .execute(&pool)
        .await?;
        // Pre-0037 canonical operations used the historical generic-resource
        // projection. Preserve that existing row while the upgrade removes
        // the FK; the migration must not create another authority row.
        sqlx::query(
            "INSERT INTO resources (id, kind, project_id, generation, observed_generation, desired_state, observed_state) VALUES (?, 'network:network', 'project-a', 1, 1, 'active', 'active')",
        )
        .bind(&canonical_network)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO canonical_networks (id, project_id, name, generation, state) VALUES (?, 'project-a', 'upgrade-network', 1, 'active')",
        )
        .bind(&canonical_network)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO operations (id, resource_id, kind, state, provider_operation_id, error_category, error_message) VALUES (?, ?, 'create', 'succeeded', 'provider-generic', NULL, NULL), (?, ?, 'network:create', 'running', 'provider-canonical', NULL, NULL)",
        )
        .bind(&generic_operation)
        .bind(&generic_resource)
        .bind(&canonical_operation)
        .bind(&canonical_network)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO canonical_operation_metadata (operation_id, service, action, actor, owner_scope, resource_type, resource_id, attempt, created_at) VALUES (?, 'compute', 'create', 'user-a', 'project-a', 'compute:server', ?, 0, '2026-01-01T00:00:00Z'), (?, 'network', 'create', 'user-a', 'project-a', 'network:network', ?, 0, '2026-01-01T00:00:01Z')",
        )
        .bind(&generic_operation)
        .bind(&generic_resource)
        .bind(&canonical_operation)
        .bind(&canonical_network)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO operation_retry_state (operation_id, attempts) VALUES (?, 2), (?, 3)",
        )
        .bind(&generic_operation)
        .bind(&canonical_operation)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO agent_commands (command_id, idempotency_key, operation_id, resource_id, agent_id, agent_epoch, payload_fingerprint_sha256, payload, state) VALUES ('command-upgrade', 'command-key-upgrade', ?, ?, 'agent-a', 'epoch-a', ?, X'01', 'accepted')",
        )
        .bind(&generic_operation)
        .bind(&generic_resource)
        .bind("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO artifact_transfers (transfer_id, command_id, operation_id, resource_id, agent_id, agent_epoch, artifact_id, artifact_kind, sha256, size_bytes, format, chunk_size_bytes, chunk_count, state) VALUES ('transfer-upgrade', 'command-upgrade', ?, ?, 'agent-a', 'epoch-a', 'artifact-upgrade', 'image', ?, 1, 'raw', 1, 1, 'offered')",
        )
        .bind(&generic_operation)
        .bind(&generic_resource)
        .bind("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO image_overlay_ownership (overlay_id, resource_id, operation_id, command_id, agent_id, agent_epoch, base_sha256, base_format, overlay_format, state) VALUES ('overlay-upgrade', ?, ?, 'command-upgrade', 'agent-a', 'epoch-a', ?, 'raw', 'qcow2', 'pending')",
        )
        .bind(&generic_resource)
        .bind(&generic_operation)
        .bind("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO idempotency_reservations (owner_scope, action, idempotency_key, fingerprint, operation_id) VALUES ('project-a', 'network:create', 'upgrade-idempotency', 'fingerprint-upgrade', ?)",
        )
        .bind(&canonical_operation)
        .execute(&pool)
        .await?;
        pool.close().await;

        let store = SqliteStore::connect_file(&path).await?;
        let operation_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operations")
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(operation_count, 2);
        let metadata_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM canonical_operation_metadata")
                .fetch_one(&store.pool)
                .await?;
        assert_eq!(metadata_count, 2);
        let retry_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operation_retry_state")
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(retry_count, 2);
        for table in [
            "agent_commands",
            "artifact_transfers",
            "image_overlay_ownership",
            "idempotency_reservations",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&store.pool)
                .await?;
            assert_eq!(count, 1, "row lost from {table}");
        }
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(foreign_keys, 1);
        let foreign_key_violations: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_check")
                .fetch_one(&store.pool)
                .await?;
        assert_eq!(foreign_key_violations, 0);
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(integrity, "ok");

        sqlx::query("DELETE FROM resources WHERE id = ?")
            .bind(&generic_resource)
            .execute(&store.pool)
            .await?;
        assert!(
            store
                .get_operation(Uuid::parse_str(&generic_operation)?)
                .await
                .is_err()
        );
        assert!(
            store
                .get_operation(Uuid::parse_str(&canonical_operation)?)
                .await
                .is_ok()
        );
        sqlx::query("DELETE FROM resources WHERE id = ?")
            .bind(&canonical_network)
            .execute(&store.pool)
            .await?;
        assert!(
            store
                .get_operation(Uuid::parse_str(&canonical_operation)?)
                .await
                .is_ok()
        );
        let canonical_metadata_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM canonical_operation_metadata WHERE operation_id = ?",
        )
        .bind(&canonical_operation)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(canonical_metadata_count, 1);
        drop(store);

        let reopened = SqliteStore::connect_file(&path).await?;
        assert!(
            reopened
                .get_operation(Uuid::parse_str(&canonical_operation)?)
                .await
                .is_ok()
        );
        let trigger_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('resources_delete_generic_operations', 'operations_validate_resource_reference')",
        )
        .fetch_one(&reopened.pool)
        .await?;
        assert_eq!(trigger_count, 2);
        let invalid_operation = Uuid::now_v7().to_string();
        let invalid_insert = sqlx::query(
            "INSERT INTO operations (id, resource_id, kind, state) VALUES (?, ?, 'network:create', 'running')",
        )
        .bind(&invalid_operation)
        .bind(Uuid::now_v7().to_string())
        .execute(&reopened.pool)
        .await;
        assert!(invalid_insert.is_err());
        drop(reopened);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn building_block_round_trip_and_generation_fence() -> Result<(), Box<dyn Error>> {
        let store = O3kStore::connect_sqlite_memory().await?;
        let block = o3k_kernel::BuildingBlock::enrolling(
            "bb-a",
            "agent-a",
            vec!["provider-a".into()],
            Some("fd-a".into()),
            None,
        )?;
        let record = BuildingBlockRecord::from_block(&block, "2026-01-01T00:00:00Z")?;
        store.upsert_building_block(&record, None).await?;
        let loaded = store
            .get_building_block("bb-a")
            .await?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "block"))?
            .block()?;
        assert_eq!(loaded, block);
        let ready = block.transition(o3k_kernel::BuildingBlockState::Ready, vec![])?;
        let ready_record = BuildingBlockRecord::from_block(&ready, "2026-01-01T00:00:01Z")?;
        assert!(matches!(
            store.upsert_building_block(&ready_record, Some(99)).await,
            Err(StoreError::StaleGeneration)
        ));
        store.upsert_building_block(&ready_record, Some(1)).await?;
        assert_eq!(store.list_building_blocks().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_scoped_operation_migration_normalizes_only_approved_legacy_checksum()
    -> Result<(), Box<dyn Error>> {
        async fn create_database() -> Result<PathBuf, Box<dyn Error>> {
            let path = std::env::temp_dir().join(format!(
                "o3k-scoped-operation-checksum-{}.sqlite",
                Uuid::now_v7()
            ));
            let store = SqliteStore::connect_file(&path).await?;
            store.pool.close().await;
            Ok(path)
        }

        async fn set_checksum(
            path: &std::path::Path,
            checksum: &[u8],
        ) -> Result<(), Box<dyn Error>> {
            let url = format!("sqlite://{}", path.display());
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await?;
            sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = 37")
                .bind(checksum)
                .execute(&pool)
                .await?;
            pool.close().await;
            Ok(())
        }

        let approved = [
            0x89, 0xe6, 0x76, 0x54, 0xcd, 0x55, 0xd6, 0xc7, 0xaf, 0xbf, 0x46, 0x1c, 0x10, 0x46,
            0x82, 0xa9, 0xda, 0x1a, 0x20, 0xee, 0x6e, 0x56, 0x40, 0x8a, 0x29, 0x37, 0x45, 0xe0,
            0x3a, 0xbf, 0x2a, 0x66, 0x73, 0x24, 0x4f, 0xc2, 0x64, 0xe6, 0x67, 0x40, 0xbb, 0x1d,
            0x8e, 0xcf, 0x13, 0x93, 0x33, 0xd6,
        ];
        let approved_path = create_database().await?;
        set_checksum(&approved_path, &approved).await?;
        let reopened = SqliteStore::connect_file(&approved_path).await?;
        let normalized: Vec<u8> =
            sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 37")
                .fetch_one(&reopened.pool)
                .await?;
        assert_ne!(normalized, approved);
        reopened.pool.close().await;
        let _ = std::fs::remove_file(&approved_path);
        let _ = std::fs::remove_file(format!("{}-wal", approved_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", approved_path.display()));

        let arbitrary = vec![0x5a; 48];
        let arbitrary_path = create_database().await?;
        set_checksum(&arbitrary_path, &arbitrary).await?;
        assert!(SqliteStore::connect_file(&arbitrary_path).await.is_err());
        let _ = std::fs::remove_file(&arbitrary_path);
        let _ = std::fs::remove_file(format!("{}-wal", arbitrary_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", arbitrary_path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_scoped_operation_migration_upgrades_legacy_checksum_with_resource_fk()
    -> Result<(), Box<dyn Error>> {
        use sqlx::migrate::Migrator;
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
        use std::str::FromStr;

        let path = std::env::temp_dir().join(format!(
            "o3k-scoped-operation-legacy-fk-{}.sqlite",
            Uuid::now_v7()
        ));
        let url = format!("sqlite://{}", path.display());
        let options = SqliteConnectOptions::from_str(&url)?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        let migration_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut historical = Migrator::new(migration_path).await?;
        historical
            .migrations
            .to_mut()
            .retain(|migration| migration.version < 37);
        historical.run(&pool).await?;

        let legacy_checksum: [u8; 48] = [
            0x89, 0xe6, 0x76, 0x54, 0xcd, 0x55, 0xd6, 0xc7, 0xaf, 0xbf, 0x46, 0x1c, 0x10, 0x46,
            0x82, 0xa9, 0xda, 0x1a, 0x20, 0xee, 0x6e, 0x56, 0x40, 0x8a, 0x29, 0x37, 0x45, 0xe0,
            0x3a, 0xbf, 0x2a, 0x66, 0x73, 0x24, 0x4f, 0xc2, 0x64, 0xe6, 0x67, 0x40, 0xbb, 0x1d,
            0x8e, 0xcf, 0x13, 0x93, 0x33, 0xd6,
        ];
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (37, 'canonical operation resource scope', CURRENT_TIMESTAMP, 1, ?, 0)",
        )
        .bind(legacy_checksum.as_slice())
        .execute(&pool)
        .await?;
        let fk_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('operations') WHERE \"table\" = 'resources' AND \"from\" = 'resource_id'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(fk_before, 1);
        pool.close().await;

        let store = SqliteStore::connect_file(&path).await?;
        let fk_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('operations') WHERE \"table\" = 'resources' AND \"from\" = 'resource_id'",
        )
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(fk_after, 0);
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(foreign_keys, 1);
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(integrity, "ok");
        store.pool.close().await;
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_relationship_intent_is_unique_replayable_and_reopenable()
    -> Result<(), StoreError> {
        let path = std::env::temp_dir().join(format!("o3k-relationship-{}.sqlite", Uuid::now_v7()));
        let parent = Uuid::now_v7();
        let operation = Uuid::now_v7();
        let resource = ResourceRecord {
            id: parent,
            kind: "database:instance".into(),
            project_id: "project-a".into(),
            generation: 1,
            observed_generation: 0,
            desired_state: "{}".into(),
            observed_state: "provisioning".into(),
            provider_id: None,
        };
        let store = SqliteStore::connect_file(&path).await?;
        store.insert_resource(&resource).await?;
        let record = ResourceRelationshipRecord {
            parent_resource_id: parent,
            parent_resource_type: "database:instance".into(),
            slot: "network-primary".into(),
            expected_child_resource_type: "network:network".into(),
            child_resource_id: None,
            ownership: "exclusive".into(),
            parent_operation_id: operation,
            child_operation_id: None,
            owner_scope: "project-a".into(),
            state: "reserved".into(),
            fingerprint: "fp-1".into(),
        };
        let reserved = store.reserve_relationship(&record).await?;
        assert_eq!(reserved.state, "reserved");
        assert_eq!(store.reserve_relationship(&record).await?, reserved);
        let mut conflicting = record.clone();
        conflicting.fingerprint = "different".into();
        assert!(matches!(
            store.reserve_relationship(&conflicting).await,
            Err(StoreError::IdempotencyConflict)
        ));
        let child = Uuid::now_v7();
        let child_operation = Uuid::now_v7();
        let bound = store
            .bind_relationship(parent, "network-primary", child, child_operation)
            .await?;
        assert_eq!(bound.child_resource_id, Some(child));
        assert_eq!(store.list_relationships(parent).await?.len(), 1);
        drop(store);
        let reopened = SqliteStore::connect_file(&path).await?;
        assert_eq!(
            reopened
                .get_relationship(parent, "network-primary")
                .await?
                .child_operation_id,
            Some(child_operation)
        );
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn unified_relationship_page_dispatch_is_bounded_and_non_recursive()
    -> Result<(), StoreError> {
        let store = O3kStore::connect_sqlite_memory().await?;
        let parent = Uuid::now_v7();
        store
            .insert_resource(&ResourceRecord {
                id: parent,
                kind: "database:instance".into(),
                project_id: "project-a".into(),
                generation: 1,
                observed_generation: 1,
                desired_state: "{}".into(),
                observed_state: "ready".into(),
                provider_id: None,
            })
            .await?;
        for slot in ["network-primary", "volume-data"] {
            store
                .reserve_relationship(&ResourceRelationshipRecord {
                    parent_resource_id: parent,
                    parent_resource_type: "database:instance".into(),
                    slot: slot.into(),
                    expected_child_resource_type: "network:network".into(),
                    child_resource_id: None,
                    ownership: "exclusive".into(),
                    parent_operation_id: Uuid::now_v7(),
                    child_operation_id: None,
                    owner_scope: "project-a".into(),
                    state: "reserved".into(),
                    fingerprint: format!("fingerprint-{slot}"),
                })
                .await?;
        }
        let first = store.list_relationships_page(parent, None, 1).await?;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].slot, "network-primary");
        let second = store
            .list_relationships_page(parent, Some(&first[0].slot), 1)
            .await?;
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].slot, "volume-data");
        Ok(())
    }

    #[tokio::test]
    async fn cloud_profile_round_trip_and_generation_fencing() -> Result<(), StoreError> {
        let store = O3kStore::connect_sqlite_memory().await?;
        let profile = o3k_kernel::CloudProfile {
            profile_id: "edge".into(),
            generation: 1,
            selected_services: vec![o3k_kernel::ServiceSelection {
                service_id: "compute".into(),
                ownership: o3k_kernel::ServiceOwnershipMode::O3kImplemented,
                version_requirement: "*".into(),
                dependencies: vec![],
                required_capabilities: vec![],
                locality: None,
                placement_requirement: None,
                config_refs: vec![],
            }],
            upgrade_order: vec![],
        };
        let record = CloudProfileRecord::from_profile(&profile, "2026-01-01T00:00:00Z")?;
        store.upsert_cloud_profile(&record, None).await?;
        assert_eq!(
            store
                .get_cloud_profile("edge")
                .await?
                .ok_or(StoreError::ResourceNotFound)?
                .profile()?,
            profile
        );
        let stale = CloudProfileRecord {
            generation: 2,
            ..record
        };
        assert!(matches!(
            store.upsert_cloud_profile(&stale, Some(99)).await,
            Err(StoreError::StaleGeneration)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_store_passes_conformance() -> Result<(), StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        run_conformance(&store).await
    }

    /// The lifecycle-convergence sweep drives exactly the rows returned by
    /// `list_non_terminal_lifecycle_operations`: lifecycle-kind operations
    /// that have not reached the reconciler's terminal predicate
    /// (`succeeded`/`failed`). Every other row — terminal lifecycle ops and
    /// non-lifecycle kinds such as `create` — must be excluded.
    #[tokio::test]
    async fn list_non_terminal_lifecycle_operations_returns_exactly_the_lifecycle_residue()
    -> Result<(), StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let resource_a = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "compute_instance".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 1,
            desired_state: "{}".to_owned(),
            observed_state: "ACTIVE".to_owned(),
            provider_id: Some("instance-a".to_owned()),
        };
        let resource_b = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "compute_instance".to_owned(),
            project_id: "project-b".to_owned(),
            generation: 1,
            observed_generation: 1,
            desired_state: "{}".to_owned(),
            observed_state: "ACTIVE".to_owned(),
            provider_id: Some("instance-b".to_owned()),
        };
        store.insert_resource(&resource_a).await?;
        store.insert_resource(&resource_b).await?;
        let operation =
            |serial: u32, resource_id: Uuid, kind: &str, state: OperationState| OperationRecord {
                id: Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!("o3k-store-lifecycle-query-{serial}").as_bytes(),
                ),
                resource_id,
                kind: kind.to_owned(),
                state,
                provider_operation_id: Some(format!("provider-op-{serial}")),
                error_category: None,
                error_message: None,
            };
        // Non-terminal lifecycle rows: the sweep must see all six.
        let pending_start = operation(1, resource_a.id, "lifecycle:start", OperationState::Pending);
        let running_stop = operation(2, resource_a.id, "lifecycle:stop", OperationState::Running);
        let running_reboot = operation(
            3,
            resource_a.id,
            "lifecycle:reboot",
            OperationState::Running,
        );
        let retryable_delete = operation(
            4,
            resource_a.id,
            "lifecycle:delete",
            OperationState::Retryable,
        );
        let unknown_delete = operation(
            5,
            resource_b.id,
            "lifecycle:delete",
            OperationState::UnknownOutcome,
        );
        let unknown_reboot = operation(
            6,
            resource_b.id,
            "lifecycle:reboot",
            OperationState::UnknownOutcome,
        );
        // Excluded rows: terminal lifecycle ops and a non-lifecycle kind.
        let succeeded_delete = operation(
            7,
            resource_a.id,
            "lifecycle:delete",
            OperationState::Succeeded,
        );
        let failed_delete = operation(8, resource_a.id, "lifecycle:delete", OperationState::Failed);
        let unknown_create = operation(9, resource_b.id, "create", OperationState::UnknownOutcome);
        for row in [
            &pending_start,
            &running_stop,
            &running_reboot,
            &retryable_delete,
            &unknown_delete,
            &unknown_reboot,
            &succeeded_delete,
            &failed_delete,
            &unknown_create,
        ] {
            store.insert_operation(row).await?;
        }

        let listed = store.list_non_terminal_lifecycle_operations().await?;
        let mut listed_ids: Vec<Uuid> = listed.iter().map(|row| row.id).collect();
        listed_ids.sort();
        let mut expected_ids = [
            pending_start.id,
            running_stop.id,
            running_reboot.id,
            retryable_delete.id,
            unknown_delete.id,
            unknown_reboot.id,
        ];
        expected_ids.sort();
        assert_eq!(listed_ids, expected_ids);
        for row in listed {
            assert!(
                row.kind.starts_with("lifecycle:"),
                "a non-lifecycle kind must never be listed: {}",
                row.kind
            );
            assert!(
                !matches!(
                    row.state,
                    OperationState::Succeeded | OperationState::Failed
                ),
                "a terminal operation must never be listed: {:?}",
                row.state
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_idempotency_reservation_is_scoped_and_atomic() -> Result<(), StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let request = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "compute:CreateServer",
            "abc",
            "compute:server",
            None,
            &serde_json::json!({"name": "demo", "size": 10}),
            Uuid::now_v7(),
        )?;
        let equivalent = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "compute:CreateServer",
            "abc",
            "compute:server",
            None,
            &serde_json::json!({"size": 10, "name": "demo"}),
            request.operation_id,
        )?;
        assert_eq!(request.fingerprint, equivalent.fingerprint);
        assert_eq!(
            store.reserve_idempotent_operation(&equivalent).await?,
            IdempotencyReservation::Created(request.operation_id)
        );
        assert_eq!(
            store.reserve_idempotent_operation(&request).await?,
            IdempotencyReservation::ExistingEquivalent(request.operation_id)
        );
        let mut conflict = request.clone();
        conflict.fingerprint = "sha256:b".into();
        assert_eq!(
            store.reserve_idempotent_operation(&conflict).await?,
            IdempotencyReservation::Conflict
        );
        let mut other = request.clone();
        other.owner_scope = "project-b".into();
        other.operation_id = Uuid::now_v7();
        assert_eq!(
            store.reserve_idempotent_operation(&other).await?,
            IdempotencyReservation::Created(other.operation_id)
        );

        // The non-creating lookup exposes the stored fingerprint and
        // operation identity: replay detection can distinguish a true replay
        // from key reuse with different semantics without writing anything.
        assert_eq!(
            store
                .get_idempotency_reservation("project-a", "compute:CreateServer", "abc")
                .await?,
            Some(StoredIdempotencyReservation {
                fingerprint: request.fingerprint.clone(),
                operation_id: request.operation_id,
            })
        );
        assert_eq!(
            store
                .get_idempotency_reservation("project-a", "compute:CreateServer", "missing")
                .await?,
            None
        );
        assert_eq!(
            store
                .get_idempotency_reservation("project-b", "compute:CreateServer", "abc")
                .await?,
            Some(StoredIdempotencyReservation {
                fingerprint: other.fingerprint.clone(),
                operation_id: other.operation_id,
            })
        );
        Ok(())
    }

    fn idempotent_operation(resource_id: Uuid, id: Uuid) -> OperationRecord {
        OperationRecord {
            id,
            resource_id,
            kind: "create".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        }
    }

    fn canonical_idempotent_operation(
        operation: &OperationRecord,
        owner_scope: &str,
        action: &str,
    ) -> CanonicalOperationRecord {
        CanonicalOperationRecord {
            id: operation.id,
            service: action
                .split_once(':')
                .map_or(action, |(service, _)| service)
                .to_owned(),
            action: action.to_owned(),
            actor: "user-a".to_owned(),
            owner_scope: owner_scope.to_owned(),
            resource_type: "compute:server".to_owned(),
            resource_id: Some(operation.resource_id.to_string()),
            state: operation.state,
            attempt: 0,
            created_at: "2026-08-22T00:00:00Z".to_owned(),
            started_at: None,
            finished_at: None,
            error: None,
            request_id: Some("request-a".to_owned()),
        }
    }

    async fn concurrent_store_fixture() -> Result<(SqliteStore, Uuid), StoreError> {
        let path = std::env::temp_dir().join(format!("o3k-p12-4-idempotency-{}", Uuid::now_v7()));
        let store = SqliteStore::connect(&format!("sqlite://{}", path.display())).await?;
        let resource_id = Uuid::now_v7();
        store
            .insert_resource(&ResourceRecord {
                id: resource_id,
                // Existing Compute rows use the durable internal discriminator;
                // native canonical reads map it to compute:server.
                kind: "compute_instance".to_owned(),
                project_id: "project-a".to_owned(),
                generation: 1,
                observed_generation: 0,
                desired_state: "{}".to_owned(),
                observed_state: "unknown".to_owned(),
                provider_id: None,
            })
            .await?;
        Ok((store, resource_id))
    }

    #[tokio::test]
    async fn sqlite_idempotency_concurrent_equivalent_requests_have_one_winner()
    -> Result<(), StoreError> {
        let (store, resource_id) = concurrent_store_fixture().await?;
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        let mut proposed = Vec::new();
        for _ in 0..2 {
            let operation_id = Uuid::now_v7();
            proposed.push(operation_id);
            let request = IdempotencyReservationRequest::from_semantics(
                "project-a",
                "compute:CreateServer",
                "ABC",
                "compute:server",
                None,
                &serde_json::json!({"name":"demo"}),
                operation_id,
            )?;
            let operation = idempotent_operation(resource_id, operation_id);
            let canonical =
                canonical_idempotent_operation(&operation, "project-a", "compute:CreateServer");
            let db = store.clone();
            let gate = barrier.clone();
            tasks.push(tokio::spawn(async move {
                gate.wait().await;
                db.create_or_replay_canonical_idempotent_operation(&operation, &canonical, &request)
                    .await
            }));
        }
        barrier.wait().await;
        let first = tasks
            .remove(0)
            .await
            .map_err(|error| StoreError::Corrupt(format!("idempotency task failed: {error}")))??;
        let second = tasks
            .remove(0)
            .await
            .map_err(|error| StoreError::Corrupt(format!("idempotency task failed: {error}")))??;
        let winner = match (first, second) {
            (IdempotencyReservation::Created(a), IdempotencyReservation::ExistingEquivalent(b))
            | (IdempotencyReservation::ExistingEquivalent(b), IdempotencyReservation::Created(a)) =>
            {
                assert_eq!(a, b);
                a
            }
            other => {
                return Err(StoreError::Corrupt(format!(
                    "equivalent race did not converge: {other:?}"
                )));
            }
        };
        let operations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operations")
            .fetch_one(&store.pool)
            .await
            .map_err(StoreError::Database)?;
        let reservations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM idempotency_reservations")
            .fetch_one(&store.pool)
            .await
            .map_err(StoreError::Database)?;
        assert_eq!(operations, 1);
        let metadata: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM canonical_operation_metadata")
            .fetch_one(&store.pool)
            .await
            .map_err(StoreError::Database)?;
        assert_eq!(metadata, 1);
        assert_eq!(reservations, 1);
        assert!(proposed.contains(&winner));
        let loser = proposed
            .into_iter()
            .find(|id| *id != winner)
            .ok_or_else(|| StoreError::Corrupt("equivalent race produced no loser".into()))?;
        assert!(matches!(
            store.get_operation(loser).await,
            Err(StoreError::OperationNotFound)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_idempotency_concurrent_conflict_leaves_one_operation() -> Result<(), StoreError>
    {
        let (store, resource_id) = concurrent_store_fixture().await?;
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for body in [
            serde_json::json!({"name":"one"}),
            serde_json::json!({"name":"two"}),
        ] {
            let operation_id = Uuid::now_v7();
            let request = IdempotencyReservationRequest::from_semantics(
                "project-a",
                "compute:CreateServer",
                "ABC",
                "compute:server",
                None,
                &body,
                operation_id,
            )?;
            let operation = idempotent_operation(resource_id, operation_id);
            let canonical =
                canonical_idempotent_operation(&operation, "project-a", "compute:CreateServer");
            let db = store.clone();
            let gate = barrier.clone();
            tasks.push(tokio::spawn(async move {
                gate.wait().await;
                db.create_or_replay_canonical_idempotent_operation(&operation, &canonical, &request)
                    .await
            }));
        }
        barrier.wait().await;
        let a = tasks
            .remove(0)
            .await
            .map_err(|error| StoreError::Corrupt(format!("idempotency task failed: {error}")))??;
        let b = tasks
            .remove(0)
            .await
            .map_err(|error| StoreError::Corrupt(format!("idempotency task failed: {error}")))??;
        assert!(matches!(
            (a, b),
            (
                IdempotencyReservation::Created(_),
                IdempotencyReservation::Conflict
            ) | (
                IdempotencyReservation::Conflict,
                IdempotencyReservation::Created(_)
            )
        ));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operations")
            .fetch_one(&store.pool)
            .await
            .map_err(StoreError::Database)?;
        assert_eq!(count, 1);
        let metadata: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM canonical_operation_metadata")
            .fetch_one(&store.pool)
            .await
            .map_err(StoreError::Database)?;
        let reservations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM idempotency_reservations")
            .fetch_one(&store.pool)
            .await
            .map_err(StoreError::Database)?;
        assert_eq!(metadata, 1);
        assert_eq!(reservations, 1);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_idempotency_concurrent_scopes_and_actions_are_isolated()
    -> Result<(), StoreError> {
        let (store, resource_id) = concurrent_store_fixture().await?;
        let project_b_resource_id = Uuid::now_v7();
        store
            .insert_resource(&ResourceRecord {
                id: project_b_resource_id,
                kind: "compute_server".to_owned(),
                project_id: "project-b".to_owned(),
                generation: 1,
                observed_generation: 0,
                desired_state: "{}".to_owned(),
                observed_state: "unknown".to_owned(),
                provider_id: None,
            })
            .await?;
        let barrier = Arc::new(tokio::sync::Barrier::new(4));
        let mut tasks = Vec::new();
        for (scope, action) in [
            ("project-a", "compute:CreateServer"),
            ("project-b", "compute:CreateServer"),
            ("project-a", "compute:DeleteServer"),
        ] {
            let operation_id = Uuid::now_v7();
            let request = IdempotencyReservationRequest::from_semantics(
                scope,
                action,
                "ABC",
                "compute:server",
                None,
                &serde_json::json!({"name":"demo"}),
                operation_id,
            )?;
            let scoped_resource_id = if scope == "project-b" {
                project_b_resource_id
            } else {
                resource_id
            };
            let operation = idempotent_operation(scoped_resource_id, operation_id);
            let canonical = canonical_idempotent_operation(&operation, scope, action);
            let db = store.clone();
            let gate = barrier.clone();
            tasks.push(tokio::spawn(async move {
                gate.wait().await;
                db.create_or_replay_canonical_idempotent_operation(&operation, &canonical, &request)
                    .await
            }));
        }
        barrier.wait().await;
        for task in tasks {
            assert!(matches!(
                task.await.map_err(|error| StoreError::Corrupt(format!(
                    "idempotency task failed: {error}"
                )))??,
                IdempotencyReservation::Created(_)
            ));
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operations")
            .fetch_one(&store.pool)
            .await
            .map_err(StoreError::Database)?;
        assert_eq!(count, 3);
        let metadata: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM canonical_operation_metadata")
            .fetch_one(&store.pool)
            .await
            .map_err(StoreError::Database)?;
        let reservations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM idempotency_reservations")
            .fetch_one(&store.pool)
            .await
            .map_err(StoreError::Database)?;
        assert_eq!(metadata, 3);
        assert_eq!(reservations, 3);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_canonical_idempotency_rolls_back_every_insert_on_failure()
    -> Result<(), StoreError> {
        let (store, resource_id) = concurrent_store_fixture().await?;
        for (trigger_name, table) in [
            ("fail_canonical_metadata", "canonical_operation_metadata"),
            ("fail_idempotency_reservation", "idempotency_reservations"),
        ] {
            sqlx::query(&format!(
                "CREATE TRIGGER {trigger_name} BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'injected P12.4 rollback'); END"
            ))
            .execute(&store.pool)
            .await
            .map_err(StoreError::Database)?;

            let operation = idempotent_operation(resource_id, Uuid::now_v7());
            let canonical =
                canonical_idempotent_operation(&operation, "project-a", "compute:CreateServer");
            let request = IdempotencyReservationRequest::from_semantics(
                "project-a",
                "compute:CreateServer",
                format!("rollback-{trigger_name}"),
                "compute:server",
                None,
                &serde_json::json!({"name":"demo"}),
                operation.id,
            )?;
            assert!(matches!(
                store
                    .create_or_replay_canonical_idempotent_operation(
                        &operation, &canonical, &request,
                    )
                    .await,
                Err(StoreError::Database(_))
            ));

            sqlx::query(&format!("DROP TRIGGER {trigger_name}"))
                .execute(&store.pool)
                .await
                .map_err(StoreError::Database)?;
            for table in [
                "operations",
                "canonical_operation_metadata",
                "idempotency_reservations",
            ] {
                let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                    .fetch_one(&store.pool)
                    .await
                    .map_err(StoreError::Database)?;
                assert_eq!(count, 0, "{table} must roll back after {trigger_name}");
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_canonical_idempotency_rejects_reservation_for_legacy_operation()
    -> Result<(), StoreError> {
        let (store, resource_id) = concurrent_store_fixture().await?;
        let operation = idempotent_operation(resource_id, Uuid::now_v7());
        store.insert_operation(&operation).await?;
        let canonical =
            canonical_idempotent_operation(&operation, "project-a", "compute:CreateServer");
        let request = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "compute:CreateServer",
            "legacy-operation",
            "compute:server",
            None,
            &serde_json::json!({"name":"demo"}),
            operation.id,
        )?;
        assert!(matches!(
            store
                .create_or_replay_canonical_idempotent_operation(&operation, &canonical, &request,)
                .await,
            Err(StoreError::Corrupt(_))
        ));
        let metadata: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM canonical_operation_metadata")
            .fetch_one(&store.pool)
            .await
            .map_err(StoreError::Database)?;
        let reservations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM idempotency_reservations")
            .fetch_one(&store.pool)
            .await
            .map_err(StoreError::Database)?;
        assert_eq!(metadata, 0);
        assert_eq!(reservations, 0);
        assert_eq!(store.get_operation(operation.id).await?, operation);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_canonical_resource_acceptance_is_atomic_and_replayable()
    -> Result<(), StoreError> {
        let store = SqliteStore::connect(":memory:").await?;
        let resource = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "compute_instance".into(),
            project_id: "project-a".into(),
            generation: 1,
            observed_generation: 0,
            desired_state: "{}".into(),
            observed_state: "requested".into(),
            provider_id: None,
        };
        let operation = idempotent_operation(resource.id, Uuid::now_v7());
        let canonical =
            canonical_idempotent_operation(&operation, "project-a", "compute:CreateServer");
        let request = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "compute:CreateServer",
            "native-create",
            "compute:server",
            None,
            &serde_json::json!({"name":"demo"}),
            operation.id,
        )?;
        assert_eq!(
            store
                .create_or_replay_canonical_resource_operation(
                    &resource, &operation, &canonical, &request, None
                )
                .await?,
            CanonicalAcceptanceOutcome::Created {
                operation_id: operation.id,
                resource_id: resource.id
            }
        );
        let losing_resource = ResourceRecord {
            id: Uuid::now_v7(),
            ..resource.clone()
        };
        let losing_operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id: losing_resource.id,
            ..operation.clone()
        };
        let losing_canonical = CanonicalOperationRecord {
            id: losing_operation.id,
            resource_id: Some(losing_resource.id.to_string()),
            ..canonical.clone()
        };
        let mut replay = request.clone();
        replay.operation_id = losing_operation.id;
        assert_eq!(
            store
                .create_or_replay_canonical_resource_operation(
                    &losing_resource,
                    &losing_operation,
                    &losing_canonical,
                    &replay,
                    None
                )
                .await?,
            CanonicalAcceptanceOutcome::ExistingEquivalent {
                operation_id: operation.id,
                resource_id: resource.id
            }
        );
        assert!(matches!(
            store.get_resource(losing_resource.id).await,
            Err(StoreError::ResourceNotFound)
        ));
        assert!(
            o3k_kernel::Operation::try_from(store.get_canonical_operation(operation.id).await?)
                .is_ok()
        );
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_canonical_lifecycle_acceptance_replays_and_conflicts() -> Result<(), StoreError>
    {
        let (store, resource_id) = concurrent_store_fixture().await?;
        let operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id,
            kind: "lifecycle:delete".into(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        let canonical =
            canonical_idempotent_operation(&operation, "project-a", "compute:DeleteServer");
        let request = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "compute:DeleteServer",
            "native-delete",
            "compute:server",
            Some(&resource_id.to_string()),
            &serde_json::json!({}),
            operation.id,
        )?;
        assert!(matches!(
            store
                .create_or_replay_canonical_lifecycle_operation(&operation, &canonical, &request)
                .await?,
            CanonicalAcceptanceOutcome::Created { .. }
        ));
        let replay = IdempotencyReservationRequest {
            operation_id: Uuid::now_v7(),
            ..request.clone()
        };
        assert_eq!(
            store
                .create_or_replay_canonical_lifecycle_operation(
                    &OperationRecord {
                        id: replay.operation_id,
                        ..operation.clone()
                    },
                    &CanonicalOperationRecord {
                        id: replay.operation_id,
                        ..canonical.clone()
                    },
                    &replay
                )
                .await?,
            CanonicalAcceptanceOutcome::ExistingEquivalent {
                operation_id: operation.id,
                resource_id
            }
        );
        let conflict = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "compute:DeleteServer",
            "native-delete",
            "compute:server",
            Some(&resource_id.to_string()),
            &serde_json::json!({"different":true}),
            Uuid::now_v7(),
        )?;
        assert_eq!(
            store
                .create_or_replay_canonical_lifecycle_operation(
                    &OperationRecord {
                        id: conflict.operation_id,
                        ..operation
                    },
                    &CanonicalOperationRecord {
                        id: conflict.operation_id,
                        ..canonical
                    },
                    &conflict
                )
                .await?,
            CanonicalAcceptanceOutcome::Conflict
        );
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_canonical_scoped_operation_uses_authoritative_network_row()
    -> Result<(), StoreError> {
        let path =
            std::env::temp_dir().join(format!("o3k-scoped-network-{}.sqlite", Uuid::now_v7()));
        let store = SqliteStore::connect(&format!("sqlite://{}", path.display())).await?;
        let resource_id = Uuid::now_v7();
        store
            .insert_canonical_network(&CanonicalNetworkRecord {
                id: resource_id,
                project_id: "project-a".to_owned(),
                name: "native-delete-network".to_owned(),
                admin_state_up: true,
                generation: 1,
                state: "active".to_owned(),
            })
            .await?;
        let operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id,
            kind: "lifecycle:delete".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        let canonical = CanonicalOperationRecord {
            resource_type: "network:network".to_owned(),
            ..canonical_idempotent_operation(&operation, "project-a", "network:DeleteNetwork")
        };
        let request = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "network:DeleteNetwork",
            "native-delete",
            "network:network",
            Some(&resource_id.to_string()),
            &serde_json::json!({}),
            operation.id,
        )?;
        assert_eq!(
            store
                .create_or_replay_canonical_scoped_operation(&operation, &canonical, &request)
                .await?,
            IdempotencyReservation::Created(operation.id)
        );
        let update = CanonicalOperationLifecycleUpdate::new(
            o3k_kernel::OperationState::Succeeded,
            1,
            Some("2026-08-22T00:00:01Z".to_owned()),
            Some("2026-08-22T00:00:02Z".to_owned()),
            None,
        )?;
        store
            .update_canonical_operation_lifecycle(operation.id, &update)
            .await?;
        assert_eq!(
            store.get_canonical_operation(operation.id).await?,
            CanonicalOperationRecord {
                state: OperationState::Succeeded,
                attempt: 1,
                finished_at: Some("2026-08-22T00:00:02Z".to_owned()),
                started_at: Some("2026-08-22T00:00:01Z".to_owned()),
                ..canonical.clone()
            }
        );
        let replay_id = Uuid::now_v7();
        assert_eq!(
            store
                .create_or_replay_canonical_scoped_operation(
                    &OperationRecord {
                        id: replay_id,
                        ..operation.clone()
                    },
                    &CanonicalOperationRecord {
                        id: replay_id,
                        ..canonical
                    },
                    &IdempotencyReservationRequest {
                        operation_id: replay_id,
                        ..request
                    },
                )
                .await?,
            IdempotencyReservation::ExistingEquivalent(operation.id)
        );
        sqlx::query(
            "UPDATE canonical_operation_metadata SET owner_scope = 'project-b' WHERE operation_id = ?",
        )
        .bind(operation.id.to_string())
        .execute(&store.pool)
        .await
        .map_err(StoreError::Database)?;
        assert!(matches!(
            store.get_canonical_operation(operation.id).await,
            Err(StoreError::Corrupt(_))
        ));
        drop(store);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_canonical_idempotency_reopens_and_replays_complete_operation()
    -> Result<(), StoreError> {
        let path = std::env::temp_dir().join(format!("o3k-p12-4-reopen-{}", Uuid::now_v7()));
        let url = format!("sqlite://{}", path.display());
        let operation_id = Uuid::now_v7();
        let resource_id = Uuid::now_v7();
        let request = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "compute:CreateServer",
            "reopen-key",
            "compute:server",
            None,
            &serde_json::json!({"name":"demo"}),
            operation_id,
        )?;
        let operation = idempotent_operation(resource_id, operation_id);
        let canonical =
            canonical_idempotent_operation(&operation, "project-a", "compute:CreateServer");
        {
            let store = SqliteStore::connect(&url).await?;
            store
                .insert_resource(&ResourceRecord {
                    id: resource_id,
                    kind: "compute:server".to_owned(),
                    project_id: "project-a".to_owned(),
                    generation: 1,
                    observed_generation: 0,
                    desired_state: "{}".to_owned(),
                    observed_state: "unknown".to_owned(),
                    provider_id: None,
                })
                .await?;
            assert_eq!(
                store
                    .create_or_replay_canonical_idempotent_operation(
                        &operation, &canonical, &request,
                    )
                    .await?,
                IdempotencyReservation::Created(operation_id)
            );
        }

        let reopened = SqliteStore::connect(&url).await?;
        let replay_operation = idempotent_operation(resource_id, Uuid::now_v7());
        let replay_canonical =
            canonical_idempotent_operation(&replay_operation, "project-a", "compute:CreateServer");
        let mut replay_request = request.clone();
        replay_request.operation_id = replay_operation.id;
        assert_eq!(
            reopened
                .create_or_replay_canonical_idempotent_operation(
                    &replay_operation,
                    &replay_canonical,
                    &replay_request,
                )
                .await?,
            IdempotencyReservation::ExistingEquivalent(operation_id)
        );
        let kernel =
            o3k_kernel::Operation::try_from(reopened.get_canonical_operation(operation_id).await?)?;
        assert_eq!(kernel.id, operation_id);
        assert_eq!(kernel.action.as_str(), "compute:CreateServer");
        assert_eq!(kernel.owner_scope.id().as_str(), "project-a");
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_canonical_replay_precedes_proposed_resource_lookup() -> Result<(), StoreError> {
        let (store, resource_id) = concurrent_store_fixture().await?;
        let operation = idempotent_operation(resource_id, Uuid::now_v7());
        let canonical =
            canonical_idempotent_operation(&operation, "project-a", "compute:CreateServer");
        let request = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "compute:CreateServer",
            "replay-before-resource",
            "compute:server",
            None,
            &serde_json::json!({"name":"demo"}),
            operation.id,
        )?;
        assert_eq!(
            store
                .create_or_replay_canonical_idempotent_operation(&operation, &canonical, &request,)
                .await?,
            IdempotencyReservation::Created(operation.id)
        );

        // A retried create may propose a newly allocated public resource ID.
        // Idempotency must resolve the committed winner before requiring that
        // losing proposal's resource to exist.
        let proposal = idempotent_operation(Uuid::now_v7(), Uuid::now_v7());
        let proposal_canonical =
            canonical_idempotent_operation(&proposal, "project-a", "compute:CreateServer");
        let mut replay = request.clone();
        replay.operation_id = proposal.id;
        assert_eq!(
            store
                .create_or_replay_canonical_idempotent_operation(
                    &proposal,
                    &proposal_canonical,
                    &replay,
                )
                .await?,
            IdempotencyReservation::ExistingEquivalent(operation.id)
        );
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_canonical_replay_fails_closed_on_winning_owner_corruption()
    -> Result<(), StoreError> {
        let (store, resource_id) = concurrent_store_fixture().await?;
        let operation = idempotent_operation(resource_id, Uuid::now_v7());
        let canonical =
            canonical_idempotent_operation(&operation, "project-a", "compute:CreateServer");
        let request = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "compute:CreateServer",
            "corrupt-winning-owner",
            "compute:server",
            None,
            &serde_json::json!({"name":"demo"}),
            operation.id,
        )?;
        store
            .create_or_replay_canonical_idempotent_operation(&operation, &canonical, &request)
            .await?;
        sqlx::query("UPDATE resources SET project_id = 'project-b' WHERE id = ?")
            .bind(resource_id.to_string())
            .execute(&store.pool)
            .await
            .map_err(StoreError::Database)?;

        let proposal = idempotent_operation(resource_id, Uuid::now_v7());
        let proposal_canonical =
            canonical_idempotent_operation(&proposal, "project-a", "compute:CreateServer");
        let mut replay = request;
        replay.operation_id = proposal.id;
        assert!(matches!(
            store
                .create_or_replay_canonical_idempotent_operation(
                    &proposal,
                    &proposal_canonical,
                    &replay,
                )
                .await,
            Err(StoreError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn canonical_idempotency_rejects_resource_type_mismatch() -> Result<(), StoreError> {
        let operation = idempotent_operation(Uuid::now_v7(), Uuid::now_v7());
        let canonical =
            canonical_idempotent_operation(&operation, "project-a", "compute:CreateServer");
        let mut request = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "compute:CreateServer",
            "resource-type-mismatch",
            "compute:image",
            None,
            &serde_json::json!({"name":"demo"}),
            operation.id,
        )?;
        // The request's retained, normalized type is part of cross-record
        // identity validation even if a caller constructs a fingerprint from
        // otherwise valid canonical semantics.
        request.resource_type = "compute:image".to_owned();
        assert!(matches!(
            validate_canonical_idempotent_operation_identity(&operation, &canonical, &request),
            Err(StoreError::Corrupt(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_generation_cas_allows_only_one_concurrent_writer() -> Result<(), StoreError> {
        let path = std::env::temp_dir().join(format!("o3k-p12-4-generation-{}", Uuid::now_v7()));
        let url = format!("sqlite://{}", path.display());
        let store = SqliteStore::connect(&url).await?;
        let resource = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "server".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: "requested".to_owned(),
            observed_state: "unknown".to_owned(),
            provider_id: None,
        };
        store.insert_resource(&resource).await?;

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let first = store.clone();
        let first_barrier = barrier.clone();
        let first_task = tokio::spawn(async move {
            first_barrier.wait().await;
            first
                .update_resource(resource.id, 1, "active", "running", 1, Some("provider-a"))
                .await
        });
        let second = store.clone();
        let second_barrier = barrier.clone();
        let second_task = tokio::spawn(async move {
            second_barrier.wait().await;
            second
                .update_resource(resource.id, 1, "active", "running", 1, Some("provider-b"))
                .await
        });
        barrier.wait().await;
        let first_result = first_task
            .await
            .map_err(|error| StoreError::Corrupt(format!("first CAS task failed: {error}")))?;
        let second_result = second_task
            .await
            .map_err(|error| StoreError::Corrupt(format!("second CAS task failed: {error}")))?;
        let winner_count = usize::from(first_result.is_ok()) + usize::from(second_result.is_ok());
        let stale_count = usize::from(matches!(first_result, Err(StoreError::StaleGeneration)))
            + usize::from(matches!(second_result, Err(StoreError::StaleGeneration)));
        assert_eq!(winner_count, 1, "exactly one writer may claim generation 1");
        assert_eq!(
            stale_count, 1,
            "the losing writer must observe a stale generation"
        );
        assert_eq!(store.get_resource(resource.id).await?.generation, 2);
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_canonical_read_fails_closed_on_cross_record_corruption()
    -> Result<(), StoreError> {
        let (store, resource_id) = concurrent_store_fixture().await?;
        let operation = idempotent_operation(resource_id, Uuid::now_v7());
        let canonical =
            canonical_idempotent_operation(&operation, "project-a", "compute:CreateServer");
        let request = IdempotencyReservationRequest::from_semantics(
            "project-a",
            "compute:CreateServer",
            "corrupt-read",
            "compute:server",
            None,
            &serde_json::json!({"name": "demo"}),
            operation.id,
        )?;
        assert!(matches!(
            store
                .create_or_replay_canonical_idempotent_operation(&operation, &canonical, &request)
                .await?,
            IdempotencyReservation::Created(_)
        ));
        sqlx::query("UPDATE canonical_operation_metadata SET owner_scope = 'project-b' WHERE operation_id = ?")
            .bind(operation.id.to_string()).execute(&store.pool).await.map_err(StoreError::Database)?;
        assert!(matches!(
            store.get_canonical_operation(operation.id).await,
            Err(StoreError::Corrupt(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_store_passes_extracted_repository_port_conformance() -> Result<(), StoreError> {
        let compute_store = SqliteStore::connect("sqlite::memory:").await?;
        run_identity_repository_conformance(&compute_store).await?;
        run_keypair_repository_conformance(&compute_store).await?;
        run_volume_attachment_repository_conformance(&compute_store).await?;
        run_conformance(&compute_store).await?;
        run_image_repository_conformance(&compute_store).await?;
        run_network_repository_conformance(&compute_store).await?;
        run_placement_repository_conformance(&compute_store).await?;
        // Invariant: exactly two `compute_instance` rows survive the combined
        // run. The keypair suite leaves one (its server-create scenario) and
        // the volume-attachment suite leaves one; the identity suite, the
        // generic `run_conformance`, the image suite, the network suite, and
        // the placement suite create none (keystone rows, a `server` resource,
        // `image_metadata` rows, `network_networks`/`network_subnets`/
        // `network_ports` rows, and `placement_providers`/`placement_*` rows
        // only). Keep this assertion on the shared store so a suite added to
        // the combined run cannot silently change the count.
        assert_eq!(
            compute_store
                .list_resources_by_kind("compute_instance")
                .await?
                .len(),
            2
        );
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_placement_diagnostics_capacity_and_bounded_providers() -> Result<(), StoreError>
    {
        let store = O3kStore::connect_sqlite_memory().await?;

        let inventory =
            |class: &str, total: u64, reserved: u64, ratio: f64| PlacementInventoryRecord {
                resource_class: class.to_owned(),
                total,
                reserved,
                allocation_ratio: ratio,
                used: 0,
            };

        // Two providers with overlapping resource classes, both Enabled.
        store
            .register_provider(
                "compute-1",
                &[
                    inventory("MEMORY_MB", 4096, 256, 1.5),
                    inventory("VCPU", 8, 1, 16.0),
                ],
            )
            .await?;
        store
            .register_provider(
                "compute-2",
                &[
                    inventory("MEMORY_MB", 2048, 128, 1.0),
                    inventory("VCPU", 4, 0, 8.0),
                ],
            )
            .await?;

        // capacity_summary aggregates allocatable/reserved/allocated across
        // providers and reports provider counts by canonical state.
        let summary = store.capacity_summary(64).await?;
        assert_eq!(summary.providers_enabled, 2);
        assert_eq!(summary.providers_draining, 0);
        assert_eq!(summary.providers_unavailable, 0);
        assert_eq!(summary.providers_deleted, 0);

        let memory = class(&summary, "MEMORY_MB")?;
        // allocatable = floor(4096*1.5) + floor(2048*1.0) = 6144 + 2048 = 8192.
        assert_eq!(memory.allocatable, 8192);
        assert_eq!(memory.reserved, 256 + 128);
        assert_eq!(memory.allocated, 0);

        let vcpu = class(&summary, "VCPU")?;
        // allocatable = floor(8*16.0) + floor(4*8.0) = 128 + 32 = 160.
        assert_eq!(vcpu.allocatable, 160);
        assert_eq!(vcpu.reserved, 1);
        assert_eq!(vcpu.allocated, 0);

        // The aggregate fails closed (Corrupt) when the stored class set
        // exceeds the caller's limit rather than silently truncating.
        assert!(matches!(
            store.capacity_summary(1).await,
            Err(StoreError::Corrupt(_))
        ));

        // list_providers_bounded paginates by id with after_id and honours limit.
        let page1 = store.list_providers_bounded(None, 1).await?;
        assert_eq!(page1.len(), 1);
        assert_eq!(page1[0].id, "compute-1");

        let page2 = store.list_providers_bounded(Some("compute-1"), 1).await?;
        assert_eq!(page2.len(), 1);
        assert_eq!(page2[0].id, "compute-2");

        assert!(
            store
                .list_providers_bounded(Some("compute-2"), 10)
                .await?
                .is_empty()
        );
        assert_eq!(store.list_providers_bounded(None, 10).await?.len(), 2);

        // Bounded reads carry inventories but deliberately omit allocations.
        let bounded = store.list_providers_bounded(None, 10).await?;
        for provider in bounded {
            assert!(!provider.inventories.is_empty());
            assert!(provider.allocations.is_empty());
        }

        // Commit an allocation so the `allocated` aggregate is exercised.
        let allocation = PlacementAllocationRecord {
            id: "alloc-1".to_owned(),
            provider_id: "compute-1".to_owned(),
            consumer_id: "consumer-1".to_owned(),
            resources: vec![
                PlacementResourceRecord {
                    resource_class: "MEMORY_MB".to_owned(),
                    amount: 1024,
                },
                PlacementResourceRecord {
                    resource_class: "VCPU".to_owned(),
                    amount: 2,
                },
            ],
        };
        store.commit_allocation("compute-1", 1, &allocation).await?;

        let summary = store.capacity_summary(64).await?;
        assert_eq!(class(&summary, "MEMORY_MB")?.allocated, 1024);
        assert_eq!(class(&summary, "VCPU")?.allocated, 2);
        // A normal allocation is not over-allocated.
        assert_eq!(summary.providers_over_allocated, 0);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_list_provider_states_pagination_and_narrow_read() -> Result<(), StoreError> {
        let store = O3kStore::connect_sqlite_memory().await?;
        let inventory = PlacementInventoryRecord {
            resource_class: "VCPU".to_owned(),
            total: 8,
            reserved: 1,
            allocation_ratio: 1.0,
            used: 0,
        };
        store
            .register_provider("compute-1", std::slice::from_ref(&inventory))
            .await?;
        store.register_provider("compute-2", &[inventory]).await?;

        // Returns id+state rows ordered by id; both default to `Enabled`.
        let all = store.list_provider_states(None, 10).await?;
        assert_eq!(all.len(), 2);
        assert_eq!(
            all.iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>(),
            vec!["compute-1", "compute-2"]
        );
        assert!(all.iter().all(|record| record.state == "Enabled"));

        // Honors `after_id` pagination and `limit`.
        let page1 = store.list_provider_states(None, 1).await?;
        assert_eq!(page1.len(), 1);
        assert_eq!(page1[0].id, "compute-1");

        let page2 = store.list_provider_states(Some("compute-1"), 1).await?;
        assert_eq!(page2.len(), 1);
        assert_eq!(page2[0].id, "compute-2");

        assert!(
            store
                .list_provider_states(Some("compute-2"), 10)
                .await?
                .is_empty()
        );

        // The aggregate read is deliberately narrow: it carries only the
        // provider id + durable state, never inventories or allocations.
        // The record type structurally prevents those fields from appearing.
        for record in store.list_provider_states(None, 10).await? {
            assert!(matches!(
                record,
                PlacementProviderStateRecord { id: _, state: _ }
            ));
        }
        Ok(())
    }

    /// Returns a single capacity aggregate class by name, or a corrupt-state
    /// error if it is absent (a test invariant failure).
    fn class<'a>(
        summary: &'a PlacementCapacitySummary,
        name: &str,
    ) -> Result<&'a PlacementCapacityClassRecord, StoreError> {
        summary
            .classes
            .iter()
            .find(|class| class.resource_class == name)
            .ok_or_else(|| {
                StoreError::Corrupt(format!("{name} class missing from capacity summary"))
            })
    }

    #[tokio::test]
    async fn sqlite_federated_binding_survives_restart() -> Result<(), Box<dyn Error>> {
        let path =
            std::env::temp_dir().join(format!("o3k-federated-binding-{}.sqlite", Uuid::now_v7()));
        let store = SqliteStore::connect_file(&path).await?;
        let domain = KeystoneDomainRecord {
            id: "restart-domain".to_owned(),
            name: "Restart".to_owned(),
            description: None,
            enabled: true,
            created_at: "2026-08-07T00:00:00Z".to_owned(),
        };
        let user = KeystoneUserRecord {
            id: "restart-user".to_owned(),
            domain_id: domain.id.clone(),
            name: "restart-user".to_owned(),
            password_hash: "not-used".to_owned(),
            email: Some("same@example.test".to_owned()),
            enabled: true,
            created_at: domain.created_at.clone(),
        };
        let binding = FederatedBindingRecord {
            id: "restart-binding".to_owned(),
            trusted_issuer_id: "restart-issuer".to_owned(),
            issuer: "https://idp.example.test".to_owned(),
            subject: "restart-subject".to_owned(),
            principal_id: user.id.clone(),
            principal_type: "user".to_owned(),
            enabled: true,
            created_at: domain.created_at.clone(),
            updated_at: domain.created_at.clone(),
        };
        store.insert_keystone_domain(&domain).await?;
        store.insert_keystone_user(&user).await?;
        store.insert_federated_binding(&binding).await?;
        let assignment = OperatorAssignmentRecord {
            id: "restart-operator-assignment".to_owned(),
            user_id: user.id.clone(),
            profile: "operator-console".to_owned(),
            enabled: true,
            created_at: domain.created_at.clone(),
            updated_at: domain.created_at.clone(),
        };
        store.insert_operator_assignment(&assignment).await?;
        drop(store);

        let reopened = SqliteStore::connect_file(&path).await?;
        assert_eq!(
            reopened
                .find_federated_binding("restart-issuer", "restart-subject")
                .await?,
            Some(binding)
        );
        assert_eq!(
            reopened.list_operator_assignments().await?,
            vec![assignment]
        );
        drop(reopened);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[tokio::test]
    async fn image_metadata_survives_store_reopen() -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!("/tmp/o3k-store-image-{}.sqlite", Uuid::now_v7()));
        let image = ImageMetadataRecord {
            id: Uuid::now_v7(),
            name: "survivor".to_owned(),
            project_id: "project-a".to_owned(),
            status: "queued".to_owned(),
            visibility: "private".to_owned(),
            container_format: "bare".to_owned(),
            disk_format: "raw".to_owned(),
            size: None,
            checksum: None,
        };
        let checksum = "b".repeat(64);
        {
            let store = testkit::open_file(&path).await?;
            store.insert_image(&image).await?;
            let active = store
                .activate_image("project-a", &image.id, 7, &checksum)
                .await?;
            assert_eq!(active.status, "active");
        }
        let reopened = testkit::open_file(&path).await?;
        let restored = reopened
            .get_image("project-a", &image.id)
            .await?
            .ok_or(StoreError::ImageNotFound)?;
        assert_eq!(restored.status, "active");
        assert_eq!(restored.size, Some(7));
        assert_eq!(restored.checksum.as_deref(), Some(checksum.as_str()));
        reopened.delete_image("project-a", &image.id).await?;
        assert!(matches!(
            reopened.get_image("project-a", &image.id).await,
            Ok(None)
        ));
        fs::remove_file(&path)?;
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn network_metadata_survives_store_reopen() -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!("/tmp/o3k-store-network-{}.sqlite", Uuid::now_v7()));
        let network = NetworkRecord {
            id: Uuid::now_v7(),
            name: "survivor".to_owned(),
            project_id: "project-a".to_owned(),
            status: "ACTIVE".to_owned(),
        };
        let subnet = SubnetRecord {
            id: Uuid::now_v7(),
            network_id: network.id,
            name: "survivor-subnet".to_owned(),
            project_id: "project-a".to_owned(),
            cidr: "10.0.9.0/24".to_owned(),
            gateway_ip: Ipv4Addr::new(10, 0, 9, 1),
            allocation_start: Ipv4Addr::new(10, 0, 9, 10),
            allocation_end: Ipv4Addr::new(10, 0, 9, 200),
            ip_version: 4,
            enable_dhcp: true,
        };
        let port = PortRecord {
            id: Uuid::now_v7(),
            network_id: network.id,
            subnet_id: Some(subnet.id),
            project_id: "project-a".to_owned(),
            name: "survivor-port".to_owned(),
            mac_address: "fa:16:3e:00:00:99".to_owned(),
            fixed_ip: Ipv4Addr::new(10, 0, 9, 5),
            status: "DOWN".to_owned(),
            binding_host: None,
            binding_state: None,
        };
        {
            let store = testkit::open_file(&path).await?;
            store.insert_network(&network).await?;
            store.insert_subnet(&subnet).await?;
            store.insert_port(&port).await?;
            let bound = store
                .update_port_binding("project-a", &port.id, Some("compute-1"), Some("active"))
                .await?;
            assert_eq!(bound.binding_host.as_deref(), Some("compute-1"));
            assert_eq!(bound.binding_state.as_deref(), Some("active"));
        }
        let reopened = testkit::open_file(&path).await?;
        assert_eq!(
            reopened.get_network("project-a", &network.id).await?,
            Some(network.clone())
        );
        assert_eq!(
            reopened.get_subnet("project-a", &subnet.id).await?,
            Some(subnet.clone())
        );
        let restored_port = reopened
            .get_port("project-a", &port.id)
            .await?
            .ok_or(StoreError::NetworkNotFound)?;
        let mut expected_port = port.clone();
        expected_port.binding_host = Some("compute-1".to_owned());
        expected_port.binding_state = Some("active".to_owned());
        assert_eq!(restored_port, expected_port);
        assert_eq!(restored_port.binding_host.as_deref(), Some("compute-1"));
        assert_eq!(restored_port.binding_state.as_deref(), Some("active"));
        reopened.delete_port("project-a", &port.id).await?;
        reopened.delete_subnet("project-a", &subnet.id).await?;
        reopened.delete_network("project-a", &network.id).await?;
        fs::remove_file(&path)?;
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn placement_metadata_survives_store_reopen() -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-store-placement-{}.sqlite",
            Uuid::now_v7()
        ));
        let inventories = vec![PlacementInventoryRecord {
            resource_class: "VCPU".to_owned(),
            total: 8,
            reserved: 1,
            allocation_ratio: 16.0,
            used: 0,
        }];
        let allocation = PlacementAllocationRecord {
            id: "alloc-survivor".to_owned(),
            provider_id: "node-1".to_owned(),
            consumer_id: "consumer-survivor".to_owned(),
            resources: vec![PlacementResourceRecord {
                resource_class: "VCPU".to_owned(),
                amount: 2,
            }],
        };
        let intent = PlacementIntentRecord {
            id: "intent-survivor".to_owned(),
            provider_id: "node-1".to_owned(),
            consumer_id: "consumer-survivor".to_owned(),
            resources: vec![PlacementResourceRecord {
                resource_class: "VCPU".to_owned(),
                amount: 2,
            }],
        };
        {
            let store = testkit::open_file(&path).await?;
            store.register_provider("node-1", &inventories).await?;
            store.commit_allocation("node-1", 1, &allocation).await?;
            store.upsert_intent(&intent).await?;
        }
        let reopened = testkit::open_file(&path).await?;
        let provider = reopened
            .get_provider("node-1")
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)?;
        assert_eq!(provider.generation, 2);
        assert_eq!(provider.allocations, vec![allocation.clone()]);
        let vcpu = provider
            .inventories
            .iter()
            .find(|inventory| inventory.resource_class == "VCPU")
            .ok_or(StoreError::PlacementProviderNotFound)?;
        assert_eq!(vcpu.total, 8);
        assert_eq!(vcpu.reserved, 1);
        assert_eq!(vcpu.used, 2);
        assert_eq!(reopened.get_intent("intent-survivor").await?, Some(intent));
        fs::remove_file(&path)?;
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_placement_commits_never_double_allocate() -> Result<(), Box<dyn Error>> {
        // Regression guard for the over-allocation invariant: two allocators
        // racing with the same generation cannot both win. Placement writes
        // run under BEGIN IMMEDIATE (the deferred read-then-write upgrade
        // fails with SQLITE_BUSY_SNAPSHOT even with a busy_timeout, see
        // issue #487 in this file), so the write lock is taken up front and
        // the losing commit deterministically observes the winner's commit:
        // the idempotent Ok(existing) for a same-id race or
        // PlacementStaleGeneration for a distinct-id race. A surfaced
        // StoreError::Database is a hard test failure.
        let path = PathBuf::from(format!(
            "/tmp/o3k-store-placement-concurrent-{}.sqlite",
            Uuid::now_v7()
        ));
        let store_a = testkit::open_file(&path).await?;
        let store_b = testkit::open_file(&path).await?;
        let inventories = vec![PlacementInventoryRecord {
            resource_class: "VCPU".to_owned(),
            total: 64,
            reserved: 0,
            allocation_ratio: 1.0,
            used: 0,
        }];
        store_a.register_provider("node-1", &inventories).await?;

        let allocation = PlacementAllocationRecord {
            id: "alloc-race".to_owned(),
            provider_id: "node-1".to_owned(),
            consumer_id: "consumer-race".to_owned(),
            resources: vec![PlacementResourceRecord {
                resource_class: "VCPU".to_owned(),
                amount: 2,
            }],
        };
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let mut handles = Vec::new();
        for store in [store_a.clone(), store_b.clone()] {
            let barrier = barrier.clone();
            let allocation = allocation.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                store.commit_allocation("node-1", 1, &allocation).await
            }));
        }
        barrier.wait().await;
        let mut first_round: Vec<Result<PlacementAllocationRecord, StoreError>> = Vec::new();
        for handle in handles {
            first_round.push(handle.await?);
        }
        // Classify the outcomes first, then assert the classification set
        // and the final database invariants. With BEGIN IMMEDIATE the loser
        // is the idempotent Ok(existing); PlacementStaleGeneration is also
        // acceptable, StoreError::Database never is.
        let mut winners = 0;
        for outcome in &first_round {
            match outcome {
                Ok(committed) => {
                    assert_eq!(committed, &allocation);
                    winners += 1;
                }
                Err(StoreError::PlacementStaleGeneration) => {}
                Err(StoreError::Database(_)) => {
                    return Err(Box::<dyn Error>::from(StoreError::Corrupt(
                        "same-id race surfaced StoreError::Database".to_owned(),
                    )));
                }
                Err(error) => return Err(error.to_string().into()),
            }
        }
        assert!(winners >= 1);
        let provider = store_a
            .get_provider("node-1")
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)?;
        assert_eq!(provider.generation, 2);
        assert_eq!(provider.allocations.len(), 1);
        let vcpu = provider
            .inventories
            .iter()
            .find(|inventory| inventory.resource_class == "VCPU")
            .ok_or(StoreError::PlacementProviderNotFound)?;
        assert_eq!(vcpu.used, 2);

        // Distinct allocation ids with the same expected generation: exactly
        // one commit wins; the loser deterministically reports
        // PlacementStaleGeneration (never StoreError::Database) and retries
        // with the current generation, after which both allocations exist
        // with usage equal to the sum.
        let first = PlacementAllocationRecord {
            id: "alloc-a".to_owned(),
            provider_id: "node-1".to_owned(),
            consumer_id: "consumer-a".to_owned(),
            resources: vec![PlacementResourceRecord {
                resource_class: "VCPU".to_owned(),
                amount: 1,
            }],
        };
        let second = PlacementAllocationRecord {
            id: "alloc-b".to_owned(),
            provider_id: "node-1".to_owned(),
            consumer_id: "consumer-b".to_owned(),
            resources: vec![PlacementResourceRecord {
                resource_class: "VCPU".to_owned(),
                amount: 3,
            }],
        };
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let mut handles = Vec::new();
        for (store, allocation) in [
            (store_a.clone(), first.clone()),
            (store_b.clone(), second.clone()),
        ] {
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                (
                    store.commit_allocation("node-1", 2, &allocation).await,
                    allocation,
                )
            }));
        }
        barrier.wait().await;
        let mut winners = 0;
        let mut loser = None;
        for handle in handles {
            let (outcome, allocation) = handle.await?;
            match outcome {
                Ok(_) => winners += 1,
                Err(StoreError::PlacementStaleGeneration) => loser = Some(allocation),
                Err(StoreError::Database(_)) => {
                    return Err(Box::<dyn Error>::from(StoreError::Corrupt(
                        "distinct-id race surfaced StoreError::Database".to_owned(),
                    )));
                }
                Err(error) => return Err(error.to_string().into()),
            }
        }
        assert_eq!(winners, 1);
        let loser = loser.ok_or_else(|| {
            Box::<dyn Error>::from(StoreError::Corrupt("expected one loser".to_owned()))
        })?;
        store_a.commit_allocation("node-1", 3, &loser).await?;
        let provider = store_a
            .get_provider("node-1")
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)?;
        assert_eq!(provider.generation, 4);
        assert_eq!(provider.allocations.len(), 3);
        let vcpu = provider
            .inventories
            .iter()
            .find(|inventory| inventory.resource_class == "VCPU")
            .ok_or(StoreError::PlacementProviderNotFound)?;
        assert_eq!(vcpu.used, 6);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn create_intent_guard_fails_closed_and_rolls_back_atomically()
    -> Result<(), Box<dyn Error>> {
        // ASR-018: the consumer intent must not outlive its placement
        // allocation. When the referenced allocation is missing (startup
        // orphan reconciliation deleted it while this create was between
        // allocation commit and intent persistence), the insert must fail
        // closed and roll back both rows atomically.
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let resource = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "compute_instance".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: "{}".to_owned(),
            observed_state: "REQUESTED".to_owned(),
            provider_id: None,
        };
        let operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id: resource.id,
            kind: "create".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        assert!(matches!(
            store
                .insert_resource_and_operation(&resource, &operation, Some("allocation-missing"))
                .await,
            Err(StoreError::PlacementAllocationNotFound)
        ));
        assert!(
            matches!(
                store.get_resource(resource.id).await,
                Err(StoreError::ResourceNotFound)
            ),
            "the resource insert must roll back with the guard failure"
        );
        assert!(
            matches!(
                store.get_operation(operation.id).await,
                Err(StoreError::OperationNotFound)
            ),
            "the operation insert must roll back with the guard failure"
        );
        Ok(())
    }

    #[tokio::test]
    async fn create_intent_guard_respects_resource_already_exists_precedence()
    -> Result<(), Box<dyn Error>> {
        // The idempotent retry path depends on ResourceAlreadyExists winning
        // over the allocation guard: a retried create whose resource is
        // already durable must re-enter the ownership/convergence path, never
        // the guard failure, even when its allocation reference is stale.
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let resource = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "compute_instance".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: "{}".to_owned(),
            observed_state: "REQUESTED".to_owned(),
            provider_id: None,
        };
        let operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id: resource.id,
            kind: "create".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        store
            .insert_resource_and_operation(&resource, &operation, None)
            .await?;
        assert!(matches!(
            store
                .insert_resource_and_operation(&resource, &operation, Some("allocation-missing"))
                .await,
            Err(StoreError::ResourceAlreadyExists)
        ));
        // The durable rows are untouched.
        assert_eq!(
            store.get_resource(resource.id).await?.observed_state,
            "REQUESTED"
        );
        assert_eq!(
            store.get_operation(operation.id).await?.state,
            OperationState::Pending
        );
        Ok(())
    }

    /// One-line TestLab recreate contract (issue #613 blocker B): reviving a
    /// tombstoned row must persist the fresh intent and the fresh lifecycle
    /// operation atomically, bump the generation, and reject a concurrent
    /// writer through the generation fence without side effects.
    #[tokio::test]
    async fn revive_resource_and_operation_persists_atomically_and_fences_generation()
    -> Result<(), Box<dyn Error>> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let id = Uuid::now_v7();
        let tombstone = ResourceRecord {
            id,
            kind: "compute_instance".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 7,
            observed_generation: 5,
            desired_state: r#"{"name":"old"}"#.to_owned(),
            observed_state: "DELETED".to_owned(),
            provider_id: None,
        };
        store.insert_resource(&tombstone).await?;
        let operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id: id,
            kind: "create".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        let revived = store
            .revive_resource_and_operation(
                id,
                7,
                r#"{"name":"fresh"}"#,
                "REQUESTED",
                5,
                None,
                &operation,
                None,
            )
            .await?;
        assert_eq!(revived.generation, 8, "the revive bumps the generation");
        assert_eq!(revived.observed_state, "REQUESTED");
        assert_eq!(
            revived.observed_generation, 5,
            "the tombstone fence is preserved"
        );
        assert_eq!(
            store.get_operation(operation.id).await?.state,
            OperationState::Pending,
            "the fresh lifecycle operation must be durable"
        );
        // A concurrent writer that already advanced the row fails the fence
        // and must not persist the competing operation row.
        let competing = OperationRecord {
            id: Uuid::now_v7(),
            resource_id: id,
            kind: "create".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        assert!(matches!(
            store
                .revive_resource_and_operation(
                    id,
                    7,
                    r#"{"name":"competing"}"#,
                    "REQUESTED",
                    5,
                    None,
                    &competing,
                    None,
                )
                .await,
            Err(StoreError::StaleGeneration)
        ));
        assert!(matches!(
            store.get_operation(competing.id).await,
            Err(StoreError::OperationNotFound)
        ));
        assert_eq!(
            store.get_resource(id).await?.desired_state,
            r#"{"name":"fresh"}"#,
            "the first writer's intent must be preserved"
        );
        Ok(())
    }

    /// The revive carries the same ASR-018 placement fence as the fresh
    /// create: a revived intent whose allocation was reconciled away must
    /// fail closed and roll back the row update and the operation insert.
    #[tokio::test]
    async fn revive_resource_and_operation_enforces_the_placement_fence()
    -> Result<(), Box<dyn Error>> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let id = Uuid::now_v7();
        store
            .insert_resource(&ResourceRecord {
                id,
                kind: "compute_instance".to_owned(),
                project_id: "project-a".to_owned(),
                generation: 3,
                observed_generation: 3,
                desired_state: r#"{"name":"old"}"#.to_owned(),
                observed_state: "DELETED".to_owned(),
                provider_id: None,
            })
            .await?;
        let operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id: id,
            kind: "create".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        assert!(matches!(
            store
                .revive_resource_and_operation(
                    id,
                    3,
                    r#"{"name":"fresh"}"#,
                    "REQUESTED",
                    3,
                    None,
                    &operation,
                    Some("allocation-missing"),
                )
                .await,
            Err(StoreError::PlacementAllocationNotFound)
        ));
        assert_eq!(
            store.get_resource(id).await?.observed_state,
            "DELETED",
            "the tombstone must be preserved when the fence fails"
        );
        assert!(matches!(
            store.get_operation(operation.id).await,
            Err(StoreError::OperationNotFound)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn placement_tables_fault_isolates_other_repositories() -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-store-placement-fault-{}.sqlite",
            Uuid::now_v7()
        ));
        let store = testkit::open_file(&path).await?;
        let inventories = vec![PlacementInventoryRecord {
            resource_class: "VCPU".to_owned(),
            total: 8,
            reserved: 0,
            allocation_ratio: 1.0,
            used: 0,
        }];
        store.register_provider("node-1", &inventories).await?;
        let allocation = PlacementAllocationRecord {
            id: "alloc-fault".to_owned(),
            provider_id: "node-1".to_owned(),
            consumer_id: "consumer-fault".to_owned(),
            resources: vec![PlacementResourceRecord {
                resource_class: "VCPU".to_owned(),
                amount: 2,
            }],
        };
        sqlx::query("DROP TABLE placement_allocations")
            .execute(&store.pool)
            .await?;
        assert!(matches!(
            store.commit_allocation("node-1", 1, &allocation).await,
            Err(StoreError::Database(_))
        ));
        let network = NetworkRecord {
            id: Uuid::now_v7(),
            name: "unaffected".to_owned(),
            project_id: "project-a".to_owned(),
            status: "ACTIVE".to_owned(),
        };
        store.insert_network(&network).await?;
        assert_eq!(
            store.get_network("project-a", &network.id).await?,
            Some(network)
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn transaction_rolls_back_when_operation_insert_fails() -> Result<(), StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let anchor = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "server".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: "requested".to_owned(),
            observed_state: "unknown".to_owned(),
            provider_id: None,
        };
        store.insert_resource(&anchor).await?;
        let resource = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "server".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: "requested".to_owned(),
            observed_state: "unknown".to_owned(),
            provider_id: None,
        };
        let operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id: anchor.id,
            kind: "test".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        // The canonical operation migration deliberately removes the generic
        // resource foreign key.  Force the operation insert to fail through a
        // real uniqueness violation so this test continues to verify the
        // transaction rollback contract.
        store.insert_operation(&operation).await?;
        assert!(
            store
                .insert_resource_and_operation(&resource, &operation, None)
                .await
                .is_err()
        );
        assert!(matches!(
            store.get_resource(resource.id).await,
            Err(StoreError::ResourceNotFound)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_resource_is_rejected() -> Result<(), StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let resource = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "image".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: "requested".to_owned(),
            observed_state: "unknown".to_owned(),
            provider_id: None,
        };
        store.insert_resource(&resource).await?;
        assert!(matches!(
            store.insert_resource(&resource).await,
            Err(StoreError::ResourceAlreadyExists)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn image_overlay_ownership_is_fenced_restart_safe_and_reference_counted()
    -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-image-overlay-ownership-{}.sqlite",
            std::process::id()
        ));
        let resource = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "server".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: "requested".to_owned(),
            observed_state: "unknown".to_owned(),
            provider_id: None,
        };
        let operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id: resource.id,
            kind: "create".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        let identity = ImageOverlayIdentity {
            resource_id: resource.id,
            operation_id: operation.id,
            command_id: "command-image-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            base_sha256: "a".repeat(64),
            base_format: "qcow2".to_owned(),
            overlay_format: "qcow2".to_owned(),
        };
        let record = ImageOverlayOwnershipRecord {
            overlay_id: "overlay-1".to_owned(),
            identity: identity.clone(),
            state: ImageOverlayState::Pending,
            created_at: String::new(),
            updated_at: String::new(),
        };
        {
            let store = SqliteStore::connect_file(&path).await?;
            store
                .insert_resource_and_operation(&resource, &operation, None)
                .await?;
            assert_eq!(
                store.insert_image_overlay(&record).await?,
                store.get_image_overlay("overlay-1").await?
            );
            assert_eq!(
                store.insert_image_overlay(&record).await?.overlay_id,
                "overlay-1"
            );
            assert_eq!(
                store
                    .count_image_overlay_references(&"a".repeat(64), "qcow2")
                    .await?,
                1
            );
            store
                .update_image_overlay(
                    "overlay-1",
                    &identity,
                    ImageOverlayUpdate {
                        state: ImageOverlayState::Materializing,
                    },
                )
                .await?;
            store
                .update_image_overlay(
                    "overlay-1",
                    &identity,
                    ImageOverlayUpdate {
                        state: ImageOverlayState::Ready,
                    },
                )
                .await?;
            let mut stale = identity.clone();
            stale.agent_epoch = "epoch-2".to_owned();
            assert!(matches!(
                store.delete_image_overlay("overlay-1", &stale).await,
                Err(StoreError::ImageOverlayEpochConflict)
            ));
            assert_eq!(
                store
                    .delete_image_overlay("overlay-1", &identity)
                    .await?
                    .state,
                ImageOverlayState::Deleted
            );
            assert_eq!(
                store
                    .count_image_overlay_references(&"a".repeat(64), "qcow2")
                    .await?,
                0
            );
        }
        let reopened = SqliteStore::connect_file(&path).await?;
        assert_eq!(
            reopened.get_image_overlay("overlay-1").await?.state,
            ImageOverlayState::Deleted
        );
        fs::remove_file(path)?;
        Ok(())
    }

    #[tokio::test]
    async fn agent_command_identity_is_idempotent_and_survives_restart()
    -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-agent-commands-{}.sqlite",
            std::process::id()
        ));
        let resource = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "server".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: "requested".to_owned(),
            observed_state: "unknown".to_owned(),
            provider_id: None,
        };
        let operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id: resource.id,
            kind: "create".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        let command = AgentCommandRecord {
            command_id: "command-1".to_owned(),
            idempotency_key: "create-1".to_owned(),
            operation_id: operation.id,
            resource_id: resource.id,
            agent_id: "agent-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            payload_fingerprint_sha256: "a".repeat(64),
            payload: b"command-payload".to_vec(),
            state: AgentCommandState::Pending,
            accepted_sequence: 0,
            last_sequence: 0,
            provider_operation_id: None,
            provider_resource_id: None,
        };
        {
            let store = SqliteStore::connect_file(&path).await?;
            store
                .insert_resource_and_operation(&resource, &operation, None)
                .await?;
            assert_eq!(store.insert_agent_command(&command).await?, command);
            assert_eq!(store.insert_agent_command(&command).await?, command);
            let updated = store
                .update_agent_command(
                    &command.command_id,
                    AgentCommandState::Accepted,
                    1,
                    1,
                    Some("provider-op-1"),
                    Some("domain-1"),
                )
                .await?;
            assert_eq!(updated.accepted_sequence, 1);
            assert_eq!(
                updated.provider_operation_id.as_deref(),
                Some("provider-op-1")
            );
            assert_eq!(updated.provider_resource_id.as_deref(), Some("domain-1"));
            let concurrent_command = AgentCommandRecord {
                command_id: "command-concurrent".to_owned(),
                idempotency_key: "create-concurrent".to_owned(),
                ..command.clone()
            };
            store.insert_agent_command(&concurrent_command).await?;
            let left_store = store.clone();
            let right_store = store.clone();
            let left = tokio::spawn(async move {
                left_store
                    .update_agent_command(
                        "command-concurrent",
                        AgentCommandState::Accepted,
                        1,
                        1,
                        None,
                        None,
                    )
                    .await
            });
            let right = tokio::spawn(async move {
                right_store
                    .update_agent_command(
                        "command-concurrent",
                        AgentCommandState::Accepted,
                        1,
                        1,
                        None,
                        None,
                    )
                    .await
            });
            assert_eq!(left.await??.state, AgentCommandState::Accepted);
            assert_eq!(right.await??.state, AgentCommandState::Accepted);
            assert_eq!(store.increment_operation_retry(operation.id).await?, 1);
            assert_eq!(store.increment_operation_retry(operation.id).await?, 2);
            assert_eq!(
                store
                    .update_agent_command(
                        &command.command_id,
                        AgentCommandState::Pending,
                        0,
                        0,
                        None,
                        None,
                    )
                    .await?
                    .state,
                AgentCommandState::Accepted
            );
            assert!(matches!(
                store
                    .update_agent_command(
                        &command.command_id,
                        AgentCommandState::Failed,
                        1,
                        1,
                        Some("provider-op-1"),
                        Some("domain-1"),
                    )
                    .await,
                Err(StoreError::Corrupt(_))
            ));
            let unknown = store
                .update_agent_command(
                    &command.command_id,
                    AgentCommandState::UnknownOutcome,
                    1,
                    2,
                    Some("provider-op-1"),
                    Some("domain-1"),
                )
                .await?;
            assert_eq!(unknown.state, AgentCommandState::UnknownOutcome);
            assert!(matches!(
                store
                    .update_agent_command(
                        &command.command_id,
                        AgentCommandState::Running,
                        1,
                        3,
                        Some("provider-op-1"),
                        Some("domain-1"),
                    )
                    .await,
                Err(StoreError::Corrupt(_))
            ));
            let terminal = store
                .update_agent_command(
                    &command.command_id,
                    AgentCommandState::Succeeded,
                    1,
                    3,
                    Some("provider-op-1"),
                    Some("domain-1"),
                )
                .await?;
            assert_eq!(terminal.state, AgentCommandState::Succeeded);
            assert!(matches!(
                store
                    .update_agent_command(
                        &command.command_id,
                        AgentCommandState::Running,
                        1,
                        4,
                        Some("provider-op-1"),
                        Some("domain-1"),
                    )
                    .await,
                Err(StoreError::Corrupt(_))
            ));
            assert!(matches!(
                store
                    .update_agent_command(
                        &command.command_id,
                        AgentCommandState::Succeeded,
                        1,
                        5,
                        Some("provider-op-1"),
                        Some("domain-2"),
                    )
                    .await,
                Err(StoreError::Corrupt(_))
            ));
        }
        let reopened = SqliteStore::connect_file(&path).await?;
        assert_eq!(
            reopened.get_agent_command(&command.command_id).await?.state,
            AgentCommandState::Succeeded
        );
        assert_eq!(reopened.increment_operation_retry(operation.id).await?, 3);
        fs::remove_file(path)?;
        Ok(())
    }

    #[tokio::test]
    async fn operation_terminal_state_rejects_stale_in_flight_projection()
    -> Result<(), Box<dyn Error>> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id: Uuid::now_v7(),
            kind: "lifecycle:reboot".to_owned(),
            state: OperationState::Running,
            provider_operation_id: Some("provider-op-1".to_owned()),
            error_category: None,
            error_message: None,
        };
        store
            .insert_resource(&ResourceRecord {
                id: operation.resource_id,
                kind: "server".to_owned(),
                project_id: "project-a".to_owned(),
                generation: 1,
                observed_generation: 0,
                desired_state: "requested".to_owned(),
                observed_state: "unknown".to_owned(),
                provider_id: None,
            })
            .await?;
        store.insert_operation(&operation).await?;

        store
            .update_operation(
                operation.id,
                OperationState::Succeeded,
                Some("provider-op-1"),
                None,
                None,
            )
            .await?;
        let stale = store
            .update_operation(
                operation.id,
                OperationState::Running,
                Some("provider-op-1"),
                None,
                None,
            )
            .await?;
        assert_eq!(stale.state, OperationState::Succeeded);
        Ok(())
    }

    #[tokio::test]
    async fn operation_terminal_conflicts_and_provider_identity_drift_fail_closed()
    -> Result<(), Box<dyn Error>> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let operation = OperationRecord {
            id: Uuid::now_v7(),
            resource_id: Uuid::now_v7(),
            kind: "lifecycle:reboot".to_owned(),
            state: OperationState::Running,
            provider_operation_id: Some("provider-op-1".to_owned()),
            error_category: None,
            error_message: None,
        };
        store
            .insert_resource(&ResourceRecord {
                id: operation.resource_id,
                kind: "server".to_owned(),
                project_id: "project-a".to_owned(),
                generation: 1,
                observed_generation: 0,
                desired_state: "requested".to_owned(),
                observed_state: "unknown".to_owned(),
                provider_id: None,
            })
            .await?;
        store.insert_operation(&operation).await?;
        store
            .update_operation(
                operation.id,
                OperationState::Failed,
                Some("provider-op-1"),
                Some("provider_error"),
                Some("failed"),
            )
            .await?;

        let terminal_conflict = store
            .update_operation(
                operation.id,
                OperationState::Succeeded,
                Some("provider-op-1"),
                None,
                None,
            )
            .await;
        assert!(matches!(terminal_conflict, Err(StoreError::Corrupt(_))));

        let identity_conflict = store
            .update_operation(
                operation.id,
                OperationState::Failed,
                Some("provider-op-2"),
                None,
                None,
            )
            .await;
        assert!(matches!(identity_conflict, Err(StoreError::Corrupt(_))));

        let final_operation = store.get_operation(operation.id).await?;
        assert_eq!(final_operation.state, OperationState::Failed);
        assert_eq!(
            final_operation.provider_operation_id.as_deref(),
            Some("provider-op-1")
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn independent_store_connections_preserve_terminal_operation_under_race()
    -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-store-operation-race-{}.sqlite",
            Uuid::now_v7()
        ));
        let first = std::sync::Arc::new(SqliteStore::connect_file(&path).await?);
        let second = std::sync::Arc::new(SqliteStore::connect_file(&path).await?);

        for _ in 0..25 {
            let operation = OperationRecord {
                id: Uuid::now_v7(),
                resource_id: Uuid::now_v7(),
                kind: "lifecycle:reboot".to_owned(),
                state: OperationState::Running,
                provider_operation_id: Some("provider-op-race".to_owned()),
                error_category: None,
                error_message: None,
            };
            first
                .insert_resource(&ResourceRecord {
                    id: operation.resource_id,
                    kind: "server".to_owned(),
                    project_id: "project-race".to_owned(),
                    generation: 1,
                    observed_generation: 0,
                    desired_state: "requested".to_owned(),
                    observed_state: "unknown".to_owned(),
                    provider_id: None,
                })
                .await?;
            first.insert_operation(&operation).await?;

            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
            let terminal_store = first.clone();
            let stale_store = second.clone();
            let terminal_barrier = barrier.clone();
            let stale_barrier = barrier;
            let terminal_operation = operation.clone();
            let stale_operation = operation.clone();
            let terminal = tokio::spawn(async move {
                terminal_barrier.wait().await;
                terminal_store
                    .update_operation(
                        terminal_operation.id,
                        OperationState::Succeeded,
                        Some("provider-op-race"),
                        None,
                        None,
                    )
                    .await
            });
            let stale = tokio::spawn(async move {
                stale_barrier.wait().await;
                stale_store
                    .update_operation(
                        stale_operation.id,
                        OperationState::Running,
                        Some("provider-op-race"),
                        None,
                        None,
                    )
                    .await
            });
            terminal.await??;
            stale.await??;

            let final_operation = first.get_operation(operation.id).await?;
            assert_eq!(final_operation.state, OperationState::Succeeded);
        }

        drop(first);
        drop(second);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn file_database_survives_restart() -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!("/tmp/o3k-store-{}.sqlite", std::process::id()));
        let resource = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "server".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: "requested".to_owned(),
            observed_state: "unknown".to_owned(),
            provider_id: Some("provider-1".to_owned()),
        };
        {
            let store = SqliteStore::connect_file(&path).await?;
            store.insert_resource(&resource).await?;
        }
        let reopened = SqliteStore::connect_file(&path).await?;
        assert_eq!(reopened.get_resource(resource.id).await?, resource);
        fs::remove_file(path)?;
        Ok(())
    }

    #[tokio::test]
    async fn network_address_allocation_survives_restart() -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-network-address-restart-{}.sqlite",
            Uuid::now_v7()
        ));
        let realm_id = Uuid::now_v7();
        let endpoint_id = Uuid::now_v7();
        let operation_id = format!("network-address-restart-{}", Uuid::now_v7());
        let allocation = {
            let store = SqliteStore::connect_file(&path).await?;
            store
                .allocate_network_address(
                    &realm_id,
                    "project-a",
                    &endpoint_id,
                    &operation_id,
                    "203.0.113.0/30",
                )
                .await?
        };
        let reopened = SqliteStore::connect_file(&path).await?;
        let replay = reopened
            .allocate_network_address(
                &realm_id,
                "project-a",
                &endpoint_id,
                &operation_id,
                "203.0.113.0/30",
            )
            .await?;
        assert_eq!(replay, allocation);
        reopened
            .release_network_address("project-a", &endpoint_id)
            .await?;
        drop(reopened);
        fs::remove_file(&path)?;
        Ok(())
    }

    #[tokio::test]
    async fn network_address_allocation_rejects_unsafe_prefix_and_empty_identity()
    -> Result<(), Box<dyn Error>> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let realm_id = Uuid::now_v7();
        let endpoint_id = Uuid::now_v7();
        let prefix_error = store
            .allocate_network_address(
                &realm_id,
                "project-a",
                &endpoint_id,
                "operation-a",
                "0.0.0.0/0",
            )
            .await;
        assert!(matches!(prefix_error, Err(StoreError::Corrupt(_))));

        let identity_error = store
            .allocate_network_address(
                &realm_id,
                " ",
                &endpoint_id,
                "operation-a",
                "198.51.100.0/30",
            )
            .await;
        assert!(matches!(identity_error, Err(StoreError::Corrupt(_))));
        Ok(())
    }

    #[tokio::test]
    async fn corrupt_database_is_rejected_without_repair() -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-store-corrupt-{}.sqlite",
            std::process::id()
        ));
        fs::write(&path, b"not a sqlite database")?;
        let result = SqliteStore::connect_file(&path).await;
        assert!(result.is_err());
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn public_key_validation_is_canonical_and_rejects_mismatches() -> Result<(), StoreError> {
        let blob = [
            0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0,
            32,
        ]
        .into_iter()
        .chain([7_u8; 32])
        .collect::<Vec<_>>();
        let encoded = BASE64.encode(&blob);
        let (key_type, fingerprint, canonical) =
            validate_public_key(&format!("ssh-ed25519 {encoded} comment"))?;
        assert_eq!(key_type, "ssh-ed25519");
        assert_eq!(fingerprint.len(), 47);
        assert_eq!(canonical, format!("ssh-ed25519 {encoded}"));
        assert!(validate_public_key(&format!("ssh-ed25519 {encoded}\n")).is_ok());
        assert!(validate_public_key(&format!("ssh-rsa {encoded}")).is_err());
        assert!(validate_public_key("ssh-ed25519 !!!").is_err());
        assert!(validate_public_key("ssh-dss AAAA").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn keypairs_are_scoped_unique_and_survive_restart() -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!("/tmp/o3k-keypairs-{}.sqlite", std::process::id()));
        let blob = [
            0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0,
            32,
        ]
        .into_iter()
        .chain([9_u8; 32])
        .collect::<Vec<_>>();
        let public_key = format!("ssh-ed25519 {}", BASE64.encode(blob));
        let (key_type, fingerprint, canonical) = validate_public_key(&public_key)?;
        let record = KeypairRecord {
            id: Uuid::now_v7(),
            user_id: "user-a".to_owned(),
            project_id: "project-a".to_owned(),
            name: "test-key".to_owned(),
            key_type,
            public_key: canonical,
            fingerprint,
            created_at: "1".to_owned(),
        };
        {
            let store = SqliteStore::connect_file(&path).await?;
            store.insert_keypair(&record).await?;
            assert!(matches!(
                store.insert_keypair(&record).await,
                Err(StoreError::KeypairAlreadyExists)
            ));
            assert!(
                store
                    .get_keypair("user-b", "project-a", "test-key")
                    .await
                    .is_err()
            );
            assert_eq!(store.list_keypairs("user-a", "project-a").await?.len(), 1);
        }
        let reopened = SqliteStore::connect_file(&path).await?;
        assert_eq!(
            reopened
                .get_keypair("user-a", "project-a", "test-key")
                .await?,
            record
        );
        reopened
            .delete_keypair("user-a", "project-a", "test-key")
            .await?;
        assert!(matches!(
            reopened
                .delete_keypair("user-a", "project-a", "test-key")
                .await,
            Err(StoreError::KeypairNotFound)
        ));
        fs::remove_file(path)?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn keypair_delete_waits_out_a_concurrent_writer() -> Result<(), Box<dyn Error>> {
        // A deferred read-then-write transaction can read through a concurrent
        // WAL writer and then fail with SQLITE_BUSY_SNAPSHOT when it promotes
        // the read transaction for DELETE. The deletion must acquire its write
        // lock before reading so the configured busy timeout can take effect.
        let path = PathBuf::from(format!(
            "/tmp/o3k-store-keypair-delete-busy-{}.sqlite",
            Uuid::now_v7()
        ));
        let blob = [
            0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0,
            32,
        ]
        .into_iter()
        .chain([13_u8; 32])
        .collect::<Vec<_>>();
        let public_key = format!("ssh-ed25519 {}", BASE64.encode(blob));
        let (key_type, fingerprint, canonical) = validate_public_key(&public_key)?;
        let record = KeypairRecord {
            id: Uuid::now_v7(),
            user_id: "user-busy".to_owned(),
            project_id: "project-busy".to_owned(),
            name: "key-busy".to_owned(),
            key_type,
            public_key: canonical,
            fingerprint,
            created_at: "1".to_owned(),
        };
        let store = SqliteStore::connect_file(&path).await?;
        store.insert_keypair(&record).await?;

        let lock_url = format!("sqlite://{}", path.display());
        let (lock_acquired, lock_acquired_rx) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(async move {
            use sqlx::Connection as _;

            let mut connection = sqlx::sqlite::SqliteConnection::connect(&lock_url).await?;
            sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut connection)
                .await?;
            let _ = lock_acquired.send(());
            tokio::time::sleep(Duration::from_millis(300)).await;
            sqlx::query("COMMIT").execute(&mut connection).await?;
            Ok::<(), sqlx::Error>(())
        });
        lock_acquired_rx.await?;

        store
            .delete_keypair(&record.user_id, &record.project_id, &record.name)
            .await?;
        holder.await??;
        assert!(matches!(
            store
                .get_keypair(&record.user_id, &record.project_id, &record.name)
                .await,
            Err(StoreError::KeypairNotFound)
        ));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn wal_mode_and_foreign_keys_enabled_for_persistent_database()
    -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!("/tmp/o3k-store-wal-{}.sqlite", Uuid::now_v7()));
        let store = SqliteStore::connect_file(&path).await?;
        assert_eq!(store.journal_mode().await?, "wal");

        for suffix in ["", "-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
            if sidecar.exists() {
                #[cfg(unix)]
                assert_eq!(
                    fs::symlink_metadata(&sidecar)?.permissions().mode() & 0o777,
                    0o600,
                    "SQLite sensitive file must not be world-readable: {}",
                    sidecar.display()
                );
            }
        }

        let health = store.database_health().await?;
        assert_eq!(health.status, "ok");
        assert_eq!(health.journal_mode, "wal");
        assert!(health.foreign_keys);
        assert_eq!(health.integrity_check, "ok");
        assert_eq!(health.wal_checkpoint_status.as_deref(), Some("active"));

        store.checkpoint(WalCheckpointMode::Passive).await?;
        store.checkpoint(WalCheckpointMode::Truncate).await?;

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn in_memory_database_uses_memory_journal_mode() -> Result<(), Box<dyn Error>> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        assert_eq!(store.journal_mode().await?, "memory");
        let health = store.database_health().await?;
        assert_eq!(health.journal_mode, "memory");
        assert!(health.wal_checkpoint_status.is_none());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn connect_file_restricts_only_created_parent_directories() -> Result<(), Box<dyn Error>>
    {
        use std::os::unix::fs::PermissionsExt;

        let parent =
            std::env::temp_dir().join(format!("o3k-store-parent-created-{}", Uuid::now_v7()));
        let path = parent.join("state.sqlite");
        let store = SqliteStore::connect_file(&path).await?;
        drop(store);
        assert_eq!(
            fs::symlink_metadata(&parent)?.permissions().mode() & 0o777,
            0o700,
            "a parent directory created by connect_file must be restricted to 0700"
        );
        // Restrict the parent back to a shared-system-like mode so the
        // second connect exercises the pre-existing-parent branch.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o1777))?;
        let reopened = SqliteStore::connect_file(&path).await?;
        drop(reopened);
        assert_eq!(
            fs::symlink_metadata(&parent)?.permissions().mode() & 0o1777,
            0o1777,
            "connect_file must not chmod a pre-existing parent directory"
        );
        assert_eq!(
            fs::symlink_metadata(&path)?.permissions().mode() & 0o777,
            0o600,
            "the database file must still be restricted to 0600"
        );
        fs::remove_dir_all(&parent)?;
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_writers_and_wal_lock_contention() -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-store-wal-concurrent-{}.sqlite",
            Uuid::now_v7()
        ));
        let store = std::sync::Arc::new(SqliteStore::connect_file(&path).await?);
        let blob = [
            0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0,
            32,
        ]
        .into_iter()
        .chain([7_u8; 32])
        .collect::<Vec<_>>();
        let encoded = BASE64.encode(&blob);

        let mut handles = Vec::new();

        for i in 0..5 {
            let store = store.clone();
            let encoded = encoded.clone();
            let handle = tokio::spawn(async move {
                let (_, fingerprint, canonical) =
                    validate_public_key(&format!("ssh-ed25519 {encoded} user-{i}"))?;
                let keypair = KeypairRecord {
                    id: Uuid::now_v7(),
                    user_id: format!("user-{i}"),
                    project_id: "project-concurrent".to_owned(),
                    name: format!("key-{i}"),
                    key_type: "ssh-ed25519".to_owned(),
                    public_key: canonical,
                    fingerprint,
                    created_at: "2024-01-01T00:00:00Z".to_owned(),
                };
                store.insert_keypair(&keypair).await
            });
            handles.push(handle);
        }

        for handle in handles {
            let res = handle.await?;
            assert!(res.is_ok());
        }

        let health = store.database_health().await?;
        assert_eq!(health.status, "ok");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn observation_update_waits_out_a_concurrent_writer() -> Result<(), Box<dyn Error>> {
        // Regression test for issue #487 (run local-1785957445): a deferred
        // read-then-write transaction failed immediately with SQLITE_BUSY
        // when a concurrent connection held the write lock, and the dropped
        // observation left the resource stuck in `requested`. BEGIN IMMEDIATE
        // honours the configured busy_timeout instead of failing immediately.
        let path = PathBuf::from(format!(
            "/tmp/o3k-store-observation-busy-{}.sqlite",
            Uuid::now_v7()
        ));
        let store = SqliteStore::connect_file(&path).await?;
        let resource = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "server".to_owned(),
            project_id: "project-busy".to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: "requested".to_owned(),
            observed_state: "unknown".to_owned(),
            provider_id: Some("provider-1".to_owned()),
        };
        store.insert_resource(&resource).await?;

        // Hold the WAL write lock on a second connection long enough that an
        // immediate-failure implementation would return SQLITE_BUSY first.
        let lock_url = format!("sqlite://{}", path.display());
        let holder = tokio::spawn(async move {
            use sqlx::Connection as _;
            let mut connection = sqlx::sqlite::SqliteConnection::connect(&lock_url).await?;
            sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut connection)
                .await?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            sqlx::query("COMMIT").execute(&mut connection).await?;
            Ok::<(), sqlx::Error>(())
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let update = ObservationUpdate {
            expected_generation: 1,
            desired_state: "active",
            observed_state: "running",
            observed_generation: 1,
            provider_id: Some("provider-1"),
            agent_epoch: "epoch-1",
            observation_sequence: 1,
        };
        let updated = store
            .update_resource_from_observation(resource.id, &update)
            .await?;
        assert_eq!(updated.observed_state, "running");
        assert_eq!(updated.generation, 2);
        holder.await??;

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn backup_and_restore_produces_consistent_database() -> Result<(), Box<dyn Error>> {
        let src_path = PathBuf::from(format!(
            "/tmp/o3k-store-backup-src-{}.sqlite",
            Uuid::now_v7()
        ));
        let backup_path = PathBuf::from(format!(
            "/tmp/o3k-store-backup-dst-{}.sqlite",
            Uuid::now_v7()
        ));

        let store = SqliteStore::connect_file(&src_path).await?;
        let blob = [
            0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0,
            32,
        ]
        .into_iter()
        .chain([7_u8; 32])
        .collect::<Vec<_>>();
        let encoded = BASE64.encode(&blob);

        let (_, fingerprint, canonical) =
            validate_public_key(&format!("ssh-ed25519 {encoded} user-backup"))?;
        let keypair = KeypairRecord {
            id: Uuid::now_v7(),
            user_id: "user-backup".to_owned(),
            project_id: "project-backup".to_owned(),
            name: "key-backup".to_owned(),
            key_type: "ssh-ed25519".to_owned(),
            public_key: canonical,
            fingerprint,
            created_at: "2024-01-01T00:00:00Z".to_owned(),
        };
        store.insert_keypair(&keypair).await?;

        store.backup_to_file(&backup_path).await?;

        let restored_store = SqliteStore::connect_file(&backup_path).await?;
        let fetched = restored_store
            .get_keypair("user-backup", "project-backup", "key-backup")
            .await?;
        assert_eq!(fetched, keypair);

        let _ = fs::remove_file(&src_path);
        let _ = fs::remove_file(format!("{}-wal", src_path.display()));
        let _ = fs::remove_file(format!("{}-shm", src_path.display()));
        let _ = fs::remove_file(&backup_path);
        let _ = fs::remove_file(format!("{}-wal", backup_path.display()));
        let _ = fs::remove_file(format!("{}-shm", backup_path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn canonical_network_relations_support_zero_realms_and_realm_removal()
    -> Result<(), Box<dyn Error>> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let network = CanonicalNetworkRecord {
            id: Uuid::from_u128(0x100),
            project_id: "project-a".to_owned(),
            name: "network-a".to_owned(),
            admin_state_up: true,
            generation: 7,
            state: "active".to_owned(),
        };
        store.insert_canonical_network(&network).await?;
        assert!(
            store
                .list_canonical_realms("project-a", &network.id)
                .await?
                .is_empty()
        );

        let realm_a = CanonicalAddressRealmRecord {
            id: Uuid::from_u128(0x101),
            network_id: network.id,
            project_id: "project-a".to_owned(),
            prefix: "10.0.0.0/24".to_owned(),
            overlapping_prefixes: true,
            generation: 3,
            state: "active".to_owned(),
        };
        let realm_b = CanonicalAddressRealmRecord {
            id: Uuid::from_u128(0x102),
            ..realm_a.clone()
        };
        store.insert_canonical_realm(&realm_a).await?;
        store.insert_canonical_realm(&realm_b).await?;
        assert_eq!(
            store
                .list_canonical_realms("project-a", &network.id)
                .await?
                .len(),
            2
        );

        let endpoint = CanonicalEndpointRecord {
            id: Uuid::from_u128(0x103),
            realm_id: realm_a.id,
            project_id: "project-a".to_owned(),
            fixed_ip: "10.0.0.10".parse()?,
            mac: "02:00:00:00:00:10".to_owned(),
            generation: 1,
            state: "active".to_owned(),
        };
        store.insert_canonical_endpoint(&endpoint).await?;
        let binding = CanonicalRealmBindingRecord {
            fabric_domain_id: "fabric-a".to_owned(),
            realm_id: realm_a.id,
            provider_kind: "geneve".to_owned(),
            provider_segment_id: 42,
            binding_generation: 5,
            state: "active".to_owned(),
        };
        store.insert_canonical_realm_binding(&binding).await?;
        assert_eq!(
            store
                .get_canonical_realm_binding("fabric-a", &realm_a.id)
                .await?,
            Some(binding)
        );
        let duplicate = CanonicalEndpointRecord {
            id: Uuid::from_u128(0x104),
            mac: "02:00:00:00:00:11".to_owned(),
            ..endpoint.clone()
        };
        assert!(matches!(
            store.insert_canonical_endpoint(&duplicate).await,
            Err(StoreError::ResourceAlreadyExists)
        ));

        assert!(matches!(
            store.delete_canonical_realm("project-a", &realm_a.id).await,
            Err(StoreError::NetworkInUse)
        ));
        store
            .delete_canonical_realm("project-a", &realm_b.id)
            .await?;
        assert!(
            store
                .get_canonical_network("project-a", &network.id)
                .await?
                .is_some()
        );
        Ok(())
    }

    #[tokio::test]
    async fn canonical_backfill_preserves_legacy_ids_and_rejects_ownership_conflicts()
    -> Result<(), Box<dyn Error>> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let network_id = Uuid::from_u128(0x200);
        let realm_id = Uuid::from_u128(0x201);
        let endpoint_id = Uuid::from_u128(0x202);
        store
            .insert_network(&NetworkRecord {
                id: network_id,
                name: "legacy-network".to_owned(),
                project_id: "project-a".to_owned(),
                status: "ACTIVE".to_owned(),
            })
            .await?;
        store
            .insert_subnet(&SubnetRecord {
                id: realm_id,
                network_id,
                name: "legacy-subnet".to_owned(),
                project_id: "project-a".to_owned(),
                cidr: "10.1.0.0/24".to_owned(),
                gateway_ip: "10.1.0.1".parse()?,
                allocation_start: "10.1.0.2".parse()?,
                allocation_end: "10.1.0.254".parse()?,
                ip_version: 4,
                enable_dhcp: true,
            })
            .await?;
        store
            .insert_port(&PortRecord {
                id: endpoint_id,
                network_id,
                subnet_id: Some(realm_id),
                project_id: "project-a".to_owned(),
                name: "legacy-port".to_owned(),
                mac_address: "02:00:00:00:02:02".to_owned(),
                fixed_ip: "10.1.0.10".parse()?,
                status: "ACTIVE".to_owned(),
                binding_host: None,
                binding_state: None,
            })
            .await?;
        store.backfill_canonical_network_state().await?;
        let canonical_network = store
            .get_canonical_network("project-a", &network_id)
            .await?
            .ok_or(StoreError::Corrupt("canonical network missing".into()))?;
        assert_eq!(canonical_network.id, network_id);
        let canonical_realms = store
            .list_canonical_realms("project-a", &network_id)
            .await?;
        assert_eq!(
            canonical_realms
                .first()
                .ok_or(StoreError::Corrupt("canonical realm missing".into()))?
                .id,
            realm_id
        );
        let canonical_endpoints = store
            .list_canonical_endpoints("project-a", &realm_id)
            .await?;
        assert_eq!(
            canonical_endpoints
                .first()
                .ok_or(StoreError::Corrupt("canonical endpoint missing".into()))?
                .id,
            endpoint_id
        );
        let policy_id = Uuid::from_u128(0x205);
        store
            .insert_network_intent(&NetworkIntentRecord {
                id: network_id,
                project_id: "project-a".to_owned(),
                generation: 1,
                payload: serde_json::json!({
                    "id": network_id,
                    "project_id": "project-a",
                    "realm": {"id": realm_id},
                    "policies": [{
                        "id": policy_id,
                        "endpoint_id": endpoint_id,
                        "direction": "Ingress",
                        "protocol": "Tcp",
                        "ports": {"start": 443, "end": 443},
                        "source": {"network": "198.51.100.0", "prefix_len": 24},
                        "destination": null,
                        "action": "Deny"
                    }]
                })
                .to_string(),
                plan_fingerprint_sha256: None,
                status: "active".to_owned(),
            })
            .await?;
        store.backfill_canonical_network_state().await?;
        let policies = store
            .list_canonical_policies("project-a", &network_id)
            .await?;
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].id, policy_id);
        assert_eq!(policies[0].endpoint_id, endpoint_id);

        let invalid_network = Uuid::from_u128(0x206);
        store
            .insert_network_intent(&NetworkIntentRecord {
                id: invalid_network,
                project_id: "project-a".to_owned(),
                generation: 1,
                payload: serde_json::json!({
                    "id": invalid_network,
                    "project_id": "project-a",
                    "policies": [{
                        "id": Uuid::from_u128(0x207),
                        "endpoint_id": Uuid::from_u128(0x208),
                        "direction": "Ingress",
                        "protocol": "Tcp",
                        "ports": {"start": 443, "end": 443},
                        "source": null,
                        "destination": null,
                        "action": "Allow"
                    }]
                })
                .to_string(),
                plan_fingerprint_sha256: None,
                status: "active".to_owned(),
            })
            .await?;
        assert!(matches!(
            store.backfill_canonical_network_state().await,
            Err(StoreError::OwnershipConflict)
                | Err(StoreError::ResourceNotFound)
                | Err(StoreError::Corrupt(_))
        ));
        assert!(
            store
                .get_canonical_network("project-a", &invalid_network)
                .await?
                .is_none()
        );

        let conflict_network = Uuid::from_u128(0x203);
        store
            .insert_network(&NetworkRecord {
                id: conflict_network,
                name: "conflict".to_owned(),
                project_id: "project-a".to_owned(),
                status: "ACTIVE".to_owned(),
            })
            .await?;
        store
            .insert_subnet(&SubnetRecord {
                id: Uuid::from_u128(0x204),
                network_id: conflict_network,
                name: "foreign-subnet".to_owned(),
                project_id: "project-b".to_owned(),
                cidr: "10.2.0.0/24".to_owned(),
                gateway_ip: "10.2.0.1".parse()?,
                allocation_start: "10.2.0.2".parse()?,
                allocation_end: "10.2.0.254".parse()?,
                ip_version: 4,
                enable_dhcp: true,
            })
            .await?;
        assert!(matches!(
            store.backfill_canonical_network_state().await,
            Err(StoreError::OwnershipConflict)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn empty_database_path_returns_error() {
        let result = SqliteStore::connect_file(Path::new("")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn canonical_l3_gateway_is_detached_and_generation_fenced() -> Result<(), StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        let gateway = CanonicalL3GatewayRecord {
            id: Uuid::now_v7(),
            project_id: "project-a".into(),
            name: "edge".into(),
            external_realm_id: None,
            enable_snat: true,
            generation: 1,
            state: "active".into(),
        };
        store.insert_canonical_l3_gateway(&gateway).await?;
        assert_eq!(
            store.list_canonical_l3_gateways("project-a").await?,
            vec![gateway.clone()]
        );
        let updated = store
            .update_canonical_l3_gateway("project-a", &gateway.id, 1, "edge-2", None, false)
            .await?;
        assert_eq!(updated.generation, 2);
        assert!(matches!(
            store
                .update_canonical_l3_gateway("project-a", &gateway.id, 1, "stale", None, true)
                .await,
            Err(StoreError::StaleGeneration)
        ));
        let reopened = store
            .get_canonical_l3_gateway("project-a", &gateway.id)
            .await?
            .ok_or(StoreError::Corrupt("gateway disappeared".into()))?;
        assert_eq!(reopened.name, "edge-2");
        assert_eq!(reopened.generation, 2);
        Ok(())
    }

    #[tokio::test]
    async fn canonical_l3_gateway_attachments_are_project_scoped_and_restartable()
    -> Result<(), StoreError> {
        let path = std::env::temp_dir().join(format!("o3k-l3-gateway-{}.sqlite", Uuid::now_v7()));
        let store = SqliteStore::connect_file(&path).await?;
        let network = Uuid::now_v7();
        let realm = Uuid::now_v7();
        store
            .insert_canonical_network(&CanonicalNetworkRecord {
                id: network,
                project_id: "project-a".into(),
                name: "net".into(),
                admin_state_up: true,
                generation: 1,
                state: "active".into(),
            })
            .await?;
        store
            .insert_canonical_realm(&CanonicalAddressRealmRecord {
                id: realm,
                network_id: network,
                project_id: "project-a".into(),
                prefix: "10.0.0.0/24".into(),
                overlapping_prefixes: false,
                generation: 1,
                state: "active".into(),
            })
            .await?;
        let gateway = CanonicalL3GatewayRecord {
            id: Uuid::now_v7(),
            project_id: "project-a".into(),
            name: "gw".into(),
            external_realm_id: None,
            enable_snat: true,
            generation: 1,
            state: "active".into(),
        };
        store.insert_canonical_l3_gateway(&gateway).await?;
        let attachment = CanonicalL3GatewayAttachmentRecord {
            id: Uuid::now_v7(),
            gateway_id: gateway.id,
            realm_id: realm,
            project_id: "project-a".into(),
            generation: 1,
            state: "active".into(),
        };
        store
            .insert_canonical_l3_gateway_attachment(&attachment)
            .await?;
        assert_eq!(
            store
                .list_canonical_l3_gateway_attachments("project-a", &gateway.id)
                .await?,
            vec![attachment.clone()]
        );
        assert_eq!(
            store
                .list_canonical_realm_l3_gateway_attachments("project-a", &realm)
                .await?,
            vec![attachment.clone()]
        );
        assert!(matches!(
            store
                .get_canonical_l3_gateway_attachment("project-b", &attachment.id)
                .await,
            Ok(None)
        ));
        let deleting = store
            .begin_canonical_l3_gateway_attachment_deletion("project-a", &attachment.id, 1)
            .await?;
        assert_eq!(deleting.generation, 2);
        let reopened = SqliteStore::connect_file(&path).await?;
        let reopened_attachment = reopened
            .get_canonical_l3_gateway_attachment("project-a", &attachment.id)
            .await?
            .ok_or(StoreError::Corrupt("attachment disappeared".into()))?;
        assert_eq!(reopened_attachment.state, "deleting");
        reopened
            .finalize_canonical_l3_gateway_attachment_deletion("project-a", &attachment.id, 2)
            .await?;
        assert!(
            reopened
                .list_canonical_l3_gateway_attachments("project-a", &gateway.id)
                .await?
                .is_empty()
        );
        Ok(())
    }
}
#[test]
fn a0_requested_limit_uses_exactly_one_lookahead() {
    assert_eq!(crate::port::durable::bounded_fetch_limit(1).ok(), Some(2));
    assert_eq!(crate::port::durable::bounded_fetch_limit(50).ok(), Some(51));
    assert!(crate::port::durable::bounded_fetch_limit(0).is_err());
    assert!(crate::port::durable::bounded_fetch_limit(201).is_err());
}
