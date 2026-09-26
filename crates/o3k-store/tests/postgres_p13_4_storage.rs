#![allow(clippy::expect_used, clippy::unwrap_used)]

use o3k_domain::{
    AttachmentAccessMode, StorageExecutionScope, Volume, VolumeAttachment, VolumeAttachmentId,
    VolumeAttachmentState, VolumeId, VolumeState,
};
use o3k_store::{PostgresStore, StorageRepository, VolumeAttachmentRecordV1, VolumeRecord};
use sqlx::{Connection, postgres::PgConnection};
use uuid::Uuid;

fn database_url() -> String {
    std::env::var("O3K_DATABASE_URL")
        .expect("O3K_DATABASE_URL must be set for PostgreSQL P13.4 storage conformance")
}

/// Acquires a session-level advisory lock on the shared PostgreSQL test
/// database, held by a dedicated connection for the caller's entire test
/// (issue #1043). The shared `o3k-shared-test-database` key serializes every
/// destructive shared-DB reset (here `clean_tables_for_testing`) against the
/// other shared-DB test groups even across separate `cargo test` processes.
/// Matches `o3k_store::conformance::prepare_shared_postgres_test_database`.
async fn acquire_database_guard(url: &str) -> PgConnection {
    let mut connection = PgConnection::connect(url)
        .await
        .expect("connect to the shared PostgreSQL test database");
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('o3k-shared-test-database', 0))")
        .execute(&mut connection)
        .await
        .expect("acquire the shared PostgreSQL test-database advisory lock");
    connection
}

#[tokio::test]
#[ignore = "requires the disposable PostgreSQL P13.4 conformance database"]
async fn postgres_p13_4_native_volume_and_attachment_reopen() {
    let _database_guard = acquire_database_guard(&database_url()).await;
    let store = PostgresStore::connect(&database_url())
        .await
        .expect("connect");
    store.clean_tables_for_testing().await.expect("clean");
    let project = format!("p13-4-{}", Uuid::now_v7());
    let volume_id = VolumeId::new();
    let volume = VolumeRecord {
        volume: Volume {
            id: volume_id,
            project_id: project.clone(),
            name: "native-volume".into(),
            description: "bounded P13.4 volume".into(),
            metadata: [("profile".into(), "p13.4".into())].into_iter().collect(),
            availability_zone: Some("local".into()),
            size_bytes: 1024 * 1024 * 1024,
            volume_type: "lvm".into(),
            backend_id: "local".into(),
            execution_scope: StorageExecutionScope::Host("host-a".into()),
            state: VolumeState::Available,
            generation: 1,
            operation_id: None,
            provider_reference: None,
        },
        created_at: "2026-08-28T00:00:00.000".into(),
    };
    store.insert_volume(&volume).await.expect("volume insert");
    let attachment = VolumeAttachmentRecordV1 {
        attachment: VolumeAttachment {
            id: VolumeAttachmentId::new(),
            project_id: project.clone(),
            volume_id,
            server_id: Uuid::now_v7(),
            execution_scope: StorageExecutionScope::Host("host-a".into()),
            access_mode: AttachmentAccessMode::ReadWrite,
            delete_on_termination: false,
            state: VolumeAttachmentState::Attached,
            generation: 1,
            operation_id: None,
        },
        created_at: "2026-08-28T00:00:00.000".into(),
    };
    store
        .insert_volume_attachment_v1(&attachment)
        .await
        .expect("attachment insert");

    let reopened = PostgresStore::connect(&database_url())
        .await
        .expect("reopen");
    let found_volume = reopened
        .get_volume(volume_id.as_uuid())
        .await
        .expect("volume read")
        .expect("volume exists");
    assert_eq!(found_volume, volume);
    let found_attachment = reopened
        .get_volume_attachment_v1(attachment.attachment.id.as_uuid())
        .await
        .expect("attachment read")
        .expect("attachment exists");
    assert_eq!(found_attachment, attachment);
    assert_eq!(
        reopened
            .list_volumes(&project)
            .await
            .expect("volume list")
            .len(),
        1
    );
    assert_eq!(
        reopened
            .list_volume_attachments_v1(&project)
            .await
            .expect("attachment list")
            .len(),
        1
    );

    reopened
        .delete_volume_attachment_v1(&project, attachment.attachment.id.as_uuid())
        .await
        .expect("detach finalization");
    let mut reattached = attachment.clone();
    reattached.attachment.id = VolumeAttachmentId::new();
    reattached.attachment.state = VolumeAttachmentState::Attached;
    reopened
        .insert_volume_attachment_v1(&reattached)
        .await
        .expect("reattach same volume with new identity");
    assert_ne!(reattached.attachment.id, attachment.attachment.id);
}
