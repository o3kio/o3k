//! PP.6.5 disposable SQLite unavailable-store coverage.

use o3k_store::{SqliteStore, StoreError};
use uuid::Uuid;

struct TempRootGuard(std::path::PathBuf);

impl Drop for TempRootGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn sqlite_unavailable_path_fails_closed_without_creating_partial_state()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("o3k-pp6-missing-{}", Uuid::now_v7()));
    let _root_guard = TempRootGuard(root.clone());
    std::fs::create_dir_all(&root)?;
    let healthy_path = root.join("healthy.sqlite");
    let database = root.join("missing").join("o3k.sqlite");
    let url = format!("sqlite://{}", database.display());
    let healthy = SqliteStore::connect_file(&healthy_path).await?;
    assert_eq!(healthy.database_health().await?.status, "ok");

    let result = SqliteStore::connect(&url).await;
    assert!(
        matches!(result, Err(StoreError::Database(_))),
        "an unavailable SQLite path must fail closed"
    );
    assert!(
        !database
            .parent()
            .ok_or("nested database has no parent")?
            .exists(),
        "a failed store open must not leave its nested parent behind"
    );
    assert_eq!(healthy.database_health().await?.status, "ok");
    assert!(healthy_path.exists(), "healthy store remains available");
    Ok(())
}
