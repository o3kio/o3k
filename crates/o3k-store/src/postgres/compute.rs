use async_trait::async_trait;

use crate::{ComputeRepository, ResourceRecord, StoreError};

use super::{PostgresStore, helpers::row_to_resource};

#[async_trait]
impl ComputeRepository for PostgresStore {
    async fn list_resources_by_kind(&self, kind: &str) -> Result<Vec<ResourceRecord>, StoreError> {
        // `DELETED` is a retained tombstone, not an absence (issue #89): the
        // contract of this method is "every resource of this kind", and callers
        // apply their own terminal-state filter. Filtering here would diverge
        // from the SQLite adapter and hide tombstones from repair scans.
        let rows = sqlx::query("SELECT * FROM resources WHERE kind = $1 ORDER BY id")
            .bind(kind)
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        rows.iter().map(row_to_resource).collect()
    }
}
