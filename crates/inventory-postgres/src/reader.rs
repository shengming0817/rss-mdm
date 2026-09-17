//! Exact-scope read model access. The product owns resource authorization.
use anyhow::{Result, ensure};
use rss_observation::Scope;
use serde::Serialize;
use sqlx::{
    PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq, Serialize)]
/// One exact-scope projected field with source-batch and timing provenance.
/// The projection writer validates Inventory content; readers only decode stored
/// rows and do not repeat domain validation or authenticate their contents.
pub struct InventoryField {
    /// Persisted Inventory field key, without read-time domain validation.
    pub field: String,
    /// Persisted text value, potentially sensitive and subject to the consumer's trust boundary.
    pub value: String,
    /// Observation batch identity that last wrote this field.
    pub batch_id: String,
    /// Producer observation time in Unix seconds.
    pub observed_at: i64,
    /// Observation receiver time in Unix seconds.
    pub received_at: i64,
}
/// Restricted reader owning a PostgreSQL pool; resource authorization remains with the caller.
pub struct InventoryReader {
    pool: PgPool,
}
impl InventoryReader {
    /// Open a pool of at most four connections with a 5s acquisition timeout and
    /// verify the restricted reader role/catalog contract. Connection or admission errors
    /// are returned; an opened pool is closed on admission failure. Applies no migrations.
    pub async fn connect(options: PgConnectOptions) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await?;
        if let Err(error) = super::admission::verify_reader(&pool).await {
            pool.close().await;
            return Err(error);
        }
        Ok(Self { pool })
    }
    /// Read fields in field-key order for the exact tenant/scope and canonical generation/coverage.
    /// Rejects a non-Inventory dataset before I/O. Begins its own transaction, sets the
    /// tenant and 5s statement timeout, reads rows and commits before returning. Encoding,
    /// SQL, decoding or commit failures return an error without partial results. An empty
    /// list does not prove that a collection is complete; caller authorization is required.
    pub async fn read(&self, scope: &Scope) -> Result<Vec<InventoryField>> {
        ensure!(
            scope.dataset().as_str() == rss_mdm_inventory::DATASET,
            "invalid inventory dataset"
        );
        let projection = super::projection_scope(scope.tenant());
        let tenant = scope.tenant().to_string();
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true), set_config('statement_timeout','5000',true)")
            .bind(&tenant).execute(&mut *tx).await?;
        let rows = sqlx::query("SELECT field,value,batch_id,observed_at,received_at FROM mdm.inventory WHERE tenant_id=$1::uuid AND journal=$4 AND generation=$5 AND scope=$2 AND coverage=$3 ORDER BY field")
            .bind(&tenant).bind(scope.encode()?).bind(serde_json::to_string(&rss_mdm_inventory::coverage())?).bind(projection.source().source()).bind(projection.generation()).fetch_all(&mut *tx).await?;
        let result = decode(rows)?;
        tx.commit().await?;
        Ok(result)
    }
    /// Close the owned pool and await outstanding connections being returned.
    /// The host should stop its readers first; this method adds no shutdown deadline.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// Read an exact Inventory scope in the host's
/// existing tenant transaction. The caller owns authorization, transaction
/// lifetime and the bounded candidate universe; this method never commits.
/// Requires SELECT only. The host selects a consistent transaction isolation level.
/// A foreign or missing transaction tenant is rejected before reading facts.
pub async fn read_in(
    connection: &mut sqlx::PgConnection,
    scope: &Scope,
) -> Result<Vec<InventoryField>> {
    ensure!(
        scope.dataset().as_str() == rss_mdm_inventory::DATASET,
        "invalid inventory dataset"
    );
    let tenant = scope.tenant().to_string();
    let current: Option<String> =
        sqlx::query_scalar("SELECT nullif(current_setting('rss.tenant_id',true),'')")
            .fetch_one(&mut *connection)
            .await?;
    ensure!(
        current.as_deref() == Some(tenant.as_str()),
        "inventory transaction tenant mismatch"
    );
    let projection = super::projection_scope(scope.tenant());
    let rows=sqlx::query("SELECT field,value,batch_id,observed_at,received_at FROM mdm.inventory WHERE tenant_id=$1::uuid AND journal=$4 AND generation=$5 AND scope=$2 AND coverage=$3 ORDER BY field")
        .bind(tenant).bind(scope.encode()?).bind(serde_json::to_string(&rss_mdm_inventory::coverage())?).bind(projection.source().source()).bind(projection.generation()).fetch_all(connection).await?;
    decode(rows)
}
fn decode(rows: Vec<sqlx::postgres::PgRow>) -> Result<Vec<InventoryField>> {
    rows.into_iter()
        .map(|row| {
            Ok(InventoryField {
                field: row.try_get("field")?,
                value: row.try_get("value")?,
                batch_id: row.try_get("batch_id")?,
                observed_at: row.try_get("observed_at")?,
                received_at: row.try_get("received_at")?,
            })
        })
        .collect::<Result<Vec<_>>>()
}
