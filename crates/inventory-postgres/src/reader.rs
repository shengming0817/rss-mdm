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
pub struct InventoryField {
    pub field: String,
    pub value: String,
    pub batch_id: String,
    pub observed_at: i64,
    pub received_at: i64,
}
pub struct InventoryReader {
    pool: PgPool,
}
impl InventoryReader {
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
        let result = rows
            .into_iter()
            .map(|row| {
                Ok(InventoryField {
                    field: row.try_get("field")?,
                    value: row.try_get("value")?,
                    batch_id: row.try_get("batch_id")?,
                    observed_at: row.try_get("observed_at")?,
                    received_at: row.try_get("received_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn close(&self) {
        self.pool.close().await;
    }
}
