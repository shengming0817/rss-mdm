//! Batched current-generation facts; the host owns current registration and resource authorization.
use anyhow::{Result, ensure};
use rss_mdm_inventory::{Evidence, FieldKey, Scalar, SourceFact, State};
use rss_observation::Scope;
use sqlx::{
    PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::time::Duration;
/// A typed source fact, addressed by its exact authenticated stream.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct InventoryField {
    /// Encoded complete stream scope.
    pub scope: String,
    /// Dictionary field.
    pub field: FieldKey,
    /// Current state, provenance, and last-known value.
    pub fact: SourceFact,
}
/// Restricted standalone reader; application composition can instead borrow a transaction.
pub struct InventoryReader {
    pool: PgPool,
}
impl InventoryReader {
    /// Open and admit a SELECT-only pool. No schema or tasks are created.
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
    /// Read a bounded batch of complete stream coordinates in one transaction.
    pub async fn read(
        &self,
        tenant: rss_request_context::TenantId,
        scopes: &[Scope],
    ) -> Result<Vec<InventoryField>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','5000',true)").bind(tenant.to_string()).execute(&mut *tx).await?;
        let rows = read_in(&mut tx, tenant, scopes).await?;
        tx.commit().await?;
        Ok(rows)
    }
    /// Close the owned pool after its callers have stopped.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}
/// Read typed source facts in the caller's tenant transaction, without committing.
/// Current registration/epoch and resource authorization must be resolved by the host first.
pub async fn read_in(
    connection: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    scopes: &[Scope],
) -> Result<Vec<InventoryField>> {
    ensure!(scopes.len() <= 20_000, "asset scope budget exceeded");
    ensure!(
        scopes.iter().all(|s| s.tenant() == tenant
            && s.dataset().as_str() == rss_mdm_inventory::DATASET
            && rss_mdm_inventory::ReportSource::parse(s.source().as_str()).is_ok()),
        "asset scope mismatch"
    );
    assert_tenant(connection, tenant).await?;
    let keys = scopes
        .iter()
        .map(Scope::encode)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let projection = super::projection_scope(tenant);
    let rows=sqlx::query("SELECT scope,field,value,state,last_known,last_known_batch,last_known_observed,last_known_received,batch_id,observed_at,received_at,registration,source,epoch FROM mdm.inventory WHERE tenant_id=$1::uuid AND journal=$2 AND generation=$3 AND coverage=$4 AND scope=ANY($5) ORDER BY scope,field")
        .bind(tenant.to_string()).bind(projection.source().source()).bind(projection.generation()).bind(serde_json::to_string(&rss_mdm_inventory::coverage())?).bind(keys).fetch_all(connection).await?;
    rows.into_iter()
        .map(|r| {
            let field = FieldKey::parse(r.try_get::<&str, _>("field")?)?;
            let state = match r.try_get::<&str, _>("state")? {
                "known" => State::Known(Scalar::String(r.try_get("value")?)),
                "deleted" => State::Deleted,
                "unsupported" => State::Unsupported,
                _ => anyhow::bail!("invalid asset state"),
            };
            let evidence = Evidence {
                source: rss_mdm_inventory::Source::parse(r.try_get("source")?)?,
                registration: Some(r.try_get("registration")?),
                registration_generation: None,
                epoch: Some(r.try_get("epoch")?),
                snapshot_id: r.try_get("batch_id")?,
                observed_at: r.try_get("observed_at")?,
                received_at: r.try_get("received_at")?,
                actor: None,
            };
            let scope: Scope = serde_json::from_str(r.try_get("scope")?)?;
            ensure!(
                scope.registration().as_str()
                    == evidence.registration.as_deref().unwrap_or_default()
                    && scope.source().as_str() == evidence.source.as_str()
                    && scope.epoch().as_str() == evidence.epoch.as_deref().unwrap_or_default(),
                "inventory provenance mismatch"
            );
            let last_known = if let Some(value) = r.try_get::<Option<String>, _>("last_known")? {
                let mut prior = evidence.clone();
                prior.snapshot_id = r.try_get("last_known_batch")?;
                prior.observed_at = r.try_get("last_known_observed")?;
                prior.received_at = r.try_get("last_known_received")?;
                Some(rss_mdm_inventory::KnownValue {
                    value: Scalar::String(value),
                    evidence: prior,
                })
            } else {
                None
            };
            Ok(InventoryField {
                scope: r.try_get("scope")?,
                field,
                fact: SourceFact {
                    state,
                    last_known,
                    evidence,
                },
            })
        })
        .collect()
}
pub(crate) async fn assert_tenant(
    connection: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
) -> Result<()> {
    let current: Option<String> =
        sqlx::query_scalar("SELECT nullif(current_setting('rss.tenant_id',true),'')")
            .fetch_one(connection)
            .await?;
    ensure!(
        current.as_deref() == Some(tenant.to_string().as_str()),
        "asset transaction tenant mismatch"
    );
    Ok(())
}
