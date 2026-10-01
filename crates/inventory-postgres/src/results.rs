//! Immutable completed collection evidence. The caller owns admission, transaction and delivery.
use anyhow::{Result, ensure};
use rss_mdm_inventory::{CollectionProgress, CollectionReference};
use rss_observation::{Batch, Id, Scope};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
/// Coordinates frozen by the collection execution owner before results become visible.
pub struct CollectionCompletion<'a> {
    /// Authenticated tenant/source/device/epoch/dataset identity.
    pub scope: &'a Scope,
    /// Server-admitted run identity.
    pub run: &'a str,
    /// Monotonic sequence allocated in this source's registration epoch.
    pub sequence: u64,
    /// Observation time; not freshness or authority.
    pub observed_at: i64,
    /// Complete quality record, including invalid/missing outcomes.
    pub progress: &'a CollectionProgress,
}
/// Freeze one immutable result and its bounded Observation reference in the same transaction.
pub async fn seal_collection_in(
    c: &mut PgConnection,
    input: CollectionCompletion<'_>,
) -> Result<Batch> {
    let CollectionCompletion {
        scope,
        run,
        sequence,
        observed_at,
        progress,
    } = input;
    crate::reader::assert_tenant(c, scope.tenant()).await?;
    progress.definition().validate_scope(scope)?;
    ensure!(progress.complete(), "collection still pending");
    let bytes = serde_json::to_vec(progress)?;
    ensure!(bytes.len() <= 33554432, "collection result capacity");
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let scope_key = scope.encode()?;
    let sequence_db = i64::try_from(sequence)?;
    let coverage = serde_json::to_string(&progress.definition().coverage()?)?;
    sqlx::query("INSERT INTO mdm.collection_results(tenant_id,run,scope,coverage,sequence,observed_at,digest,document) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING")
        .bind(scope.tenant().to_string()).bind(run).bind(&scope_key).bind(&coverage).bind(sequence_db).bind(observed_at).bind(&digest).bind(&bytes).execute(&mut *c).await?;
    let matches:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm.collection_results WHERE tenant_id=$1::uuid AND run=$2 AND scope=$3 AND coverage=$4 AND sequence=$5 AND observed_at=$6 AND digest=$7 AND document=$8)")
        .bind(scope.tenant().to_string()).bind(run).bind(scope_key).bind(coverage).bind(sequence_db).bind(observed_at).bind(&digest).bind(bytes).fetch_one(c).await?;
    ensure!(matches, "collection result conflict");
    Ok(CollectionReference::batch(
        Id::new(run)?,
        sequence,
        observed_at.try_into()?,
        progress.definition(),
        digest,
    )?)
}
/// Restore the exact completed result referenced by one accepted Observation event.
pub async fn collection_result_in(
    c: &mut PgConnection,
    scope: &Scope,
    batch: &Batch,
    definition: &rss_mdm_inventory::CollectionDefinition,
) -> Result<CollectionProgress> {
    crate::reader::assert_tenant(c, scope.tenant()).await?;
    definition.validate_scope(scope)?;
    let reference = CollectionReference::from_batch(definition, batch)?;
    let row=sqlx::query("SELECT scope,coverage,sequence,observed_at,digest,document FROM mdm.collection_results WHERE tenant_id=$1::uuid AND run=$2")
        .bind(scope.tenant().to_string()).bind(batch.id().as_str()).fetch_one(c).await?;
    let bytes: Vec<u8> = row.try_get("document")?;
    ensure!(
        bytes.len() <= 33554432
            && format!("{:x}", Sha256::digest(&bytes)) == reference.digest()
            && row.try_get::<&str, _>("digest")? == reference.digest()
            && row.try_get::<&str, _>("scope")? == scope.encode()?
            && row.try_get::<&str, _>("coverage")? == serde_json::to_string(batch.coverage())?
            && row.try_get::<i64, _>("sequence")? == i64::try_from(batch.sequence())?
            && row.try_get::<i64, _>("observed_at")? == batch.observed_at_seconds(),
        "collection result mismatch"
    );
    let progress: CollectionProgress = serde_json::from_slice(&bytes)?;
    ensure!(
        progress.definition() == definition
            && progress.complete()
            && serde_json::to_vec(&progress)? == bytes,
        "collection result contract"
    );
    Ok(progress)
}
