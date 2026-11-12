//! Immutable completed collection evidence. The caller owns admission, transaction and delivery.
use anyhow::{Result, ensure};
use rss_mdm_inventory::{CollectionProgress, CollectionReference};
use rss_observation::{Batch, Id, Scope};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
/// Coordinates frozen by the collection execution owner before results become visible.
pub struct CollectionCompletion<'a> {
    /// Original ingress/task owner trust, independent of current projection eligibility.
    pub trusted: bool,
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
        trusted,
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
    let batch = CollectionReference::batch(
        Id::new(run)?,
        sequence,
        observed_at.try_into()?,
        progress.definition(),
        digest.clone(),
    )?;
    let device = rss_mdm_agent_wire::DeviceId::parse(scope.registration().as_str())?;
    let (serial, uuid) = hardware(progress)?;
    // Retention may remove the full result; retained locator evidence still freezes acceptance.
    let unchanged:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM mdm.device_hardware_evidence WHERE tenant_id=$1::uuid AND scope=$2 AND run=$3 AND (NOT $13 OR device<>$4 OR source<>$5 OR epoch<>$6 OR coverage<>$7 OR sequence<>$8 OR result_digest<>$9 OR observed_at<>$10 OR serial_number IS DISTINCT FROM $11 OR hardware_uuid IS DISTINCT FROM $12))")
        .bind(scope.tenant().to_string()).bind(&scope_key).bind(run).bind(device.into_uuid()).bind(scope.source().as_str()).bind(scope.epoch().as_str()).bind(&coverage).bind(sequence_db).bind(&digest).bind(observed_at).bind(&serial).bind(&uuid).bind(trusted).fetch_one(&mut *c).await?;
    ensure!(unchanged, "retained hardware evidence conflict");
    sqlx::query("INSERT INTO mdm.collection_results(tenant_id,run,scope,coverage,sequence,observed_at,digest,document,trusted) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING")
        .bind(scope.tenant().to_string()).bind(run).bind(&scope_key).bind(&coverage).bind(sequence_db).bind(observed_at).bind(&digest).bind(&bytes).bind(trusted).execute(&mut *c).await?;
    let matches:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm.collection_results WHERE tenant_id=$1::uuid AND run=$2 AND scope=$3 AND coverage=$4 AND sequence=$5 AND observed_at=$6 AND digest=$7 AND document=$8 AND trusted=$9)")
        .bind(scope.tenant().to_string()).bind(run).bind(&scope_key).bind(&coverage).bind(sequence_db).bind(observed_at).bind(&digest).bind(bytes).bind(trusted).fetch_one(&mut *c).await?;
    ensure!(matches, "collection result conflict");
    if trusted && (serial.is_some() || uuid.is_some()) {
        sqlx::query("INSERT INTO mdm.device_hardware_evidence(tenant_id,scope,run,device,source,epoch,coverage,sequence,result_digest,observed_at,serial_number,hardware_uuid) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING")
                .bind(scope.tenant().to_string()).bind(&scope_key).bind(run).bind(device.into_uuid()).bind(scope.source().as_str()).bind(scope.epoch().as_str()).bind(&coverage).bind(sequence_db).bind(&digest).bind(observed_at).bind(&serial).bind(&uuid).execute(&mut *c).await?;
        let same: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm.device_hardware_evidence WHERE tenant_id=$1::uuid AND scope=$2 AND run=$3 AND device=$4 AND source=$5 AND epoch=$6 AND coverage=$7 AND sequence=$8 AND result_digest=$9 AND observed_at=$10 AND serial_number IS NOT DISTINCT FROM $11 AND hardware_uuid IS NOT DISTINCT FROM $12)")
                .bind(scope.tenant().to_string()).bind(&scope_key).bind(run).bind(device.into_uuid()).bind(scope.source().as_str()).bind(scope.epoch().as_str()).bind(&coverage).bind(sequence_db).bind(&digest).bind(observed_at).bind(&serial).bind(&uuid).fetch_one(&mut *c).await?;
        ensure!(same, "hardware evidence conflict");
    }
    Ok(batch)
}
fn hardware(progress: &CollectionProgress) -> Result<(Option<String>, Option<String>)> {
    use rss_mdm_inventory::{CollectedValue, CollectionScope, FieldKey, Scalar};
    let mut serial = None;
    let mut uuid = None;
    if let Some(body) = progress.body()? {
        for change in body.changes() {
            let key = FieldKey::parse(change.key().as_str())?;
            if !matches!(
                key.as_str(),
                "device.serial_number" | "device.hardware_uuid"
            ) || progress.definition().field_scope(key)? != &CollectionScope::Device
            {
                continue;
            }
            let field = progress.definition().field(key)?;
            let Some(bytes) = change.value() else {
                continue;
            };
            if let CollectedValue::Value(value) = CollectedValue::decode(field, bytes)?
                && let Scalar::String(value) = field.canonical_value(value)?
            {
                if key.as_str() == "device.serial_number" {
                    serial = Some(value);
                } else {
                    uuid = Some(value);
                }
            }
        }
    }
    Ok((serial, uuid))
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
    let row=sqlx::query("SELECT scope,coverage,sequence,observed_at,digest,document FROM mdm.collection_results WHERE tenant_id=$1::uuid AND scope=$3 AND run=$2")
        .bind(scope.tenant().to_string()).bind(batch.id().as_str()).bind(scope.encode()?).fetch_one(c).await?;
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
