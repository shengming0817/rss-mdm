//! Batched current-generation facts; the host owns current registration and resource authorization.
use anyhow::{Result, ensure};
use rss_mdm_inventory::{Evidence, FieldKey, Scalar, SourceFact, State};
use rss_observation::Scope;
use sqlx::{
    PgPool,
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
/// Scalar facts and immutable array references; item payloads are read separately.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct InventoryFacts {
    /// Complete non-array facts, with their original provenance.
    pub scalars: Vec<InventoryField>,
    /// Array metadata, never a reconstructed full array.
    pub arrays: Vec<crate::arrays::InventoryArray>,
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
        fields: &[FieldKey],
    ) -> Result<InventoryFacts> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','5000',true)").bind(tenant.to_string()).execute(&mut *tx).await?;
        let rows = read_in(&mut tx, tenant, scopes, fields).await?;
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
    fields: &[FieldKey],
) -> Result<InventoryFacts> {
    ensure!(scopes.len() <= 20_000, "asset scope budget exceeded");
    ensure!(
        scopes.iter().all(|s| s.tenant() == tenant
            && rss_mdm_inventory::Source::parse(s.source().as_str())
                .is_ok_and(|s| s != rss_mdm_inventory::Source::Manual)),
        "asset scope mismatch"
    );
    assert_tenant(connection, tenant).await?;
    let keys = scopes
        .iter()
        .map(Scope::encode)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let projection = super::projection_scope(tenant);
    let rows=sqlx::query("SELECT DISTINCT ON(i.scope,i.field,i.field_scope) i.*,d.definition::text AS definition FROM mdm.inventory i JOIN mdm.collection_definitions d ON(d.tenant_id,d.coverage,d.source)=(i.tenant_id,i.coverage,i.source) WHERE i.tenant_id=$1::uuid AND i.journal=$2 AND i.generation=$3 AND i.scope=ANY($4) AND i.field=ANY($5) ORDER BY i.scope,i.field,i.field_scope,i.collection_sequence DESC")
        .bind(tenant.to_string()).bind(projection.source().source()).bind(projection.generation()).bind(keys).bind(fields.iter().map(|f|f.as_str()).collect::<Vec<_>>()).fetch_all(&mut *connection).await?;
    let mut scalars = Vec::new();
    let mut arrays = Vec::new();
    for row in rows {
        if matches!(
            envelope(&crate::snapshot_record::Record::observed(&row)?)?
                .definition
                .value_type,
            rss_mdm_inventory::ValueType::Array { .. }
        ) {
            arrays.push(row);
        } else {
            scalars.push(row);
        }
    }
    Ok(InventoryFacts {
        scalars: decode_rows(scalars)?,
        arrays: crate::arrays::decode_observed(connection, tenant, arrays).await?,
    })
}

pub(crate) fn decode_rows(rows: Vec<sqlx::postgres::PgRow>) -> Result<Vec<InventoryField>> {
    decode_records(
        rows.into_iter()
            .map(|row| crate::snapshot_record::Record::observed(&row))
            .collect::<Result<Vec<_>>>()?,
    )
}
pub(crate) fn decode_records(
    rows: Vec<crate::snapshot_record::Record>,
) -> Result<Vec<InventoryField>> {
    rows.into_iter()
        .map(|r| {
            let Envelope {
                field,
                definition: field_definition,
                scope,
                evidence,
            } = envelope(&r)?;
            ensure!(
                !matches!(
                    field_definition.value_type,
                    rss_mdm_inventory::ValueType::Array { .. }
                ),
                "scalar reader received array field"
            );
            let state = match r.try_get::<&str, _>("state")? {
                "known" => State::Known(decode_stored(
                    &field_definition,
                    r.try_get("value")?,
                    r.try_get("value_version")?,
                )?),
                "null" => State::Null,
                "deleted" => State::Deleted,
                "unsupported" => State::Unsupported,
                "unknown_conflict" => State::Unknown {
                    reason: rss_mdm_inventory::UnknownReason::UnorderedConflict,
                },
                "unknown_incomplete" => State::Unknown {
                    reason: rss_mdm_inventory::UnknownReason::Incomplete,
                },
                "unknown_native" => State::Unknown {
                    reason: rss_mdm_inventory::UnknownReason::NativeStatus,
                },
                "unknown_limit" => State::Unknown {
                    reason: rss_mdm_inventory::UnknownReason::EvidenceLimit,
                },
                _ => anyhow::bail!("invalid asset state"),
            };
            let last_known = if r.try_get::<Option<String>, _>("last_known")?.is_some()
                || r.try_get::<Option<String>, _>("last_known_version")?
                    .is_some()
            {
                let mut prior = evidence.clone();
                prior.snapshot_id = r.try_get("last_known_batch")?;
                prior.observed_at = r.try_get("last_known_observed")?;
                prior.received_at = r.try_get("last_known_received")?;
                Some(rss_mdm_inventory::KnownValue {
                    value: decode_stored(
                        &field_definition,
                        r.try_get("last_known")?,
                        r.try_get("last_known_version")?,
                    )?,
                    evidence: prior,
                })
            } else {
                None
            };
            Ok(InventoryField {
                scope,
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

fn decode_stored(
    field: &rss_mdm_inventory::FieldDefinition,
    value: Option<String>,
    version: Option<String>,
) -> Result<Scalar> {
    ensure!(
        version.is_none()
            && !matches!(field.value_type, rss_mdm_inventory::ValueType::Array { .. }),
        "scalar read received array"
    );
    let scalar = serde_json::from_str(&value.ok_or_else(|| anyhow::anyhow!("missing scalar"))?)?;
    field.validate_scalar(&scalar)?;
    Ok(scalar)
}

pub(crate) struct Envelope {
    pub field: FieldKey,
    pub definition: rss_mdm_inventory::FieldDefinition,
    pub scope: String,
    pub evidence: Evidence,
}
pub(crate) fn envelope(r: &crate::snapshot_record::Record) -> Result<Envelope> {
    let field = FieldKey::parse(r.try_get::<&str, _>("field")?)?;
    let definition: rss_mdm_inventory::CollectionDefinition =
        serde_json::from_str(r.try_get("definition")?)?;
    let field_definition = definition.field(field)?;
    ensure!(
        definition.field_scope(field)?.canonical()? == r.try_get::<String, _>("field_scope")?,
        "inventory field scope mismatch"
    );
    let evidence = Evidence {
        scope: definition.field_scope(field)?.clone(),
        source: rss_mdm_inventory::Source::parse(r.try_get("source")?)?,
        dataset: Some(definition.dataset().to_owned()),
        registration: Some(r.try_get("registration")?),
        registration_generation: None,
        epoch: Some(r.try_get("epoch")?),
        snapshot_id: r.try_get("batch_id")?,
        observed_at: r.try_get("observed_at")?,
        received_at: r.try_get("received_at")?,
        actor: None,
    };
    let scope: Scope = serde_json::from_str(r.try_get("scope")?)?;
    definition.validate_scope(&scope)?;
    ensure!(
        serde_json::to_string(&definition.coverage()?)? == r.try_get::<String, _>("coverage")?,
        "inventory coverage mismatch"
    );
    ensure!(
        scope.registration().as_str() == evidence.registration.as_deref().unwrap_or_default()
            && scope.source().as_str() == evidence.source.as_str()
            && scope.epoch().as_str() == evidence.epoch.as_deref().unwrap_or_default(),
        "inventory provenance mismatch"
    );
    Ok(Envelope {
        field,
        definition: field_definition.clone(),
        scope: r.try_get("scope")?,
        evidence,
    })
}
