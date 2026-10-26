//! Manual CAS and versioned values borrow the original product transaction.
use anyhow::{Result, ensure};
use rss_mdm_inventory::{Evidence, FieldKey, Scalar, SourceFact, State};
use rss_request_context::TenantId;
use sqlx::Row;
/// Versioned manual value or tombstone. Revisions survive deletion.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Assignment {
    /// Stable device identity.
    pub device: String,
    /// Manual dictionary key.
    pub field: FieldKey,
    /// CAS revision.
    pub revision: i64,
    /// Current and last-known evidence, reconstructed for rule/worker consumers.
    pub fact: SourceFact,
}
/// Decode explicitly selected scalar assignment rows. Arrays use the metadata reader.
pub(crate) fn decode(rows: Vec<sqlx::postgres::PgRow>) -> Result<Vec<Assignment>> {
    rows.into_iter()
        .map(|row| {
            ensure!(
                row.try_get::<Option<String>, _>("value_version")?.is_none()
                    && row
                        .try_get::<Option<String>, _>("last_known_version")?
                        .is_none(),
                "scalar assignment contains array"
            );
            let fact: SourceFact = serde_json::from_value(row.try_get("fact")?)?;
            ensure!(
                !matches!(fact.state, State::Known(Scalar::Array(_)))
                    && fact
                        .last_known
                        .as_ref()
                        .is_none_or(|v| !matches!(v.value, Scalar::Array(_))),
                "scalar assignment contains inline array"
            );
            Ok(Assignment {
                device: row.try_get("device")?,
                field: FieldKey::parse(row.try_get("field")?)?,
                revision: row.try_get("revision")?,
                fact,
            })
        })
        .collect()
}
/// Compare-and-set one field. The owner preserves last-known evidence by immutable
/// reference; a tombstone never reads or decodes the old array. No transaction is committed.
/// The caller authorizes the device and serializes initial field creation.
pub async fn assign_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    device: &str,
    field: FieldKey,
    expected: i64,
    state: &State,
    evidence: &Evidence,
) -> Result<Option<i64>> {
    crate::reader::assert_tenant(c, tenant).await?;
    let catalog = crate::catalog_in(c, tenant).await?;
    let definition = catalog.definition(field)?;
    ensure!(
        definition.manual && (0..i64::MAX).contains(&expected),
        "invalid manual assignment"
    );
    let fact = SourceFact {
        state: state.clone(),
        evidence: evidence.clone(),
        last_known: None,
    };
    rss_mdm_inventory::resolve(definition, vec![fact.clone()])?;
    let old=sqlx::query("SELECT revision,fact,last_known_version FROM mdm.manual_assignments WHERE tenant_id=$1::uuid AND device=$2 AND field=$3 FOR UPDATE")
        .bind(tenant.to_string()).bind(device).bind(field.as_str()).fetch_optional(&mut *c).await?;
    if old
        .as_ref()
        .map(|row| row.try_get::<i64, _>("revision"))
        .transpose()?
        .unwrap_or(0)
        != expected
    {
        return Ok(None);
    }
    let mut document = serde_json::to_value(&fact)?;
    let mut last_version = None;
    let array = if let State::Known(Scalar::Array(values)) = state {
        Some(crate::arrays::prepare(definition, values)?)
    } else {
        None
    };
    let value_version = array.as_ref().map(|a| a.metadata.version.clone());
    if let State::Known(value) = state {
        document["lastKnown"] = serde_json::json!({"value":value,"evidence":evidence});
        if value_version.is_some() {
            document["state"]
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("manual state"))?
                .remove("value");
            document["lastKnown"]
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("manual last known"))?
                .remove("value");
            last_version = value_version.clone();
        }
    } else if let Some(old) = &old {
        let old: serde_json::Value = old.try_get("fact")?;
        document["lastKnown"] = old["lastKnown"].clone();
    }
    if !matches!(state, State::Known(_)) {
        last_version = old
            .as_ref()
            .map(|row| row.try_get("last_known_version"))
            .transpose()?
            .flatten();
    }
    let revision=sqlx::query_scalar("INSERT INTO mdm.manual_assignments(tenant_id,device,field,revision,fact,value_version,last_known_version) SELECT $1::uuid,$2,$3,1,$5,$6,$7 WHERE $4=0 ON CONFLICT(tenant_id,device,field) DO NOTHING RETURNING revision")
        .bind(tenant.to_string()).bind(device).bind(field.as_str()).bind(expected).bind(&document).bind(&value_version).bind(&last_version).fetch_optional(&mut *c).await?;
    let revision = if revision.is_some() {
        revision
    } else {
        sqlx::query_scalar("UPDATE mdm.manual_assignments SET revision=revision+1,fact=$5,value_version=$6,last_known_version=$7 WHERE tenant_id=$1::uuid AND device=$2 AND field=$3 AND revision=$4 RETURNING revision")
            .bind(tenant.to_string()).bind(device).bind(field.as_str()).bind(expected).bind(document).bind(value_version).bind(last_version).fetch_optional(&mut *c).await?
    };
    if revision.is_some()
        && let Some(array) = array
    {
        crate::arrays::store(c, tenant, &array).await?;
    }
    Ok(revision)
}
