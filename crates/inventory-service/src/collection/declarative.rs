//! Authenticated unsolicited reports enter the existing CollectionRun/Observation transaction.
use super::*;
use crate::database::db;
use rss_mdm_inventory::{
    CollectionDefinition, CollectionProgress, CollectionScope, NativeValue, Source,
    builtin::apple_status,
};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// One unique report after the protocol owner checks registration, publication and subscription.
pub struct Report {
    pub target: super::native::Target,
    pub id: Uuid,
    pub scope: CollectionScope,
    pub subscribed: BTreeSet<String>,
    pub values: BTreeMap<String, serde_json::Value>,
    pub unknown: BTreeSet<String>,
    pub received_at: i64,
    pub evidence: serde_json::Value,
}
pub async fn receive(
    c: &mut PgConnection,
    report: Report,
) -> Result<Vec<rss_mdm_audit_integration::Fact>, Error> {
    let p = report.target;
    let catalog = rss_mdm_inventory_postgres::catalog_in(c, p.tenant)
        .await
        .map_err(|_| corrupt())?;
    let fields = apple_status::fields()
        .into_iter()
        .filter(|(name, _)| report.subscribed.contains(*name))
        .map(|(name, seed)| {
            catalog
                .definition(seed.key)
                .map(|f| (name, seed.value_type.clone(), f.clone()))
                .map_err(|_| Error::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if fields.is_empty() {
        return Ok(Vec::new());
    }
    let dataset = format!(
        "apple.ddm.{:x}",
        Sha256::digest(serde_json::to_vec(&report.scope).map_err(|_| Error::Malformed)?)
    );
    let definitions: Vec<_> = fields.iter().map(|(_, _, f)| f.clone()).collect();
    let version = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&("apple-ddm-v1", &definitions)).map_err(|_| Error::Malformed)?
        )
    );
    let definition = CollectionDefinition::new(
        report.scope,
        &dataset,
        &version,
        Source::MdmApple,
        definitions,
    )
    .map_err(|_| Error::Malformed)?;
    let values = fields
        .iter()
        .map(|(name, safe_type, f)| {
            let value = if report.unknown.contains(*name) {
                NativeValue::Value(rss_mdm_inventory::CollectedValue::Unknown {
                    reason: rss_mdm_inventory::UnknownReason::NativeStatus,
                })
            } else if let Some(value) = report.values.get(*name) {
                let safe = apple_status::sanitized(safe_type, value);
                match f
                    .value_type
                    .decode_json(&safe)
                    .and_then(|v| f.canonical_value(v))
                {
                    Ok(value) => {
                        NativeValue::Value(rss_mdm_inventory::CollectedValue::Value(value))
                    }
                    Err(_) => NativeValue::Value(rss_mdm_inventory::CollectedValue::Unknown {
                        reason: rss_mdm_inventory::UnknownReason::NativeStatus,
                    }),
                }
            } else {
                NativeValue::Value(rss_mdm_inventory::CollectedValue::Unknown {
                    reason: rss_mdm_inventory::UnknownReason::Incomplete,
                })
            };
            (f.key, value)
        })
        .collect();
    let progress =
        CollectionProgress::native_partial(definition.clone(), values, report.received_at)
            .map_err(|_| Error::Malformed)?;
    let target = crate::device::store::allocate_collection_in(
        c,
        &p.tenant.to_string(),
        &p.device,
        rss_mdm_inventory::ReportSource::MdmApple,
    )
    .await?;
    if target.registration != p.registration || target.generation != p.generation {
        return Err(Error::Conflict);
    }
    let scope = crate::device::scope_dataset(
        p.tenant,
        p.registration,
        "mdm.apple",
        target.epoch,
        &dataset,
    )?;
    definition
        .validate_scope(&scope)
        .map_err(|_| Error::Malformed)?;
    rss_mdm_inventory_postgres::register_collection_in(c, p.tenant, &definition)
        .await
        .map_err(|_| Error::Malformed)?;
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,deadline,evidence) VALUES($1::uuid,$2,$3,'mdm.apple',$4,$5,$6,$7,$8,'pending',clock_timestamp(),$9)")
        .bind(p.tenant.to_string()).bind(report.id).bind(p.registration).bind(target.epoch).bind(scope.encode().map_err(|_|Error::Malformed)?).bind(target.sequence)
        .bind(report.received_at).bind(serde_json::to_string(&progress).map_err(|_|Error::Malformed)?).bind(report.evidence).execute(&mut *c).await.map_err(db)?;
    let mut run = store::load_on(c, &p.tenant.to_string(), report.id).await?;
    Ok(store::seal(c, &mut run, "complete")
        .await?
        .into_iter()
        .collect())
}
