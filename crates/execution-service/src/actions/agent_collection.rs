//! Native query quality enters the existing CollectionRun/Observation path.
use super::storage::Run;
use crate::{Error, Result, action_contract::FrozenAgentCollection, checked_input, stored};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_inventory::{CollectedValue, CollectionProgress, FieldKey, NativeValue};
use rss_transactional_messaging_postgres::PgTransaction;
pub async fn reserve(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenAgentCollection,
    run: &Run,
    now: i64,
) -> Result<()> {
    let tenant = tx.tenant_id();
    let registration = run.target.registration;
    let task = run.id;
    let attempt = run.state.attempt().ok_or(Error::Conflict)?;
    let definition = frozen.collection.clone();
    tx.with_connection(move |c| {
        Box::pin(crate::collection::enterprise::start_in(
            c,
            tenant,
            registration,
            task,
            attempt,
            definition,
            now,
        ))
    })
    .await?;
    Ok(())
}
pub async fn finish(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenAgentCollection,
    run: &mut Run,
    result: &wire::NativeCollectionResult,
    allowed: bool,
    now: i64,
) -> Result<()> {
    let spec = frozen.definition.spec();
    checked_input(result.validate_for(&spec.plan, now))?;
    let trusted = allowed
        && run
            .state
            .trusts_result(now, spec.plan.spec().budget.timeout_seconds)
        && run
            .state
            .started_at
            .is_some_and(|at| result.queries.values().all(|q| q.collected_at >= at));
    let mut values = std::collections::BTreeMap::new();
    for (name, binding) in &spec.mappings {
        let key = stored(FieldKey::parse(name))?;
        let field = stored(frozen.collection.field(key))?;
        let query = &spec.plan.spec().queries[&binding.query];
        let answer = &result.queries[&binding.query];
        let complete = answer.complete_for(query, now);
        let missing = serde_json::to_vec(answer)
            .is_ok_and(|v| v.len() <= query.budget.output_bytes as usize)
            && answer.enumeration_complete
            && answer.rows.is_empty()
            && answer.row_count == 0
            && query.cardinality == wire::NativeCardinality::ExactlyOne
            && matches!(
                answer.status,
                wire::NativeQueryStatus::Missing | wire::NativeQueryStatus::Complete
            );
        let value = if !trusted {
            NativeValue::Failed
        } else if complete {
            let raw = match query.cardinality {
                wire::NativeCardinality::ExactlyOne => serde_json::to_value(&answer.rows[0]),
                wire::NativeCardinality::List => serde_json::to_value(&answer.rows),
            };
            rss_mdm_inventory_service::collection::native::mapped_value(
                field,
                &binding.mapping,
                &stored(raw)?,
            )
        } else if missing {
            NativeValue::Missing
        } else {
            match answer.status {
                wire::NativeQueryStatus::Unsupported => {
                    NativeValue::Value(CollectedValue::Unsupported)
                }
                wire::NativeQueryStatus::Invalid | wire::NativeQueryStatus::Complete => {
                    NativeValue::Invalid
                }
                wire::NativeQueryStatus::Missing => NativeValue::Missing,
                _ => NativeValue::Failed,
            }
        };
        let value = if trusted && (complete || missing) {
            apply_missing(value, binding.missing, field.nullable)
        } else {
            value
        };
        values.insert(key, value);
    }
    let progress = stored(CollectionProgress::native(
        frozen.collection.clone(),
        values,
        result.collected_at,
    ))?;
    let tenant = tx.tenant_id();
    let attempt = run.state.attempt().ok_or(Error::Conflict)?;
    let report = crate::collection::enterprise::Report {
        registration: run.target.registration,
        task: run.id,
        attempt,
        progress,
        now,
    };
    tx.with_connection(move |c| {
        Box::pin(crate::collection::enterprise::accept_in(c, tenant, report))
    })
    .await?;
    // Both inline and chunked input retain the same recoverable canonical evidence.
    super::output::retain_native(tx, run, result).await?;
    if allowed {
        run.state.result(attempt, true)?;
    } else {
        run.state.uncertain_result(attempt)?;
    }
    use sha2::{Digest, Sha256};
    let bytes = stored(serde_json::to_vec(result))?;
    let queries:std::collections::BTreeMap<_,_>=result.queries.iter().map(|(id,q)|(id,serde_json::json!({"queryDigest":q.query_digest,"collectedAt":q.collected_at,"status":q.status,"enumerationComplete":q.enumeration_complete,"rowCount":q.row_count}))).collect();
    run.result = Some(
        serde_json::json!({"native":if bytes.len()<=256*1024{stored(serde_json::to_value(result))?}else{serde_json::Value::Null},"queries":queries,"planDigest":result.plan_digest,"outputReference":{"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes))},"trusted":trusted,"receivedAt":now}),
    );
    Ok(())
}

fn apply_missing(
    value: NativeValue,
    policy: rss_mdm_resource::NativeMissing,
    nullable: bool,
) -> NativeValue {
    if !matches!(value, NativeValue::Missing) {
        return value;
    }
    match policy {
        rss_mdm_resource::NativeMissing::Missing => NativeValue::Missing,
        rss_mdm_resource::NativeMissing::Null if nullable => {
            NativeValue::Value(CollectedValue::Null)
        }
        rss_mdm_resource::NativeMissing::Delete => NativeValue::Value(CollectedValue::Deleted),
        _ => NativeValue::Invalid,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_absence_policy_does_not_promote_errors() {
        use rss_mdm_resource::NativeMissing as M;
        assert!(matches!(
            apply_missing(NativeValue::Missing, M::Delete, false),
            NativeValue::Value(CollectedValue::Deleted)
        ));
        assert!(matches!(
            apply_missing(NativeValue::Missing, M::Null, true),
            NativeValue::Value(CollectedValue::Null)
        ));
        assert!(matches!(
            apply_missing(NativeValue::Missing, M::Null, false),
            NativeValue::Invalid
        ));
        assert!(matches!(
            apply_missing(NativeValue::Failed, M::Delete, false),
            NativeValue::Failed
        ));
        assert!(matches!(
            apply_missing(NativeValue::Invalid, M::Null, true),
            NativeValue::Invalid
        ));
    }
}
