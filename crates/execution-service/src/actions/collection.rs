//! One accepted template execution produces one CollectionRun, including partial field quality.
use super::storage::Run;
use crate::action_contract::FrozenAction;
use crate::{Result, stored};
use rss_mdm_inventory::{CollectionProgress, FieldKey, NativeValue};
use rss_mdm_resource::ScriptPurpose;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;

pub async fn accept(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenAction,
    run: &Run,
    result: &rss_mdm_agent_wire::runtime::TaskResult,
    trusted: bool,
    now: i64,
    project: bool,
) -> Result<()> {
    let output = result.output();
    let collected_at = result.collected_at();
    let ScriptPurpose::Collection { mappings, .. } = &frozen.definition.spec().purpose else {
        return Ok(());
    };
    let definition = frozen.collection.as_ref().ok_or(crate::Error::Malformed)?;
    let mut values = std::collections::BTreeMap::new();
    for (name, pointer) in mappings {
        let key = stored(FieldKey::parse(name))?;
        let field = stored(definition.field(key))?;
        let outcome = if !trusted {
            NativeValue::Failed
        } else {
            rss_mdm_inventory_service::collection::native::mapped_value(field, pointer, output)
        };
        values.insert(key, outcome);
    }
    let progress = stored(CollectionProgress::native(
        definition.clone(),
        values,
        collected_at,
    ))?;
    let tenant = tx.tenant_id();
    let report = crate::collection::enterprise::Report {
        registration: run.target.registration,
        task: run.id,
        attempt: run.state.attempt().ok_or(crate::Error::Conflict)?,
        progress,
        now,
        observed_at: collected_at,
        trusted,
        project,
    };
    tx.with_connection(move |c| {
        Box::pin(crate::collection::enterprise::accept_in(c, tenant, report))
    })
    .await?;
    Ok(())
}

pub async fn reserve(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenAction,
    run: &Run,
    now: i64,
) -> Result<()> {
    let Some(definition) = frozen.collection.clone() else {
        return Ok(());
    };
    let tenant = tx.tenant_id();
    let registration = run.target.registration;
    let task = run.id;
    let attempt = run.state.attempt().ok_or(crate::Error::Conflict)?;
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
/// Finish an abandoned attempt without publishing missing values as device facts.
pub async fn abandon(
    service: &crate::ExecutionService,
    tx: &mut PgTransaction<'_>,
    attempt: uuid::Uuid,
    reason: &'static str,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let fact=tx.with_connection(move|c|Box::pin(async move {
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2 AND sealed_at IS NULL AND (source IN('agent.script','agent.osquery','agent.native') OR evidence ? 'nativeTemplate'))")
            .bind(&tenant).bind(attempt).fetch_one(&mut *c).await?;
        if !exists {return Ok(None);}
        let mut run=crate::collection::store::load_on(c,&tenant,attempt).await.map_err(|_|sqlx::Error::Protocol("invalid pending collection".into()))?;
        crate::collection::store::seal(c,&mut run,reason).await.map_err(|_|sqlx::Error::Protocol("collection termination failed".into()))
    })).await?;
    if let Some(fact) = fact {
        service.audit_store.append_in(tx, &fact, false).await?;
    }
    Ok(())
}

pub async fn finish(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenAction,
    run: &mut Run,
    result: &rss_mdm_agent_wire::runtime::TaskResult,
    allowed: bool,
    effect_allowed: bool,
    now: i64,
) -> Result<()> {
    use rss_mdm_agent_wire::runtime::OutputQuality;
    use sha2::{Digest, Sha256};
    let output = result.output();
    let bytes = stored(serde_json::to_vec(output))?;
    if bytes.len() > frozen.definition.spec().output_bytes as usize {
        return Err(crate::Error::Malformed.into());
    }
    let budget_valid = frozen.definition.validate_output_budget(output).is_ok();
    let schema_valid = frozen.definition.validate_output(output).is_ok();
    let process_complete =
        result.exit_code() == Some(0) && result.quality() == OutputQuality::Complete;
    let success = process_complete && budget_valid && (schema_valid || frozen.collection.is_some());
    let trusted = success
        && result.collected_at() <= now
        && run.state.trusts_result(
            result.collected_at(),
            frozen.definition.spec().timeout_seconds,
        );
    run.state
        .result(run.state.attempt().ok_or(crate::Error::Conflict)?, success)?;
    accept(
        tx,
        frozen,
        run,
        result,
        trusted,
        now,
        allowed && effect_allowed,
    )
    .await?;
    let (output, reference) = if !budget_valid || bytes.len() > 1024 * 1024 {
        (
            Value::Null,
            Some(rss_mdm_agent_wire::runtime::ScriptOutputReference {
                bytes: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(&bytes)),
            }),
        )
    } else {
        (output.clone(), None)
    };
    run.result = Some(stored(serde_json::to_value(
        rss_mdm_agent_wire::runtime::ScriptRunResult {
            collected_at: result.collected_at(),
            received_at: now,
            exit_code: result.exit_code(),
            quality: result.quality(),
            schema_valid,
            budget_valid,
            output,
            output_reference: reference,
            diagnostics: result.diagnostics().clone(),
            trusted,
        },
    ))?);
    Ok(())
}
