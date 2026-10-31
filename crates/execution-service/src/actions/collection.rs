//! One accepted template execution produces one CollectionRun, including partial field quality.
use super::storage::Run;
use crate::{Result, stored};
use rss_mdm_resource::ScriptPurpose;
use rss_mdm_script_service::FrozenScript;
use rss_transactional_messaging_postgres::PgTransaction;

pub async fn accept(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenScript,
    run: &Run,
    result: &rss_mdm_agent_wire::runtime::TaskResult,
    trusted: bool,
    now: i64,
    project: bool,
) -> Result<()> {
    let collected_at = result.collected_at();
    let ScriptPurpose::Collection { mappings, .. } = &frozen.definition.spec().purpose else {
        return Ok(());
    };
    let definition = frozen.collection.as_ref().ok_or(crate::Error::Malformed)?;
    let progress = rss_mdm_inventory_service::collection::enterprise::script_progress(
        definition, mappings, result, trusted,
    )?;
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
    frozen: &FrozenScript,
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
    let tenant = tx.tenant_id();
    let fact = tx
        .with_connection(move |c| {
            Box::pin(
                rss_mdm_inventory_service::collection::enterprise::abandon_in(
                    c, tenant, attempt, reason,
                ),
            )
        })
        .await?;
    if let Some(fact) = fact {
        service
            .transactions
            .audit_store
            .append_in(tx, &fact)
            .await?;
    }
    Ok(())
}

pub async fn finish(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenScript,
    run: &mut Run,
    result: &rss_mdm_agent_wire::runtime::TaskResult,
    allowed: bool,
    effect_allowed: bool,
    now: i64,
) -> Result<()> {
    run.result = Some(super::result::RunResult::Script(
        rss_mdm_script_service::results::finish_in(
            tx,
            frozen,
            run.id,
            &rss_mdm_script_service::Target {
                device: run.target.device.clone(),
                registration: run.target.registration,
                generation: run.target.generation,
            },
            &mut run.state,
            result,
            allowed,
            effect_allowed,
            now,
        )
        .await?,
    ));
    Ok(())
}
