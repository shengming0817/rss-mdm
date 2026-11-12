//! Script process result and bounded output; Inventory owns collection interpretation.
use crate::{FrozenScript, Result, stored};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;

pub async fn finish_in(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenScript,
    run: &mut crate::runs::Run,
    result: &rss_mdm_agent_wire::runtime::TaskResult,
    project: bool,
    now: i64,
) -> Result<rss_mdm_agent_wire::runtime::ScriptRunResult> {
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
    let trusted =
        success && result.collected_at() <= now && run.state.trusts_result(result.collected_at());
    run.state
        .result(run.state.attempt().ok_or(crate::Error::Conflict)?, success)?;
    if let rss_mdm_resource::ScriptPurpose::Collection { mappings, .. } =
        &frozen.definition.spec().purpose
    {
        let definition = frozen.collection.as_ref().ok_or(crate::Error::Invariant)?;
        let progress = rss_mdm_inventory_service::collection::enterprise::script_progress(
            definition, mappings, result, trusted,
        )?;
        let tenant = tx.tenant_id();
        let report = rss_mdm_inventory_service::collection::enterprise::Report {
            device: run.target.device,
            task: run.id,
            attempt: run.state.attempt().ok_or(crate::Error::Conflict)?,
            progress,
            now,
            observed_at: result.collected_at(),
            trusted,
            project,
        };
        tx.with_connection(move |c| {
            Box::pin(
                rss_mdm_inventory_service::collection::enterprise::accept_in(c, tenant, report),
            )
        })
        .await?;
    }
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
    Ok(rss_mdm_agent_wire::runtime::ScriptRunResult {
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
    })
}
