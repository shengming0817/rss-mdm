//! Task result intake shares the existing durable CollectionRun delivery owner.
use super::storage::Run;
use crate::execution::{Result, stored};
use crate::planning::action_contract::FrozenAction;
use rss_mdm_inventory::{CollectedValue, FieldKey, Scalar};
use rss_mdm_resource::{ScriptField, ScriptPurpose};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;

pub async fn accept(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenAction,
    run: &Run,
    output: &Value,
    trusted: bool,
    now: i64,
) -> Result<()> {
    let ScriptPurpose::Collection { mappings } = &frozen.definition.spec().purpose else {
        return Ok(());
    };
    for (field, pointer) in mappings {
        let field = match field {
            ScriptField::CorporateAgentVersion => FieldKey::CorporateAgentVersion,
            ScriptField::CorporateAgentHealthy => FieldKey::CorporateAgentHealthy,
            ScriptField::OsqueryVersion => FieldKey::OsqueryVersion,
        };
        let value = if trusted {
            let value = output.pointer(pointer).ok_or(crate::Error::Malformed)?;
            let scalar = if field == FieldKey::CorporateAgentHealthy {
                Scalar::Boolean(value.as_bool().ok_or(crate::Error::Malformed)?)
            } else {
                Scalar::String(value.as_str().ok_or(crate::Error::Malformed)?.into())
            };
            Some(stored(CollectedValue::Scalar(scalar).encode(field))?)
        } else {
            None
        };
        let tenant = tx.tenant_id();
        let target = run.target.clone();
        let task = run.id;
        let attempt = run.state.attempt().ok_or(crate::Error::Conflict)?;
        tx.with_connection(move |c| {
            Box::pin(crate::collection::enterprise::accept_in(
                c,
                tenant,
                crate::collection::enterprise::Report {
                    registration: target.registration,
                    task,
                    attempt,
                    field,
                    value,
                    trusted,
                    now,
                },
            ))
        })
        .await?;
    }
    Ok(())
}
