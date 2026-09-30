//! One accepted template execution produces one CollectionRun, including partial field quality.
use super::storage::Run;
use crate::execution::{Result, stored};
use crate::planning::action_contract::FrozenAction;
use rss_mdm_inventory::{CollectedValue, CollectionProgress, FieldKey, NativeValue};
use rss_mdm_resource::ScriptPurpose;
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
    let definition = frozen.collection.as_ref().ok_or(crate::Error::Malformed)?;
    let mut values = std::collections::BTreeMap::new();
    for (name, pointer) in mappings {
        let key = stored(FieldKey::parse(name))?;
        let field = stored(definition.field(key))?;
        let outcome = if !trusted {
            NativeValue::Failed
        } else {
            match output.pointer(pointer) {
                None => NativeValue::Missing,
                Some(Value::Null) if field.nullable => NativeValue::Value(CollectedValue::Null),
                Some(value) => match field.value_type.decode_json(value) {
                    Ok(value) => NativeValue::Value(CollectedValue::Value(value)),
                    Err(_) => NativeValue::Invalid,
                },
            }
        };
        values.insert(key, outcome);
    }
    let progress = stored(CollectionProgress::native(definition.clone(), values, now))?;
    let tenant = tx.tenant_id();
    let report = crate::collection::enterprise::Report {
        registration: run.target.registration,
        task: run.id,
        attempt: run.state.attempt().ok_or(crate::Error::Conflict)?,
        progress,
        now,
    };
    tx.with_connection(move |c| {
        Box::pin(crate::collection::enterprise::accept_in(c, tenant, report))
    })
    .await?;
    Ok(())
}
