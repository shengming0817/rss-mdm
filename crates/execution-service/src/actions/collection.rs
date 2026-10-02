//! One accepted template execution produces one CollectionRun, including partial field quality.
use super::storage::Run;
use crate::action_contract::FrozenAction;
use crate::{Result, stored};
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
                None if frozen.definition.spec().profile
                    == rss_mdm_resource::ScriptProfile::Osquery
                    && output.as_array().is_some_and(Vec::is_empty) =>
                {
                    NativeValue::Value(CollectedValue::Deleted)
                }
                None => NativeValue::Missing,
                Some(Value::Null) if field.nullable => NativeValue::Value(CollectedValue::Null),
                Some(Value::Array(rows))
                    if matches!(field.value_type, rss_mdm_inventory::ValueType::Array { .. }) =>
                {
                    let rss_mdm_inventory::ValueType::Array { items, .. } = &field.value_type
                    else {
                        unreachable!()
                    };
                    let values = rows
                        .iter()
                        .map(|v| {
                            if frozen.definition.spec().profile
                                == rss_mdm_resource::ScriptProfile::Osquery
                            {
                                sql_value(items, v)
                            } else {
                                items.decode_json(v)
                            }
                        })
                        .collect();
                    stored(NativeValue::list(field, values))?
                }
                Some(value) => match if frozen.definition.spec().profile
                    == rss_mdm_resource::ScriptProfile::Osquery
                {
                    sql_value(&field.value_type, value)
                } else {
                    field.value_type.decode_json(value)
                } {
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
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2 AND sealed_at IS NULL AND (source IN('agent.script','agent.osquery') OR evidence ? 'nativeTemplate'))")
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

// osquery's JSON writer emits SQL INTEGER/DOUBLE columns as strings. Convert only according to
// the frozen field type at this adapter boundary; script/MDM JSON remains strictly typed.
fn sql_value(
    kind: &rss_mdm_inventory::ValueType,
    value: &Value,
) -> rss_mdm_inventory::Result<rss_mdm_inventory::Scalar> {
    use rss_mdm_inventory::{Invalid, ValueType as T};
    let converted = match (kind, value) {
        (T::Integer | T::Time, Value::String(text)) => {
            Value::from(text.parse::<i64>().map_err(|_| Invalid::TypeMismatch)?)
        }
        (T::Number, Value::String(text)) => Value::Number(
            serde_json::Number::from_f64(text.parse::<f64>().map_err(|_| Invalid::TypeMismatch)?)
                .ok_or(Invalid::Value)?,
        ),
        (T::Boolean, Value::String(text)) => Value::Bool(match text.as_str() {
            "0" => false,
            "1" => true,
            _ => return Err(Invalid::TypeMismatch),
        }),
        (T::Array { items, max_items }, Value::Array(values))
            if values.len() <= *max_items as usize =>
        {
            return Ok(rss_mdm_inventory::Scalar::Array(
                values
                    .iter()
                    .map(|v| sql_value(items, v))
                    .collect::<rss_mdm_inventory::Result<_>>()?,
            ));
        }
        (T::Object { properties }, Value::Object(values)) if properties.len() == values.len() => {
            return Ok(rss_mdm_inventory::Scalar::Object(
                properties
                    .iter()
                    .map(|(k, t)| {
                        Ok((
                            k.clone(),
                            sql_value(t, values.get(k).ok_or(Invalid::TypeMismatch)?)?,
                        ))
                    })
                    .collect::<rss_mdm_inventory::Result<_>>()?,
            ));
        }
        _ => value.clone(),
    };
    kind.decode_json(&converted)
}

pub async fn finish(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenAction,
    run: &mut Run,
    result: &rss_mdm_agent_wire::TaskResult,
    allowed: bool,
    now: i64,
) -> Result<()> {
    use rss_mdm_agent_wire::OutputQuality;
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
        && allowed
        && run
            .state
            .trusts_result(now, frozen.definition.spec().timeout_seconds);
    run.state
        .result(run.state.attempt().ok_or(crate::Error::Conflict)?, success)?;
    accept(tx, frozen, run, output, trusted, now).await?;
    let (output, reference) = if !budget_valid || bytes.len() > 1024 * 1024 {
        (
            Value::Null,
            serde_json::json!({"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes))}),
        )
    } else {
        (output.clone(), Value::Null)
    };
    run.result = Some(
        serde_json::json!({"exitCode":result.exit_code(),"quality":result.quality(),"schemaValid":schema_valid,"budgetValid":budget_valid,"output":output,"outputReference":reference,"diagnostics":result.diagnostics(),"trusted":trusted}),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_mdm_inventory::{Scalar, ValueType as T};
    #[test]
    fn sql_text_columns_decode_only_by_declared_type() {
        assert_eq!(
            sql_value(&T::Integer, &Value::String("42".into())).unwrap(),
            Scalar::Integer(42)
        );
        assert_eq!(
            sql_value(&T::Boolean, &Value::String("0".into())).unwrap(),
            Scalar::Boolean(false)
        );
        assert!(sql_value(&T::Number, &Value::String("NaN".into())).is_err());
        assert!(sql_value(&T::Integer, &Value::String("1.5".into())).is_err());
        assert!(sql_value(&T::Boolean, &Value::String("yes".into())).is_err());
        assert!(T::Integer.decode_json(&Value::String("42".into())).is_err());
    }
}
