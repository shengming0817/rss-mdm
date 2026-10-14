//! Native template runs share CollectionRun, field quality and immutable result delivery.
use crate::{Error, database::db};
use rss_mdm_inventory::{
    CollectedValue, CollectionDefinition, CollectionProgress, FieldKey, NativeValue, ValueType,
};
use rss_mdm_resource::{NativeAdapter, NativeCollectionDefinition};
use sqlx::PgConnection;
use uuid::Uuid;
pub struct Target {
    pub tenant: rss_request_context::TenantId,
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
}
pub async fn start(
    c: &mut PgConnection,
    p: &Target,
    id: Uuid,
    definition: CollectionDefinition,
    template: NativeCollectionDefinition,
    deadline: i64,
) -> Result<(), Error> {
    let source = match template.spec().adapter {
        NativeAdapter::WindowsCsp => rss_mdm_inventory::ReportSource::MdmWindows,
        _ => rss_mdm_inventory::ReportSource::MdmApple,
    };
    let target =
        crate::device::store::allocate_collection_in(c, &p.tenant.to_string(), &p.device, source)
            .await
            .map_err(|error| {
                #[cfg(feature = "integration")]
                eprintln!("native source allocation: {error:?}");
                Error::from(error)
            })?;
    if target.registration != p.registration || target.generation != p.generation {
        return Err(Error::Conflict);
    }
    let scope = crate::device::scope_dataset(
        p.tenant,
        p.registration,
        source.as_str(),
        target.epoch,
        definition.dataset(),
    )?;
    definition
        .validate_scope(&scope)
        .map_err(|_| Error::Malformed)?;
    rss_mdm_inventory_postgres::register_collection_in(c, p.tenant, &definition)
        .await
        .map_err(|_| Error::Malformed)?;
    let progress = CollectionProgress::new(definition);
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,deadline,evidence) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,floor(extract(epoch FROM clock_timestamp()))::bigint,$8,'pending',to_timestamp($9),$10)")
        .bind(p.tenant.to_string()).bind(id).bind(p.registration).bind(source.as_str()).bind(target.epoch).bind(scope.encode().map_err(|_|Error::Malformed)?).bind(target.sequence)
        .bind(serde_json::to_string(&progress).map_err(|_|Error::Malformed)?).bind(deadline as f64).bind(serde_json::json!({"nativeTemplate":template})).execute(&mut *c).await.map_err(db)?;
    crate::wake::notify(c).await.map_err(db)?;
    Ok(())
}
pub async fn template(
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<Option<NativeCollectionDefinition>, Error> {
    let value:Option<serde_json::Value>=sqlx::query_scalar("SELECT evidence->'nativeTemplate' FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await.map_err(db)?;
    value
        .map(|v| serde_json::from_value(v).map_err(|_| Error::Malformed))
        .transpose()
}
/// Validate projected columns and converted scalar types before publishing a template.
pub fn validate_mapping(
    field: &rss_mdm_inventory::FieldDefinition,
    mapping: &rss_mdm_resource::ValueMapping,
) -> Result<(), Error> {
    fn check(ty: &ValueType, mapping: &rss_mdm_resource::ValueMapping) -> Result<(), Error> {
        use rss_mdm_resource::Conversion;
        if !mapping.columns.is_empty() {
            let ty = match ty {
                ValueType::Array { items, .. } => items.as_ref(),
                other => other,
            };
            let ValueType::Object { properties } = ty else {
                return Err(Error::Malformed);
            };
            if mapping.columns.keys().ne(properties.keys()) {
                return Err(Error::Malformed);
            }
            for (name, column) in &mapping.columns {
                check(&properties[name], column)?;
            }
        } else {
            let valid = match &mapping.conversion {
                Conversion::Identity => true,
                Conversion::Integer | Conversion::Scale { .. } => {
                    matches!(ty, ValueType::Integer | ValueType::Time)
                }
                Conversion::Number => matches!(ty, ValueType::Number),
                Conversion::Enum { values } => values.values().all(|v| ty.decode_json(v).is_ok()),
                Conversion::Bitmask { flags } => ty
                    .decode_json(&serde_json::json!(flags.values().collect::<Vec<_>>()))
                    .is_ok(),
            };
            if !valid {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
    mapping.validate().map_err(|_| Error::Malformed)?;
    check(&field.value_type, mapping)
}
/// Shared mapping boundary for native, SQL and script output. Missing data is never a tombstone.
pub fn mapped_value(
    field: &rss_mdm_inventory::FieldDefinition,
    mapping: &rss_mdm_resource::ValueMapping,
    raw: &serde_json::Value,
) -> NativeValue {
    let Some(raw) = raw.pointer(&mapping.pointer) else {
        return NativeValue::Missing;
    };
    if let (ValueType::Array { items, .. }, serde_json::Value::Array(rows)) =
        (&field.value_type, raw)
    {
        return NativeValue::list(
            field,
            rows.iter()
                .map(|row| {
                    let value = mapping
                        .project(row)
                        .map_err(|_| rss_mdm_inventory::Invalid::Value)?;
                    items.decode_json(&value)
                })
                .collect(),
        )
        .unwrap_or(NativeValue::Invalid);
    }
    let Ok(projected) = mapping.project(raw) else {
        return NativeValue::Invalid;
    };
    if projected.is_null() && field.nullable {
        return NativeValue::Value(CollectedValue::Null);
    }
    match field
        .value_type
        .decode_json(&projected)
        .and_then(|v| field.canonical_value(v))
    {
        Ok(v) => NativeValue::Value(CollectedValue::Value(v)),
        Err(_) => NativeValue::Invalid,
    }
}
pub fn value(
    field: &rss_mdm_inventory::FieldDefinition,
    mapping: &rss_mdm_resource::NativeMapping,
    raw: &serde_json::Value,
) -> NativeValue {
    let parsed = if (!mapping.mapping.pointer.is_empty() || !mapping.mapping.columns.is_empty())
        && raw.is_string()
    {
        serde_json::from_str(raw.as_str().expect("checked string")).ok()
    } else {
        None
    };
    mapped_value(field, &mapping.mapping, parsed.as_ref().unwrap_or(raw))
}

pub fn result(
    template: &NativeCollectionDefinition,
    definition: CollectionDefinition,
    values: &serde_json::Value,
    now: i64,
    success: bool,
) -> Result<CollectionProgress, Error> {
    let values = template
        .spec()
        .mappings
        .iter()
        .map(|(key, mapping)| {
            let key = FieldKey::parse(key).map_err(|_| Error::Malformed)?;
            let field = definition.field(key).map_err(|_| Error::Malformed)?;
            let raw = if mapping.query.is_empty() {
                Some(values)
            } else {
                values.get(&mapping.query)
            };
            Ok((
                key,
                if !success {
                    NativeValue::Failed
                } else {
                    raw.map_or(NativeValue::Missing, |v| value(field, mapping, v))
                },
            ))
        })
        .collect::<Result<_, Error>>()?;
    CollectionProgress::native(definition, values, now).map_err(|_| Error::Malformed)
}
