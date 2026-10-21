//! Explicit protocol/domain conversion; only Inventory creates coverage and stored values.
use crate::Error;
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_inventory as d;
fn to_wire_source(value: d::Source) -> w::Source {
    match value {
        d::Source::AgentScript => w::Source::AgentScript,
        d::Source::AgentNative => w::Source::AgentNative,
        d::Source::AgentOsquery => w::Source::AgentOsquery,
        d::Source::MdmApple => w::Source::MdmApple,
        d::Source::AgentBuiltin => w::Source::AgentBuiltin,
        d::Source::Manual => w::Source::Manual,
        d::Source::MdmWindows => w::Source::MdmWindows,
    }
}
fn to_wire_platform(value: d::Platform) -> w::Platform {
    match value {
        d::Platform::Windows => w::Platform::Windows,
        d::Platform::Macos => w::Platform::Macos,
    }
}
fn to_wire_sensitivity(value: d::Sensitivity) -> w::Sensitivity {
    match value {
        d::Sensitivity::Standard => w::Sensitivity::Standard,
        d::Sensitivity::Sensitive => w::Sensitivity::Sensitive,
    }
}
fn to_wire_type(value: &d::ValueType) -> Result<w::ValueType, Error> {
    use d::ValueType as S;
    use w::ValueType as T;
    Ok(match value {
        S::Record { properties } => T::Record {
            properties: properties
                .iter()
                .map(|(k, p)| {
                    Ok((
                        k.clone(),
                        w::Property {
                            value_type: to_wire_type(&p.value_type)?,
                            required: p.required,
                        },
                    ))
                })
                .collect::<Result<_, Error>>()?,
        },
        S::String {
            max_length,
            allow_empty,
        } => T::String {
            max_length: *max_length,
            allow_empty: *allow_empty,
        },
        S::Enum { values } => T::Enum {
            values: values.clone(),
        },
        S::Integer => T::Integer,
        S::Number => T::Number,
        S::Boolean => T::Boolean,
        S::Time => T::Time,
        S::Array { items, max_items } => T::Array {
            items: Box::new(to_wire_type(items)?),
            max_items: *max_items,
        },
        S::Object { properties } => T::Object {
            properties: properties
                .iter()
                .map(|(k, v)| Ok((k.clone(), to_wire_type(v)?)))
                .collect::<Result<_, Error>>()?,
        },
    })
}
/// Convert an Inventory definition to its current Agent DTO.
pub fn to_wire_field(value: &d::FieldDefinition) -> Result<w::FieldDefinition, Error> {
    Ok(w::FieldDefinition {
        time_series: value.time_series.as_ref().map(binding_to_wire),
        key: w::FieldKey::parse(value.key.as_str()).map_err(|_| Error::Malformed)?,
        version: value.version,
        value_type: to_wire_type(&value.value_type)?,
        nullable: value.nullable,
        manual: value.manual,
        sources: value
            .sources
            .iter()
            .map(|(k, v)| (to_wire_source(*k), *v))
            .collect(),
        platforms: value
            .platforms
            .iter()
            .map(|v| to_wire_platform(*v))
            .collect(),
        sensitivity: to_wire_sensitivity(value.sensitivity),
        unit: value.unit.clone(),
        searchable: value.searchable,
        item_key: value.item_key.clone(),
    })
}
/// Convert a device-scoped collection without transferring publication authority.
pub fn to_wire(value: &d::CollectionDefinition) -> Result<w::CollectionDefinition, Error> {
    if value
        .bindings()
        .iter()
        .any(|f| f.scope != d::CollectionScope::Device)
    {
        return Err(Error::Malformed);
    }
    w::CollectionDefinition::new(
        value.dataset(),
        value.version(),
        to_wire_source(value.source()),
        value
            .fields()
            .map(to_wire_field)
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(|_| Error::Malformed)
}
fn to_domain_source(value: w::Source) -> d::Source {
    match value {
        w::Source::AgentScript => d::Source::AgentScript,
        w::Source::AgentNative => d::Source::AgentNative,
        w::Source::AgentOsquery => d::Source::AgentOsquery,
        w::Source::MdmApple => d::Source::MdmApple,
        w::Source::AgentBuiltin => d::Source::AgentBuiltin,
        w::Source::Manual => d::Source::Manual,
        w::Source::MdmWindows => d::Source::MdmWindows,
    }
}
fn to_domain_platform(value: w::Platform) -> d::Platform {
    match value {
        w::Platform::Windows => d::Platform::Windows,
        w::Platform::Macos => d::Platform::Macos,
    }
}
fn to_domain_sensitivity(value: w::Sensitivity) -> d::Sensitivity {
    match value {
        w::Sensitivity::Standard => d::Sensitivity::Standard,
        w::Sensitivity::Sensitive => d::Sensitivity::Sensitive,
    }
}
fn to_domain_type(value: &w::ValueType) -> d::ValueType {
    use d::ValueType as T;
    use w::ValueType as S;
    match value {
        S::Record { properties } => T::Record {
            properties: properties
                .iter()
                .map(|(k, p)| {
                    (
                        k.clone(),
                        d::Property {
                            value_type: to_domain_type(&p.value_type),
                            required: p.required,
                        },
                    )
                })
                .collect(),
        },
        S::String {
            max_length,
            allow_empty,
        } => T::String {
            max_length: *max_length,
            allow_empty: *allow_empty,
        },
        S::Enum { values } => T::Enum {
            values: values.clone(),
        },
        S::Integer => T::Integer,
        S::Number => T::Number,
        S::Boolean => T::Boolean,
        S::Time => T::Time,
        S::Array { items, max_items } => T::Array {
            items: Box::new(to_domain_type(items)),
            max_items: *max_items,
        },
        S::Object { properties } => T::Object {
            properties: properties
                .iter()
                .map(|(k, v)| (k.clone(), to_domain_type(v)))
                .collect(),
        },
    }
}
/// Reconstruct domain field data; the collection/domain constructor validates its meaning.
pub fn to_domain_field(value: &w::FieldDefinition) -> Result<d::FieldDefinition, Error> {
    Ok(d::FieldDefinition {
        time_series: value.time_series.as_ref().map(binding_to_domain),
        key: d::FieldKey::parse(value.key.as_str()).map_err(|_| Error::Malformed)?,
        version: value.version,
        value_type: to_domain_type(&value.value_type),
        nullable: value.nullable,
        manual: value.manual,
        sources: value
            .sources
            .iter()
            .map(|(k, v)| (to_domain_source(*k), *v))
            .collect(),
        platforms: value
            .platforms
            .iter()
            .map(|v| to_domain_platform(*v))
            .collect(),
        sensitivity: to_domain_sensitivity(value.sensitivity),
        unit: value.unit.clone(),
        searchable: value.searchable,
        item_key: value.item_key.clone(),
    })
}
/// Convert the Agent DTO through the Inventory collection constructor.
pub fn to_domain(value: &w::CollectionDefinition) -> Result<d::CollectionDefinition, Error> {
    d::CollectionDefinition::new(
        value.dataset(),
        value.version(),
        to_domain_source(value.source()),
        value
            .fields()
            .iter()
            .map(|f| {
                to_domain_field(f).map(|definition| d::CollectionField {
                    definition,
                    scope: d::CollectionScope::Device,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(|_| Error::Malformed)
}
/// Preserve exact typed numbers, nulls and object/array structure.
pub fn scalar(value: &w::Scalar) -> d::Scalar {
    match value {
        w::Scalar::String(v) => d::Scalar::String(v.clone()),
        w::Scalar::Integer(v) => d::Scalar::Integer(*v),
        w::Scalar::Number(v) => d::Scalar::Number(*v),
        w::Scalar::Boolean(v) => d::Scalar::Boolean(*v),
        w::Scalar::Time(v) => d::Scalar::Time(*v),
        w::Scalar::Array(v) => d::Scalar::Array(v.iter().map(scalar).collect()),
        w::Scalar::Object(v) => {
            d::Scalar::Object(v.iter().map(|(k, v)| (k.clone(), scalar(v))).collect())
        }
    }
}
/// Select declared attributes without modifying the raw input, then validate Inventory semantics.
pub fn project_scalar(
    value: &w::Scalar,
    definition: &d::FieldDefinition,
) -> Result<w::Scalar, Error> {
    let w::CollectedValue::Value(projected) = w::CollectedValue::Value(value.clone())
        .project(&to_wire_field(definition)?)
        .map_err(|_| Error::Malformed)?
    else {
        return Err(Error::Malformed);
    };
    definition
        .validate_scalar(&scalar(&projected))
        .map_err(|_| Error::Malformed)?;
    Ok(projected)
}
/// Preserve explicit outcome distinctions at the Inventory boundary.
pub fn value(value: &w::CollectedValue) -> d::CollectedValue {
    match value {
        w::CollectedValue::Value(v) => d::CollectedValue::Value(scalar(v)),
        w::CollectedValue::Null => d::CollectedValue::Null,
        w::CollectedValue::Deleted => d::CollectedValue::Deleted,
        w::CollectedValue::Unsupported => d::CollectedValue::Unsupported,
    }
}

fn binding_to_wire(value: &d::TimeSeriesBinding) -> w::TimeSeriesBinding {
    w::TimeSeriesBinding {
        kind: match value.kind {
            d::TelemetryKind::Gauge => w::TelemetryKind::Gauge,
            d::TelemetryKind::CumulativeCounter => w::TelemetryKind::CumulativeCounter,
            d::TelemetryKind::DeltaCounter => w::TelemetryKind::DeltaCounter,
            d::TelemetryKind::State => w::TelemetryKind::State,
        },
        value_path: value.value_path.clone(),
        interval_start_path: value.interval_start_path.clone(),
        dimensions: value
            .dimensions
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    w::TelemetryDimension {
                        path: v.path.clone(),
                        values: v.values.clone(),
                    },
                )
            })
            .collect(),
        aggregations: value
            .aggregations
            .iter()
            .map(|v| match v {
                d::TelemetryAggregation::Min => w::TelemetryAggregation::Min,
                d::TelemetryAggregation::Max => w::TelemetryAggregation::Max,
                d::TelemetryAggregation::Sum => w::TelemetryAggregation::Sum,
                d::TelemetryAggregation::Count => w::TelemetryAggregation::Count,
                d::TelemetryAggregation::Mean => w::TelemetryAggregation::Mean,
                d::TelemetryAggregation::Increase => w::TelemetryAggregation::Increase,
                d::TelemetryAggregation::Rate => w::TelemetryAggregation::Rate,
                d::TelemetryAggregation::Timeline => w::TelemetryAggregation::Timeline,
                d::TelemetryAggregation::Transitions => w::TelemetryAggregation::Transitions,
                d::TelemetryAggregation::Coverage => w::TelemetryAggregation::Coverage,
            })
            .collect(),
        retention: w::RetentionReference {
            key: value.retention.key.clone(),
            revision: value.retention.revision,
        },
        max_resources: value.max_resources,
    }
}

fn binding_to_domain(value: &w::TimeSeriesBinding) -> d::TimeSeriesBinding {
    d::TimeSeriesBinding {
        kind: match value.kind {
            w::TelemetryKind::Gauge => d::TelemetryKind::Gauge,
            w::TelemetryKind::CumulativeCounter => d::TelemetryKind::CumulativeCounter,
            w::TelemetryKind::DeltaCounter => d::TelemetryKind::DeltaCounter,
            w::TelemetryKind::State => d::TelemetryKind::State,
        },
        value_path: value.value_path.clone(),
        interval_start_path: value.interval_start_path.clone(),
        dimensions: value
            .dimensions
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    d::TelemetryDimension {
                        path: v.path.clone(),
                        values: v.values.clone(),
                    },
                )
            })
            .collect(),
        aggregations: value
            .aggregations
            .iter()
            .map(|v| match v {
                w::TelemetryAggregation::Min => d::TelemetryAggregation::Min,
                w::TelemetryAggregation::Max => d::TelemetryAggregation::Max,
                w::TelemetryAggregation::Sum => d::TelemetryAggregation::Sum,
                w::TelemetryAggregation::Count => d::TelemetryAggregation::Count,
                w::TelemetryAggregation::Mean => d::TelemetryAggregation::Mean,
                w::TelemetryAggregation::Increase => d::TelemetryAggregation::Increase,
                w::TelemetryAggregation::Rate => d::TelemetryAggregation::Rate,
                w::TelemetryAggregation::Timeline => d::TelemetryAggregation::Timeline,
                w::TelemetryAggregation::Transitions => d::TelemetryAggregation::Transitions,
                w::TelemetryAggregation::Coverage => d::TelemetryAggregation::Coverage,
            })
            .collect(),
        retention: d::RetentionReference {
            key: value.retention.key.clone(),
            revision: value.retention.revision,
        },
        max_resources: value.max_resources,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collection_conversion_preserves_domain_meaning_and_coverage() {
        let fields = d::builtin::fields()
            .into_iter()
            .filter(|field| field.sources.contains_key(&d::Source::AgentBuiltin))
            .collect();
        let original = d::CollectionDefinition::new("inventory", "1", d::Source::AgentBuiltin, {
            let scope = d::CollectionScope::Device;
            let fields: Vec<rss_mdm_inventory::FieldDefinition> = fields;
            fields
                .into_iter()
                .map(|definition| rss_mdm_inventory::CollectionField {
                    definition,
                    scope: scope.clone(),
                })
                .collect()
        })
        .unwrap();
        let wire = to_wire(&original).unwrap();
        assert_ne!(original.fingerprint().unwrap(), wire.fingerprint().unwrap());
        let restored = to_domain(&wire).unwrap();
        assert_eq!(original, restored);
        assert_eq!(original.coverage().unwrap(), restored.coverage().unwrap());
    }
    #[test]
    fn field_outcomes_keep_explicit_null_deletion_unsupported_and_numeric_encoding() {
        for json in [
            r#"{"kind":"null"}"#,
            r#"{"kind":"deleted"}"#,
            r#"{"kind":"unsupported"}"#,
            r#"{"kind":"value","value":{"kind":"number","value":1.0}}"#,
            r#"{"kind":"value","value":{"kind":"array","value":[{"kind":"integer","value":2},{"kind":"integer","value":1}]}}"#,
            r#"{"kind":"value","value":{"kind":"object","value":{"z":{"kind":"boolean","value":false},"a":{"kind":"string","value":""}}}}"#,
        ] {
            let wire: w::CollectedValue = serde_json::from_str(json).unwrap();
            let original: d::CollectedValue = serde_json::from_str(json).unwrap();
            assert_eq!(value(&wire), original);
            assert_eq!(
                serde_json::to_vec(&wire).unwrap(),
                serde_json::to_vec(&original).unwrap()
            );
        }
    }
}
