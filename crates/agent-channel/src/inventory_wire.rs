//! Explicit protocol/domain conversion; only Inventory creates coverage and stored values.
use crate::Error;
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_inventory as d;
fn to_wire_source(value: d::Source) -> w::Source {
    match value {
        d::Source::AgentScript => w::Source::AgentScript,
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
fn to_wire_type(value: &d::ValueType) -> w::ValueType {
    use d::ValueType as S;
    use w::ValueType as T;
    match value {
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
            items: Box::new(to_wire_type(items)),
            max_items: *max_items,
        },
        S::Object { properties } => T::Object {
            properties: properties
                .iter()
                .map(|(k, v)| (k.clone(), to_wire_type(v)))
                .collect(),
        },
    }
}
fn to_wire_field(value: &d::FieldDefinition) -> Result<w::FieldDefinition, Error> {
    Ok(w::FieldDefinition {
        key: w::FieldKey::parse(value.key.as_str()).map_err(|_| Error::Malformed)?,
        version: value.version,
        value_type: to_wire_type(&value.value_type),
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
pub(crate) fn to_wire(value: &d::CollectionDefinition) -> Result<w::CollectionDefinition, Error> {
    w::CollectionDefinition::new(
        value.dataset(),
        value.version(),
        to_wire_source(value.source()),
        value
            .fields()
            .iter()
            .map(to_wire_field)
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(|_| Error::Malformed)
}
fn to_domain_source(value: w::Source) -> d::Source {
    match value {
        w::Source::AgentScript => d::Source::AgentScript,
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
fn to_domain_field(value: &w::FieldDefinition) -> Result<d::FieldDefinition, Error> {
    Ok(d::FieldDefinition {
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
pub(crate) fn to_domain(value: &w::CollectionDefinition) -> Result<d::CollectionDefinition, Error> {
    d::CollectionDefinition::new(
        value.dataset(),
        value.version(),
        to_domain_source(value.source()),
        value
            .fields()
            .iter()
            .map(to_domain_field)
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(|_| Error::Malformed)
}
fn scalar(value: &w::Scalar) -> d::Scalar {
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
pub(crate) fn value(value: &w::CollectedValue) -> d::CollectedValue {
    match value {
        w::CollectedValue::Value(v) => d::CollectedValue::Value(scalar(v)),
        w::CollectedValue::Null => d::CollectedValue::Null,
        w::CollectedValue::Deleted => d::CollectedValue::Deleted,
        w::CollectedValue::Unsupported => d::CollectedValue::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_collection_conversion_preserves_bytes_fingerprint_and_coverage() {
        let fields = d::builtin::fields()
            .into_iter()
            .filter(|field| field.sources.contains_key(&d::Source::AgentBuiltin))
            .collect();
        let original =
            d::CollectionDefinition::new("inventory", "1", d::Source::AgentBuiltin, fields)
                .unwrap();
        let wire = to_wire(&original).unwrap();
        assert_eq!(
            serde_json::to_vec(&original).unwrap(),
            serde_json::to_vec(&wire).unwrap()
        );
        assert_eq!(original.fingerprint().unwrap(), wire.fingerprint().unwrap());
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
