use rss_mdm_agent_wire::runtime::*;
use std::collections::BTreeMap;

pub fn projection(
    plan: &NativeCollectionPlan,
) -> (
    Vec<FieldDefinition>,
    BTreeMap<String, AgentCollectionMapping>,
) {
    let (query_id, query) = plan.spec().queries.first_key_value().unwrap();
    let properties = query.definition.properties();
    let key = if properties.contains_key("id") {
        "id"
    } else {
        properties.first_key_value().unwrap().0.as_str()
    };
    let ty = match &properties[key] {
        NativeType::Integer => ValueType::Integer,
        NativeType::Number => ValueType::Number,
        NativeType::Boolean => ValueType::Boolean,
        _ => ValueType::String {
            max_length: 4096,
            allow_empty: true,
        },
    };
    let list = query.cardinality == NativeCardinality::List;
    let mapping = if list {
        ValueMapping {
            pointer: String::new(),
            conversion: Conversion::Identity,
            columns: [("value".into(), ValueMapping::identity(format!("/{key}")))].into(),
        }
    } else {
        ValueMapping::identity(format!("/{key}"))
    };
    let value_type = if list {
        ValueType::Array {
            items: Box::new(ValueType::Object {
                properties: [("value".into(), ty)].into(),
            }),
            max_items: 4096,
        }
    } else {
        ty
    };
    let field = FieldDefinition {
        key: FieldKey::parse("custom.vector").unwrap(),
        version: 1,
        value_type,
        nullable: false,
        manual: false,
        sources: [(Source::AgentNative, 0)].into(),
        platforms: [match plan.platform() {
            TaskPlatform::Windows => Platform::Windows,
            TaskPlatform::Macos => Platform::Macos,
        }]
        .into(),
        sensitivity: Sensitivity::Standard,
        unit: None,
        searchable: false,
        item_key: None,
        time_series: None,
    };
    (
        vec![field],
        [(
            "custom.vector".into(),
            AgentCollectionMapping {
                query: query_id.clone(),
                mapping,
                missing: NativeMissing::Missing,
                counter_normalization: None,
            },
        )]
        .into(),
    )
}
