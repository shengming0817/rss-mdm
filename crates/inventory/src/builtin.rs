//! Product-owned seed definitions. All consumers use the same Catalog lookup as custom fields.
use crate::*;
use std::collections::BTreeMap;
/// Hardware model.
pub const MODEL: FieldKey = FieldKey::literal("device.model");
/// Operating system version.
pub const OS_VERSION: FieldKey = FieldKey::literal("device.os.version");
/// Agent installation observed through native MDM.
pub const AGENT_INSTALLATION: FieldKey = FieldKey::literal("channel.agent.installation");
/// MDM enrollment observed through Agent.
pub const MDM_ENROLLMENT: FieldKey = FieldKey::literal("channel.mdm.enrollment");
/// Corporate agent's version.
pub const CORPORATE_AGENT_VERSION: FieldKey = FieldKey::literal("custom.corporate_agent.version");
/// Corporate agent's health.
pub const CORPORATE_AGENT_HEALTHY: FieldKey = FieldKey::literal("custom.corporate_agent.healthy");
/// Ordinary osquery version observation.
pub const OSQUERY_VERSION: FieldKey = FieldKey::literal("custom.osquery.version");
/// Organization asset tag.
pub const ASSET_TAG: FieldKey = FieldKey::literal("custom.asset_tag");
/// Office floor.
pub const OFFICE_FLOOR: FieldKey = FieldKey::literal("custom.office_floor");
/// Loaner designation.
pub const IS_LOANER: FieldKey = FieldKey::literal("custom.is_loaner");
/// Purchase timestamp.
pub const PURCHASE_DATE: FieldKey = FieldKey::literal("custom.purchase_date");
fn string() -> ValueType {
    ValueType::String {
        max_length: 256,
        allow_empty: false,
    }
}
fn vocabulary(values: &[&str]) -> ValueType {
    ValueType::Enum {
        values: values.iter().map(|v| (*v).into()).collect(),
    }
}
fn field(key: FieldKey, value_type: ValueType, sources: &[Source]) -> FieldDefinition {
    let manual = sources.contains(&Source::Manual);
    FieldDefinition {
        key,
        version: 1,
        value_type,
        nullable: manual,
        manual,
        sources: sources.iter().map(|s| (*s, 0)).collect(),
        platforms: [Platform::Windows, Platform::Macos].into(),
        sensitivity: Sensitivity::Standard,
        unit: None,
        searchable: true,
        item_key: None,
    }
}
/// Seed definitions are immutable inputs to the same published catalog, never a fallback reader.
pub fn fields() -> Vec<FieldDefinition> {
    use Source::*;
    let collected = &[
        MdmWindows,
        MdmApple,
        AgentBuiltin,
        AgentScript,
        AgentOsquery,
    ];
    let mut fields = vec![
        field(MODEL, string(), collected),
        field(OS_VERSION, string(), collected),
        field(
            AGENT_INSTALLATION,
            vocabulary(&["installed", "absent", "unknown"]),
            &[MdmWindows, MdmApple],
        ),
        field(
            MDM_ENROLLMENT,
            vocabulary(&[
                "this_organization",
                "other_organization",
                "unenrolled",
                "unknown",
            ]),
            &[AgentBuiltin],
        ),
        field(
            CORPORATE_AGENT_VERSION,
            string(),
            &[AgentScript, AgentOsquery],
        ),
        field(
            CORPORATE_AGENT_HEALTHY,
            ValueType::Boolean,
            &[AgentScript, AgentOsquery],
        ),
        field(OSQUERY_VERSION, string(), &[AgentOsquery]),
        field(ASSET_TAG, string(), &[Manual]),
        field(OFFICE_FLOOR, ValueType::Integer, &[Manual]),
        field(IS_LOANER, ValueType::Boolean, &[Manual]),
        field(PURCHASE_DATE, ValueType::Time, &[Manual]),
    ];
    for (name, kind, unit) in [
        ("device.serial_number", string(), None),
        ("device.manufacturer", string(), None),
        ("device.cpu.model", string(), None),
        ("device.cpu.logical_cores", ValueType::Integer, None),
        ("device.memory.bytes", ValueType::Integer, Some("bytes")),
        ("device.os.name", string(), None),
        ("device.os.build", string(), None),
        ("device.architecture", string(), None),
    ] {
        let mut definition = field(
            FieldKey::parse(name).expect("seed identity"),
            kind,
            collected,
        );
        definition.unit = unit.map(str::to_owned);
        fields.push(definition);
    }
    for (name, properties) in [
        (
            "device.storage.devices",
            vec![
                ("id", string()),
                ("name", string()),
                ("size_bytes", ValueType::Integer),
            ],
        ),
        (
            "device.network.interfaces",
            vec![
                ("id", string()),
                ("name", string()),
                (
                    "addresses",
                    ValueType::Array {
                        items: Box::new(string()),
                        max_items: 64,
                    },
                ),
            ],
        ),
        (
            "device.software.installed",
            vec![
                ("id", string()),
                ("name", string()),
                (
                    "version",
                    ValueType::String {
                        max_length: 256,
                        allow_empty: true,
                    },
                ),
                (
                    "publisher",
                    ValueType::String {
                        max_length: 256,
                        allow_empty: true,
                    },
                ),
                ("scope", string()),
            ],
        ),
    ] {
        let properties: BTreeMap<_, _> =
            properties.into_iter().map(|(k, v)| (k.into(), v)).collect();
        let mut definition = field(
            FieldKey::parse(name).expect("seed identity"),
            ValueType::Array {
                items: Box::new(ValueType::Object { properties }),
                max_items: 100000,
            },
            collected,
        );
        definition.item_key = Some("id".into());
        fields.push(definition);
    }
    fields
}
