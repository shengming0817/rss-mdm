//! Windows Agent templates; ordinary tenant Resources, never implicit Script fallbacks.
//! ref: microsoft/windows-rs crates/libs/windows/src/Windows/Win32/System/Wmi/mod.rs@0.61.0
use super::*;
use rss_mdm_agent_wire::{CollectionScope, runtime as w};
fn budget() -> w::NativeBudget {
    w::NativeBudget {
        timeout_seconds: 300,
        output_bytes: 16 * 1024 * 1024,
        max_rows: 65535,
    }
}
fn query(definition: w::NativeQueryDefinition, list: bool, keys: &[&str]) -> w::NativeQuery {
    w::NativeQuery {
        version: 1,
        definition,
        cardinality: if list {
            w::NativeCardinality::List
        } else {
            w::NativeCardinality::ExactlyOne
        },
        instance_keys: keys.iter().map(|s| (*s).into()).collect(),
        budget: budget(),
    }
}
fn wmi(
    class: &str,
    properties: &[(&str, w::CimType)],
    list: bool,
    keys: &[&str],
) -> w::NativeQuery {
    query(
        w::NativeQueryDefinition::WindowsWmi {
            namespace: "root\\cimv2".into(),
            class: class.into(),
            properties: properties
                .iter()
                .map(|(name, t)| {
                    (
                        (*name).into(),
                        w::WmiProperty {
                            cim_type: *t,
                            array: false,
                        },
                    )
                })
                .collect(),
            filter: None,
        },
        list,
        keys,
    )
}
fn mapping(query: &str, pointer: &str, conversion: Conversion) -> AgentCollectionMapping {
    AgentCollectionMapping {
        query: query.into(),
        mapping: ValueMapping {
            pointer: pointer.into(),
            conversion,
            columns: Default::default(),
        },
        missing: NativeMissing::Missing,
    }
}
fn pack(
    id: &str,
    category: &str,
    queries: Vec<(&str, w::NativeQuery)>,
    mappings: Vec<(&str, AgentCollectionMapping)>,
) -> Blueprint {
    Blueprint {
        id: format!("windows.agent.{id}"),
        version: "1".into(),
        category: category.into(),
        platform: Platform::Windows,
        definition: Definition::AgentCollection {
            template: AgentCollectionDefinition::new(AgentCollectionSpec {
                plan: w::NativeCollectionPlan::new(w::NativePlanSpec {
                    version: 1,
                    scope: CollectionScope::Device,
                    queries: queries.into_iter().map(|(k, v)| (k.into(), v)).collect(),
                    budget: budget(),
                })
                .expect("official native plan"),
                mappings: mappings.into_iter().map(|(k, v)| (k.into(), v)).collect(),
            })
            .expect("official native mapping"),
        },
    }
}
fn list(query: &str, columns: &[(&str, &str, Conversion)]) -> AgentCollectionMapping {
    AgentCollectionMapping {
        query: query.into(),
        missing: NativeMissing::Missing,
        mapping: ValueMapping {
            pointer: "".into(),
            conversion: Conversion::Identity,
            columns: columns
                .iter()
                .map(|(k, p, c)| {
                    (
                        (*k).into(),
                        ValueMapping {
                            pointer: (*p).into(),
                            conversion: c.clone(),
                            columns: Default::default(),
                        },
                    )
                })
                .collect(),
        },
    }
}
pub(super) fn catalog() -> Vec<Blueprint> {
    use Conversion::Identity as I;
    use w::CimType::*;
    vec![
        pack(
            "identity",
            "identity",
            vec![
                (
                    "system",
                    wmi(
                        "Win32_ComputerSystem",
                        &[("Model", String), ("Manufacturer", String)],
                        false,
                        &[],
                    ),
                ),
                (
                    "product",
                    wmi(
                        "Win32_ComputerSystemProduct",
                        &[("UUID", String)],
                        false,
                        &[],
                    ),
                ),
                (
                    "bios",
                    wmi("Win32_BIOS", &[("SerialNumber", String)], false, &[]),
                ),
                (
                    "os",
                    wmi(
                        "Win32_OperatingSystem",
                        &[
                            ("Caption", String),
                            ("Version", String),
                            ("BuildNumber", String),
                        ],
                        false,
                        &[],
                    ),
                ),
            ],
            vec![
                ("device.model", mapping("system", "/Model", I)),
                ("device.manufacturer", mapping("system", "/Manufacturer", I)),
                ("device.hardware_uuid", mapping("product", "/UUID", I)),
                ("device.serial_number", mapping("bios", "/SerialNumber", I)),
                ("device.os.name", mapping("os", "/Caption", I)),
                ("device.os.version", mapping("os", "/Version", I)),
                ("device.os.build", mapping("os", "/BuildNumber", I)),
            ],
        ),
        pack(
            "cpu",
            "hardware",
            vec![(
                "cpu",
                query(w::NativeQueryDefinition::WindowsCpu, false, &[]),
            )],
            vec![
                ("device.cpu.model", mapping("cpu", "/model", I)),
                (
                    "device.cpu.physical_cores",
                    mapping("cpu", "/physical_cores", I),
                ),
                (
                    "device.cpu.logical_cores",
                    mapping("cpu", "/logical_cores", I),
                ),
            ],
        ),
        pack(
            "memory",
            "hardware",
            vec![(
                "memory",
                wmi(
                    "Win32_ComputerSystem",
                    &[("TotalPhysicalMemory", Uint64)],
                    false,
                    &[],
                ),
            )],
            vec![(
                "device.memory.bytes",
                mapping("memory", "/TotalPhysicalMemory", Conversion::Integer),
            )],
        ),
        pack(
            "firmware",
            "hardware",
            vec![(
                "firmware",
                wmi("Win32_BIOS", &[("SMBIOSBIOSVersion", String)], false, &[]),
            )],
            vec![(
                "device.firmware.version",
                mapping("firmware", "/SMBIOSBIOSVersion", I),
            )],
        ),
        pack(
            "disks",
            "hardware",
            vec![(
                "disks",
                wmi(
                    "Win32_DiskDrive",
                    &[("DeviceID", String), ("Model", String), ("Size", Uint64)],
                    true,
                    &["DeviceID"],
                ),
            )],
            vec![(
                "device.storage.devices",
                list(
                    "disks",
                    &[
                        ("id", "/DeviceID", I),
                        ("name", "/Model", I),
                        ("size_bytes", "/Size", Conversion::Integer),
                    ],
                ),
            )],
        ),
        pack(
            "volumes",
            "hardware",
            vec![(
                "volumes",
                wmi(
                    "Win32_Volume",
                    &[
                        ("DeviceID", String),
                        ("Name", String),
                        ("FileSystem", String),
                        ("Capacity", Uint64),
                        ("FreeSpace", Uint64),
                        ("BootVolume", Boolean),
                    ],
                    true,
                    &["DeviceID"],
                ),
            )],
            vec![(
                "device.storage.volumes",
                list(
                    "volumes",
                    &[
                        ("id", "/DeviceID", I),
                        ("name", "/Name", I),
                        ("filesystem", "/FileSystem", I),
                        ("size_bytes", "/Capacity", Conversion::Integer),
                        ("free_bytes", "/FreeSpace", Conversion::Integer),
                        ("system_volume", "/BootVolume", I),
                    ],
                ),
            )],
        ),
        pack(
            "network",
            "hardware",
            vec![(
                "network",
                query(w::NativeQueryDefinition::WindowsNetwork, true, &["id"]),
            )],
            vec![(
                "device.network.interfaces",
                list(
                    "network",
                    &[
                        ("id", "/id", I),
                        ("name", "/name", I),
                        ("addresses", "/addresses", I),
                    ],
                ),
            )],
        ),
        pack(
            "battery",
            "hardware",
            vec![(
                "battery",
                query(w::NativeQueryDefinition::WindowsBattery, false, &[]),
            )],
            vec![(
                "device.battery.charge_percent",
                mapping("battery", "/charge_percent", I),
            )],
        ),
        pack(
            "software",
            "software",
            vec![(
                "software",
                query(w::NativeQueryDefinition::WindowsSoftware, true, &["id"]),
            )],
            vec![(
                "device.software.installations",
                list(
                    "software",
                    &[
                        ("id", "/id", I),
                        ("native_id", "/native_id", I),
                        ("name", "/name", I),
                        ("version", "/version", I),
                        ("publisher", "/publisher", I),
                        ("scope", "/scope", I),
                        ("owner", "/owner", I),
                        ("origin", "/origin", I),
                        ("location", "/location", I),
                    ],
                ),
            )],
        ),
    ]
}
