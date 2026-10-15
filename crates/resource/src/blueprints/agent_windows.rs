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
// ref: microsoft/WSL tools/deploy/deploy-to-host.ps1@6747ae808acd3895ed1b23ffdb8aa9d4b6978066
fn registry(path: &str, name: &str) -> w::NativeQuery {
    query(
        w::NativeQueryDefinition::WindowsRegistry {
            hive: w::RegistryHive::LocalMachine,
            view: w::RegistryView::Registry64,
            path: path.into(),
            enumerate_subkeys: false,
            values: [(
                name.into(),
                w::RegistryValue {
                    name: name.into(),
                    value_type: w::RegistryType::Sz,
                },
            )]
            .into(),
        },
        false,
        &[],
    )
}
fn codes(values: &[(&str, &str)]) -> Conversion {
    Conversion::Enum {
        values: values
            .iter()
            .map(|(from, to)| ((*from).into(), serde_json::Value::from(*to)))
            .collect(),
    }
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
        version: if matches!(id, "identity" | "software") {
            "2"
        } else {
            "1"
        }
        .into(),
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
                (
                    "edition",
                    registry(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID"),
                ),
                (
                    "architecture",
                    registry(
                        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                        "PROCESSOR_ARCHITECTURE",
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
                ("device.os.edition", mapping("edition", "/EditionID", I)),
                (
                    "device.architecture",
                    mapping(
                        "architecture",
                        "/PROCESSOR_ARCHITECTURE",
                        codes(&[("AMD64", "x86_64"), ("ARM64", "aarch64")]),
                    ),
                ),
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
                        (
                            "installation_state",
                            "/origin",
                            codes(&[
                                ("win32.uninstall.32", "installed"),
                                ("win32.uninstall.64", "installed"),
                                ("msix.registered", "registered"),
                                ("msix.provisioned", "provisioned"),
                            ]),
                        ),
                        ("location", "/location", I),
                    ],
                ),
            )],
        ),
    ]
}
