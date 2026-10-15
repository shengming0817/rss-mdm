//! Closed macOS Agent recipes. Field scopes are bound from the signed execution offer.
//! ref: osquery/osquery osquery/tables/system/darwin/apps.mm@5.23.1
//! ref: Homebrew/brew Library/Homebrew/cmd/info.rb@7cce6eac8d897b0b8440e16f33dbcb21770da7cf
//! ref: osquery/osquery specs/darwin/package_receipts.table@5.23.1
use super::*;
use rss_mdm_agent_wire::{CollectionScope, runtime as w};
fn budget() -> w::NativeBudget {
    w::NativeBudget {
        timeout_seconds: 300,
        output_bytes: 16 * 1024 * 1024,
        max_rows: 65535,
    }
}
fn scalar(pointer: &str, conversion: Conversion) -> ValueMapping {
    ValueMapping {
        pointer: pointer.into(),
        conversion,
        columns: Default::default(),
    }
}
fn columns(items: &[(&str, &str, Conversion)]) -> ValueMapping {
    ValueMapping {
        pointer: String::new(),
        conversion: Conversion::Identity,
        columns: items
            .iter()
            .map(|(name, path, conversion)| ((*name).into(), scalar(path, conversion.clone())))
            .collect(),
    }
}
fn pack(
    id: &str,
    definition: w::NativeQueryDefinition,
    mappings: Vec<(&str, ValueMapping)>,
) -> Blueprint {
    let cardinality = match definition {
        w::NativeQueryDefinition::MacosHardware { section } => section.cardinality(),
        _ => w::NativeCardinality::List,
    };
    let query = w::NativeQuery {
        version: 1,
        definition,
        cardinality,
        instance_keys: if cardinality == w::NativeCardinality::List {
            vec!["id".into()]
        } else {
            vec![]
        },
        budget: budget(),
    };
    let mut queries = std::collections::BTreeMap::from([(id.into(), query)]);
    if id == "volumes" {
        queries.insert(
            "apfs_containers".into(),
            w::NativeQuery {
                version: 1,
                definition: w::NativeQueryDefinition::MacosHardware {
                    section: w::MacosHardwareSection::ApfsContainers,
                },
                cardinality: w::NativeCardinality::List,
                instance_keys: vec!["id".into()],
                budget: budget(),
            },
        );
    }
    Blueprint {
        id: format!("macos.agent.{id}"),
        version: "1".into(),
        category: if id == "receipts" || id.starts_with("applications") || id.starts_with("brew") {
            "software"
        } else {
            "hardware"
        }
        .into(),
        platform: Platform::MacOS,
        definition: Definition::AgentCollection {
            template: AgentCollectionDefinition::new(AgentCollectionSpec {
                plan: w::NativeCollectionPlan::new(w::NativePlanSpec {
                    version: 1,
                    scope: CollectionScope::Device,
                    queries,
                    budget: budget(),
                })
                .expect("official macOS plan"),
                mappings: mappings
                    .into_iter()
                    .map(|(field, mapping)| {
                        (
                            field.into(),
                            AgentCollectionMapping {
                                query: id.into(),
                                mapping,
                                missing: NativeMissing::Missing,
                            },
                        )
                    })
                    .collect(),
            })
            .expect("official macOS mapping"),
        },
    }
}
pub(super) fn catalog() -> Vec<Blueprint> {
    use Conversion::{Identity as I, Integer as N};
    use w::{MacosHardwareSection as H, NativeQueryDefinition::MacosHardware};
    let mut catalog = vec![
        pack(
            "identity",
            MacosHardware {
                section: H::Identity,
            },
            vec![
                ("device.hardware_uuid", scalar("/hardware_uuid", I)),
                ("device.serial_number", scalar("/serial", I)),
                ("device.model", scalar("/model", I)),
            ],
        ),
        pack(
            "os",
            MacosHardware { section: H::Os },
            vec![
                ("device.os.name", scalar("/name", I)),
                ("device.os.version", scalar("/version", I)),
                ("device.os.build", scalar("/build", I)),
            ],
        ),
        pack(
            "cpu",
            MacosHardware { section: H::Cpu },
            vec![
                ("device.cpu.model", scalar("/model", I)),
                ("device.cpu.physical_cores", scalar("/physical_cores", I)),
                ("device.cpu.logical_cores", scalar("/logical_cores", I)),
            ],
        ),
        pack(
            "memory",
            MacosHardware { section: H::Memory },
            vec![("device.memory.bytes", scalar("/total_bytes", N))],
        ),
        pack(
            "firmware",
            MacosHardware {
                section: H::Firmware,
            },
            vec![("device.firmware.version", scalar("/version", I))],
        ),
        pack(
            "disks",
            MacosHardware { section: H::Disks },
            vec![(
                "device.storage.devices",
                columns(&[
                    ("id", "/id", I),
                    ("name", "/model", I),
                    ("size_bytes", "/size_bytes", N),
                ]),
            )],
        ),
        pack(
            "volumes",
            MacosHardware {
                section: H::Volumes,
            },
            vec![(
                "device.storage.volumes",
                columns(&[
                    ("id", "/id", I),
                    ("name", "/name", I),
                    ("filesystem", "/filesystem", I),
                    ("size_bytes", "/size_bytes", N),
                    ("free_bytes", "/free_bytes", N),
                    ("system_volume", "/system_volume", I),
                ]),
            )],
        ),
        pack(
            "network",
            MacosHardware {
                section: H::Network,
            },
            vec![(
                "device.network.interfaces",
                columns(&[
                    ("id", "/id", I),
                    ("name", "/name", I),
                    ("addresses", "/addresses", I),
                ]),
            )],
        ),
        pack(
            "battery",
            MacosHardware {
                section: H::Battery,
            },
            vec![(
                "device.battery.charge_percent",
                scalar("/charge_percent", I),
            )],
        ),
        pack(
            "receipts",
            w::NativeQueryDefinition::MacosPkgReceipts {},
            vec![(
                "device.software.receipts",
                columns(&[
                    ("id", "/id", I),
                    ("native_id", "/native_id", I),
                    ("name", "/name", I),
                    ("version", "/version", I),
                    ("publisher", "/publisher", I),
                    ("scope", "/scope", I),
                    ("owner", "/owner", I),
                    ("origin", "/origin", I),
                    ("location", "/location", I),
                ]),
            )],
        ),
    ];
    let software = || {
        columns(&[
            ("id", "/id", I),
            ("native_id", "/native_id", I),
            ("name", "/name", I),
            ("version", "/version", I),
            ("publisher", "/publisher", I),
            ("scope", "/scope", I),
            ("owner", "/owner", I),
            ("origin", "/origin", I),
            ("location", "/location", I),
        ])
    };
    for (id, root) in [
        (
            "applications_local",
            w::MacosApplicationRoot::LocalApplications,
        ),
        (
            "applications_system",
            w::MacosApplicationRoot::SystemApplications,
        ),
        (
            "applications_user",
            w::MacosApplicationRoot::UserApplications,
        ),
    ] {
        let mut mapping = software();
        mapping.columns.insert(
            "installation_state".into(),
            scalar(
                "/origin",
                Conversion::Enum {
                    values: [("application".into(), serde_json::json!("installed"))].into(),
                },
            ),
        );
        catalog.push(pack(
            id,
            w::NativeQueryDefinition::MacosApplications { root, max_depth: 4 },
            vec![("device.software.installations", mapping)],
        ));
    }
    for (prefix_name, prefix) in [("arm", "/opt/homebrew"), ("intel", "/usr/local")] {
        for (kind, package) in [
            ("formula", w::MacosBrewPackage::Formula),
            ("cask", w::MacosBrewPackage::Cask),
        ] {
            catalog.push(pack(
                &format!("brew_{prefix_name}_{kind}"),
                w::NativeQueryDefinition::MacosBrew {
                    prefix: prefix.into(),
                    package,
                    taps: Default::default(),
                },
                vec![("device.software.packages", software())],
            ));
        }
    }
    catalog
}
