//! Ordinary Agent Resource packages for local security, account, certificate and update facts.
//! ref: osquery/osquery osquery/tables/system/windows/bitlocker_info.cpp@5.23.1
//! ref: osquery/osquery osquery/tables/system/darwin/gatekeeper.cpp@5.23.1
use super::*;
use rss_mdm_agent_wire::{CollectionScope, runtime as w};
fn mapping(pointer: &str, conversion: Conversion) -> ValueMapping {
    ValueMapping {
        pointer: pointer.into(),
        conversion,
        columns: Default::default(),
    }
}
fn columns(query: &w::NativeQueryDefinition, omit: &[&str]) -> ValueMapping {
    ValueMapping {
        pointer: String::new(),
        conversion: Conversion::Identity,
        columns: query
            .properties()
            .keys()
            .filter(|k| !omit.contains(&k.as_str()))
            .map(|k| {
                (
                    k.clone(),
                    mapping(
                        &format!("/{k}"),
                        if matches!(k.as_str(), "not_before" | "not_after") {
                            Conversion::Integer
                        } else {
                            Conversion::Identity
                        },
                    ),
                )
            })
            .collect(),
    }
}
fn pack(
    id: &str,
    category: &str,
    query: w::NativeQueryDefinition,
    cardinality: w::NativeCardinality,
    mappings: Vec<(&str, ValueMapping)>,
) -> Blueprint {
    let platform = match query.platform() {
        w::TaskPlatform::Windows => Platform::Windows,
        w::TaskPlatform::Macos => Platform::MacOS,
    };
    let query = w::NativeQuery {
        version: query.engine().contract_version(),
        definition: query,
        cardinality,
        instance_keys: if cardinality == w::NativeCardinality::List {
            vec!["id".into()]
        } else {
            vec![]
        },
        budget: w::NativeBudget {
            timeout_seconds: 300,
            output_bytes: w::NATIVE_SYSTEM_MAX_BYTES,
            max_rows: 65535,
        },
    };
    let applicability = Applicability {
        minimum_os_version: Some(
            if platform == Platform::Windows {
                "10.0"
            } else {
                "12.0"
            }
            .into(),
        ),
        minimum_build: (platform == Platform::Windows).then_some(10240),
        editions: if matches!(
            query.definition,
            w::NativeQueryDefinition::System {
                query: w::NativeSystemQuery::WindowsBitlocker
            }
        ) {
            [
                "Professional",
                "ProfessionalN",
                "Enterprise",
                "EnterpriseN",
                "Education",
                "EducationN",
                "IoTEnterprise",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        } else {
            Default::default()
        },
        ..Default::default()
    };
    Blueprint {
        id: format!(
            "{}.agent.{id}",
            if platform == Platform::Windows {
                "windows"
            } else {
                "macos"
            }
        ),
        version: "1".into(),
        presentation: serde_json::json!({"category":category})
            .as_object()
            .unwrap()
            .clone(),
        platform,
        definition: Definition::AgentCollection {
            template: AgentCollectionDefinition::new(AgentCollectionSpec {
                // API/engine support is negotiated independently; these are product package bounds,
                // not a claim that all editions or physical machines have been tested.
                applicability,
                plan: w::NativeCollectionPlan::new(w::NativePlanSpec {
                    version: 1,
                    scope: CollectionScope::Device,
                    budget: query.budget,
                    queries: [("facts".into(), query)].into(),
                })
                .expect("system plan"),
                mappings: mappings
                    .into_iter()
                    .map(|(field, mapping)| {
                        (
                            field.into(),
                            AgentCollectionMapping {
                                counter_normalization: None,
                                query: "facts".into(),
                                mapping,
                                missing: NativeMissing::Missing,
                            },
                        )
                    })
                    .collect(),
            })
            .expect("system mappings"),
        },
    }
}
fn system(
    id: &str,
    category: &str,
    query: w::NativeSystemQuery,
    field: &str,
    scalar: Option<&str>,
) -> Blueprint {
    let cardinality = query.cardinality();
    let query = w::NativeQueryDefinition::System { query };
    let value = if let Some(property) = scalar {
        mapping(&format!("/{property}"), Conversion::Identity)
    } else {
        columns(&query, &[])
    };
    pack(id, category, query, cardinality, vec![(field, value)])
}
pub(super) fn catalog() -> Vec<Blueprint> {
    use w::{
        AccountSection as A, MacosSecuritySection as M, NativeSystemQuery as Q,
        UpdateScanMode as Mode, UpdateSection as U,
    };
    let mut out = vec![
        system(
            "bitlocker",
            "security",
            Q::WindowsBitlocker,
            "device.security.windows.bitlocker.volumes",
            None,
        ),
        system(
            "firewall",
            "security",
            Q::WindowsFirewall,
            "device.security.windows.firewall.profiles",
            None,
        ),
        system(
            "defender",
            "security",
            Q::WindowsDefender,
            "device.security.windows.defender.observation",
            None,
        ),
        system(
            "secure_boot",
            "security",
            Q::WindowsSecureBoot,
            "device.security.windows.secure_boot",
            Some("state"),
        ),
        system(
            "join_observation",
            "identity",
            Q::WindowsJoin,
            "device.accounts.windows.join",
            None,
        ),
    ];
    for (section, id, field) in [
        (
            M::Gatekeeper,
            "gatekeeper",
            "device.security.macos.gatekeeper_observation",
        ),
        (
            M::Xprotect,
            "xprotect",
            "device.security.macos.xprotect.observation",
        ),
        (
            M::SystemExtensions,
            "system_extensions",
            "device.security.macos.system_extensions",
        ),
        (M::Filevault, "filevault", "device.security.macos.filevault"),
        (M::Firewall, "firewall", "device.security.macos.firewall"),
        (M::Sip, "sip", "device.security.macos.sip"),
        (
            M::HardwareEncryption,
            "hardware_encryption",
            "device.security.macos.hardware_encryption",
        ),
        (
            M::SecureToken,
            "secure_token",
            "device.security.macos.secure_token.local",
        ),
        (
            M::BootstrapToken,
            "bootstrap_token",
            "device.security.macos.bootstrap_token.local",
        ),
    ] {
        out.push(system(
            id,
            "security",
            Q::MacosSecurity { section },
            field,
            if matches!(section, M::Gatekeeper | M::Xprotect | M::SystemExtensions) {
                None
            } else {
                Some("state")
            },
        ));
    }
    for windows in [true, false] {
        for (section, id) in [
            (A::Accounts, "accounts"),
            (A::Administrators, "administrators_direct"),
            (A::Sessions, "sessions"),
        ] {
            let query = if windows {
                Q::WindowsAccounts {
                    section,
                    selection: w::AccountSelection::Local,
                }
            } else {
                Q::MacosAccounts {
                    section,
                    selection: w::AccountSelection::Local,
                }
            };
            let field = match section {
                A::Accounts => {
                    if windows {
                        "device.accounts.windows.identities"
                    } else {
                        "device.accounts.macos.identities"
                    }
                }
                A::Administrators => "device.accounts.administrators.direct",
                A::Sessions => "device.accounts.sessions",
            };
            out.push(system(id, "identity", query, field, None));
        }
        for (section, id, field) in [
            (U::Scan, "update_scan", "device.updates.scan"),
            (
                U::Available,
                "updates_available",
                "device.updates.available",
            ),
            (
                U::Installed,
                "updates_installed",
                "device.updates.installed",
            ),
            (U::History, "update_history", "device.updates.history"),
            (
                U::Reboot,
                "update_reboot",
                "device.updates.reboot_observation",
            ),
        ] {
            for mode in [Mode::Local, Mode::Online] {
                if mode == Mode::Online && !matches!(section, U::Scan | U::Available) {
                    continue;
                }
                let query = if windows {
                    Q::WindowsUpdates { section, mode }
                } else {
                    Q::MacosUpdates { section, mode }
                };
                let id = format!(
                    "{id}_{}",
                    if mode == Mode::Local {
                        "local"
                    } else {
                        "online"
                    }
                );
                out.push(system(
                    &id,
                    "updates",
                    query,
                    field,
                    if section == U::Reboot {
                        Some("state")
                    } else {
                        None
                    },
                ));
            }
        }
    }
    for store in [
        w::WindowsCertificateStore::My,
        w::WindowsCertificateStore::Root,
        w::WindowsCertificateStore::Ca,
        w::WindowsCertificateStore::TrustedPublisher,
    ] {
        for user in [false, true] {
            let query = Q::WindowsCertificates { store, user };
            let id = format!(
                "certificates_{}_{}",
                if user { "user" } else { "device" },
                query.certificate_store().expect("store")
            );
            out.push(system(
                &id,
                "security",
                query,
                "device.certificates.metadata",
                None,
            ));
        }
    }
    for store in [
        w::MacosCertificateStore::System,
        w::MacosCertificateStore::SystemRoots,
        w::MacosCertificateStore::Login,
    ] {
        let query = Q::MacosCertificates { store };
        let id = format!("certificates_{}", query.certificate_store().expect("store"));
        out.push(system(
            &id,
            "security",
            query,
            "device.certificates.metadata",
            None,
        ));
    }
    for query in [
        Q::WindowsApplication {
            target: w::WindowsApplicationTarget::Agent,
        },
        Q::MacosApplication {
            target: w::MacosApplicationTarget::Agent,
            permissions: [w::ApplicationPermission::FullDiskAccess].into(),
        },
    ] {
        let query = w::NativeQueryDefinition::System { query };
        let mut mappings = vec![(
            "device.security.application.observation",
            columns(&query, &["permissions"]),
        )];
        if query.platform() == w::TaskPlatform::Macos {
            mappings.push((
                "device.security.application.permissions",
                mapping("/permissions", Conversion::Identity),
            ));
        }
        out.push(pack(
            "agent_health",
            "security",
            query,
            w::NativeCardinality::ExactlyOne,
            mappings,
        ));
    }
    // Existing WMI declaration fully represents these raw arrays; no second DeviceGuard engine.
    let mut properties = std::collections::BTreeMap::new();
    for (name, array) in [
        ("SecurityServicesConfigured", true),
        ("SecurityServicesRunning", true),
        ("VirtualizationBasedSecurityStatus", false),
    ] {
        properties.insert(
            name.into(),
            w::WmiProperty {
                cim_type: w::CimType::Uint32,
                array,
            },
        );
    }
    let query = w::NativeQueryDefinition::WindowsWmi {
        namespace: "root\\Microsoft\\Windows\\DeviceGuard".into(),
        class: "Win32_DeviceGuard".into(),
        properties,
        filter: None,
    };
    let value = ValueMapping {
        pointer: String::new(),
        conversion: Conversion::Identity,
        columns: [
            ("configured", "SecurityServicesConfigured"),
            ("running", "SecurityServicesRunning"),
            ("vbs_status", "VirtualizationBasedSecurityStatus"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), mapping(&format!("/{v}"), Conversion::Identity)))
        .collect(),
    };
    let member = |n| {
        mapping(
            "/SecurityServicesRunning",
            Conversion::ArrayMember {
                member: n,
                present: serde_json::json!("enabled"),
                absent: serde_json::json!("disabled"),
            },
        )
    };
    out.push(pack(
        "device_guard",
        "security",
        query,
        w::NativeCardinality::ExactlyOne,
        vec![
            ("device.security.windows.device_guard", value),
            ("device.security.windows.credential_guard", member(1)),
            ("device.security.windows.hvci", member(2)),
            (
                "device.security.windows.vbs",
                mapping(
                    "/VirtualizationBasedSecurityStatus",
                    Conversion::Enum {
                        values: [
                            ("0".into(), serde_json::json!("disabled")),
                            ("1".into(), serde_json::json!("disabled")),
                            ("2".into(), serde_json::json!("enabled")),
                        ]
                        .into(),
                    },
                ),
            ),
        ],
    ));
    let query = w::NativeQueryDefinition::WindowsWmi {
        namespace: "root\\CIMV2\\Security\\MicrosoftTpm".into(),
        class: "Win32_Tpm".into(),
        properties: [(
            "IsEnabled_InitialValue".into(),
            w::WmiProperty {
                cim_type: w::CimType::Boolean,
                array: false,
            },
        )]
        .into(),
        filter: None,
    };
    out.push(pack(
        "tpm",
        "security",
        query,
        w::NativeCardinality::ExactlyOne,
        vec![(
            "device.security.windows.tpm",
            mapping(
                "/IsEnabled_InitialValue",
                Conversion::Enum {
                    values: [
                        ("true".into(), serde_json::json!("enabled")),
                        ("false".into(), serde_json::json!("disabled")),
                    ]
                    .into(),
                },
            ),
        )],
    ));
    out
}
