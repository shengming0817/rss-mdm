//! Windows native collection packs. Each list has an exact source namespace.
//! ref: Microsoft Learn DevInfo, DevDetail, DeviceStatus, Win32AppInventory,
//! EnterpriseModernAppManagement, BitLocker, Defender, DMClient and Update CSP.
use super::*;
use rss_mdm_agent_wire::runtime::{Conversion, ValueMapping};
fn mapping(pointer: &str, conversion: Conversion) -> ValueMapping {
    ValueMapping {
        pointer: pointer.into(),
        conversion,
        columns: Default::default(),
    }
}
fn codes(values: &[(&str, &str)]) -> Conversion {
    Conversion::Enum {
        values: values
            .iter()
            .map(|(k, v)| ((*k).into(), serde_json::Value::String((*v).into())))
            .collect(),
    }
}
fn boolean() -> Conversion {
    Conversion::Enum {
        values: [
            ("true".into(), true.into()),
            ("false".into(), false.into()),
            ("1".into(), true.into()),
            ("0".into(), false.into()),
        ]
        .into(),
    }
}
fn scalar(field: &str, uri: &str, conversion: Conversion) -> (String, NativeMapping) {
    (
        field.into(),
        NativeMapping {
            query: NativeQuery::Windows(WindowsRead::Scalar { uri: uri.into() }),
            mapping: mapping("", conversion),
        },
    )
}
fn pack(id: &str, category: &str, build: u32, mappings: Vec<(String, NativeMapping)>) -> Blueprint {
    Blueprint {
        id: format!("windows.{id}"),
        version: "1".into(),
        presentation: serde_json::json!({"category":category})
            .as_object()
            .unwrap()
            .clone(),
        platform: Platform::Windows,
        definition: NativeCollectionDefinition::new(NativeCollectionSpec {
            scope: TemplateScope::Device,
            applicability: Applicability {
                minimum_build: Some(build),
                enrollments: ["primary".into()].into(),
                ..Default::default()
            },
            adapter: NativeAdapter::WindowsRead,
            mappings: mappings.into_iter().collect(),
            timeout_seconds: 300,
            output_bytes: 1048576,
        })
        .expect("official Windows read template")
        .into(),
    }
}
fn inventory(
    id: &str,
    category: &str,
    build: u32,
    field: &str,
    kind: WindowsInventory,
    columns: Vec<(&str, &str, Conversion)>,
) -> Blueprint {
    let mut projection: std::collections::BTreeMap<_, _> = columns
        .into_iter()
        .map(|(key, pointer, conversion)| (key.into(), mapping(pointer, conversion)))
        .collect();
    projection.insert("id".into(), ValueMapping::identity("/id"));
    projection.insert("origin".into(), ValueMapping::identity("/origin"));
    pack(
        id,
        category,
        build,
        vec![(
            field.into(),
            NativeMapping {
                query: NativeQuery::Windows(WindowsRead::Inventory { inventory: kind }),
                mapping: ValueMapping {
                    pointer: "".into(),
                    conversion: Conversion::Identity,
                    columns: projection,
                },
            },
        )],
    )
}
pub(super) fn catalog() -> Vec<Blueprint> {
    use Conversion::{Identity as I, Integer as N};
    let mut out = vec![
        pack(
            "identity",
            "identity",
            10586,
            vec![
                scalar("device.os.version", "./DevDetail/SwV", I),
                scalar("device.name", "./DevDetail/Ext/Microsoft/DeviceName", I),
                scalar("device.manufacturer", "./DevInfo/Man", I),
                scalar("device.os.name", "./DevDetail/Ext/Microsoft/OSPlatform", I),
            ],
        ),
        pack(
            "hardware",
            "hardware",
            10586,
            vec![
                scalar("device.model", "./DevInfo/Mod", I),
                scalar("device.firmware.version", "./DevDetail/FwV", I),
                scalar(
                    "device.hardware.windows.processor_architecture",
                    "./DevDetail/Ext/Microsoft/ProcessorArchitecture",
                    I,
                ),
                scalar(
                    "device.hardware.windows.available_memory_bytes",
                    "./DevDetail/Ext/Microsoft/TotalRAM",
                    Conversion::Scale {
                        numerator: 1048576,
                        denominator: 1,
                    },
                ),
            ],
        ),
        pack(
            "hardware.serial",
            "hardware",
            17763,
            vec![scalar(
                "device.serial_number",
                "./DevDetail/Ext/Microsoft/SMBIOSSerialNumber",
                I,
            )],
        ),
        pack(
            "identity.edition",
            "identity",
            15063,
            vec![scalar(
                "device.os.edition",
                "./Vendor/MSFT/DeviceStatus/OS/Edition",
                I,
            )],
        ),
        pack(
            "security.firewall",
            "security",
            15063,
            vec![scalar(
                "device.security.windows.firewall.status",
                "./Vendor/MSFT/DeviceStatus/Firewall/Status",
                codes(&[
                    ("0", "enabled"),
                    ("1", "disabled"),
                    ("2", "partial"),
                    ("3", "temporarily_unmonitored"),
                    ("4", "not_applicable"),
                ]),
            )],
        ),
        pack(
            "security.antivirus",
            "security",
            15063,
            vec![
                scalar(
                    "device.security.windows.antivirus.status",
                    "./Vendor/MSFT/DeviceStatus/Antivirus/Status",
                    codes(&[
                        ("0", "enabled"),
                        ("1", "disabled"),
                        ("2", "partial"),
                        ("3", "temporarily_unmonitored"),
                        ("4", "not_applicable"),
                    ]),
                ),
                scalar(
                    "device.security.windows.antivirus.signatures",
                    "./Vendor/MSFT/DeviceStatus/Antivirus/SignatureStatus",
                    codes(&[
                        ("0", "outdated_or_absent"),
                        ("1", "current"),
                        ("2", "not_applicable"),
                    ]),
                ),
            ],
        ),
        pack(
            "security.bitlocker",
            "security",
            18362,
            vec![scalar(
                "device.security.windows.bitlocker.compliance_errors",
                "./Device/Vendor/MSFT/BitLocker/Status/DeviceEncryptionStatus",
                Conversion::Bitmask {
                    flags: [
                        ("1".into(), "consent_required".into()),
                        ("2".into(), "os_method_mismatch".into()),
                        ("4".into(), "os_unprotected".into()),
                        ("8".into(), "tpm_only_required".into()),
                        ("16".into(), "tpm_pin_required".into()),
                        ("32".into(), "tpm_startup_key_required".into()),
                        ("64".into(), "tpm_pin_startup_key_required".into()),
                        ("128".into(), "tpm_required".into()),
                        ("256".into(), "recovery_backup_failed".into()),
                        ("512".into(), "fixed_drive_unprotected".into()),
                        ("1024".into(), "fixed_method_mismatch".into()),
                        ("2048".into(), "administrator_required".into()),
                        ("4096".into(), "winre_missing".into()),
                        ("8192".into(), "tpm_unavailable".into()),
                        ("16384".into(), "tpm_not_ready".into()),
                        ("32768".into(), "network_unavailable".into()),
                        ("65536".into(), "os_encryption_type_mismatch".into()),
                        ("131072".into(), "fixed_encryption_type_mismatch".into()),
                    ]
                    .into(),
                },
            )],
        ),
        pack(
            "security.defender",
            "security",
            15063,
            vec![
                scalar(
                    "device.security.windows.defender.enabled",
                    "./Device/Vendor/MSFT/Defender/Health/DefenderEnabled",
                    boolean(),
                ),
                scalar(
                    "device.security.windows.defender.realtime_enabled",
                    "./Device/Vendor/MSFT/Defender/Health/RtpEnabled",
                    boolean(),
                ),
                scalar(
                    "device.security.windows.defender.signature_outdated",
                    "./Device/Vendor/MSFT/Defender/Health/SignatureOutOfDate",
                    boolean(),
                ),
                scalar(
                    "device.security.windows.defender.engine_version",
                    "./Device/Vendor/MSFT/Defender/Health/EngineVersion",
                    I,
                ),
                scalar(
                    "device.security.windows.defender.signature_version",
                    "./Device/Vendor/MSFT/Defender/Health/SignatureVersion",
                    I,
                ),
            ],
        ),
        pack(
            "security.device_guard",
            "security",
            17134,
            vec![
                scalar(
                    "device.security.windows.vbs_runtime",
                    "./Vendor/MSFT/DeviceStatus/DeviceGuard/VirtualizationBasedSecurityStatus",
                    codes(&[
                        ("0", "running"),
                        ("1", "reboot_required"),
                        ("2", "requires_64_bit"),
                        ("3", "not_licensed"),
                        ("4", "not_configured"),
                        ("5", "hardware_requirements"),
                        ("42", "other"),
                    ]),
                ),
                scalar(
                    "device.security.windows.credential_guard_runtime",
                    "./Vendor/MSFT/DeviceStatus/DeviceGuard/LsaCfgCredGuardStatus",
                    codes(&[
                        ("0", "running"),
                        ("1", "reboot_required"),
                        ("2", "not_licensed"),
                        ("3", "not_configured"),
                        ("4", "vbs_not_running"),
                    ]),
                ),
            ],
        ),
        pack(
            "security.hvci",
            "security",
            22000,
            vec![scalar(
                "device.security.windows.hvci_runtime",
                "./Vendor/MSFT/DeviceStatus/DeviceGuard/HypervisorEnforcedCodeIntegrityStatus",
                codes(&[
                    ("0", "running"),
                    ("1", "reboot_required"),
                    ("2", "not_configured"),
                    ("3", "vbs_not_running"),
                ]),
            )],
        ),
        pack(
            "management",
            "management",
            14393,
            vec![
                (
                    "device.management.windows.enrollment_id".into(),
                    NativeMapping {
                        query: NativeQuery::Windows(WindowsRead::EnrollmentId),
                        mapping: ValueMapping::identity(""),
                    },
                ),
                (
                    "device.management.windows.enrollment_type".into(),
                    NativeMapping {
                        query: NativeQuery::Windows(WindowsRead::EnrollmentType),
                        mapping: ValueMapping::identity(""),
                    },
                ),
            ],
        ),
        pack(
            "management.domain",
            "management",
            17134,
            vec![scalar(
                "device.management.windows.domain_name",
                "./Vendor/MSFT/DeviceStatus/DomainName",
                I,
            )],
        ),
        pack(
            "updates.scan",
            "updates",
            10240,
            vec![scalar(
                "device.updates.windows.last_scan",
                "./Vendor/MSFT/Update/LastSuccessfulScanTime",
                I,
            )],
        ),
        inventory(
            "software.win32",
            "software",
            10240,
            "device.software.windows.win32",
            WindowsInventory::Win32,
            vec![
                ("name", "/Name", I),
                ("publisher", "/Publisher", I),
                ("version", "/Version", I),
                ("registry_key", "/RegKey", I),
                ("discovery_source", "/Source", I),
                ("installation_scope", "/installation_scope", I),
            ],
        ),
        inventory(
            "hardware.network",
            "hardware",
            10586,
            "device.network.windows.identifiers",
            WindowsInventory::Network,
            vec![
                ("ipv4", "/IPAddressV4", I),
                ("ipv6", "/IPAddressV6", I),
                ("connected", "/IsConnected", boolean()),
                (
                    "kind",
                    "/Type",
                    codes(&[("0", "unknown"), ("1", "wired"), ("2", "wireless")]),
                ),
            ],
        ),
    ];
    for (id, kind) in [
        ("store", WindowsInventory::Store),
        ("non_store", WindowsInventory::NonStore),
        ("system", WindowsInventory::System),
    ] {
        out.push(inventory(
            &format!("software.{id}"),
            "software",
            10586,
            &format!("device.software.windows.{id}"),
            kind,
            vec![
                ("name", "/Name", I),
                ("publisher", "/Publisher", I),
                ("version", "/Version", I),
                ("architecture", "/Architecture", I),
                ("is_bundle", "/IsBundle", boolean()),
                ("is_framework", "/IsFramework", boolean()),
                ("is_provisioned", "/IsProvisioned", boolean()),
                ("package_status", "/PackageStatus", N),
                ("registered_users_native", "/Users", I),
                ("collection_scope", "/collection_scope", I),
            ],
        ));
    }
    for (id, kind, extra) in [
        ("installed", WindowsInventory::InstalledUpdates, vec![]),
        (
            "installable",
            WindowsInventory::InstallableUpdates,
            vec![(
                "classification",
                "/Type",
                codes(&[("0", "none"), ("1", "security"), ("2", "critical")]),
            )],
        ),
        (
            "failed",
            WindowsInventory::FailedUpdates,
            vec![("hresult", "/HResult", N), ("state", "/State", N)],
        ),
        (
            "pending_reboot",
            WindowsInventory::PendingRebootUpdates,
            vec![("installed_time", "/InstalledTime", I)],
        ),
    ] {
        let mut columns = vec![("revision", "/RevisionNumber", N)];
        columns.extend(extra);
        out.push(inventory(
            &format!("updates.{id}"),
            "updates",
            15063,
            &format!("device.updates.windows.{id}"),
            kind,
            columns,
        ));
    }
    out
}
