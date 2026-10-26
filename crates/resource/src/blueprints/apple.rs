//! Fixed Apple command packs. Profiles and certificates explicitly cover managed objects only.
use super::*;
use rss_mdm_agent_wire::runtime::ValueMapping;
fn pack(id: &str, category: &str, adapter: NativeAdapter, fields: &[(&str, &str)]) -> Blueprint {
    Blueprint {
        id: format!("macos.{id}"),
        version: "1".into(),
        presentation: serde_json::json!({"category":category})
            .as_object()
            .unwrap()
            .clone(),
        platform: Platform::MacOS,
        definition: NativeCollectionDefinition::new(NativeCollectionSpec {
            scope: TemplateScope::Device,
            applicability: Default::default(),
            adapter,
            mappings: fields
                .iter()
                .map(|(field, query)| {
                    (
                        (*field).into(),
                        NativeMapping {
                            query: NativeQuery::Apple((*query).into()),
                            mapping: ValueMapping::identity(if query.is_empty() {
                                "/items"
                            } else {
                                ""
                            }),
                        },
                    )
                })
                .collect(),
            timeout_seconds: 300,
            output_bytes: 1048576,
        })
        .expect("official Apple collection")
        .into(),
    }
}
pub(super) fn catalog() -> Vec<Blueprint> {
    use NativeAdapter::*;
    vec![
        pack(
            "identity",
            "identity",
            AppleDeviceInformation,
            &[
                ("device.serial_number", "SerialNumber"),
                ("device.model", "Model"),
                ("device.os.version", "OSVersion"),
                ("device.os.apple.build", "BuildVersion"),
                (
                    "device.os.apple.supplemental_build",
                    "SupplementalBuildVersion",
                ),
                (
                    "device.os.apple.supplemental_extra",
                    "SupplementalOSVersionExtra",
                ),
            ],
        ),
        pack(
            "hardware",
            "hardware",
            AppleDeviceInformation,
            &[
                ("device.hardware.apple.model_name", "ModelName"),
                ("device.hardware.apple.model_number", "ModelNumber"),
                ("device.hardware.apple.product_name", "ProductName"),
                ("device.hardware.apple.silicon", "IsAppleSilicon"),
                ("device.hardware.apple.capacity_gb", "DeviceCapacity"),
                (
                    "device.hardware.apple.available_gb",
                    "AvailableDeviceCapacity",
                ),
                ("device.hardware.apple.battery_level", "BatteryLevel"),
            ],
        ),
        pack(
            "network",
            "hardware",
            AppleDeviceInformation,
            &[
                ("device.network.apple.host_name", "HostName"),
                ("device.network.apple.local_host_name", "LocalHostName"),
                ("device.network.apple.wifi_mac", "WiFiMAC"),
                ("device.network.apple.ethernet_mac", "EthernetMAC"),
            ],
        ),
        pack(
            "installed_applications",
            "software",
            AppleInstalledApplications,
            &[("device.software.apple.installed_applications", "")],
        ),
        pack(
            "security",
            "security",
            AppleSecurity,
            &[
                ("device.security.apple.filevault_enabled", "FDE_Enabled"),
                (
                    "device.security.apple.personal_recovery_key_exists",
                    "FDE_HasPersonalRecoveryKey",
                ),
                (
                    "device.security.apple.institutional_recovery_key_exists",
                    "FDE_HasInstitutionalRecoveryKey",
                ),
                (
                    "device.security.apple.sip_enabled",
                    "SystemIntegrityProtectionEnabled",
                ),
                (
                    "device.security.apple.recovery_lock_enabled",
                    "IsRecoveryLockEnabled",
                ),
                ("device.security.apple.firewall", "FirewallSettings"),
                (
                    "device.security.apple.firmware_password",
                    "FirmwarePasswordStatus",
                ),
                ("device.security.apple.secure_boot", "SecureBoot"),
                (
                    "device.security.apple.bootstrap_authentication",
                    "BootstrapTokenAllowedForAuthentication",
                ),
                (
                    "device.security.apple.bootstrap_required_update",
                    "BootstrapTokenRequiredForSoftwareUpdate",
                ),
                (
                    "device.security.apple.bootstrap_required_kernel",
                    "BootstrapTokenRequiredForKernelExtensionApproval",
                ),
            ],
        ),
        pack(
            "enrollment",
            "management",
            AppleSecurity,
            &[("device.management.apple.enrollment", "ManagementStatus")],
        ),
        pack(
            "management",
            "management",
            AppleDeviceInformation,
            &[
                ("device.management.apple.supervised", "IsSupervised"),
                (
                    "device.management.apple.awaiting_configuration",
                    "AwaitingConfiguration",
                ),
                (
                    "device.security.apple.activation_lock_enabled",
                    "IsActivationLockEnabled",
                ),
                (
                    "device.security.apple.locator_enabled",
                    "IsDeviceLocatorServiceEnabled",
                ),
            ],
        ),
        pack(
            "managed_profiles",
            "management",
            AppleProfiles,
            &[("device.management.apple.managed_profiles", "")],
        ),
        pack(
            "managed_certificates",
            "security",
            AppleCertificates,
            &[("device.security.apple.managed_certificates", "")],
        ),
        pack(
            "users",
            "management",
            AppleUsers,
            &[("device.management.apple.users", "")],
        ),
    ]
}

fn status_pack(id: &str, category: &str, items: &[&str]) -> Blueprint {
    let identifier = format!("com.rss.inventory.{id}");
    use rss_mdm_apple_mdm::native::{
        ddm::DeclarationInput,
        input::{FieldValue, Fields},
        request::Request,
    };
    let status_items = items
        .iter()
        .map(|name| {
            FieldValue::Dictionary(Fields(
                [("Name".into(), FieldValue::String((*name).into()))].into(),
            ))
        })
        .collect();
    Blueprint {
        id: format!("macos.ddm.{id}"),
        version: "1".into(),
        presentation: serde_json::json!({"category":category})
            .as_object()
            .unwrap()
            .clone(),
        platform: Platform::MacOS,
        definition: Definition::Configuration {
            content: Configuration {
                target: ConfigurationTarget::Device,
                apply: ConfigurationTask::Macos {
                    request: Request::Declarations {
                        assets: vec![],
                        declarations: vec![
                            DeclarationInput {
                                identifier: identifier.clone(),
                                declaration_type:
                                    "com.apple.configuration.management.status-subscriptions".into(),
                                payload: Fields(
                                    [("StatusItems".into(), FieldValue::Array(status_items))]
                                        .into(),
                                ),
                            },
                            DeclarationInput {
                                identifier: format!("{identifier}.activation"),
                                declaration_type: "com.apple.activation.simple".into(),
                                payload: Fields(
                                    [(
                                        "StandardConfigurations".into(),
                                        FieldValue::Array(vec![FieldValue::String(identifier)]),
                                    )]
                                    .into(),
                                ),
                            },
                        ],
                    },
                },
                remove: ConfigurationTask::Macos {
                    request: Request::Declarations {
                        assets: vec![],
                        declarations: vec![],
                    },
                },
            },
        },
    }
}
pub(super) fn status_catalog() -> Vec<Blueprint> {
    vec![
        status_pack(
            "identity",
            "identity",
            &[
                "device.identifier.serial-number",
                "device.identifier.udid",
                "device.model.family",
                "device.model.identifier",
                "device.model.marketing-name",
                "device.model.number",
                "device.operating-system.family",
                "device.operating-system.marketing-name",
                "device.operating-system.version",
                "device.operating-system.build-version",
                "device.operating-system.supplemental.build-version",
                "device.operating-system.supplemental.extra-version",
            ],
        ),
        status_pack("hardware", "hardware", &["device.power.battery-health"]),
        status_pack(
            "software",
            "software",
            &["app.managed.list", "package.list"],
        ),
        status_pack(
            "security",
            "security",
            &[
                "diskmanagement.filevault.enabled",
                "security.certificate.list",
                "security.lockdown-mode",
            ],
        ),
        status_pack(
            "management",
            "management",
            &[
                "management.declarations",
                "management.client-capabilities",
                "mdm.enrollment-type",
                "mdm.is-awaiting-configuration",
            ],
        ),
        status_pack(
            "updates",
            "updates",
            &[
                "softwareupdate.beta-enrollment",
                "softwareupdate.device-id",
                "softwareupdate.failure-reason",
                "softwareupdate.install-reason",
                "softwareupdate.install-state",
                "softwareupdate.pending-version",
            ],
        ),
    ]
}
