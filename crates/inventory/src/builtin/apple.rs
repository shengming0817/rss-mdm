//! Apple native namespaces retain protocol coverage; optional properties are never invented.
use super::*;
fn text() -> ValueType {
    ValueType::String {
        max_length: 4096,
        allow_empty: true,
    }
}
fn record(properties: &[(&str, ValueType)]) -> ValueType {
    ValueType::Record {
        properties: properties
            .iter()
            .map(|(name, ty)| {
                (
                    (*name).into(),
                    Property {
                        value_type: if *name == "id" {
                            ValueType::String {
                                max_length: 4096,
                                allow_empty: false,
                            }
                        } else {
                            ty.clone()
                        },
                        required: *name == "id",
                    },
                )
            })
            .collect(),
    }
}
fn definition(key: &str, ty: ValueType, sensitive: bool) -> FieldDefinition {
    let mut f = field(
        FieldKey::parse(key).expect("Apple field"),
        ty,
        &[Source::MdmApple],
    );
    f.platforms = [Platform::Macos].into();
    if sensitive {
        f.sensitivity = Sensitivity::Sensitive;
    }
    f
}
pub(super) fn fields() -> Vec<FieldDefinition> {
    use ValueType::{Boolean as B, Integer as I};
    let mut out = Vec::new();
    for (key, ty) in [
        ("device.hardware.apple.model_name", text()),
        ("device.hardware.apple.model_number", text()),
        ("device.hardware.apple.product_name", text()),
        ("device.hardware.apple.silicon", B),
        ("device.hardware.apple.capacity_gb", ValueType::Number),
        ("device.hardware.apple.available_gb", ValueType::Number),
        ("device.hardware.apple.battery_level", ValueType::Number),
        ("device.os.apple.build", text()),
        ("device.os.apple.supplemental_build", text()),
        ("device.os.apple.supplemental_extra", text()),
        ("device.network.apple.host_name", text()),
        ("device.network.apple.local_host_name", text()),
        ("device.network.apple.wifi_mac", text()),
        ("device.network.apple.ethernet_mac", text()),
        ("device.security.apple.filevault_enabled", B),
        ("device.security.apple.personal_recovery_key_exists", B),
        ("device.security.apple.institutional_recovery_key_exists", B),
        ("device.security.apple.sip_enabled", B),
        ("device.security.apple.recovery_lock_enabled", B),
        ("device.security.apple.activation_lock_enabled", B),
        ("device.security.apple.locator_enabled", B),
        ("device.security.apple.bootstrap_authentication", text()),
        ("device.security.apple.bootstrap_required_update", B),
        ("device.security.apple.bootstrap_required_kernel", B),
        ("device.management.apple.supervised", B),
        ("device.management.apple.awaiting_configuration", B),
    ] {
        out.push(definition(key, ty, key.contains("network")));
    }
    for (key, properties) in [
        (
            "device.security.apple.firewall",
            vec![
                ("block_all_incoming", B),
                ("firewall_enabled", B),
                ("logging_enabled", B),
                ("logging_option", text()),
                ("stealth_mode", B),
            ],
        ),
        (
            "device.security.apple.firmware_password",
            vec![
                ("allow_oroms", B),
                ("change_pending", B),
                ("password_exists", B),
            ],
        ),
        (
            "device.security.apple.secure_boot",
            vec![
                ("external_boot_level", text()),
                ("secure_boot_level", text()),
                (
                    "reduced_security",
                    ValueType::Array {
                        items: Box::new(text()),
                        max_items: 1024,
                    },
                ),
            ],
        ),
        (
            "device.management.apple.enrollment",
            vec![
                ("enrolled_via_dep", B),
                ("is_activation_lock_manageable", B),
                ("is_user_enrollment", B),
                ("user_approved_enrollment", B),
            ],
        ),
    ] {
        out.push(definition(key, record(&properties), false));
    }
    for (key, properties, sensitive) in [
        (
            "device.software.apple.installed_applications",
            vec![
                ("id", text()),
                ("name", text()),
                ("version", text()),
                ("short_version", text()),
                ("bundle_bytes", I),
                ("dynamic_bytes", I),
                ("installing", B),
                ("validated", B),
                ("app_store", B),
                ("device_vpp", B),
                ("external_version", I),
                ("update_available", B),
                ("ad_hoc_signed", B),
                ("beta", B),
            ],
            false,
        ),
        (
            "device.management.apple.managed_profiles",
            vec![
                ("id", text()),
                ("identifier", text()),
                ("name", text()),
                ("description", text()),
                ("organization", text()),
                ("version", I),
                ("removal_passcode", B),
                ("encrypted", B),
                ("managed", B),
                ("removal_disallowed", B),
                ("source", text()),
            ],
            true,
        ),
        (
            "device.security.apple.managed_certificates",
            vec![
                ("id", text()),
                ("common_name", text()),
                ("identity", B),
                ("serial", text()),
                ("not_before", text()),
                ("not_after", text()),
            ],
            true,
        ),
        (
            "device.management.apple.users",
            vec![
                ("id", text()),
                ("uid", I),
                ("name", text()),
                ("full_name", text()),
                ("secure_token", B),
                ("logged_in", B),
                ("mobile_account", B),
            ],
            true,
        ),
    ] {
        let mut f = definition(
            key,
            ValueType::Array {
                items: Box::new(record(&properties)),
                max_items: 100000,
            },
            sensitive,
        );
        f.item_key = Some("id".into());
        out.push(f);
    }
    out
}
