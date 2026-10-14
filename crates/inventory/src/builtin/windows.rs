//! Native Windows facts whose coverage differs from portable/Agent inventory.
use super::*;
fn text() -> ValueType {
    ValueType::String {
        max_length: 65536,
        allow_empty: true,
    }
}
fn list(columns: &[(&str, ValueType)]) -> ValueType {
    ValueType::Array {
        max_items: 32768,
        items: Box::new(ValueType::Object {
            properties: columns
                .iter()
                .map(|(k, v)| {
                    (
                        (*k).into(),
                        if *k == "id" {
                            ValueType::String {
                                max_length: 65536,
                                allow_empty: false,
                            }
                        } else {
                            v.clone()
                        },
                    )
                })
                .collect(),
        }),
    }
}
fn definition(key: &str, ty: ValueType, sensitive: bool) -> FieldDefinition {
    let list = matches!(ty, ValueType::Array { .. });
    let mut f = field(
        FieldKey::parse(key).expect("native Windows key"),
        ty,
        &[Source::MdmWindows],
    );
    f.platforms = [Platform::Windows].into();
    if list {
        f.item_key = Some("id".into());
    }
    if sensitive {
        f.sensitivity = Sensitivity::Sensitive;
    }
    f
}
pub(super) fn fields() -> Vec<FieldDefinition> {
    let mut out = Vec::new();
    for key in [
        "device.name",
        "device.hardware.windows.processor_architecture",
        "device.management.windows.enrollment_id",
        "device.management.windows.enrollment_type",
        "device.management.windows.domain_name",
        "device.security.windows.defender.engine_version",
        "device.security.windows.defender.signature_version",
        "device.updates.windows.last_scan",
    ] {
        out.push(definition(key, text(), key.contains("management")));
    }
    let mut memory = definition(
        "device.hardware.windows.available_memory_bytes",
        ValueType::Integer,
        false,
    );
    memory.unit = Some("bytes".into());
    out.push(memory);
    for key in [
        "device.security.windows.defender.enabled",
        "device.security.windows.defender.realtime_enabled",
        "device.security.windows.defender.signature_outdated",
    ] {
        out.push(definition(key, ValueType::Boolean, false));
    }
    for (key, values) in [
        (
            "device.security.windows.antivirus.status",
            vec![
                "enabled",
                "disabled",
                "partial",
                "temporarily_unmonitored",
                "not_applicable",
            ],
        ),
        (
            "device.security.windows.antivirus.signatures",
            vec!["outdated_or_absent", "current", "not_applicable"],
        ),
        (
            "device.security.windows.vbs_runtime",
            vec![
                "running",
                "reboot_required",
                "requires_64_bit",
                "not_licensed",
                "not_configured",
                "hardware_requirements",
                "other",
            ],
        ),
        (
            "device.security.windows.credential_guard_runtime",
            vec![
                "running",
                "reboot_required",
                "not_licensed",
                "not_configured",
                "vbs_not_running",
            ],
        ),
        (
            "device.security.windows.hvci_runtime",
            vec![
                "running",
                "reboot_required",
                "not_configured",
                "vbs_not_running",
            ],
        ),
    ] {
        out.push(definition(key, vocabulary(&values), false));
    }
    // The integer is the observed policy-compliance mask, not a volume encryption boolean.
    let mut bitlocker = definition(
        "device.security.windows.bitlocker.compliance_errors",
        ValueType::Array {
            max_items: 18,
            items: Box::new(vocabulary(&[
                "consent_required",
                "os_method_mismatch",
                "os_unprotected",
                "tpm_only_required",
                "tpm_pin_required",
                "tpm_startup_key_required",
                "tpm_pin_startup_key_required",
                "tpm_required",
                "recovery_backup_failed",
                "fixed_drive_unprotected",
                "fixed_method_mismatch",
                "administrator_required",
                "winre_missing",
                "tpm_unavailable",
                "tpm_not_ready",
                "network_unavailable",
                "os_encryption_type_mismatch",
                "fixed_encryption_type_mismatch",
            ])),
        },
        false,
    );
    bitlocker.item_key = None;
    out.push(bitlocker);
    out.push(definition(
        "device.software.windows.win32",
        list(&[
            ("id", text()),
            ("origin", text()),
            ("name", text()),
            ("publisher", text()),
            ("version", text()),
            ("registry_key", text()),
            ("discovery_source", text()),
            ("installation_scope", text()),
        ]),
        true,
    ));
    for kind in ["store", "non_store", "system"] {
        out.push(definition(
            &format!("device.software.windows.{kind}"),
            list(&[
                ("id", text()),
                ("origin", text()),
                ("name", text()),
                ("publisher", text()),
                ("version", text()),
                ("architecture", text()),
                ("is_bundle", ValueType::Boolean),
                ("is_framework", ValueType::Boolean),
                ("is_provisioned", ValueType::Boolean),
                ("package_status", ValueType::Integer),
                ("registered_users_native", text()),
                ("collection_scope", text()),
            ]),
            true,
        ));
    }
    out.push(definition(
        "device.network.windows.identifiers",
        list(&[
            ("id", text()),
            ("origin", text()),
            ("ipv4", text()),
            ("ipv6", text()),
            ("connected", ValueType::Boolean),
            ("kind", vocabulary(&["unknown", "wired", "wireless"])),
        ]),
        true,
    ));
    for (name, extra) in [
        ("installed", vec![]),
        (
            "installable",
            vec![(
                "classification",
                vocabulary(&["none", "security", "critical"]),
            )],
        ),
        (
            "failed",
            vec![
                ("hresult", ValueType::Integer),
                ("state", ValueType::Integer),
            ],
        ),
        ("pending_reboot", vec![("installed_time", text())]),
    ] {
        let mut cols = vec![
            ("id", text()),
            ("origin", text()),
            ("revision", ValueType::Integer),
        ];
        cols.extend(extra);
        out.push(definition(
            &format!("device.updates.windows.{name}"),
            list(&cols),
            false,
        ));
    }
    out
}
