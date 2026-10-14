//! Fixed ordinary-asset projection of subscribed Apple declarative status.
use super::*;
fn text() -> ValueType {
    ValueType::String {
        max_length: 4096,
        allow_empty: true,
    }
}
fn record(properties: &[(&str, ValueType, bool)]) -> ValueType {
    ValueType::Record {
        properties: properties
            .iter()
            .map(|(k, v, required)| {
                (
                    k.replace('-', "_").replace("serverToken", "server_token"),
                    Property {
                        value_type: v.clone(),
                        required: *required,
                    },
                )
            })
            .collect(),
    }
}
fn array(items: ValueType) -> ValueType {
    ValueType::Array {
        items: Box::new(items),
        max_items: 100000,
    }
}
/// Native status identity and its closed product field schema.
pub fn fields() -> Vec<(&'static str, FieldDefinition)> {
    use ValueType::{Boolean as B, Integer as I};
    let mut types = vec![];
    for name in [
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
        "softwareupdate.beta-enrollment",
        "softwareupdate.device-id",
    ] {
        types.push((name, text()));
    }
    for name in [
        "diskmanagement.filevault.enabled",
        "security.lockdown-mode",
        "mdm.is-awaiting-configuration",
    ] {
        types.push((name, B));
    }
    types.extend([
        (
            "device.power.battery-health",
            vocabulary(&[
                "non-genuine",
                "normal",
                "service-recommended",
                "unknown",
                "unsupported",
            ]),
        ),
        (
            "mdm.enrollment-type",
            vocabulary(&["none", "supervised", "device", "user"]),
        ),
        (
            "softwareupdate.install-state",
            vocabulary(&["none", "downloading", "prepared", "installing", "failed"]),
        ),
        (
            "softwareupdate.pending-version",
            record(&[
                ("build-version", text(), true),
                ("os-version", text(), true),
                ("target-local-date-time", text(), false),
            ]),
        ),
        (
            "softwareupdate.failure-reason",
            record(&[
                ("count", I, true),
                ("reason", text(), false),
                ("timestamp", text(), false),
            ]),
        ),
        (
            "softwareupdate.install-reason",
            record(&[
                (
                    "reason",
                    array(vocabulary(&[
                        "system-settings",
                        "install-tonight",
                        "auto-update",
                        "notification",
                        "setup-assistant",
                        "command-line",
                        "mdm",
                        "declaration",
                    ])),
                    true,
                ),
                ("declaration-id", text(), false),
            ]),
        ),
        (
            "app.managed.list",
            array(record(&[
                ("identifier", string(), true),
                ("name", text(), false),
                ("version", text(), false),
                ("short-version", text(), false),
                ("declaration-identifier", text(), false),
                ("external-version-id", I, false),
                (
                    "state",
                    vocabulary(&[
                        "optional",
                        "queued",
                        "not-present",
                        "prompting-for-consent",
                        "prompting-for-login",
                        "prompting-for-management",
                        "downloading",
                        "installing",
                        "managed",
                        "managed-but-uninstalled",
                        "failed",
                    ]),
                    false,
                ),
                (
                    "update-state",
                    vocabulary(&[
                        "available",
                        "prompting-for-update",
                        "prompting-for-update-login",
                        "updating",
                        "failed",
                    ]),
                    false,
                ),
            ])),
        ),
        (
            "package.list",
            array(record(&[
                ("identifier", string(), true),
                ("name", text(), false),
                ("version", text(), false),
                ("declaration-identifier", text(), false),
                (
                    "state",
                    vocabulary(&[
                        "optional",
                        "queued",
                        "prompting-for-consent",
                        "downloading",
                        "installing",
                        "installed",
                        "failed",
                    ]),
                    false,
                ),
            ])),
        ),
        (
            "security.certificate.list",
            array(record(&[
                ("identifier", string(), true),
                ("is-identity", B, true),
                ("subject-summary", text(), true),
                ("declaration-identifier", text(), false),
            ])),
        ),
        (
            "management.declarations",
            array(record(&[
                ("identifier", string(), true),
                ("serverToken", text(), true),
                ("kind", text(), true),
                (
                    "native",
                    record(&[("valid", text(), true), ("active", B, true)]),
                    true,
                ),
            ])),
        ),
        (
            "management.client-capabilities",
            record(&[
                ("supported-versions", array(text()), true),
                (
                    "supported-payloads",
                    record(&[
                        (
                            "declarations",
                            record(&[
                                ("activations", array(text()), true),
                                ("assets", array(text()), true),
                                ("configurations", array(text()), true),
                                ("management", array(text()), true),
                            ]),
                            true,
                        ),
                        ("status-items", array(text()), true),
                    ]),
                    true,
                ),
            ]),
        ),
    ]);
    types
        .into_iter()
        .map(|(name, ty)| {
            let key = format!("device.ddm.{}", name.replace('-', "_"));
            let list = matches!(ty, ValueType::Array { .. });
            let mut definition = field(
                FieldKey::parse(&key).expect("DDM field"),
                ty,
                &[Source::MdmApple],
            );
            definition.platforms = [Platform::Macos].into();
            if list {
                definition.item_key = Some("identifier".into());
            }
            if name.contains("certificate") || name.contains("identifier") {
                definition.sensitivity = Sensitivity::Sensitive;
            }
            (name, definition)
        })
        .collect()
}
/// Strip fields outside the fixed schema before decoding ordinary assets.
pub fn sanitized(ty: &ValueType, value: &serde_json::Value) -> serde_json::Value {
    match (ty, value) {
        (ValueType::Record { properties }, serde_json::Value::Object(values)) => {
            serde_json::Value::Object(
                properties
                    .iter()
                    .filter_map(|(name, p)| {
                        values
                            .get(name)
                            .or_else(|| values.get(&name.replace('_', "-")))
                            .or_else(|| {
                                if name == "server_token" {
                                    values.get("serverToken")
                                } else {
                                    None
                                }
                            })
                            .map(|v| (name.clone(), sanitized(&p.value_type, v)))
                    })
                    .collect(),
            )
        }
        (ValueType::Array { items, .. }, serde_json::Value::Array(values)) => {
            serde_json::Value::Array(values.iter().map(|v| sanitized(items, v)).collect())
        }
        _ => value.clone(),
    }
}
