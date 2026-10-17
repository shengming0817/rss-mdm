//! Local native facts are not management authority. Existing field identities keep their meaning.
//! ref: osquery/osquery specs/windows/bitlocker_info.table@5.23.1
use super::*;
fn object(names: &[&str]) -> ValueType {
    ValueType::Object {
        properties: names.iter().map(|k| ((*k).into(), text())).collect(),
    }
}
fn integers(mut ty: ValueType, names: &[&str]) -> ValueType {
    if let ValueType::Object { properties } = &mut ty {
        for name in names {
            properties.insert((*name).into(), ValueType::Integer);
        }
    }
    ty
}
fn array(ty: ValueType) -> ValueType {
    ValueType::Array {
        max_items: 65535,
        items: Box::new(ty),
    }
}
pub(super) fn fields() -> Vec<FieldDefinition> {
    let mut out = Vec::new();
    let mut add = |key: &str, ty: ValueType, platforms: &[Platform], sensitive: bool| {
        let mut f = field(
            FieldKey::parse(key).expect("system field"),
            ty,
            &[Source::AgentNative],
        );
        f.platforms = platforms.iter().copied().collect();
        f.sensitivity = if sensitive {
            Sensitivity::Sensitive
        } else {
            Sensitivity::Standard
        };
        if matches!(f.value_type, ValueType::Array { .. }) {
            f.item_key = Some("id".into());
        }
        out.push(f);
    };
    let win = &[Platform::Windows];
    let mac = &[Platform::Macos];
    let both = &[Platform::Windows, Platform::Macos];
    add(
        "device.security.windows.firewall.profiles",
        array(object(&["id", "configured", "running"])),
        win,
        false,
    );
    add(
        "device.security.windows.defender.observation",
        object(&[
            "presence",
            "configured",
            "running",
            "mode",
            "health",
            "signature_version",
        ]),
        win,
        false,
    );
    add(
        "device.security.windows.device_guard",
        ValueType::Object {
            properties: [
                (
                    "configured".into(),
                    ValueType::Array {
                        max_items: 64,
                        items: Box::new(ValueType::Integer),
                    },
                ),
                (
                    "running".into(),
                    ValueType::Array {
                        max_items: 64,
                        items: Box::new(ValueType::Integer),
                    },
                ),
                ("vbs_status".into(), ValueType::Integer),
            ]
            .into(),
        },
        win,
        false,
    );
    add(
        "device.accounts.windows.join",
        object(&["ad", "entra", "mdm"]),
        win,
        true,
    );
    add(
        "device.accounts.windows.identities",
        array(object(&["id", "name", "account_type", "enabled"])),
        win,
        true,
    );
    add(
        "device.accounts.macos.identities",
        array(integers(
            object(&["id", "name", "account_type", "enabled"]),
            &["uid"],
        )),
        mac,
        true,
    );
    add(
        "device.accounts.administrators.direct",
        array(object(&["id", "member", "member_type", "resolved"])),
        both,
        true,
    );
    add(
        "device.accounts.sessions",
        array(object(&["id", "owner", "state"])),
        both,
        true,
    );
    for key in [
        "device.security.macos.gatekeeper.observation",
        "device.security.macos.xprotect.observation",
    ] {
        add(
            key,
            object(&["presence", "configured", "running", "version"]),
            mac,
            false,
        );
    }
    add(
        "device.security.macos.system_extensions",
        array(object(&[
            "id",
            "team_id",
            "bundle_id",
            "version",
            "configured",
            "running",
        ])),
        mac,
        false,
    );
    for key in [
        "device.security.macos.hardware_encryption",
        "device.security.macos.secure_token.local",
        "device.security.macos.bootstrap_token.local",
    ] {
        add(
            key,
            vocabulary(&["enabled", "disabled", "unknown"]),
            mac,
            true,
        );
    }
    add(
        "device.security.application.observation",
        object(&[
            "identity",
            "signer",
            "presence",
            "signature",
            "running",
            "health",
        ]),
        both,
        true,
    );
    add(
        "device.security.application.permissions",
        ValueType::Array {
            max_items: 3,
            items: Box::new(text()),
        },
        mac,
        true,
    );
    // Permission values form a scalar array, not an item-keyed inventory.
    for key in ["device.updates.installed", "device.updates.history"] {
        add(
            key,
            array(object(&["id", "title", "version", "origin", "state"])),
            both,
            false,
        );
    }
    add(
        "device.updates.scan",
        integers(
            object(&["availability", "mode", "source", "coverage"]),
            &["scan_started_at", "scan_finished_at"],
        ),
        both,
        false,
    );
    add(
        "device.updates.reboot_observation",
        vocabulary(&["required", "not_required", "unknown"]),
        both,
        false,
    );
    for f in &mut out {
        if f.key.as_str() == "device.security.application.permissions" {
            f.item_key = None;
        }
    }
    out
}
