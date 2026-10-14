//! Standard extension definitions. Native adapters retain platform-specific evidence meanings.
//! ref: osquery/osquery specs/windows/bitlocker_info.table@5.23.1
use super::*;
fn text() -> ValueType {
    ValueType::String { max_length: 4096, allow_empty: true }
}
fn list(properties: &[(&str, ValueType)]) -> ValueType {
    ValueType::Array {
        max_items: 100000,
        items: Box::new(ValueType::Object {
            properties: properties.iter().map(|(k,v)| ((*k).into(),v.clone())).collect(),
        }),
    }
}
pub(super) fn fields() -> Vec<FieldDefinition> {
    use Source::*;
    let all = &[MdmWindows, MdmApple, AgentBuiltin, AgentScript, AgentOsquery];
    let windows = &[MdmWindows, AgentBuiltin, AgentScript, AgentOsquery];
    let apple = &[MdmApple, AgentBuiltin, AgentScript, AgentOsquery];
    let mut out = Vec::new();
    let mut add = |key: &str, ty: ValueType, sources: &[Source], platforms: &[Platform], sensitive: bool, unit: Option<&str>| {
        let mut f = field(FieldKey::parse(key).expect("standard field"), ty, sources);
        f.platforms = platforms.iter().copied().collect();
        f.sensitivity = if sensitive { Sensitivity::Sensitive } else { Sensitivity::Standard };
        f.unit = unit.map(str::to_owned);
        if matches!(f.value_type, ValueType::Array { .. }) { f.item_key = Some("id".into()); }
        out.push(f);
    };
    let both = &[Platform::Windows, Platform::Macos];
    for (key, ty, unit) in [
        ("device.os.edition", string(), None),
        ("device.cpu.physical_cores", ValueType::Integer, None),
        ("device.firmware.version", text(), None),
        ("device.battery.charge_percent", ValueType::Number, Some("percent")),
        ("device.disk_encryption.enabled", ValueType::Boolean, None),
    ] { add(key, ty, all, both, false, unit); }
    add("device.storage.volumes", list(&[
        ("id", string()), ("name", text()), ("filesystem", text()),
        ("size_bytes", ValueType::Integer), ("free_bytes", ValueType::Integer),
        ("system_volume", ValueType::Boolean),
    ]), all, both, false, None);
    // Installation instances, package receipts and package-manager records are distinct facts.
    for key in ["device.software.installations", "device.software.receipts", "device.software.packages"] {
        add(key, list(&[
            ("id", string()), ("native_id", text()), ("name", text()),
            ("version", text()), ("publisher", text()),
            ("scope", vocabulary(&["device", "user"])), ("owner", text()),
            ("origin", string()), ("location", text()),
        ]), all, both, true, None);
    }
    add("device.security.windows.firewall.status", vocabulary(&[
        "enabled", "disabled", "partial", "temporarily_unmonitored", "not_applicable",
    ]), windows, &[Platform::Windows], false, None);
    add("device.security.windows.firewall.health", vocabulary(&[
        "good", "poor", "snoozed", "not_monitored",
    ]), &[AgentOsquery, AgentBuiltin, AgentScript], &[Platform::Windows], false, None);
    add("device.security.windows.bitlocker.volumes", list(&[
        ("id", string()),
        ("conversion", vocabulary(&["decrypted", "encrypted", "encrypting", "decrypting", "encryption_paused", "decryption_paused"])),
        ("protection", vocabulary(&["unprotected", "protected", "unknown"])),
        ("lock", vocabulary(&["unlocked", "locked"])),
        ("algorithm", text()), ("encrypted_percent", ValueType::Integer),
    ]), windows, &[Platform::Windows], false, None);
    for key in ["device.security.windows.tpm", "device.security.windows.secure_boot", "device.security.windows.vbs", "device.security.windows.credential_guard", "device.security.windows.hvci"] {
        add(key, vocabulary(&["enabled", "disabled", "unknown"]), windows, &[Platform::Windows], false, None);
    }
    for key in ["device.security.macos.filevault", "device.security.macos.firewall", "device.security.macos.sip", "device.security.macos.secure_boot", "device.security.macos.gatekeeper"] {
        add(key, vocabulary(&["enabled", "disabled", "unknown"]), apple, &[Platform::Macos], false, None);
    }
    add("device.security.products", list(&[
        ("id", string()), ("name", text()), ("version", text()),
        ("health", vocabulary(&["healthy", "unhealthy", "passive", "unknown"])),
    ]), all, both, false, None);
    add("device.accounts.local", list(&[
        ("id", string()), ("name", text()),
        ("enabled", ValueType::Boolean), ("administrator", ValueType::Boolean),
    ]), all, both, true, None);
    add("device.certificates.metadata", list(&[
        ("id", string()), ("subject", text()), ("issuer", text()),
        ("not_before", ValueType::Time), ("not_after", ValueType::Time),
        ("scope", vocabulary(&["device", "user"])), ("owner", text()), ("store", string()),
    ]), all, both, true, None);
    add("device.management.profiles", list(&[
        ("id", string()), ("name", text()), ("scope", vocabulary(&["device", "user"])), ("owner", text()),
    ]), apple, &[Platform::Macos], true, None);
    add("device.updates.available", list(&[
        ("id", string()), ("title", text()), ("version", text()), ("origin", string()),
        ("state", vocabulary(&["available", "installed", "failed", "pending_reboot"])),
    ]), all, both, false, None);
    add("device.updates.reboot_required", ValueType::Boolean, all, both, false, None);
    out
}
