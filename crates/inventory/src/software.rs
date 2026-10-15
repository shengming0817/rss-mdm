//! Installation facts are distinct from receipts and future-user provisioning.
use crate::{Invalid, Result, Scalar};
use std::collections::BTreeMap;

pub(crate) fn validate(item: &Scalar) -> Result<()> {
    let Scalar::Object(row) = item else {
        return Err(Invalid::TypeMismatch);
    };
    let text = |key| text(row, key);
    let state = text("installation_state")?;
    let scope = text("scope")?;
    let owner = text("owner")?;
    let origin = text("origin")?;
    if !matches!(
        (scope, owner.is_empty()),
        ("device", true) | ("user", false)
    ) {
        return Err(Invalid::Value);
    }
    let windows = origin.starts_with("win32.") || origin.starts_with("msix.");
    if windows && scope == "user" && !sid(owner) {
        return Err(Invalid::Value);
    }
    let valid = match origin {
        "win32.uninstall.32" | "win32.uninstall.64" => state == "installed",
        "msix.registered" => state == "registered" && scope == "user",
        "msix.provisioned" => state == "provisioned" && scope == "device",
        origin if origin.starts_with("win32.") || origin.starts_with("msix.") => false,
        _ => state == "installed",
    };
    if valid { Ok(()) } else { Err(Invalid::Value) }
}

fn text<'a>(row: &'a BTreeMap<String, Scalar>, key: &str) -> Result<&'a str> {
    match row.get(key) {
        Some(Scalar::String(value)) => Ok(value),
        _ => Err(Invalid::Value),
    }
}

// A Windows installation owner is a canonical textual SID, never a display name.
fn sid(value: &str) -> bool {
    let Some(parts) = value.strip_prefix("S-1-") else {
        return false;
    };
    let mut parts = parts.split('-');
    let Some(authority) = parts.next() else {
        return false;
    };
    if !authority
        .parse::<u64>()
        .is_ok_and(|n| n < (1 << 48) && n.to_string() == authority)
    {
        return false;
    }
    let mut count = 0;
    for part in parts {
        count += 1;
        if !part.parse::<u32>().is_ok_and(|n| n.to_string() == part) {
            return false;
        }
    }
    (1..=15).contains(&count)
}
