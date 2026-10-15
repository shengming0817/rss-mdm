//! Product hardware identity values shared by collection and device association.
//! ref: uuid-rs/uuid src/parser.rs (Uuid::parse_str).
use crate::{Invalid, Result};

fn text(value: &str) -> Result<String> {
    let value = value.trim().to_uppercase();
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || [
            "UNKNOWN",
            "NONE",
            "NULL",
            "N/A",
            "NA",
            "NOT SPECIFIED",
            "NOT APPLICABLE",
            "DEFAULT STRING",
            "SYSTEM SERIAL NUMBER",
            "TO BE FILLED BY O.E.M.",
            "TO BE FILLED BY OEM",
        ]
        .contains(&value.as_str())
        || value.chars().all(|c| c == '0' || c == '-' || c == ' ')
    {
        return Err(Invalid::Value);
    }
    Ok(value)
}

/// Canonical serial comparison value; placeholders never establish a hardware identity.
pub fn normalize_serial_number(value: &str) -> Result<String> {
    text(value)
}

/// Canonical SMBIOS UUID, excluding empty, sentinel and known firmware placeholder values.
pub fn normalize_hardware_uuid(value: &str) -> Result<String> {
    let id = uuid::Uuid::parse_str(&text(value)?).map_err(|_| Invalid::Value)?;
    if id.is_nil()
        || id.as_u128() == u128::MAX
        || id.as_u128() == 0x03000200_0400_0500_0006_000700080009
    {
        return Err(Invalid::Value);
    }
    Ok(id.to_string())
}
