//! Decode one composed source snapshot through the canonical persistence decoders.
use crate::snapshot_record::Record;
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;

/// Scalar and array facts without item payloads or source authority decisions.
pub struct Facts {
    /// Authenticated observed scalar rows.
    pub scalars: Vec<crate::InventoryField>,
    /// Observed immutable array references.
    pub arrays: Vec<crate::arrays::InventoryArray>,
    /// Manual scalar facts and revisions.
    pub manual: Vec<crate::Assignment>,
    /// Manual immutable array references and revisions.
    pub manual_arrays: Vec<crate::arrays::ManualArray>,
}
/// The caller obtains these rows and their referenced metadata in the same SELECT.
pub fn decode(
    observed: Vec<Value>,
    manual: Vec<Value>,
    versions: BTreeMap<String, crate::arrays::Metadata>,
) -> Result<Facts> {
    let mut scalars = Vec::new();
    let mut arrays = Vec::new();
    for value in observed {
        let row = Record(value);
        if matches!(
            crate::reader::envelope(&row)?.definition.value_type,
            rss_mdm_inventory::ValueType::Array { .. }
        ) {
            arrays.push(row);
        } else {
            scalars.push(row);
        }
    }
    let mut manual_scalars = Vec::new();
    let mut manual_arrays = Vec::new();
    for mut value in manual {
        let array = value
            .as_object_mut()
            .and_then(|v| v.remove("array"))
            .and_then(|v| v.as_bool())
            .ok_or_else(|| anyhow::anyhow!("manual snapshot field kind"))?;
        if array {
            manual_arrays.push(Record(value));
        } else {
            manual_scalars.push(Record(value));
        }
    }
    Ok(Facts {
        scalars: crate::reader::decode_records(scalars)?,
        arrays: crate::arrays::decode_observed_records(arrays, &versions)?,
        manual: crate::manual::decode_records(manual_scalars)?,
        manual_arrays: crate::arrays::decode_manual_records(manual_arrays, &versions)?,
    })
}
