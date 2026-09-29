//! Order-preserving scalar keys for immutable query result indexes.
use super::*;
use rss_mdm_inventory::State;
pub(super) fn key(value: Option<&State>, descending: bool) -> Vec<u8> {
    let Some(State::Known(value)) = value else {
        return vec![1];
    };
    let mut payload = match value {
        Scalar::String(value) => {
            let mut result = Vec::with_capacity(value.len() + 2);
            for byte in value.bytes() {
                if byte == 0 {
                    result.extend([0, 255]);
                } else {
                    result.push(byte);
                }
            }
            result.extend([0, 0]);
            result
        }
        Scalar::Integer(value) | Scalar::Time(value) => {
            ((*value as u64) ^ (1 << 63)).to_be_bytes().to_vec()
        }
        Scalar::Boolean(value) => vec![u8::from(*value)],
    };
    if descending {
        for byte in &mut payload {
            *byte = !*byte;
        }
    }
    let mut result = vec![0];
    result.extend(payload);
    result
}
#[cfg(test)]
#[path = "../../tests/assets/query_sort_unit.rs"]
mod tests;
