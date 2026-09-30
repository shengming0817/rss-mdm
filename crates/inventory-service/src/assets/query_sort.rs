//! Order-preserving scalar keys for immutable query result indexes.
use super::*;
use rss_mdm_inventory::State;
pub(super) fn key(value: Option<&State>, descending: bool) -> Result<Vec<u8>> {
    let Some(State::Known(value)) = value else {
        return Ok(vec![1]);
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
        Scalar::Number(value) => {
            let n = if value.into_inner() == 0.0 {
                0.0
            } else {
                value.into_inner()
            };
            let bits = n.to_bits();
            (if bits >> 63 != 0 {
                !bits
            } else {
                bits ^ (1 << 63)
            })
            .to_be_bytes()
            .to_vec()
        }
        Scalar::Array(_) | Scalar::Object(_) => return Err(Error::Malformed.into()),
        Scalar::Boolean(value) => vec![u8::from(*value)],
    };
    if descending {
        for byte in &mut payload {
            *byte = !*byte;
        }
    }
    let mut result = vec![0];
    result.extend(payload);
    Ok(result)
}
#[cfg(test)]
#[path = "../../tests/assets/query_sort_unit.rs"]
mod tests;
