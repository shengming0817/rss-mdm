//! OMA DM 1.2.1 §7: measure actual XML frames, never split a compound command.
use super::*;

/// One encoded-size-bounded message from an immutable native object.
#[derive(Debug)]
pub struct Fragment {
    /// Complete message including the caller's header and preceding protocol commands.
    pub message: Message,
    /// Exclusive UTF-8 byte offset in the original object's encoded Data.
    pub end: usize,
}
/// Fit a command after an existing protocol envelope. Only a single Add/Replace Data item
/// may span messages. The caller persists each returned frame and authenticates its receipt
/// before advancing `offset`; this function supplies no execution or delivery authority.
pub fn fragment(
    prefix: &Message,
    command: &Command,
    offset: usize,
    peer_message_bytes: usize,
    limits: &CodecLimits,
) -> Result<Fragment> {
    let mut wire_limits = limits.clone();
    wire_limits.syncml_bytes = limits.syncml_bytes.min(peer_message_bytes);
    let mut full = prefix.clone();
    full.commands.push(command.clone());
    validate(&full, limits)?;
    let data = match command {
        Command::Add { items, .. } | Command::Replace { items, .. } if items.len() == 1 => {
            items[0].data.as_ref().map(|d| d.0.as_str())
        }
        _ => None,
    };
    if offset == 0 {
        match encode(&full, &wire_limits) {
            Ok(_) => {
                return Ok(Fragment {
                    message: full,
                    end: data.map_or(0, str::len),
                });
            }
            Err(E::LimitExceeded) => (),
            Err(error) => return Err(error),
        }
    }
    let data = data.ok_or(E::Unsupported)?;
    if offset >= data.len() || !data.is_char_boundary(offset) {
        return Err(E::InvalidValue);
    }
    let size = u32::try_from(data.len()).map_err(|_| E::LimitExceeded)?;
    let build = |end: usize| -> Result<Message> {
        let mut message = prefix.clone();
        let mut command = command.clone();
        let (parent, items) = match &mut command {
            Command::Add { meta, items, .. } | Command::Replace { meta, items, .. } => {
                (meta, items)
            }
            _ => return Err(E::Unsupported),
        };
        if let Some(meta) = parent {
            meta.size = None;
        }
        let item = &mut items[0];
        item.meta.get_or_insert_with(Meta::default).size = (offset == 0).then_some(size);
        item.data = Some(Secret(data[offset..end].into()));
        item.more_data = end < data.len();
        message.final_message = end == data.len() && prefix.final_message;
        message.commands.push(command);
        Ok(message)
    };
    // The final marker changes the envelope, so try the entire remainder separately.
    let final_message = build(data.len())?;
    match encode(&final_message, &wire_limits) {
        Ok(_) => {
            return Ok(Fragment {
                message: final_message,
                end: data.len(),
            });
        }
        Err(E::LimitExceeded) => (),
        Err(error) => return Err(error),
    }
    let mut low = offset + 1;
    let mut high = data.len() - 1;
    let mut best = None;
    while low <= high {
        let midpoint = low + (high - low) / 2;
        let mut end = midpoint;
        while !data.is_char_boundary(end) {
            end -= 1;
        }
        if end <= offset {
            low = midpoint + 1;
            continue;
        }
        let message = build(end)?;
        match encode(&message, &wire_limits) {
            Ok(_) => {
                best = Some(Fragment { message, end });
                low = midpoint + 1;
            }
            Err(E::LimitExceeded) => high = end - 1,
            Err(error) => return Err(error),
        }
    }
    best.ok_or(E::LimitExceeded)
}
