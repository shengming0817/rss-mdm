//! OMA DM 1.2.1 §7: one contiguous object, with encoded-byte Size and no invented chunk identity.
use base64::Engine;
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    syncml::{self as s, Command, CommandName, Item, Message, Meta, Reference, Status},
};

#[derive(Debug)]
pub(crate) enum Fault {
    Invalid,
    Size(u32),
    Interrupted(Reference),
}
struct Partial {
    reference: Reference,
    meta: Meta,
    size: usize,
    next: u32,
    data: String,
}
#[derive(Default)]
pub(crate) struct Assembly {
    partial: Option<Partial>,
    statuses: Vec<(u32, u32, Vec<String>, u16)>,
}
pub(crate) struct Frame {
    pub message: Message,
    pub controls: Vec<Command>,
}
fn metadata(item: &Item, parent: Option<&Meta>) -> Meta {
    let local = item.meta.as_ref();
    Meta {
        format: local
            .and_then(|m| m.format.clone())
            .or_else(|| parent.and_then(|m| m.format.clone())),
        media_type: local
            .and_then(|m| m.media_type.clone())
            .or_else(|| parent.and_then(|m| m.media_type.clone())),
        size: local
            .and_then(|m| m.size)
            .or_else(|| parent.and_then(|m| m.size)),
        ..Meta::default()
    }
}
impl Assembly {
    pub fn pending(&self) -> Option<Reference> {
        self.partial.as_ref().map(|p| p.reference.clone())
    }

    /// Replay protected original input messages to recover the sole active object.
    pub fn feed(
        &mut self,
        raw: &Message,
        expected: &s::Expected,
        limits: &CodecLimits,
    ) -> Result<Frame, Fault> {
        let required = self.partial.as_ref().map(|p| p.reference.clone());
        if let Some(p) = &self.partial
            && p.next != raw.header.message_id
        {
            return Err(Fault::Interrupted(p.reference.clone()));
        }
        let mut touched = false;
        let mut output = raw.clone();
        let mut controls = Vec::new();
        for (position, command) in raw.commands.iter().enumerate() {
            if let Command::Status(status) = command {
                if status.command == CommandName::Get {
                    self.statuses.push((
                        status.message_ref,
                        status.command_ref,
                        status.target_refs.clone(),
                        status.code,
                    ));
                }
                continue;
            }
            let Command::Results(result) = command else {
                if let Some(partial) = &self.partial {
                    return Err(Fault::Interrupted(partial.reference.clone()));
                }
                continue;
            };
            let mut items = Vec::new();
            for item in &result.items {
                if let Some(partial) = &self.partial
                    && (partial.next != raw.header.message_id
                        || result.message_ref.unwrap_or(1) != partial.reference.message_id
                        || result.command_ref.unwrap_or(1) != partial.reference.command_id
                        || item.source.as_deref() != Some(partial.reference.uri.as_str()))
                {
                    return Err(Fault::Interrupted(partial.reference.clone()));
                }
                let reference = expected
                    .get_reference(
                        result.message_ref.unwrap_or(1),
                        result.command_ref.unwrap_or(1),
                        item.source.as_deref().ok_or(Fault::Invalid)?,
                    )
                    .map_err(|_| Fault::Invalid)?;
                let meta = metadata(item, result.meta.as_ref());
                let data = &item.data.as_ref().ok_or(Fault::Invalid)?.0;
                if self.partial.is_none() && !item.more_data {
                    if meta.size.is_some_and(|size| size as usize != data.len()) {
                        return Err(Fault::Size(result.id));
                    }
                    let mut complete = item.clone();
                    complete.meta = Some(meta);
                    items.push(complete);
                    continue;
                }
                if !self
                    .statuses
                    .iter()
                    .rev()
                    .find(|(m, c, uris, _)| {
                        *m == reference.message_id
                            && *c == reference.command_id
                            && (uris.is_empty() || uris.contains(&reference.uri))
                    })
                    .is_some_and(|(_, _, _, code)| matches!(code, 200 | 206 | 214))
                {
                    return Err(Fault::Invalid);
                }
                if let Some(partial) = self.partial.as_mut() {
                    if partial.reference != reference
                        || meta.size.is_some()
                        || meta
                            .format
                            .as_ref()
                            .is_some_and(|f| f != partial.meta.format.as_deref().unwrap_or("chr"))
                        || meta
                            .media_type
                            .as_ref()
                            .is_some_and(|t| Some(t) != partial.meta.media_type.as_ref())
                    {
                        return Err(Fault::Interrupted(partial.reference.clone()));
                    }
                    let size = partial
                        .data
                        .len()
                        .checked_add(data.len())
                        .ok_or(Fault::Size(result.id))?;
                    if data.is_empty()
                        || size > partial.size
                        || size > limits.object_bytes
                        || (item.more_data && size == partial.size)
                    {
                        return Err(Fault::Size(result.id));
                    }
                    partial.data.push_str(data);
                    partial.next = raw.header.message_id.checked_add(1).ok_or(Fault::Invalid)?;
                    touched = true;
                    if !item.more_data {
                        let partial = self.partial.take().ok_or(Fault::Invalid)?;
                        if partial.data.len() != partial.size {
                            return Err(Fault::Size(result.id));
                        }
                        if partial.meta.format.as_deref() == Some("b64") {
                            let data = partial
                                .data
                                .bytes()
                                .filter(|b| !b.is_ascii_whitespace())
                                .collect::<Vec<_>>();
                            let decoded = base64::engine::general_purpose::STANDARD
                                .decode(data)
                                .map_err(|_| Fault::Invalid)?;
                            if decoded.len() > limits.decoded_object_bytes {
                                return Err(Fault::Size(result.id));
                            }
                        }
                        let mut item = item.clone();
                        item.data = Some(Secret(partial.data));
                        item.meta = Some(partial.meta);
                        item.more_data = false;
                        items.push(item);
                        continue;
                    }
                } else {
                    let size = meta.size.ok_or(Fault::Invalid)? as usize;
                    if size > limits.object_bytes || data.is_empty() || data.len() >= size {
                        return Err(Fault::Size(result.id));
                    }
                    self.partial = Some(Partial {
                        reference: reference.clone(),
                        meta,
                        size,
                        next: raw.header.message_id.checked_add(1).ok_or(Fault::Invalid)?,
                        data: data.clone(),
                    });
                    touched = true;
                }
                controls.push(Command::Status(Status {
                    id: 0,
                    message_ref: raw.header.message_id,
                    command_ref: result.id,
                    command: CommandName::Results,
                    target_refs: vec![],
                    source_refs: vec![reference.uri],
                    code: 213,
                    items: vec![],
                    challenge: None,
                    credential: None,
                }));
            }
            if let Command::Results(result) = &mut output.commands[position] {
                result.items = items;
                result.meta = None;
            }
        }
        if !touched && let Some(reference) = required {
            return Err(Fault::Interrupted(reference));
        }
        output
            .commands
            .retain(|c| !matches!(c,Command::Results(r) if r.items.is_empty()));
        Ok(Frame {
            message: output,
            controls,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> s::Expected {
        let request = Message {
            header: s::Header {
                session_id: 1,
                message_id: 1,
                target: "device".into(),
                source: "server".into(),
                credential: None,
                meta: None,
            },
            commands: vec![Command::Get {
                id: 4,
                meta: None,
                items: vec![
                    Item {
                        more_data: false,
                        source: None,
                        target: Some("./one".into()),
                        meta: None,
                        data: None,
                    },
                    Item {
                        more_data: false,
                        source: None,
                        target: Some("./two".into()),
                        meta: None,
                        data: None,
                    },
                ],
            }],
            final_message: true,
        };
        let limits = CodecLimits::default();
        let (_, sent) = s::encode_request(&request, &limits).unwrap();
        s::Expected::new(sent, 2, &limits).unwrap()
    }
    fn packet(message: u32, command: u32, data: &str, more: bool, size: Option<u32>) -> Message {
        let mut commands = vec![Command::Status(Status {
            id: 1,
            message_ref: message - 1,
            command_ref: 0,
            command: CommandName::SyncHdr,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        })];
        if message == 2 {
            commands.push(Command::Status(Status {
                id: 2,
                message_ref: 1,
                command_ref: 4,
                command: CommandName::Get,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }));
        }
        commands.push(Command::Results(s::Results {
            id: command,
            message_ref: Some(1),
            command_ref: Some(4),
            command: Some(CommandName::Get),
            meta: None,
            items: vec![Item {
                more_data: more,
                source: Some("./one".into()),
                target: None,
                meta: Some(Meta {
                    size,
                    format: (message == 2).then(|| "b64".into()),
                    ..Meta::default()
                }),
                data: Some(Secret(data.into())),
            }],
        }));
        Message {
            header: s::Header {
                session_id: 1,
                message_id: message,
                target: "server".into(),
                source: "device".into(),
                credential: None,
                meta: None,
            },
            commands,
            final_message: !more,
        }
    }
    #[test]
    fn encoded_size_and_changing_command_ids_reassemble_only_at_the_last_chunk() {
        let expected = expected();
        let limits = CodecLimits::default();
        let mut a = Assembly::default();
        let first = a
            .feed(&packet(2, 7, "YWJ", true, Some(8)), &expected, &limits)
            .unwrap();
        assert!(
            first
                .message
                .commands
                .iter()
                .all(|c| !matches!(c, Command::Results(_)))
        );
        assert!(
            matches!(&first.controls[0],Command::Status(s) if s.code==213 && s.command_ref==7 && s.command==CommandName::Results)
        );
        let second = a
            .feed(&packet(3, 9, "jZ", true, None), &expected, &limits)
            .unwrap();
        assert!(
            second
                .message
                .commands
                .iter()
                .all(|c| !matches!(c, Command::Results(_)))
        );
        let last = a
            .feed(&packet(4, 3, "A==", false, None), &expected, &limits)
            .unwrap();
        assert!(last.controls.is_empty());
        let value = last
            .message
            .commands
            .iter()
            .find_map(|c| match c {
                Command::Results(r) => r.items[0].data.as_ref(),
                _ => None,
            })
            .unwrap();
        assert_eq!(value.0, "YWJjZA==");
        assert!(a.partial.is_none());
        let mut a = Assembly::default();
        a.feed(&packet(2, 7, "YWJ", true, Some(4)), &expected, &limits)
            .unwrap();
        assert!(matches!(
            a.feed(&packet(3, 9, "jZA==", false, None), &expected, &limits),
            Err(Fault::Size(9))
        ));
    }
    #[test]
    fn interrupted_reference_missing_chunk_and_repeated_size_never_form_an_object() {
        let expected = expected();
        let limits = CodecLimits::default();
        for kind in 0..5 {
            let mut a = Assembly::default();
            a.feed(&packet(2, 7, "YWJ", true, Some(8)), &expected, &limits)
                .unwrap();
            let mut next = packet(3, 9, "jZA==", false, None);
            if kind == 0
                && let Command::Results(r) = &mut next.commands[1]
            {
                r.items[0].source = Some("./two".into());
            }
            if kind == 3
                && let Command::Results(r) = &mut next.commands[1]
            {
                r.items[0].source = Some("./unknown".into());
            }
            if kind == 4 {
                next.header.message_id = 4;
            }
            if kind == 1 {
                next.commands.truncate(1);
            }
            if kind == 2
                && let Command::Results(r) = &mut next.commands[1]
            {
                r.items[0].meta.as_mut().unwrap().size = Some(8);
            }
            assert!(matches!(
                a.feed(&next, &expected, &limits),
                Err(Fault::Interrupted(_))
            ));
        }
        let mut a = Assembly::default();
        a.feed(&packet(2, 7, "YWJ", true, Some(8)), &expected, &limits)
            .unwrap();
        let small = CodecLimits {
            decoded_object_bytes: 3,
            ..limits
        };
        assert!(matches!(
            a.feed(&packet(3, 9, "jZA==", false, None), &expected, &small),
            Err(Fault::Size(9))
        ));
    }
    #[test]
    fn two_chunks_in_one_message_cannot_complete_the_object() {
        let mut a = Assembly::default();
        let mut first = packet(2, 7, "YWJ", true, Some(8));
        let mut second = packet(3, 9, "jZA==", false, None);
        first.commands.push(second.commands.pop().unwrap());
        assert!(matches!(
            a.feed(&first, &expected(), &CodecLimits::default()),
            Err(Fault::Interrupted(_))
        ));
    }
    #[test]
    fn another_items_get_status_does_not_authorize_this_chunk() {
        let expected = expected();
        let mut a = Assembly::default();
        let mut first = packet(2, 7, "YWJ", true, Some(8));
        if let Command::Status(status) = &mut first.commands[1] {
            status.target_refs = vec!["./two".into()];
        }
        assert!(matches!(
            a.feed(&first, &expected, &CodecLimits::default()),
            Err(Fault::Invalid)
        ));
    }
}
