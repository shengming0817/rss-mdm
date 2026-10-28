//! Admission measures the entire wire message, including its possible receipt shape.
use super::*;

/// Notification that can accompany, but never replace, initialization.
pub fn initialization_companion(command: &Command) -> bool {
    matches!(
        command,
        Command::Alert {
            alert: Alert::Generic { .. } | Alert::DeclaredConfiguration { .. },
            ..
        }
    )
}

/// Candidate disposition; callers own persistence and business failure settlement.
#[derive(Debug)]
pub enum Admission {
    /// Complete response fits the current peer and local structural limits.
    Send(Vec<u8>),
    /// The candidate can fit the supported profile, but not this exchange.
    Defer,
    /// The candidate cannot fit even an otherwise empty supported response.
    Unsupported,
}

/// Evaluate a candidate without mutating the caller's draft or recording delivery.
/// The prefix must already contain authentication, acknowledgements and required controls.
pub fn admit(prefix: &Message, commands: &[Command], limits: &CodecLimits) -> Result<Admission> {
    let mut candidate = prefix.clone();
    candidate.commands.extend_from_slice(commands);
    match encode_outbound(&candidate, limits) {
        Ok(bytes) => return Ok(Admission::Send(bytes)),
        Err(E::LimitExceeded) => (),
        Err(E::Unsupported) => return Ok(Admission::Unsupported),
        Err(error) => return Err(error),
    }
    let mut minimum = prefix.clone();
    minimum
        .commands
        .retain(|c| matches!(c, Command::Status(s) if s.command_ref == 0));
    minimum.commands.extend_from_slice(commands);
    minimum.final_message = true;
    match encode_outbound(&minimum, &CodecLimits::default()) {
        Ok(_) => Ok(Admission::Defer),
        Err(E::LimitExceeded | E::Unsupported) => Ok(Admission::Unsupported),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn measures_actual_escaped_bytes_and_defers_peer_only_limits() {
        let prefix = Message {
            header: Header {
                session_id: 1,
                message_id: 2,
                source: "server".into(),
                target: "device".into(),
                credential: None,
                meta: None,
            },
            commands: vec![Command::Status(Status {
                id: 1,
                message_ref: 1,
                command_ref: 0,
                command: CommandName::SyncHdr,
                code: 200,
                target_refs: vec![],
                source_refs: vec![],
                items: vec![],
                challenge: None,
                credential: None,
            })],
            final_message: true,
        };
        let command = Command::Replace {
            id: 1024,
            meta: None,
            items: vec![Item {
                target: Some("./Vendor/MSFT/Test".into()),
                source: None,
                meta: None,
                data: Some(Secret("<&>".repeat(10))),
                more_data: false,
            }],
        };
        let commands = [command];
        let Admission::Send(bytes) = admit(&prefix, &commands, &CodecLimits::default()).unwrap()
        else {
            panic!("valid candidate rejected")
        };
        let limits = CodecLimits {
            syncml_bytes: bytes.len(),
            ..CodecLimits::default()
        };
        assert!(matches!(
            admit(&prefix, &commands, &limits).unwrap(),
            Admission::Send(_)
        ));
        let limits = CodecLimits {
            syncml_bytes: bytes.len() - 1,
            ..limits
        };
        assert!(matches!(
            admit(&prefix, &commands, &limits).unwrap(),
            Admission::Defer
        ));
        let limits = CodecLimits {
            object_bytes: 1,
            ..CodecLimits::default()
        };
        assert!(matches!(
            admit(&prefix, &commands, &limits).unwrap(),
            Admission::Defer
        ));
    }
}
