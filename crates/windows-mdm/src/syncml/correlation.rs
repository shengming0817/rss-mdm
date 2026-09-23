//! Pure correlation; caller owns authentication, cross-message accumulation and replay storage.
use super::*;
use crate::{CorrelationError as C, CorrelationResult};
use std::collections::BTreeMap;
#[derive(Debug, Clone)]
struct SentCommand {
    id: u32,
    kind: CommandName,
    targets: Vec<String>,
}
/// Opaque snapshot minted only alongside successfully encoded outbound bytes.
/// Encoding is not proof of delivery: the product records this after sending those bytes.
/// ```compile_fail
/// use rss_mdm_windows_mdm::syncml::SentMessage;
/// fn forge(sent: &mut SentMessage) { sent.id = 99; }
/// ```
#[derive(Debug, Clone)]
pub struct SentMessage {
    session_id: u32,
    source: String,
    target: String,
    id: u32,
    commands: Vec<SentCommand>,
}
/// Correlation state cannot be fabricated from response fields.
/// ```compile_fail
/// use rss_mdm_windows_mdm::syncml::Expected;
/// let fabricated = Expected { response_message_id: 2, messages: vec![] };
/// ```
#[derive(Debug, Clone)]
pub struct Expected {
    response_message_id: u32,
    messages: Vec<SentMessage>,
}
/// Encode a server Get/Status message and derive its immutable correlation snapshot.
/// No token is returned on profile or output-budget failure.
pub fn encode_request(message: &Message, l: &CodecLimits) -> Result<(Vec<u8>, SentMessage)> {
    let bytes = encode(message, l)?;
    let mut commands = Vec::new();
    for command in &message.commands {
        let (kind, targets) = match command {
            Command::Get { items, .. } => (
                CommandName::Get,
                items
                    .iter()
                    .map(|i| i.target.clone().ok_or(E::Structure))
                    .collect::<Result<Vec<_>>>()?,
            ),
            Command::Replace { .. } => (
                CommandName::Replace,
                vec![crate::configuration::FIREWALL_URI.into()],
            ),
            Command::Status(_) => (CommandName::Status, Vec::new()),
            _ => return Err(E::Unsupported),
        };
        commands.push(SentCommand {
            id: command.id(),
            kind,
            targets,
        });
    }
    Ok((
        bytes,
        SentMessage {
            session_id: message.header.session_id,
            source: message.header.source.clone(),
            target: message.header.target.clone(),
            id: message.header.message_id,
            commands,
        },
    ))
}
impl Expected {
    /// Bind an encoded sent snapshot to a positive expected response message ID.
    /// Validates retained-message/command/item/URI budgets under the supplied limits;
    /// failures return [`crate::CorrelationError::InvalidExpected`]. Does not send bytes,
    /// verify delivery or authenticate the endpoints.
    pub fn new(
        sent: SentMessage,
        response_message_id: u32,
        l: &CodecLimits,
    ) -> CorrelationResult<Self> {
        let expected = Self {
            response_message_id,
            messages: vec![sent],
        };
        expected.validate(l).map_err(C::InvalidExpected)?;
        Ok(expected)
    }
    /// Add a successfully sent snapshot from this same session and endpoint pair.
    /// Failure leaves the prior expectation intact.
    pub fn record_sent(&mut self, sent: SentMessage, l: &CodecLimits) -> CorrelationResult<()> {
        bound(self.messages.len().saturating_add(1), l.commands).map_err(C::InvalidExpected)?;
        self.validate(l).map_err(C::InvalidExpected)?;
        let mut candidate = self.clone();
        candidate.messages.push(sent);
        candidate.validate(l).map_err(C::InvalidExpected)?;
        *self = candidate;
        Ok(())
    }
    fn validate(&self, l: &CodecLimits) -> Result<()> {
        if self.response_message_id == 0 {
            return Err(E::InvalidValue);
        }
        bound(self.messages.len(), l.commands)?;
        let first = self.messages.first().ok_or(E::Structure)?;
        let mut ids = BTreeSet::new();
        let mut commands = 0usize;
        let mut items = 0usize;
        for m in &self.messages {
            if m.session_id != first.session_id
                || m.source != first.source
                || m.target != first.target
            {
                return Err(E::InvalidValue);
            }
            if !ids.insert(m.id) {
                return Err(E::Duplicate);
            }
            text(&m.source, l.uri_bytes, false)?;
            text(&m.target, l.uri_bytes, false)?;
            commands = commands
                .checked_add(m.commands.len())
                .ok_or(E::LimitExceeded)?;
            bound(commands, l.commands)?;
            for c in &m.commands {
                items = items.checked_add(c.targets.len()).ok_or(E::LimitExceeded)?;
                bound(items, l.items)?;
                for uri in &c.targets {
                    text(uri, l.uri_bytes, false)?;
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// Exact original Get item identity within a sent message.
pub struct Reference {
    /// Original outbound message ID.
    pub message_id: u32,
    /// Original outbound Get command ID.
    pub command_id: u32,
    /// Exact target URI originally requested.
    pub uri: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
/// One structurally matched Get value, still requiring authenticated source handling.
pub struct CorrelatedItem {
    /// Original message/command/URI matched to this result.
    pub reference: Reference,
    /// Untrusted result text; Debug redaction does not encrypt it.
    pub value: Secret<String>,
    /// Whether the response provided MsgRef rather than using the default 1.
    pub explicit_message_ref: bool,
    /// Whether the response provided CmdRef rather than using the default 1.
    pub explicit_command_ref: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
/// Matched status report with its effective target coverage and untrusted details.
pub struct CorrelatedStatus {
    /// Original outbound message being acknowledged.
    pub message_id: u32,
    /// Original command, or zero for SyncHdr.
    pub command_id: u32,
    /// Reported protocol code; matching does not by itself make this a success.
    pub code: u16,
    /// Effective Get target coverage; empty for header/non-targeted command status.
    pub targets: Vec<String>,
    /// Original status details retained for product interpretation.
    pub item_details: Vec<Item>,
}
#[must_use = "Inspect statuses and missing results; correlation alone is not collection completion"]
#[derive(Debug, Clone, PartialEq, Eq)]
/// One response's matched values, statuses and unresolved requests.
/// Not a completeness, authentication or durable replay receipt. The product owns
/// cross-response accumulation, status interpretation and collection completion.
pub struct Correlated {
    /// Matched unique Get items, in response order.
    pub results: Vec<CorrelatedItem>,
    /// Matched statuses, including a required first header status.
    pub statuses: Vec<CorrelatedStatus>,
    /// Sorted requested Get items not returned in this response; prior responses are not accumulated.
    pub missing_results: Vec<Reference>,
}
/// Structural errors never yield partial success. A valid partial response preserves missing items.
/// Validates expected/response profiles, session and message IDs, original command/URI
/// references, status order and nonoverlapping coverage. Results must not contradict
/// failure statuses. Invalid inputs are classified by [`crate::CorrelationError`];
/// unmatched identities/coverage return Mismatch. This does not authenticate source/
/// target claims, modify expected state, persist replay protection or finish a collection.
pub fn correlate(
    expected: &Expected,
    response: &Message,
    l: &CodecLimits,
) -> CorrelationResult<Correlated> {
    expected.validate(l).map_err(C::InvalidExpected)?;
    validate(response, l).map_err(C::InvalidResponse)?;
    let first = &expected.messages[0];
    if response.header.session_id != first.session_id
        || response.header.message_id != expected.response_message_id
    {
        return Err(C::Mismatch);
    }
    let messages: BTreeSet<_> = expected.messages.iter().map(|m| m.id).collect();
    let requests: BTreeMap<_, _> = expected
        .messages
        .iter()
        .flat_map(|m| m.commands.iter().map(move |c| ((m.id, c.id), c)))
        .collect();
    let mut remaining: BTreeSet<_> = requests
        .iter()
        .filter(|(_, c)| c.kind == CommandName::Get)
        .flat_map(|(&(message_id, command_id), c)| {
            c.targets.iter().map(move |uri| Reference {
                message_id,
                command_id,
                uri: uri.clone(),
            })
        })
        .collect();
    let mut results = Vec::new();
    let mut statuses = Vec::new();
    let mut status_coverage: BTreeMap<(u32, u32), BTreeSet<String>> = BTreeMap::new();
    let mut last_status = BTreeMap::new();
    let order: BTreeMap<_, _> = expected
        .messages
        .iter()
        .flat_map(|m| {
            std::iter::once((m.id, 0)).chain(m.commands.iter().map(move |c| (m.id, c.id)))
        })
        .enumerate()
        .map(|(i, k)| (k, i))
        .collect();
    for c in &response.commands {
        match c {
            Command::Results(r) => {
                let key = (r.message_ref.unwrap_or(1), r.command_ref.unwrap_or(1));
                let request = requests.get(&key).ok_or(C::Mismatch)?;
                if request.kind != CommandName::Get {
                    return Err(C::Mismatch);
                }
                for i in &r.items {
                    let reference = Reference {
                        message_id: key.0,
                        command_id: key.1,
                        uri: i.source.as_ref().ok_or(C::Mismatch)?.clone(),
                    };
                    if !remaining.remove(&reference) {
                        return Err(C::Mismatch);
                    }
                    results.push(CorrelatedItem {
                        reference,
                        value: i.data.clone().ok_or(C::Mismatch)?,
                        explicit_message_ref: r.message_ref.is_some(),
                        explicit_command_ref: r.command_ref.is_some(),
                    });
                }
            }
            Command::Status(s) => {
                let key = (s.message_ref, s.command_ref);
                let index = *order.get(&key).ok_or(C::Mismatch)?;
                // A current header may precede remaining statuses for an earlier
                // request. Command ordering applies within each referenced message.
                if s.command_ref != 0 {
                    if last_status.get(&s.message_ref).is_some_and(|n| index < *n) {
                        return Err(C::Mismatch);
                    }
                    last_status.insert(s.message_ref, index);
                }
                let targets = if s.command_ref == 0 {
                    if !messages.contains(&s.message_ref)
                        || s.command != CommandName::SyncHdr
                        || !s.target_refs.is_empty()
                        || !s.source_refs.is_empty()
                    {
                        return Err(C::Mismatch);
                    }
                    vec![String::new()]
                } else {
                    let request = requests.get(&key).ok_or(C::Mismatch)?;
                    if request.kind != s.command || !s.source_refs.is_empty() {
                        return Err(C::Mismatch);
                    }
                    if s.target_refs.is_empty() {
                        if request.targets.is_empty() {
                            vec![String::new()]
                        } else {
                            request.targets.clone()
                        }
                    } else {
                        if s.target_refs.iter().any(|v| !request.targets.contains(v)) {
                            return Err(C::Mismatch);
                        }
                        s.target_refs.clone()
                    }
                };
                let seen = status_coverage.entry(key).or_default();
                for t in &targets {
                    if !seen.insert(t.clone()) {
                        return Err(C::InvalidResponse(E::Duplicate));
                    }
                }
                statuses.push(CorrelatedStatus {
                    message_id: key.0,
                    command_id: key.1,
                    code: s.code,
                    item_details: s.items.clone(),
                    targets: targets.into_iter().filter(|s| !s.is_empty()).collect(),
                });
            }
            _ => return Err(C::Mismatch),
        }
    }
    // A header Status is required whenever a response contains Status elements.
    if statuses.first().is_none_or(|first| first.command_id != 0) {
        return Err(C::Mismatch);
    }
    for r in &results {
        if statuses.iter().any(|s| {
            s.message_id == r.reference.message_id
                && !(200..300).contains(&s.code)
                && (s.command_id == 0
                    || (s.command_id == r.reference.command_id
                        && (s.targets.is_empty() || s.targets.contains(&r.reference.uri))))
        }) {
            return Err(C::Mismatch);
        }
    }
    Ok(Correlated {
        results,
        statuses,
        missing_results: remaining.into_iter().collect(),
    })
}
