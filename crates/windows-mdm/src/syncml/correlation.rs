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
/// Opaque snapshot minted from encoded outbound bytes or validated recorded wire.
/// Neither encoding nor decoding proves delivery; the product owns committed history.
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
    message_ids: BTreeSet<u32>,
    requests: BTreeMap<(u32, u32), (usize, usize)>,
    references: BTreeSet<Reference>,
    order: BTreeMap<(u32, u32), usize>,
    items: usize,
    max_uri_bytes: usize,
}
/// Encode a new server message only when its possible receipts fit local limits.
/// Get items can each produce both a Status and a Results command. Other operations
/// can report per-item statuses; compound commands also have their own status.
/// This is outbound admission, not a protocol command-count maximum or a restriction
/// on rebuilding the correlation snapshot of a previously committed message.
pub fn encode_outbound(message: &Message, limits: &CodecLimits) -> Result<Vec<u8>> {
    let mut commands = 1usize; // The client's SyncHdr status.
    let mut items = 0usize;
    for command in flattened(&message.commands, limits)? {
        let (receipt_commands, receipt_items) = match command {
            Command::Get { items, .. } => {
                let receipts = items.len().checked_mul(2).ok_or(E::LimitExceeded)?;
                (receipts, receipts)
            }
            Command::Add { items, .. }
            | Command::Replace { items, .. }
            | Command::Delete { items, .. }
            | Command::Exec { items, .. } => (items.len().max(1), items.len()),
            Command::Atomic { .. } | Command::Sequence { .. } => (1, 0),
            Command::Alert { .. } => (2, 0),
            Command::Status(_) => (0, 0),
            _ => return Err(E::Unsupported),
        };
        commands = commands
            .checked_add(receipt_commands)
            .ok_or(E::LimitExceeded)?;
        items = items.checked_add(receipt_items).ok_or(E::LimitExceeded)?;
        bound(commands, limits.commands)?;
        bound(items, limits.items)?;
    }
    encode(message, limits)
}
/// Encode a server Get/Status message and derive its immutable correlation snapshot.
/// No token is returned on profile or output-budget failure.
pub fn encode_request(message: &Message, l: &CodecLimits) -> Result<(Vec<u8>, SentMessage)> {
    let bytes = encode(message, l)?;
    Ok((bytes, sent_snapshot(message, l)?))
}
/// Decode a recorded server message and recover its opaque correlation snapshot.
/// The caller supplies committed, authenticated history. This validates wire/profile
/// budgets but neither authenticates the history nor proves that it was delivered.
pub fn decode_request(bytes: &[u8], l: &CodecLimits) -> Result<(Message, SentMessage)> {
    let message = decode(bytes, l)?;
    let sent = sent_snapshot(&message, l)?;
    Ok((message, sent))
}
fn sent_snapshot(message: &Message, l: &CodecLimits) -> Result<SentMessage> {
    let mut commands = Vec::new();
    for command in flattened(&message.commands, l)? {
        let (kind, targets) = match command {
            Command::Get { items, .. } => (
                CommandName::Get,
                items
                    .iter()
                    .map(|i| i.target.clone().ok_or(E::Structure))
                    .collect::<Result<Vec<_>>>()?,
            ),
            Command::Add { items, .. }
            | Command::Exec { items, .. }
            | Command::Delete { items, .. }
            | Command::Replace { items, .. } => (
                match command {
                    Command::Add { .. } => CommandName::Add,
                    Command::Exec { .. } => CommandName::Exec,
                    Command::Delete { .. } => CommandName::Delete,
                    _ => CommandName::Replace,
                },
                items
                    .iter()
                    .map(|i| i.target.clone().ok_or(E::Structure))
                    .collect::<Result<Vec<_>>>()?,
            ),
            Command::Atomic { .. } => (CommandName::Atomic, Vec::new()),
            Command::Sequence { .. } => (CommandName::Sequence, Vec::new()),
            Command::Status(_) => (CommandName::Status, Vec::new()),
            Command::Alert { .. } => (CommandName::Alert, Vec::new()),
            _ => return Err(E::Unsupported),
        };
        commands.push(SentCommand {
            id: command.id(),
            kind,
            targets,
        });
    }
    Ok(SentMessage {
        session_id: message.header.session_id,
        source: message.header.source.clone(),
        target: message.header.target.clone(),
        id: message.header.message_id,
        commands,
    })
}
impl Expected {
    /// Resolve an exact original Get item from successfully encoded outbound messages.
    /// This establishes protocol correlation only; the channel still authenticates the sender.
    pub fn get_reference(
        &self,
        message_id: u32,
        command_id: u32,
        uri: &str,
    ) -> CorrelationResult<Reference> {
        let reference = Reference {
            message_id,
            command_id,
            uri: uri.into(),
        };
        if self.references.contains(&reference) {
            Ok(reference)
        } else {
            Err(C::Mismatch)
        }
    }
    /// Bind an encoded sent snapshot to a positive expected response message ID.
    /// Validates retained-message/command/item/URI budgets under the supplied limits;
    /// failures return [`crate::CorrelationError::InvalidExpected`]. Does not send bytes,
    /// verify delivery or authenticate the endpoints.
    pub fn new(
        sent: SentMessage,
        response_message_id: u32,
        l: &CodecLimits,
    ) -> CorrelationResult<Self> {
        let mut expected = Self {
            response_message_id,
            messages: Vec::new(),
            message_ids: BTreeSet::new(),
            requests: BTreeMap::new(),
            references: BTreeSet::new(),
            order: BTreeMap::new(),
            items: 0,
            max_uri_bytes: 0,
        };
        expected.record_sent(sent, l)?;
        Ok(expected)
    }
    /// Add a sent snapshot atomically, checking new data once. Tighter limits also
    /// recheck retained totals; failure never changes the existing expectation.
    pub fn record_sent(&mut self, sent: SentMessage, l: &CodecLimits) -> CorrelationResult<()> {
        let checked = || -> Result<(usize, usize)> {
            if self.response_message_id == 0 {
                return Err(E::InvalidValue);
            }
            if let Some(first) = self.messages.first()
                && (first.session_id != sent.session_id
                    || first.source != sent.source
                    || first.target != sent.target)
            {
                return Err(E::InvalidValue);
            }
            if self.message_ids.contains(&sent.id) {
                return Err(E::Duplicate);
            }
            bound(self.messages.len().saturating_add(1), l.session_messages)?;
            bound(
                self.requests.len().saturating_add(sent.commands.len()),
                l.session_commands,
            )?;
            let mut items = self.items;
            let mut uri_bytes = self.max_uri_bytes;
            for uri in std::iter::once(&sent.source)
                .chain(std::iter::once(&sent.target))
                .chain(sent.commands.iter().flat_map(|c| c.targets.iter()))
            {
                text(uri, l.uri_bytes, false)?;
                uri_bytes = uri_bytes.max(uri.len());
            }
            for command in &sent.commands {
                items = items
                    .checked_add(command.targets.len())
                    .ok_or(E::LimitExceeded)?;
            }
            bound(items, l.session_items)?;
            bound(uri_bytes, l.uri_bytes)?;
            Ok((items, uri_bytes))
        };
        let (items, uri_bytes) = checked().map_err(C::InvalidExpected)?;
        let message_index = self.messages.len();
        self.message_ids.insert(sent.id);
        self.order.insert((sent.id, 0), self.order.len());
        for (index, command) in sent.commands.iter().enumerate() {
            let key = (sent.id, command.id);
            self.requests.insert(key, (message_index, index));
            self.order.insert(key, self.order.len());
            if command.kind == CommandName::Get {
                self.references
                    .extend(command.targets.iter().map(|uri| Reference {
                        message_id: sent.id,
                        command_id: command.id,
                        uri: uri.clone(),
                    }));
            }
        }
        self.messages.push(sent);
        self.items = items;
        self.max_uri_bytes = uri_bytes;
        Ok(())
    }
    fn request(&self, key: &(u32, u32)) -> Option<&SentCommand> {
        let &(message, command) = self.requests.get(key)?;
        Some(&self.messages[message].commands[command])
    }
    fn validate(&self, l: &CodecLimits) -> Result<()> {
        if self.response_message_id == 0 {
            return Err(E::InvalidValue);
        }
        if self.messages.is_empty() {
            return Err(E::Structure);
        }
        bound(self.messages.len(), l.session_messages)?;
        bound(self.requests.len(), l.session_commands)?;
        bound(self.items, l.session_items)?;
        bound(self.max_uri_bytes, l.uri_bytes)
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
    let mut remaining = expected.references.clone();
    let mut results = Vec::new();
    let mut statuses = Vec::new();
    let mut status_coverage: BTreeMap<(u32, u32), BTreeSet<String>> = BTreeMap::new();
    let mut last_status = BTreeMap::new();
    for c in &response.commands {
        match c {
            Command::Results(r) => {
                let key = (r.message_ref.unwrap_or(1), r.command_ref.unwrap_or(1));
                let request = expected.request(&key).ok_or(C::Mismatch)?;
                if request.kind != CommandName::Get {
                    return Err(C::Mismatch);
                }
                for i in &r.items {
                    if i.more_data {
                        return Err(C::InvalidResponse(E::Structure));
                    }
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
                let index = *expected.order.get(&key).ok_or(C::Mismatch)?;
                // A current header may precede remaining statuses for an earlier
                // request. Command ordering applies within each referenced message.
                if s.command_ref != 0 {
                    if last_status.get(&s.message_ref).is_some_and(|n| index < *n) {
                        return Err(C::Mismatch);
                    }
                    last_status.insert(s.message_ref, index);
                }
                let targets = if s.command_ref == 0 {
                    if !expected.message_ids.contains(&s.message_ref)
                        || s.command != CommandName::SyncHdr
                        || !s.target_refs.is_empty()
                        || !s.source_refs.is_empty()
                    {
                        return Err(C::Mismatch);
                    }
                    vec![String::new()]
                } else {
                    let request = expected.request(&key).ok_or(C::Mismatch)?;
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
