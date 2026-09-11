//! Bounded SyncML 1.2. Device IDs and values are claims, never authentication.
use crate::{
    CodecError as E, CodecLimits, Result, Secret, bound, text,
    xml::{Input, Output},
};
use std::collections::BTreeSet;
mod correlation;
pub use correlation::{
    Correlated, CorrelatedItem, CorrelatedStatus, Expected, Reference, SentMessage, correlate,
    encode_request,
};
pub const NS: &str = "SYNCML:SYNCML1.2";
const META: &str = "syncml:metinf";
const LOGIN_STATUS: &str = "com.microsoft/MDM/LoginStatus";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub session_id: u32,
    pub message_id: u32,
    pub target: String,
    pub source: String,
    pub credential: Option<Credential>,
    pub meta: Option<Meta>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub meta: Meta,
    pub data: Secret<String>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meta {
    pub format: Option<String>,
    pub media_type: Option<String>,
    pub max_message_size: Option<u32>,
    pub max_object_size: Option<u32>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub commands: Vec<Command>,
    pub final_message: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Get {
        id: u32,
        meta: Option<Meta>,
        items: Vec<Item>,
    },
    Status(Status),
    Results(Results),
    Alert {
        id: u32,
        alert: Alert,
    },
    /// Only device-to-server DevInfo initialization; never a device write API.
    DevInfo {
        id: u32,
        items: Vec<Item>,
    },
}
/// Supported initialization alerts. Login state is an untrusted device claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alert {
    ClientInitiated,
    LoginStatus {
        status: LoginStatus,
        explicit_format: bool,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginStatus {
    User,
    Others,
    None,
}
impl LoginStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Others => "others",
            Self::None => "none",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub source: Option<String>,
    pub target: Option<String>,
    pub meta: Option<Meta>,
    pub data: Option<Secret<String>>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommandName {
    SyncHdr,
    Get,
    Status,
    Alert,
    Replace,
}
impl CommandName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SyncHdr => "SyncHdr",
            Self::Get => "Get",
            Self::Status => "Status",
            Self::Alert => "Alert",
            Self::Replace => "Replace",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "SyncHdr" => Ok(Self::SyncHdr),
            "Get" => Ok(Self::Get),
            "Status" => Ok(Self::Status),
            "Alert" => Ok(Self::Alert),
            "Replace" => Ok(Self::Replace),
            _ => Err(E::Unsupported),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub id: u32,
    pub message_ref: u32,
    pub command_ref: u32,
    pub command: CommandName,
    pub target_refs: Vec<String>,
    pub source_refs: Vec<String>,
    pub code: u16,
    pub items: Vec<Item>,
    pub challenge: Option<Challenge>,
    pub credential: Option<Credential>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub media_type: String,
    pub nonce: Option<Secret<String>>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Results {
    pub id: u32,
    /// MS-MDM default is 1 when absent; presence is retained for diagnostics.
    pub message_ref: Option<u32>,
    pub command_ref: Option<u32>,
    pub command: Option<CommandName>,
    pub meta: Option<Meta>,
    pub items: Vec<Item>,
}
impl Command {
    pub fn id(&self) -> u32 {
        match self {
            Self::Get { id, .. } | Self::Alert { id, .. } | Self::DevInfo { id, .. } => *id,
            Self::Status(s) => s.id,
            Self::Results(r) => r.id,
        }
    }
}
pub(crate) fn number(s: &str, zero: bool) -> Result<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(E::InvalidValue);
    }
    let n = s.parse().map_err(|_| E::InvalidValue)?;
    if n == 0 && !zero {
        return Err(E::InvalidValue);
    }
    Ok(n)
}
fn num(p: &mut Input<'_>, name: &str, zero: bool) -> Result<u32> {
    number(&p.scalar(NS, name, p.limits.identifier_bytes, false)?, zero)
}
fn location(p: &mut Input<'_>, name: &str) -> Result<String> {
    p.open(NS, name)?;
    let s = p.scalar(NS, "LocURI", p.limits.uri_bytes, false)?;
    p.end(NS, name)?;
    Ok(s)
}
fn optional_location(p: &mut Input<'_>, name: &str) -> Result<Option<String>> {
    if p.is(NS, name)? {
        Ok(Some(location(p, name)?))
    } else {
        Ok(None)
    }
}
fn meta(p: &mut Input<'_>) -> Result<Option<Meta>> {
    if !p.is(NS, "Meta")? {
        return Ok(None);
    }
    p.open(NS, "Meta")?;
    let m = Meta {
        format: p.optional(META, "Format", p.limits.identifier_bytes)?,
        media_type: p.optional(META, "Type", p.limits.uri_bytes)?,
        max_message_size: p
            .optional(META, "MaxMsgSize", p.limits.identifier_bytes)?
            .map(|s| number(&s, false))
            .transpose()?,
        max_object_size: p
            .optional(META, "MaxObjSize", p.limits.identifier_bytes)?
            .map(|s| number(&s, false))
            .transpose()?,
    };
    p.end(NS, "Meta")?;
    Ok(Some(m))
}
fn items(p: &mut Input<'_>) -> Result<Vec<Item>> {
    let mut out = Vec::new();
    while p.is(NS, "Item")? {
        p.item()?;
        p.open(NS, "Item")?;
        let i = Item {
            target: optional_location(p, "Target")?,
            source: optional_location(p, "Source")?,
            meta: meta(p)?,
            data: if p.is(NS, "Data")? {
                Some(Secret(p.scalar(NS, "Data", p.limits.field_bytes, true)?))
            } else {
                None
            },
        };
        p.end(NS, "Item")?;
        out.push(i);
    }
    if out.is_empty() {
        return Err(E::Structure);
    }
    Ok(out)
}
fn read_login_status(p: &mut Input<'_>) -> Result<Alert> {
    p.item()?;
    p.open(NS, "Item")?;
    p.open(NS, "Meta")?;
    let mut media_type = false;
    let mut explicit_format = false;
    loop {
        if p.is(META, "Type")? {
            if media_type {
                return Err(E::Duplicate);
            }
            if p.scalar(META, "Type", p.limits.uri_bytes, false)? != LOGIN_STATUS {
                return Err(E::Unsupported);
            }
            media_type = true;
        } else if p.is(META, "Format")? {
            if explicit_format {
                return Err(E::Duplicate);
            }
            if p.scalar(META, "Format", p.limits.identifier_bytes, false)? != "chr" {
                return Err(E::Unsupported);
            }
            explicit_format = true;
        } else {
            break;
        }
    }
    p.end(NS, "Meta")?;
    if !media_type {
        return Err(E::Structure);
    }
    let status = match p.scalar(NS, "Data", p.limits.field_bytes, false)?.as_str() {
        "user" => LoginStatus::User,
        "others" => LoginStatus::Others,
        "none" => LoginStatus::None,
        _ => return Err(E::Unsupported),
    };
    p.end(NS, "Item")?;
    Ok(Alert::LoginStatus {
        status,
        explicit_format,
    })
}
fn refs(p: &mut Input<'_>, name: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    while p.is(NS, name)? {
        bound(out.len() + 1, p.limits.items)?;
        out.push(p.scalar(NS, name, p.limits.uri_bytes, false)?);
    }
    Ok(out)
}
/// Parse exactly one complete document; unsupported commands are not skipped.
pub fn decode(bytes: &[u8], l: &CodecLimits) -> Result<Message> {
    let mut p = Input::new(bytes, l.syncml_bytes, l)?;
    p.open(NS, "SyncML")?;
    p.open(NS, "SyncHdr")?;
    if p.scalar(NS, "VerDTD", l.identifier_bytes, false)? != "1.2"
        || p.scalar(NS, "VerProto", l.identifier_bytes, false)? != "DM/1.2"
    {
        return Err(E::Unsupported);
    }
    let session_id = num(&mut p, "SessionID", false)?;
    let message_id = num(&mut p, "MsgID", false)?;
    let target = location(&mut p, "Target")?;
    let source = location(&mut p, "Source")?;
    let credential = read_credential(&mut p)?;
    let header = Header {
        session_id,
        message_id,
        target,
        source,
        credential,
        meta: meta(&mut p)?,
    };
    p.end(NS, "SyncHdr")?;
    p.open(NS, "SyncBody")?;
    let mut commands = Vec::new();
    loop {
        let c = if p.is(NS, "Get")? {
            p.command()?;
            p.open(NS, "Get")?;
            let id = num(&mut p, "CmdID", false)?;
            let meta = meta(&mut p)?;
            let items = items(&mut p)?;
            p.end(NS, "Get")?;
            Command::Get { id, meta, items }
        } else if p.is(NS, "Status")? {
            p.command()?;
            p.open(NS, "Status")?;
            let id = num(&mut p, "CmdID", false)?;
            let message_ref = num(&mut p, "MsgRef", false)?;
            let command_ref = num(&mut p, "CmdRef", true)?;
            let command = CommandName::parse(&p.scalar(NS, "Cmd", l.identifier_bytes, false)?)?;
            let oma = !p.is(NS, "Data")?;
            let mut target_refs = refs(&mut p, "TargetRef")?;
            let mut source_refs = refs(&mut p, "SourceRef")?;
            let credential = read_credential(&mut p)?;
            let challenge = if p.is(NS, "Chal")? {
                p.open(NS, "Chal")?;
                p.open(NS, "Meta")?;
                let format = p.optional(META, "Format", l.identifier_bytes)?;
                if format.as_deref().is_some_and(|f| f != "b64") {
                    return Err(E::Unsupported);
                }
                let media_type = p.scalar(META, "Type", l.uri_bytes, false)?;
                let nonce = p
                    .optional(META, "NextNonce", l.identifier_bytes)?
                    .map(Secret);
                p.end(NS, "Meta")?;
                p.end(NS, "Chal")?;
                Some(Challenge { media_type, nonce })
            } else {
                None
            };
            let code = num(&mut p, "Data", false)?
                .try_into()
                .map_err(|_| E::InvalidValue)?;
            let items = if p.is(NS, "Item")? {
                items(&mut p)?
            } else {
                Vec::new()
            };
            // Accept each documented grammar, never a mixture of their reference positions.
            if !oma {
                target_refs = refs(&mut p, "TargetRef")?;
                source_refs = refs(&mut p, "SourceRef")?;
            }
            p.end(NS, "Status")?;
            Command::Status(Status {
                id,
                message_ref,
                command_ref,
                command,
                target_refs,
                source_refs,
                challenge,
                credential,
                code,
                items,
            })
        } else if p.is(NS, "Results")? {
            p.command()?;
            p.open(NS, "Results")?;
            let id = num(&mut p, "CmdID", false)?;
            let message_ref = p
                .optional(NS, "MsgRef", l.identifier_bytes)?
                .map(|s| number(&s, false))
                .transpose()?;
            let command_ref = p
                .optional(NS, "CmdRef", l.identifier_bytes)?
                .map(|s| number(&s, false))
                .transpose()?;
            let command = p
                .optional(NS, "Cmd", l.identifier_bytes)?
                .map(|s| CommandName::parse(&s))
                .transpose()?;
            let meta = meta(&mut p)?;
            let items = items(&mut p)?;
            p.end(NS, "Results")?;
            Command::Results(Results {
                id,
                message_ref,
                command_ref,
                command,
                meta,
                items,
            })
        } else if p.is(NS, "Alert")? {
            p.command()?;
            p.open(NS, "Alert")?;
            let id = num(&mut p, "CmdID", false)?;
            let alert = match num(&mut p, "Data", false)? {
                1201 => Alert::ClientInitiated,
                1224 => read_login_status(&mut p)?,
                _ => return Err(E::Unsupported),
            };
            p.end(NS, "Alert")?;
            Command::Alert { id, alert }
        } else if p.is(NS, "Replace")? {
            p.command()?;
            p.open(NS, "Replace")?;
            let id = num(&mut p, "CmdID", false)?;
            let items = items(&mut p)?;
            p.end(NS, "Replace")?;
            Command::DevInfo { id, items }
        } else {
            break;
        };
        commands.push(c);
    }
    let final_message = if p.is(NS, "Final")? {
        p.open(NS, "Final")?;
        p.end(NS, "Final")?;
        true
    } else {
        false
    };
    p.end(NS, "SyncBody")?;
    p.end(NS, "SyncML")?;
    p.finish()?;
    let message = Message {
        header,
        commands,
        final_message,
    };
    validate(&message, l)?;
    Ok(message)
}
fn validate_meta(m: Option<&Meta>, l: &CodecLimits, credential: bool) -> Result<()> {
    if let Some(m) = m {
        if let Some(f) = &m.format {
            text(f, l.identifier_bytes, false)?;
            if !matches!(f.as_str(), "chr" | "int" | "bool" | "b64") {
                return Err(E::Unsupported);
            }
        }
        if let Some(t) = &m.media_type {
            text(t, l.uri_bytes, false)?;
            if credential {
                if !matches!(t.as_str(), "syncml:auth-basic" | "syncml:auth-md5") {
                    return Err(E::Unsupported);
                }
            } else if t != "text/plain" {
                return Err(E::Unsupported);
            }
        }
        if m.max_message_size == Some(0) || m.max_object_size == Some(0) {
            return Err(E::InvalidValue);
        }
    }
    Ok(())
}
fn validate_items(items: &[Item], l: &CodecLimits, get: bool, devinfo: bool) -> Result<()> {
    if items.is_empty() {
        return Err(E::Structure);
    }
    bound(items.len(), l.items)?;
    let mut seen = BTreeSet::new();
    for i in items {
        let uri = if get {
            if i.source.is_some() || i.data.is_some() {
                return Err(E::Structure);
            }
            i.target.as_ref()
        } else {
            if i.target.is_some() {
                return Err(E::Structure);
            }
            i.source.as_ref()
        }
        .ok_or(E::Structure)?;
        text(uri, l.uri_bytes, false)?;
        if !seen.insert(uri) {
            return Err(E::Duplicate);
        }
        validate_meta(i.meta.as_ref(), l, false)?;
        if !get {
            text(&i.data.as_ref().ok_or(E::Structure)?.0, l.field_bytes, true)?;
        }
        if devinfo
            && !matches!(
                uri.as_str(),
                "./DevInfo/DevId"
                    | "./DevInfo/Man"
                    | "./DevInfo/Mod"
                    | "./DevInfo/DmV"
                    | "./DevInfo/Lang"
            )
        {
            return Err(E::Unsupported);
        }
        if devinfo {
            text(
                &i.data.as_ref().ok_or(E::Structure)?.0,
                if uri == "./DevInfo/DevId" {
                    l.identifier_bytes
                } else {
                    l.field_bytes
                },
                false,
            )?;
        }
    }
    if devinfo && items.len() != 5 {
        return Err(E::Structure);
    }
    Ok(())
}
pub(crate) fn validate(m: &Message, l: &CodecLimits) -> Result<()> {
    if m.header.session_id == 0 || m.header.session_id > u16::MAX.into() || m.header.message_id == 0
    {
        return Err(E::InvalidValue);
    }
    text(&m.header.target, l.uri_bytes, false)?;
    text(&m.header.source, l.uri_bytes, false)?;
    validate_meta(m.header.meta.as_ref(), l, false)?;
    if let Some(c) = &m.header.credential {
        validate_meta(Some(&c.meta), l, true)?;
        text(&c.data.0, l.field_bytes, false)?;
    }
    bound(m.commands.len(), l.commands)?;
    if m.commands.is_empty() {
        return Err(E::Structure);
    }
    let mut ids = BTreeSet::new();
    let mut count = 0usize;
    let mut initialization = false;
    for c in &m.commands {
        if c.id() == 0 {
            return Err(E::InvalidValue);
        }
        if !ids.insert(c.id()) {
            return Err(E::Duplicate);
        }
        match c {
            Command::Get { meta, items, .. } => {
                validate_meta(meta.as_ref(), l, false)?;
                validate_items(items, l, true, false)?;
                count = count.checked_add(items.len()).ok_or(E::LimitExceeded)?;
            }
            Command::DevInfo { items, .. } => {
                initialization = true;
                validate_items(items, l, false, true)?;
                count = count.checked_add(items.len()).ok_or(E::LimitExceeded)?;
            }
            Command::Alert { alert, .. } => {
                initialization = true;
                if let Alert::LoginStatus {
                    status,
                    explicit_format,
                } = alert
                {
                    text(LOGIN_STATUS, l.uri_bytes, false)?;
                    text(status.as_str(), l.field_bytes, false)?;
                    if *explicit_format {
                        text("chr", l.identifier_bytes, false)?;
                    }
                    count = count.checked_add(1).ok_or(E::LimitExceeded)?;
                }
            }
            Command::Results(r) => {
                if r.message_ref == Some(0)
                    || r.command_ref == Some(0)
                    || r.command.is_some_and(|c| c != CommandName::Get)
                {
                    return Err(E::InvalidValue);
                }
                validate_meta(r.meta.as_ref(), l, false)?;
                validate_items(&r.items, l, false, false)?;
                count = count.checked_add(r.items.len()).ok_or(E::LimitExceeded)?;
            }
            Command::Status(s) => {
                if let Some(c) = &s.credential {
                    validate_meta(Some(&c.meta), l, true)?;
                    text(&c.data.0, l.field_bytes, false)?;
                }
                if let Some(challenge) = &s.challenge {
                    if s.command != CommandName::SyncHdr
                        || !matches!(
                            challenge.media_type.as_str(),
                            "syncml:auth-basic" | "syncml:auth-md5"
                        )
                    {
                        return Err(E::Unsupported);
                    }
                    if let Some(nonce) = &challenge.nonce {
                        use base64::Engine;
                        text(&nonce.0, l.identifier_bytes, false)?;
                        if !base64::engine::general_purpose::STANDARD
                            .decode(&nonce.0)
                            .is_ok_and(|b| (16..=64).contains(&b.len()))
                        {
                            return Err(E::InvalidValue);
                        }
                    }
                    if (challenge.media_type == "syncml:auth-md5") != challenge.nonce.is_some() {
                        return Err(E::Structure);
                    }
                }
                if s.message_ref == 0
                    || !(100..=599).contains(&s.code)
                    || (s.command_ref == 0) != (s.command == CommandName::SyncHdr)
                {
                    return Err(E::InvalidValue);
                }
                for rs in [&s.target_refs, &s.source_refs] {
                    bound(rs.len(), l.items)?;
                    let mut seen = BTreeSet::new();
                    for r in rs {
                        text(r, l.uri_bytes, false)?;
                        if !seen.insert(r) {
                            return Err(E::Duplicate);
                        }
                    }
                }
                bound(s.items.len(), l.items)?;
                for item in &s.items {
                    for uri in [&item.source, &item.target].into_iter().flatten() {
                        text(uri, l.uri_bytes, false)?;
                    }
                    validate_meta(item.meta.as_ref(), l, false)?;
                    if let Some(data) = &item.data {
                        text(&data.0, l.field_bytes, true)?;
                    }
                    if item.data.is_none() && item.source.is_none() && item.target.is_none() {
                        return Err(E::Structure);
                    }
                }
                count = count.checked_add(s.items.len()).ok_or(E::LimitExceeded)?;
                count = count
                    .checked_add(s.target_refs.len())
                    .and_then(|n| n.checked_add(s.source_refs.len()))
                    .ok_or(E::LimitExceeded)?;
            }
        }
        bound(count, l.items)?;
    }
    if initialization {
        let init = m
            .commands
            .iter()
            .filter(|c| !matches!(c, Command::Status(_)))
            .collect::<Vec<_>>();
        if !matches!(
            init.as_slice(),
            [Command::Alert { .. }, Command::DevInfo { .. }]
        ) || !m.final_message
        {
            return Err(E::Structure);
        }
        if m.commands
            .iter()
            .skip_while(|c| matches!(c, Command::Status(_)))
            .any(|c| matches!(c, Command::Status(_)))
        {
            return Err(E::Structure);
        }
    }
    Ok(())
}
fn write_meta(w: &mut Output<'_>, m: Option<&Meta>, l: &CodecLimits) -> Result<()> {
    if let Some(m) = m {
        w.start("Meta", &[])?;
        if let Some(v) = &m.format {
            w.start("Format", &[("xmlns", META)])?;
            w.content(v, l.identifier_bytes)?;
            w.end("Format")?;
        }
        if let Some(v) = &m.media_type {
            w.start("Type", &[("xmlns", META)])?;
            w.content(v, l.uri_bytes)?;
            w.end("Type")?;
        }
        for (name, v) in [
            ("MaxMsgSize", m.max_message_size),
            ("MaxObjSize", m.max_object_size),
        ] {
            if let Some(v) = v {
                w.start(name, &[("xmlns", META)])?;
                w.content(&v.to_string(), l.identifier_bytes)?;
                w.end(name)?;
            }
        }
        w.end("Meta")?;
    }
    Ok(())
}
fn write_location(w: &mut Output<'_>, name: &str, value: &str, l: &CodecLimits) -> Result<()> {
    w.start(name, &[])?;
    w.scalar("LocURI", value, l.uri_bytes, false)?;
    w.end(name)
}
fn write_items(w: &mut Output<'_>, items: &[Item], l: &CodecLimits) -> Result<()> {
    for i in items {
        w.item()?;
        w.start("Item", &[])?;
        if let Some(v) = &i.target {
            write_location(w, "Target", v, l)?;
        }
        if let Some(v) = &i.source {
            write_location(w, "Source", v, l)?;
        }
        write_meta(w, i.meta.as_ref(), l)?;
        if let Some(v) = &i.data {
            w.scalar("Data", &v.0, l.field_bytes, true)?;
        }
        w.end("Item")?;
    }
    Ok(())
}
fn write_num(w: &mut Output<'_>, name: &str, n: u32, l: &CodecLimits) -> Result<()> {
    w.scalar(name, &n.to_string(), l.identifier_bytes, false)
}
pub fn encode(m: &Message, l: &CodecLimits) -> Result<Vec<u8>> {
    validate(m, l)?;
    let mut w = Output::new(l.syncml_bytes, l);
    w.start("SyncML", &[("xmlns", NS)])?;
    w.start("SyncHdr", &[])?;
    w.scalar("VerDTD", "1.2", l.identifier_bytes, false)?;
    w.scalar("VerProto", "DM/1.2", l.identifier_bytes, false)?;
    write_num(&mut w, "SessionID", m.header.session_id, l)?;
    write_num(&mut w, "MsgID", m.header.message_id, l)?;
    write_location(&mut w, "Target", &m.header.target, l)?;
    write_location(&mut w, "Source", &m.header.source, l)?;
    write_credential(&mut w, m.header.credential.as_ref(), l)?;
    write_meta(&mut w, m.header.meta.as_ref(), l)?;
    w.end("SyncHdr")?;
    w.start("SyncBody", &[])?;
    for c in &m.commands {
        w.command()?;
        let name = match c {
            Command::Get { .. } => "Get",
            Command::Status(_) => "Status",
            Command::Results(_) => "Results",
            Command::Alert { .. } => "Alert",
            Command::DevInfo { .. } => "Replace",
        };
        w.start(name, &[])?;
        write_num(&mut w, "CmdID", c.id(), l)?;
        match c {
            Command::Get { meta, items, .. } => {
                write_meta(&mut w, meta.as_ref(), l)?;
                write_items(&mut w, items, l)?;
            }
            Command::DevInfo { items, .. } => write_items(&mut w, items, l)?,
            Command::Alert { alert, .. } => {
                write_num(
                    &mut w,
                    "Data",
                    if matches!(alert, Alert::ClientInitiated) {
                        1201
                    } else {
                        1224
                    },
                    l,
                )?;
                if let Alert::LoginStatus {
                    status,
                    explicit_format,
                } = alert
                {
                    w.item()?;
                    w.start("Item", &[])?;
                    w.start("Meta", &[])?;
                    w.start("Type", &[("xmlns", META)])?;
                    w.content(LOGIN_STATUS, l.uri_bytes)?;
                    w.end("Type")?;
                    if *explicit_format {
                        w.start("Format", &[("xmlns", META)])?;
                        w.content("chr", l.identifier_bytes)?;
                        w.end("Format")?;
                    }
                    w.end("Meta")?;
                    w.scalar("Data", status.as_str(), l.field_bytes, false)?;
                    w.end("Item")?;
                }
            }
            Command::Status(s) => {
                write_num(&mut w, "MsgRef", s.message_ref, l)?;
                write_num(&mut w, "CmdRef", s.command_ref, l)?;
                w.scalar("Cmd", s.command.as_str(), l.identifier_bytes, false)?;
                let oma = s.challenge.is_some() || s.credential.is_some();
                if oma {
                    write_refs(&mut w, s, l)?;
                }
                write_credential(&mut w, s.credential.as_ref(), l)?;
                if let Some(challenge) = &s.challenge {
                    w.start("Chal", &[])?;
                    w.start("Meta", &[])?;
                    w.start("Format", &[("xmlns", META)])?;
                    w.content("b64", l.identifier_bytes)?;
                    w.end("Format")?;
                    w.start("Type", &[("xmlns", META)])?;
                    w.content(&challenge.media_type, l.uri_bytes)?;
                    w.end("Type")?;
                    if let Some(nonce) = &challenge.nonce {
                        w.start("NextNonce", &[("xmlns", META)])?;
                        w.content(&nonce.0, l.identifier_bytes)?;
                        w.end("NextNonce")?;
                    }
                    w.end("Meta")?;
                    w.end("Chal")?;
                }
                write_num(&mut w, "Data", s.code.into(), l)?;
                write_items(&mut w, &s.items, l)?;
                if !oma {
                    write_refs(&mut w, s, l)?;
                }
            }
            Command::Results(r) => {
                if let Some(v) = r.message_ref {
                    write_num(&mut w, "MsgRef", v, l)?;
                }
                if let Some(v) = r.command_ref {
                    write_num(&mut w, "CmdRef", v, l)?;
                }
                if let Some(v) = r.command {
                    w.scalar("Cmd", v.as_str(), l.identifier_bytes, false)?;
                }
                write_meta(&mut w, r.meta.as_ref(), l)?;
                write_items(&mut w, &r.items, l)?;
            }
        }
        w.end(name)?;
    }
    if m.final_message {
        w.empty("Final")?;
    }
    w.end("SyncBody")?;
    w.end("SyncML")?;
    w.finish()
}

fn read_credential(p: &mut Input<'_>) -> Result<Option<Credential>> {
    if !p.is(NS, "Cred")? {
        return Ok(None);
    }
    p.open(NS, "Cred")?;
    let meta = meta(p)?.ok_or(E::Structure)?;
    let data = Secret(p.scalar(NS, "Data", p.limits.field_bytes, false)?);
    p.end(NS, "Cred")?;
    Ok(Some(Credential { meta, data }))
}
fn write_credential(
    w: &mut Output<'_>,
    credential: Option<&Credential>,
    l: &CodecLimits,
) -> Result<()> {
    if let Some(c) = credential {
        w.start("Cred", &[])?;
        write_meta(w, Some(&c.meta), l)?;
        w.scalar("Data", &c.data.0, l.field_bytes, false)?;
        w.end("Cred")?;
    }
    Ok(())
}
fn write_refs(w: &mut Output<'_>, s: &Status, l: &CodecLimits) -> Result<()> {
    for (name, refs) in [("TargetRef", &s.target_refs), ("SourceRef", &s.source_refs)] {
        for value in refs {
            w.item()?;
            w.scalar(name, value, l.uri_bytes, false)?;
        }
    }
    Ok(())
}
