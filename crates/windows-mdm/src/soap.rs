//! SOAP 1.2 / WS-Addressing enrollment, restricted to the V1 enrollment profile.
use crate::{
    CodecError as E, CodecLimits, CorrelationError as C, CorrelationResult, Result, Secret, bound,
    text,
    xml::{Input, Output, XML, XSI},
};
mod enrollment;
mod policy;
mod security;
pub use enrollment::{
    AuthPolicy, Discover, DiscoverResponse, Disposition, Issue, IssueResponse, NillableText,
};
pub use policy::Policy;
pub use security::{Security, Timestamp, UsernameToken};
pub const NS: &str = "http://www.w3.org/2003/05/soap-envelope";
pub const ADDRESS: &str = "http://www.w3.org/2005/08/addressing";
pub const ENROLL: &str = "http://schemas.microsoft.com/windows/management/2012/01/enrollment";
pub const XCEP: &str = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy";
pub const TRUST: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
pub const WSTEP: &str = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
const SECURITY: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const UTILITY: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const CONTEXT: &str = "http://schemas.xmlsoap.org/ws/2006/12/authorization";
const ANONYMOUS: &str = "http://www.w3.org/2005/08/addressing/anonymous";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Discover,
    DiscoverResponse,
    GetPolicies,
    GetPoliciesResponse,
    Issue,
    IssueResponse,
    Fault,
}
impl Operation {
    pub fn action(self) -> &'static str {
        match self {
            Self::Discover => {
                "http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/Discover"
            }
            Self::DiscoverResponse => {
                "http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse"
            }
            Self::GetPolicies => {
                "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"
            }
            Self::GetPoliciesResponse => {
                "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse"
            }
            Self::Issue => "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep",
            Self::IssueResponse => {
                "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"
            }
            Self::Fault => "http://www.w3.org/2005/08/addressing/soap/fault",
        }
    }
    fn max(self, l: &CodecLimits) -> usize {
        match self {
            Self::Discover | Self::DiscoverResponse | Self::Fault => l.discovery_bytes,
            Self::GetPolicies | Self::GetPoliciesResponse => l.xcep_bytes,
            _ => l.wstep_bytes,
        }
    }
    fn response(self) -> bool {
        matches!(
            self,
            Self::DiscoverResponse | Self::GetPoliciesResponse | Self::IssueResponse | Self::Fault
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub message_id: Option<String>,
    pub relates_to: Option<String>,
    pub to: Option<String>,
    pub reply_to: bool,
    pub security: Option<Security>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub body: Body,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Discover(Discover),
    DiscoverResponse(DiscoverResponse),
    GetPolicies,
    GetPoliciesResponse(Policy),
    Issue(Issue),
    IssueResponse(IssueResponse),
    Fault(FaultKind),
}
impl Body {
    pub fn operation(&self) -> Operation {
        match self {
            Self::Discover(_) => Operation::Discover,
            Self::DiscoverResponse(_) => Operation::DiscoverResponse,
            Self::GetPolicies => Operation::GetPolicies,
            Self::GetPoliciesResponse(_) => Operation::GetPoliciesResponse,
            Self::Issue(_) => Operation::Issue,
            Self::IssueResponse(_) => Operation::IssueResponse,
            Self::Fault(_) => Operation::Fault,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    MessageFormat,
    Authentication,
    Authorization,
    CertificateRequest,
    EnrollmentServer,
}
impl FaultKind {
    fn subcode(self) -> &'static str {
        match self {
            Self::MessageFormat => "MessageFormat",
            Self::Authentication => "Authentication",
            Self::Authorization => "Authorization",
            Self::CertificateRequest => "CertificateRequest",
            Self::EnrollmentServer => "EnrollmentServer",
        }
    }
    fn reason(self) -> &'static str {
        match self {
            Self::MessageFormat => "The request format is invalid.",
            Self::Authentication => "Authentication failed.",
            Self::Authorization => "Authorization failed.",
            Self::CertificateRequest => "The certificate request could not be processed.",
            Self::EnrollmentServer => "The enrollment service could not process the request.",
        }
    }
}
fn understood(s: &crate::xml::Start) -> Result<()> {
    s.attrs(&[(NS, "mustUnderstand")])?;
    if s.attr(NS, "mustUnderstand")
        .is_some_and(|v| !matches!(v, "0" | "1" | "true" | "false"))
    {
        return Err(E::InvalidValue);
    }
    Ok(())
}
fn header_value(p: &mut Input<'_>, name: &str) -> Result<String> {
    let s = p.start(ADDRESS, name)?;
    understood(&s)?;
    p.content(ADDRESS, name, p.limits.uri_bytes, false)
}
fn parse_header(
    p: &mut Input<'_>,
    expected: Operation,
    allow_fault: bool,
) -> Result<(Header, Operation)> {
    p.open(NS, "Header")?;
    let mut h = Header {
        message_id: None,
        relates_to: None,
        to: None,
        reply_to: false,
        security: None,
    };
    let mut action = None;
    loop {
        if p.is(ADDRESS, "Action")? {
            if action.is_some() {
                return Err(E::Duplicate);
            }
            action = Some(header_value(p, "Action")?);
        } else if p.is(ADDRESS, "MessageID")? {
            if h.message_id.is_some() {
                return Err(E::Duplicate);
            }
            h.message_id = Some(header_value(p, "MessageID")?);
        } else if p.is(ADDRESS, "RelatesTo")? {
            if h.relates_to.is_some() {
                return Err(E::Duplicate);
            }
            h.relates_to = Some(header_value(p, "RelatesTo")?);
        } else if p.is(ADDRESS, "To")? {
            if h.to.is_some() {
                return Err(E::Duplicate);
            }
            h.to = Some(header_value(p, "To")?);
        } else if p.is(ADDRESS, "ReplyTo")? {
            if h.reply_to {
                return Err(E::Duplicate);
            }
            p.open(ADDRESS, "ReplyTo")?;
            if p.scalar(ADDRESS, "Address", p.limits.uri_bytes, false)? != ANONYMOUS {
                return Err(E::Unsupported);
            }
            p.end(ADDRESS, "ReplyTo")?;
            h.reply_to = true;
        } else if p.is(SECURITY, "Security")? {
            if h.security.is_some() {
                return Err(E::Duplicate);
            }
            h.security = Some(security::read(p)?);
        } else {
            break;
        }
    }
    p.end(NS, "Header")?;
    let op = if action.as_deref() == Some(expected.action()) {
        expected
    } else if allow_fault && action.as_deref() == Some(Operation::Fault.action()) {
        Operation::Fault
    } else {
        return Err(E::UnexpectedOperation);
    };
    validate_header(&h, op, p.limits)?;
    Ok((h, op))
}
fn validate_header(h: &Header, op: Operation, l: &CodecLimits) -> Result<()> {
    for v in [&h.message_id, &h.relates_to, &h.to].into_iter().flatten() {
        text(v, l.uri_bytes, false)?;
    }
    if op.response() {
        if h.relates_to.is_none() || h.reply_to {
            return Err(E::Structure);
        }
    } else if h.message_id.is_none() || h.to.is_none() || h.relates_to.is_some() {
        return Err(E::Structure);
    }
    if matches!(op, Operation::GetPolicies | Operation::Issue)
        && h.security
            .as_ref()
            .and_then(|s| s.username.as_ref())
            .is_none()
    {
        return Err(E::Structure);
    }
    if op == Operation::IssueResponse
        && h.security
            .as_ref()
            .and_then(|s| s.timestamp.as_ref())
            .is_none()
    {
        return Err(E::Structure);
    }
    if let Some(s) = &h.security {
        security::validate(s, l)?;
    }
    Ok(())
}
pub fn decode(bytes: &[u8], expected_operation: Operation, l: &CodecLimits) -> Result<Message> {
    decode_expected(bytes, expected_operation, false, l)
}
fn response_operation(request: &Message) -> Result<Operation> {
    match request.body.operation() {
        Operation::Discover => Ok(Operation::DiscoverResponse),
        Operation::GetPolicies => Ok(Operation::GetPoliciesResponse),
        Operation::Issue => Ok(Operation::IssueResponse),
        _ => Err(E::UnexpectedOperation),
    }
}
/// Decode once, accepting only the originating operation's response or a SOAP Fault.
/// The matched message still carries untrusted claims; inspect its body for failure.
pub fn decode_response(
    request: &Message,
    bytes: &[u8],
    l: &CodecLimits,
) -> CorrelationResult<Message> {
    validate(request, l).map_err(C::InvalidRequest)?;
    let wanted = response_operation(request).map_err(C::InvalidRequest)?;
    let response = decode_expected(bytes, wanted, true, l).map_err(C::InvalidResponse)?;
    let _matched = correlate(request, &response, l)?;
    Ok(response)
}
fn decode_expected(
    bytes: &[u8],
    expected_operation: Operation,
    allow_fault: bool,
    l: &CodecLimits,
) -> Result<Message> {
    // Faults use the originating operation's input budget in this path.
    let mut p = Input::new(bytes, expected_operation.max(l), l)?;
    p.open(NS, "Envelope")?;
    let (header, operation) = parse_header(&mut p, expected_operation, allow_fault)?;
    p.open(NS, "Body")?;
    let body = match operation {
        Operation::Discover => Body::Discover(enrollment::read_discover(&mut p)?),
        Operation::DiscoverResponse => {
            Body::DiscoverResponse(enrollment::read_discover_response(&mut p)?)
        }
        Operation::GetPolicies => {
            policy::read_request(&mut p)?;
            Body::GetPolicies
        }
        Operation::GetPoliciesResponse => Body::GetPoliciesResponse(policy::read(&mut p)?),
        Operation::Issue => Body::Issue(enrollment::read_issue(&mut p)?),
        Operation::IssueResponse => Body::IssueResponse(enrollment::read_issue_response(&mut p)?),
        Operation::Fault => Body::Fault(read_fault(&mut p)?),
    };
    p.end(NS, "Body")?;
    p.end(NS, "Envelope")?;
    p.finish()?;
    let m = Message { header, body };
    validate(&m, l)?;
    Ok(m)
}
fn validate(m: &Message, l: &CodecLimits) -> Result<()> {
    validate_header(&m.header, m.body.operation(), l)?;
    match &m.body {
        Body::Discover(v) => enrollment::validate_discover(v, l),
        Body::DiscoverResponse(v) => enrollment::validate_discover_response(v, l),
        Body::GetPoliciesResponse(v) => policy::validate(v, l),
        Body::Issue(v) => enrollment::validate_issue(v, l),
        Body::IssueResponse(v) => enrollment::validate_issue_response(v, l),
        _ => Ok(()),
    }
}
pub fn encode(m: &Message, l: &CodecLimits) -> Result<Vec<u8>> {
    validate(m, l)?;
    let op = m.body.operation();
    let mut w = Output::new(op.max(l), l);
    w.start(
        "s:Envelope",
        &[
            ("xmlns:s", NS),
            ("xmlns:a", ADDRESS),
            ("xmlns:e", ENROLL),
            ("xmlns:p", XCEP),
            ("xmlns:t", TRUST),
            ("xmlns:w", WSTEP),
            ("xmlns:o", SECURITY),
            ("xmlns:u", UTILITY),
            ("xmlns:c", CONTEXT),
            ("xmlns:xsi", XSI),
        ],
    )?;
    w.start("s:Header", &[])?;
    w.start("a:Action", &[("s:mustUnderstand", "1")])?;
    w.content(op.action(), l.uri_bytes)?;
    w.end("a:Action")?;
    for (name, v) in [
        ("a:MessageID", &m.header.message_id),
        ("a:RelatesTo", &m.header.relates_to),
    ] {
        if let Some(v) = v {
            w.scalar(name, v, l.uri_bytes, false)?;
        }
    }
    if m.header.reply_to {
        w.start("a:ReplyTo", &[])?;
        w.scalar("a:Address", ANONYMOUS, l.uri_bytes, false)?;
        w.end("a:ReplyTo")?;
    }
    if let Some(v) = &m.header.to {
        w.scalar("a:To", v, l.uri_bytes, false)?;
    }
    if let Some(v) = &m.header.security {
        security::write(&mut w, v, l)?;
    }
    w.end("s:Header")?;
    w.start("s:Body", &[])?;
    match &m.body {
        Body::Discover(v) => enrollment::write_discover(&mut w, v, l)?,
        Body::DiscoverResponse(v) => enrollment::write_discover_response(&mut w, v, l)?,
        Body::GetPolicies => policy::write_request(&mut w)?,
        Body::GetPoliciesResponse(v) => policy::write(&mut w, v, l)?,
        Body::Issue(v) => enrollment::write_issue(&mut w, v, l)?,
        Body::IssueResponse(v) => enrollment::write_issue_response(&mut w, v, l)?,
        Body::Fault(v) => write_fault(&mut w, *v, l)?,
    }
    w.end("s:Body")?;
    w.end("s:Envelope")?;
    w.finish()
}
/// A matched wire response is not proof of authentication, signing or enrollment.
#[must_use = "Inspect the matched response or fault; correlation does not mean enrollment succeeded"]
#[derive(Debug, PartialEq, Eq)]
pub enum CorrelatedResponse<'a> {
    Discovery(&'a DiscoverResponse),
    Policies(&'a Policy),
    IssueResponse(&'a IssueResponse),
    Fault(FaultKind),
}
/// Match a decoded response to its originating request. Does not authenticate either party.
pub fn correlate<'a>(
    request: &Message,
    response: &'a Message,
    l: &CodecLimits,
) -> CorrelationResult<CorrelatedResponse<'a>> {
    validate(request, l).map_err(C::InvalidRequest)?;
    let wanted = response_operation(request).map_err(C::InvalidRequest)?;
    validate(response, l).map_err(C::InvalidResponse)?;
    if response.header.relates_to != request.header.message_id
        || !matches!(response.body, Body::Fault(_)) && response.body.operation() != wanted
    {
        return Err(C::Mismatch);
    }
    if let (Body::Issue(a), Body::IssueResponse(b)) = (&request.body, &response.body)
        && a.context != b.context
    {
        return Err(C::Mismatch);
    }
    match &response.body {
        Body::DiscoverResponse(v) => Ok(CorrelatedResponse::Discovery(v)),
        Body::GetPoliciesResponse(v) => Ok(CorrelatedResponse::Policies(v)),
        Body::IssueResponse(v) => Ok(CorrelatedResponse::IssueResponse(v)),
        Body::Fault(v) => Ok(CorrelatedResponse::Fault(*v)),
        _ => Err(C::Mismatch),
    }
}
fn nil(p: &mut Input<'_>, ns: &str, name: &str) -> Result<()> {
    let s = p.start(ns, name)?;
    s.attrs(&[(XSI, "nil")])?;
    if !matches!(s.attr(XSI, "nil"), Some("true" | "1")) {
        return Err(E::Unsupported);
    }
    p.end(ns, name)
}
fn write_nil(w: &mut Output<'_>, name: &str) -> Result<()> {
    w.start(name, &[("xsi:nil", "true")])?;
    w.end(name)
}
fn read_fault(p: &mut Input<'_>) -> Result<FaultKind> {
    p.open(NS, "Fault")?;
    p.open(NS, "Code")?;
    let code = p.qname_scalar(NS, "Value")?;
    p.open(NS, "Subcode")?;
    let sub = p.qname_scalar(NS, "Value")?;
    p.end(NS, "Subcode")?;
    p.end(NS, "Code")?;
    let kind = match sub.1.as_str() {
        "MessageFormat" => FaultKind::MessageFormat,
        "Authentication" => FaultKind::Authentication,
        "Authorization" => FaultKind::Authorization,
        "CertificateRequest" => FaultKind::CertificateRequest,
        "EnrollmentServer" => FaultKind::EnrollmentServer,
        _ => return Err(E::Unsupported),
    };
    if sub.0 != ENROLL
        || code.0 != NS
        || code.1
            != if kind == FaultKind::EnrollmentServer {
                "Receiver"
            } else {
                "Sender"
            }
    {
        return Err(E::InvalidValue);
    }
    p.open(NS, "Reason")?;
    let s = p.start(NS, "Text")?;
    s.attrs(&[(XML, "lang")])?;
    if s.attr(XML, "lang").is_none() {
        return Err(E::Structure);
    }
    let _ = p.content(NS, "Text", p.limits.field_bytes, false)?;
    p.end(NS, "Reason")?;
    p.end(NS, "Fault")?;
    Ok(kind)
}
fn write_fault(w: &mut Output<'_>, kind: FaultKind, l: &CodecLimits) -> Result<()> {
    w.start("s:Fault", &[])?;
    w.start("s:Code", &[])?;
    w.scalar(
        "s:Value",
        if kind == FaultKind::EnrollmentServer {
            "s:Receiver"
        } else {
            "s:Sender"
        },
        l.identifier_bytes,
        false,
    )?;
    w.start("s:Subcode", &[])?;
    w.scalar(
        "s:Value",
        &format!("e:{}", kind.subcode()),
        l.identifier_bytes,
        false,
    )?;
    w.end("s:Subcode")?;
    w.end("s:Code")?;
    w.start("s:Reason", &[])?;
    w.start("s:Text", &[("xml:lang", "en-US")])?;
    w.content(kind.reason(), l.field_bytes)?;
    w.end("s:Text")?;
    w.end("s:Reason")?;
    w.end("s:Fault")
}
