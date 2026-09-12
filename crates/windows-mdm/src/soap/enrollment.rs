use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::collections::BTreeSet;
const TOKEN: &str =
    "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken";
const PROVISION: &str = "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc";
const PKCS10: &str = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10";
const B64: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary";
const ISSUE: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discover {
    pub email: Secret<String>,
    pub request_version: String,
    pub device_type: String,
    pub application_version: String,
    pub os_edition: u32,
    pub auth_policies: Vec<AuthPolicy>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthPolicy {
    OnPremise,
    Federated,
    Certificate,
}
impl AuthPolicy {
    fn name(self) -> &'static str {
        match self {
            Self::OnPremise => "OnPremise",
            Self::Federated => "Federated",
            Self::Certificate => "Certificate",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "OnPremise" => Ok(Self::OnPremise),
            "Federated" => Ok(Self::Federated),
            "Certificate" => Ok(Self::Certificate),
            _ => Err(E::Unsupported),
        }
    }
}
/// Preserves nullable WSTEP string values without treating them as identifiers or integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NillableText {
    Nil,
    Value(Secret<String>),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disposition {
    pub language: Option<String>,
    pub value: NillableText,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverResponse {
    pub enrollment_version: String,
    pub policy_url: String,
    pub enrollment_url: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub context: Option<String>,
    pub csr: Secret<Vec<u8>>,
    pub additional_context: Secret<Vec<(String, String)>>,
    pub request_id: Option<NillableText>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueResponse {
    pub context: Option<String>,
    pub provisioning: Secret<Vec<u8>>,
    pub request_id: Option<NillableText>,
    pub disposition: Option<Disposition>,
}
fn once<T>(slot: &mut Option<T>, value: T) -> Result<()> {
    if slot.is_some() {
        return Err(E::Duplicate);
    }
    *slot = Some(value);
    Ok(())
}
pub(super) fn read_discover(p: &mut Input<'_>) -> Result<Discover> {
    p.open(ENROLL, "Discover")?;
    p.open(ENROLL, "request")?;
    let (
        mut email,
        mut request_version,
        mut device_type,
        mut application_version,
        mut os_edition,
        mut auth_policies,
    ) = (None, None, None, None, None, None);
    loop {
        if p.is(ENROLL, "EmailAddress")? {
            once(
                &mut email,
                Secret(p.scalar(ENROLL, "EmailAddress", p.limits.field_bytes, false)?),
            )?;
        } else if p.is(ENROLL, "RequestVersion")? {
            once(
                &mut request_version,
                p.scalar(ENROLL, "RequestVersion", p.limits.identifier_bytes, false)?,
            )?;
        } else if p.is(ENROLL, "DeviceType")? {
            once(
                &mut device_type,
                p.scalar(ENROLL, "DeviceType", p.limits.identifier_bytes, false)?,
            )?;
        } else if p.is(ENROLL, "ApplicationVersion")? {
            once(
                &mut application_version,
                p.scalar(
                    ENROLL,
                    "ApplicationVersion",
                    p.limits.identifier_bytes,
                    false,
                )?,
            )?;
        } else if p.is(ENROLL, "OSEdition")? {
            once(
                &mut os_edition,
                crate::syncml::number(
                    &p.scalar(ENROLL, "OSEdition", p.limits.identifier_bytes, false)?,
                    true,
                )?,
            )?;
        } else if p.is(ENROLL, "AuthPolicies")? {
            p.open(ENROLL, "AuthPolicies")?;
            let mut policies = Vec::new();
            while p.is(ENROLL, "AuthPolicy")? {
                p.item()?;
                bound(policies.len() + 1, 3)?;
                policies.push(AuthPolicy::parse(&p.scalar(
                    ENROLL,
                    "AuthPolicy",
                    p.limits.identifier_bytes,
                    false,
                )?)?);
            }
            p.end(ENROLL, "AuthPolicies")?;
            once(&mut auth_policies, policies)?;
        } else {
            break;
        }
    }
    p.end(ENROLL, "request")?;
    p.end(ENROLL, "Discover")?;
    Ok(Discover {
        email: email.ok_or(E::Structure)?,
        request_version: request_version.ok_or(E::Structure)?,
        device_type: device_type.ok_or(E::Structure)?,
        application_version: application_version.ok_or(E::Structure)?,
        os_edition: os_edition.ok_or(E::Structure)?,
        auth_policies: auth_policies.ok_or(E::Structure)?,
    })
}
pub(super) fn validate_discover(d: &Discover, l: &CodecLimits) -> Result<()> {
    text(&d.email.0, l.field_bytes, false)?;
    for v in [&d.request_version, &d.device_type, &d.application_version] {
        text(v, l.identifier_bytes, false)?;
    }
    if !matches!(
        d.request_version.as_str(),
        "1.0" | "2.0" | "3.0" | "4.0" | "5.0" | "6.0" | "7.0"
    ) || d.device_type != "CIMClient_Windows"
    {
        return Err(E::Unsupported);
    }
    bound(d.auth_policies.len(), 3)?;
    bound(d.auth_policies.len(), l.items)?;
    let mut policies = BTreeSet::new();
    for policy in &d.auth_policies {
        if !policies.insert(*policy) {
            return Err(E::Duplicate);
        }
    }
    if !policies.contains(&AuthPolicy::OnPremise) {
        return Err(E::Unsupported);
    }
    version(&d.application_version)
}
fn version(s: &str) -> Result<()> {
    if s.split('.').count() != 4 {
        return Err(E::InvalidValue);
    }
    for n in s.split('.') {
        crate::syncml::number(n, true)?;
    }
    Ok(())
}
pub(super) fn write_discover(w: &mut Output<'_>, d: &Discover, l: &CodecLimits) -> Result<()> {
    w.start("e:Discover", &[])?;
    w.start("e:request", &[])?;
    w.scalar("e:EmailAddress", &d.email.0, l.field_bytes, false)?;
    for (k, v) in [
        ("e:RequestVersion", &d.request_version),
        ("e:DeviceType", &d.device_type),
        ("e:ApplicationVersion", &d.application_version),
    ] {
        w.scalar(k, v, l.identifier_bytes, false)?;
    }
    w.scalar(
        "e:OSEdition",
        &d.os_edition.to_string(),
        l.identifier_bytes,
        false,
    )?;
    w.start("e:AuthPolicies", &[])?;
    for policy in &d.auth_policies {
        w.item()?;
        w.scalar("e:AuthPolicy", policy.name(), l.identifier_bytes, false)?;
    }
    w.end("e:AuthPolicies")?;
    w.end("e:request")?;
    w.end("e:Discover")
}
pub(super) fn read_discover_response(p: &mut Input<'_>) -> Result<DiscoverResponse> {
    p.open(ENROLL, "DiscoverResponse")?;
    p.open(ENROLL, "DiscoverResult")?;
    let (mut auth, mut version, mut policy, mut enroll) = (None, None, None, None);
    loop {
        if p.is(ENROLL, "AuthPolicy")? {
            once(
                &mut auth,
                p.scalar(ENROLL, "AuthPolicy", p.limits.identifier_bytes, false)?,
            )?;
        } else if p.is(ENROLL, "EnrollmentVersion")? {
            once(
                &mut version,
                p.scalar(
                    ENROLL,
                    "EnrollmentVersion",
                    p.limits.identifier_bytes,
                    false,
                )?,
            )?;
        } else if p.is(ENROLL, "EnrollmentPolicyServiceUrl")? {
            once(
                &mut policy,
                p.scalar(
                    ENROLL,
                    "EnrollmentPolicyServiceUrl",
                    p.limits.uri_bytes,
                    false,
                )?,
            )?;
        } else if p.is(ENROLL, "EnrollmentServiceUrl")? {
            once(
                &mut enroll,
                p.scalar(ENROLL, "EnrollmentServiceUrl", p.limits.uri_bytes, false)?,
            )?;
        } else {
            break;
        }
    }
    p.end(ENROLL, "DiscoverResult")?;
    p.end(ENROLL, "DiscoverResponse")?;
    if auth.as_deref() != Some("OnPremise") {
        return Err(E::Unsupported);
    }
    Ok(DiscoverResponse {
        enrollment_version: version.ok_or(E::Structure)?,
        policy_url: policy.ok_or(E::Structure)?,
        enrollment_url: enroll.ok_or(E::Structure)?,
    })
}
pub(super) fn validate_discover_response(d: &DiscoverResponse, l: &CodecLimits) -> Result<()> {
    text(&d.enrollment_version, l.identifier_bytes, false)?;
    if d.enrollment_version != "4.0" {
        return Err(E::Unsupported);
    }
    text(&d.policy_url, l.uri_bytes, false)?;
    text(&d.enrollment_url, l.uri_bytes, false)
}
pub(super) fn write_discover_response(
    w: &mut Output<'_>,
    d: &DiscoverResponse,
    l: &CodecLimits,
) -> Result<()> {
    w.start("e:DiscoverResponse", &[])?;
    w.start("e:DiscoverResult", &[])?;
    w.scalar("e:AuthPolicy", "OnPremise", l.identifier_bytes, false)?;
    w.scalar(
        "e:EnrollmentVersion",
        &d.enrollment_version,
        l.identifier_bytes,
        false,
    )?;
    w.scalar(
        "e:EnrollmentPolicyServiceUrl",
        &d.policy_url,
        l.uri_bytes,
        false,
    )?;
    w.scalar(
        "e:EnrollmentServiceUrl",
        &d.enrollment_url,
        l.uri_bytes,
        false,
    )?;
    w.end("e:DiscoverResult")?;
    w.end("e:DiscoverResponse")
}
fn binary(p: &mut Input<'_>, value_type: &str) -> Result<Secret<Vec<u8>>> {
    let s = p.start(SECURITY, "BinarySecurityToken")?;
    s.attrs(&[("", "ValueType"), ("", "EncodingType")])?;
    if s.attr("", "ValueType") != Some(value_type) || s.attr("", "EncodingType") != Some(B64) {
        return Err(E::Unsupported);
    }
    let value = p.content(SECURITY, "BinarySecurityToken", p.limits.wstep_bytes, false)?;
    let n = value.bytes().filter(|b| !b.is_ascii_whitespace()).count();
    let max = p
        .limits
        .binary_bytes
        .checked_add(2)
        .and_then(|n| n.checked_div(3))
        .and_then(|n| n.checked_mul(4))
        .ok_or(E::LimitExceeded)?;
    bound(n, max)?;
    let value: String = value
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect();
    let decoded = STANDARD.decode(value).map_err(|_| E::InvalidValue)?;
    bound(decoded.len(), p.limits.binary_bytes)?;
    if decoded.is_empty() {
        return Err(E::InvalidValue);
    }
    Ok(Secret(decoded))
}
fn write_binary(w: &mut Output<'_>, data: &[u8], value_type: &str, l: &CodecLimits) -> Result<()> {
    bound(data.len(), l.binary_bytes)?;
    if data.is_empty() {
        return Err(E::InvalidValue);
    }
    w.start(
        "o:BinarySecurityToken",
        &[("ValueType", value_type), ("EncodingType", B64)],
    )?;
    w.content(&STANDARD.encode(data), l.wstep_bytes)?;
    w.end("o:BinarySecurityToken")
}
fn context(p: &mut Input<'_>, name: &str) -> Result<Option<String>> {
    let s = p.start(TRUST, name)?;
    s.attrs(&[("", "Context")])?;
    let v = s.attr("", "Context").map(str::to_owned);
    if let Some(v) = &v {
        text(v, p.limits.identifier_bytes, false)?;
    }
    Ok(v)
}
pub(super) fn read_issue(p: &mut Input<'_>) -> Result<Issue> {
    let context = context(p, "RequestSecurityToken")?;
    // WS-Trust defines this body as an unordered collection; accept either order
    // of TokenType/RequestType while requiring each exactly once.
    let mut token = false;
    let mut request = false;
    let mut csr = None;
    let mut additional_context = None;
    let mut request_id = None;
    loop {
        if p.is(TRUST, "TokenType")? {
            if token {
                return Err(E::Duplicate);
            }
            token = true;
            if p.scalar(TRUST, "TokenType", p.limits.uri_bytes, false)? != TOKEN {
                return Err(E::Unsupported);
            }
        } else if p.is(TRUST, "RequestType")? {
            if request {
                return Err(E::Duplicate);
            }
            request = true;
            if p.scalar(TRUST, "RequestType", p.limits.uri_bytes, false)? != ISSUE {
                return Err(E::Unsupported);
            }
        } else if p.is(SECURITY, "BinarySecurityToken")? {
            if csr.is_some() {
                return Err(E::Duplicate);
            }
            csr = Some(binary(p, PKCS10)?);
        } else if p.is(WSTEP, "RequestID")? {
            once(&mut request_id, read_nillable(p, "RequestID")?)?;
        } else if p.is(CONTEXT, "AdditionalContext")? {
            if additional_context.is_some() {
                return Err(E::Duplicate);
            }
            p.open(CONTEXT, "AdditionalContext")?;
            let mut values = Vec::new();
            while p.is(CONTEXT, "ContextItem")? {
                p.item()?;
                let s = p.start(CONTEXT, "ContextItem")?;
                s.attrs(&[("", "Name")])?;
                let key = s.attr("", "Name").ok_or(E::Structure)?.to_string();
                text(&key, p.limits.identifier_bytes, false)?;
                let value = p.scalar(CONTEXT, "Value", p.limits.field_bytes, true)?;
                p.end(CONTEXT, "ContextItem")?;
                values.push((key, value));
            }
            p.end(CONTEXT, "AdditionalContext")?;
            additional_context = Some(Secret(values));
        } else {
            break;
        }
    }
    p.end(TRUST, "RequestSecurityToken")?;
    if !token || !request {
        return Err(E::Structure);
    }
    Ok(Issue {
        context,
        csr: csr.ok_or(E::Structure)?,
        additional_context: additional_context.ok_or(E::Structure)?,
        request_id,
    })
}
pub(super) fn validate_issue(i: &Issue, l: &CodecLimits) -> Result<()> {
    if let Some(c) = &i.context {
        text(c, l.identifier_bytes, false)?;
    }
    validate_nillable(&i.request_id, l)?;
    bound(i.csr.0.len(), l.binary_bytes)?;
    if i.csr.0.is_empty() {
        return Err(E::InvalidValue);
    }
    bound(i.additional_context.0.len(), l.items)?;
    let mut keys = BTreeSet::new();
    let mut repeated = BTreeSet::new();
    for (k, v) in &i.additional_context.0 {
        text(k, l.identifier_bytes, false)?;
        text(v, l.field_bytes, true)?;
        if matches!(k.as_str(), "MAC" | "IMEI") {
            if !repeated.insert((k, v)) {
                return Err(E::Duplicate);
            }
        } else if !keys.insert(k.as_str()) {
            return Err(E::Duplicate);
        }
        match k.as_str() {
            "OSEdition" => {
                crate::syncml::number(v, true)?;
            }
            "OSVersion" | "ApplicationVersion" => version(v)?,
            "DeviceType" if v != "CIMClient_Windows" => return Err(E::Unsupported),
            "EnrollmentType" if !matches!(v.as_str(), "Device" | "Full") => {
                return Err(E::Unsupported);
            }
            "DeviceName" | "DeviceID" => text(v, l.identifier_bytes, false)?,
            "UXInitiated" | "NotInOobe" | "TargetedUserLoggedIn" => {
                if !matches!(v.as_str(), "true" | "false" | "0" | "1") {
                    return Err(E::InvalidValue);
                }
            }
            "ZeroTouchProvisioning" => {
                // A context claim only; never a tenant or enrollment authorization.
                if v.len() != 36
                    || !v.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_hexdigit()
                        }
                    })
                {
                    return Err(E::InvalidValue);
                }
            }
            "OfflineAutoPilotEnrollmentCorrelator" => {
                if v.is_empty()
                    || v.len() > 100
                    || v.starts_with('-')
                    || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                {
                    return Err(E::InvalidValue);
                }
            }
            "DeviceType"
            | "EnrollmentType"
            | "EnrollmentData"
            | "MAC"
            | "IMEI"
            | "Locale"
            | "HWDevID"
            | "DomainName"
            | "ExternalMgmtAgentHint" => {}
            _ => return Err(E::Unsupported),
        }
    }
    if [
        "OSEdition",
        "OSVersion",
        "DeviceName",
        "EnrollmentType",
        "DeviceType",
        "ApplicationVersion",
        "DeviceID",
    ]
    .iter()
    .any(|k| !keys.contains(k))
    {
        return Err(E::Structure);
    }
    Ok(())
}
pub(super) fn write_issue(w: &mut Output<'_>, i: &Issue, l: &CodecLimits) -> Result<()> {
    let attrs = i
        .context
        .as_deref()
        .map(|s| vec![("Context", s)])
        .unwrap_or_default();
    w.start("t:RequestSecurityToken", &attrs)?;
    w.scalar("t:TokenType", TOKEN, l.uri_bytes, false)?;
    w.scalar("t:RequestType", ISSUE, l.uri_bytes, false)?;
    write_binary(w, &i.csr.0, PKCS10, l)?;
    w.start("c:AdditionalContext", &[])?;
    for (k, v) in &i.additional_context.0 {
        w.item()?;
        w.start("c:ContextItem", &[("Name", k)])?;
        w.scalar("c:Value", v, l.field_bytes, true)?;
        w.end("c:ContextItem")?;
    }
    w.end("c:AdditionalContext")?;
    write_nillable(w, &i.request_id, l)?;
    w.end("t:RequestSecurityToken")
}
fn read_nillable(p: &mut Input<'_>, name: &str) -> Result<NillableText> {
    let start = p.start(WSTEP, name)?;
    start.attrs(&[(XSI, "nil")])?;
    nillable_content(p, name, &start)
}
fn nillable_content(
    p: &mut Input<'_>,
    name: &str,
    start: &crate::xml::Start,
) -> Result<NillableText> {
    match start.attr(XSI, "nil") {
        Some("true" | "1") => {
            p.end(WSTEP, name)?;
            Ok(NillableText::Nil)
        }
        None | Some("false" | "0") => Ok(NillableText::Value(Secret(p.content(
            WSTEP,
            name,
            p.limits.field_bytes,
            true,
        )?))),
        _ => Err(E::InvalidValue),
    }
}
fn validate_nillable(value: &Option<NillableText>, l: &CodecLimits) -> Result<()> {
    if let Some(NillableText::Value(v)) = value {
        text(&v.0, l.field_bytes, true)?;
    }
    Ok(())
}
fn write_nillable(w: &mut Output<'_>, value: &Option<NillableText>, l: &CodecLimits) -> Result<()> {
    match value {
        None => Ok(()),
        Some(NillableText::Nil) => write_nil(w, "w:RequestID"),
        Some(NillableText::Value(v)) => w.scalar("w:RequestID", &v.0, l.field_bytes, true),
    }
}
pub(super) fn read_issue_response(p: &mut Input<'_>) -> Result<IssueResponse> {
    p.open(TRUST, "RequestSecurityTokenResponseCollection")?;
    let context = context(p, "RequestSecurityTokenResponse")?;
    let (mut token, mut disposition, mut provisioning, mut request_id) = (None, None, None, None);
    loop {
        if p.is(TRUST, "TokenType")? {
            once(
                &mut token,
                p.scalar(TRUST, "TokenType", p.limits.uri_bytes, false)?,
            )?;
        } else if p.is(WSTEP, "DispositionMessage")? {
            let start = p.start(WSTEP, "DispositionMessage")?;
            start.attrs(&[(XSI, "nil"), (XML, "lang")])?;
            let language = start.attr(XML, "lang").map(str::to_owned);
            once(
                &mut disposition,
                Disposition {
                    language,
                    value: nillable_content(p, "DispositionMessage", &start)?,
                },
            )?;
        } else if p.is(TRUST, "RequestedSecurityToken")? {
            p.open(TRUST, "RequestedSecurityToken")?;
            once(&mut provisioning, binary(p, PROVISION)?)?;
            p.end(TRUST, "RequestedSecurityToken")?;
        } else if p.is(WSTEP, "RequestID")? {
            once(&mut request_id, read_nillable(p, "RequestID")?)?;
        } else {
            break;
        }
    }
    p.end(TRUST, "RequestSecurityTokenResponse")?;
    p.end(TRUST, "RequestSecurityTokenResponseCollection")?;
    if token.as_deref() != Some(TOKEN) {
        return Err(E::Unsupported);
    }
    Ok(IssueResponse {
        context,
        provisioning: provisioning.ok_or(E::Structure)?,
        request_id,
        disposition,
    })
}
pub(super) fn validate_issue_response(i: &IssueResponse, l: &CodecLimits) -> Result<()> {
    if let Some(c) = &i.context {
        text(c, l.identifier_bytes, false)?;
    }
    if let Some(d) = &i.disposition {
        if let Some(language) = &d.language {
            text(language, l.identifier_bytes, false)?;
        }
        if let NillableText::Value(v) = &d.value {
            text(&v.0, l.field_bytes, true)?;
        }
    }
    validate_nillable(&i.request_id, l)?;
    bound(i.provisioning.0.len(), l.binary_bytes)?;
    if i.provisioning.0.is_empty() {
        return Err(E::InvalidValue);
    }
    Ok(())
}
pub(super) fn write_issue_response(
    w: &mut Output<'_>,
    i: &IssueResponse,
    l: &CodecLimits,
) -> Result<()> {
    w.start("t:RequestSecurityTokenResponseCollection", &[])?;
    let attrs = i
        .context
        .as_deref()
        .map(|s| vec![("Context", s)])
        .unwrap_or_default();
    w.start("t:RequestSecurityTokenResponse", &attrs)?;
    w.scalar("t:TokenType", TOKEN, l.uri_bytes, false)?;
    if let Some(d) = &i.disposition {
        let mut attrs = Vec::new();
        if let Some(language) = &d.language {
            attrs.push(("xml:lang", language.as_str()));
        }
        if d.value == NillableText::Nil {
            attrs.push(("xsi:nil", "true"));
        }
        w.start("w:DispositionMessage", &attrs)?;
        if let NillableText::Value(v) = &d.value {
            w.content(&v.0, l.field_bytes)?;
        }
        w.end("w:DispositionMessage")?;
    }
    w.start("t:RequestedSecurityToken", &[])?;
    write_binary(w, &i.provisioning.0, PROVISION, l)?;
    w.end("t:RequestedSecurityToken")?;
    write_nillable(w, &i.request_id, l)?;
    w.end("t:RequestSecurityTokenResponse")?;
    w.end("t:RequestSecurityTokenResponseCollection")
}
