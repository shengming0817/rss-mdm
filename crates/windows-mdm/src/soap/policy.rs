//! The enrollment profile's single-policy XCEP response. No CA or policy engine.
use super::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub policy_id: String,
    pub common_name: String,
    pub validity_seconds: u32,
    pub renewal_seconds: u32,
    pub minimum_key_length: u32,
    pub major_revision: u32,
    pub minor_revision: u32,
}
pub(super) fn read_request(p: &mut Input<'_>) -> Result<()> {
    p.open(XCEP, "GetPolicies")?;
    p.open(XCEP, "client")?;
    nil(p, XCEP, "lastUpdate")?;
    nil(p, XCEP, "preferredLanguage")?;
    p.end(XCEP, "client")?;
    nil(p, XCEP, "requestFilter")?;
    p.end(XCEP, "GetPolicies")
}
pub(super) fn write_request(w: &mut Output<'_>) -> Result<()> {
    w.start("p:GetPolicies", &[])?;
    w.start("p:client", &[])?;
    write_nil(w, "p:lastUpdate")?;
    write_nil(w, "p:preferredLanguage")?;
    w.end("p:client")?;
    write_nil(w, "p:requestFilter")?;
    w.end("p:GetPolicies")
}
fn number(p: &mut Input<'_>, name: &str) -> Result<u32> {
    crate::syncml::number(
        &p.scalar(XCEP, name, p.limits.identifier_bytes, false)?,
        true,
    )
}
fn constant(p: &mut Input<'_>, name: &str, value: &str) -> Result<()> {
    if p.scalar(XCEP, name, p.limits.identifier_bytes, false)? != value {
        return Err(E::Unsupported);
    }
    Ok(())
}
const PRIVATE_NIL: &[&str] = &[
    "keySpec",
    "keyUsageProperty",
    "permissions",
    "algorithmOIDReference",
    "cryptoProviders",
];
const ATTRIBUTE_NIL: &[&str] = &[
    "supersededPolicies",
    "privateKeyFlags",
    "subjectNameFlags",
    "enrollmentFlags",
    "generalFlags",
];
const END_NIL: &[&str] = &["rARequirements", "keyArchivalAttributes", "extensions"];
pub(super) fn read(p: &mut Input<'_>) -> Result<Policy> {
    p.open(XCEP, "GetPoliciesResponse")?;
    p.open(XCEP, "response")?;
    let policy_id = p.scalar(XCEP, "policyID", p.limits.identifier_bytes, true)?;
    for name in [
        "policyFriendlyName",
        "nextUpdateHours",
        "policiesNotChanged",
    ] {
        nil(p, XCEP, name)?;
    }
    p.open(XCEP, "policies")?;
    p.open(XCEP, "policy")?;
    constant(p, "policyOIDReference", "0")?;
    nil(p, XCEP, "cAs")?;
    p.open(XCEP, "attributes")?;
    let common_name = p.scalar(XCEP, "commonName", p.limits.field_bytes, false)?;
    constant(p, "policySchema", "3")?;
    p.open(XCEP, "certificateValidity")?;
    let validity_seconds = number(p, "validityPeriodSeconds")?;
    let renewal_seconds = number(p, "renewalPeriodSeconds")?;
    p.end(XCEP, "certificateValidity")?;
    p.open(XCEP, "permission")?;
    constant(p, "enroll", "true")?;
    constant(p, "autoEnroll", "false")?;
    p.end(XCEP, "permission")?;
    p.open(XCEP, "privateKeyAttributes")?;
    let minimum_key_length = number(p, "minimalKeyLength")?;
    for name in PRIVATE_NIL {
        nil(p, XCEP, name)?;
    }
    p.end(XCEP, "privateKeyAttributes")?;
    p.open(XCEP, "revision")?;
    let major_revision = number(p, "majorRevision")?;
    let minor_revision = number(p, "minorRevision")?;
    p.end(XCEP, "revision")?;
    for name in ATTRIBUTE_NIL {
        nil(p, XCEP, name)?;
    }
    constant(p, "hashAlgorithmOIDReference", "0")?;
    for name in END_NIL {
        nil(p, XCEP, name)?;
    }
    p.end(XCEP, "attributes")?;
    p.end(XCEP, "policy")?;
    p.end(XCEP, "policies")?;
    p.end(XCEP, "response")?;
    nil(p, XCEP, "cAs")?;
    p.open(XCEP, "oIDs")?;
    p.open(XCEP, "oID")?;
    constant(p, "value", "2.16.840.1.101.3.4.2.1")?;
    constant(p, "group", "1")?;
    constant(p, "oIDReferenceID", "0")?;
    constant(p, "defaultName", "szOID_NIST_sha256")?;
    p.end(XCEP, "oID")?;
    p.end(XCEP, "oIDs")?;
    p.end(XCEP, "GetPoliciesResponse")?;
    Ok(Policy {
        policy_id,
        common_name,
        validity_seconds,
        renewal_seconds,
        minimum_key_length,
        major_revision,
        minor_revision,
    })
}
pub(super) fn validate(p: &Policy, l: &CodecLimits) -> Result<()> {
    text(&p.policy_id, l.identifier_bytes, true)?;
    text(&p.common_name, l.field_bytes, false)?;
    if p.validity_seconds == 0
        || p.minimum_key_length == 0
        || p.renewal_seconds >= p.validity_seconds
    {
        return Err(E::InvalidValue);
    }

    Ok(())
}
fn scalar(w: &mut Output<'_>, name: &str, value: &str, l: &CodecLimits) -> Result<()> {
    w.scalar(&format!("p:{name}"), value, l.field_bytes, true)
}
fn nils(w: &mut Output<'_>, names: &[&str]) -> Result<()> {
    for name in names {
        write_nil(w, &format!("p:{name}"))?;
    }
    Ok(())
}
pub(super) fn write(w: &mut Output<'_>, p: &Policy, l: &CodecLimits) -> Result<()> {
    w.start("p:GetPoliciesResponse", &[])?;
    w.start("p:response", &[])?;
    scalar(w, "policyID", &p.policy_id, l)?;
    nils(
        w,
        &[
            "policyFriendlyName",
            "nextUpdateHours",
            "policiesNotChanged",
        ],
    )?;
    w.start("p:policies", &[])?;
    w.start("p:policy", &[])?;
    scalar(w, "policyOIDReference", "0", l)?;
    write_nil(w, "p:cAs")?;
    w.start("p:attributes", &[])?;
    scalar(w, "commonName", &p.common_name, l)?;
    scalar(w, "policySchema", "3", l)?;
    w.start("p:certificateValidity", &[])?;
    scalar(
        w,
        "validityPeriodSeconds",
        &p.validity_seconds.to_string(),
        l,
    )?;
    scalar(w, "renewalPeriodSeconds", &p.renewal_seconds.to_string(), l)?;
    w.end("p:certificateValidity")?;
    w.start("p:permission", &[])?;
    scalar(w, "enroll", "true", l)?;
    scalar(w, "autoEnroll", "false", l)?;
    w.end("p:permission")?;
    w.start("p:privateKeyAttributes", &[])?;
    scalar(w, "minimalKeyLength", &p.minimum_key_length.to_string(), l)?;
    nils(w, PRIVATE_NIL)?;
    w.end("p:privateKeyAttributes")?;
    w.start("p:revision", &[])?;
    scalar(w, "majorRevision", &p.major_revision.to_string(), l)?;
    scalar(w, "minorRevision", &p.minor_revision.to_string(), l)?;
    w.end("p:revision")?;
    nils(w, ATTRIBUTE_NIL)?;
    scalar(w, "hashAlgorithmOIDReference", "0", l)?;
    nils(w, END_NIL)?;
    w.end("p:attributes")?;
    w.end("p:policy")?;
    w.end("p:policies")?;
    w.end("p:response")?;
    write_nil(w, "p:cAs")?;
    w.start("p:oIDs", &[])?;
    w.start("p:oID", &[])?;
    scalar(w, "value", "2.16.840.1.101.3.4.2.1", l)?;
    scalar(w, "group", "1", l)?;
    scalar(w, "oIDReferenceID", "0", l)?;
    scalar(w, "defaultName", "szOID_NIST_sha256", l)?;
    w.end("p:oID")?;
    w.end("p:oIDs")?;
    w.end("p:GetPoliciesResponse")
}
