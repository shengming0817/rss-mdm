//! V1 owner encoding; core constructors validate every restored value.
use crate::{core::*, db::*};
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgError;
use serde_json::{Value, json};
pub(crate) fn array(v: &Value, n: usize) -> Result<&[Value], PgError> {
    v.as_array()
        .filter(|v| v.len() == n)
        .map(Vec::as_slice)
        .ok_or_else(fault)
}
pub(crate) fn text(v: &Value) -> Result<&str, PgError> {
    v.as_str().ok_or_else(fault)
}
pub(crate) fn number(v: &Value) -> Result<u64, PgError> {
    v.as_u64().ok_or_else(fault)
}
pub(crate) fn time(v: &Value) -> Result<Timepoint, PgError> {
    data(Timepoint::try_from(v.as_i64().ok_or_else(fault)?))
}
fn tenant(v: &Value) -> Result<TenantId, PgError> {
    data(TenantId::parse(text(v)?))
}
pub(crate) fn version(v: &Version) -> Value {
    json!([
        v.policy().tenant().to_string(),
        v.policy().value(),
        v.number(),
        v.payload().object().value(),
        v.payload().revision(),
        v.payload().digest(),
        0
    ])
}
pub(crate) fn read_version(v: &Value) -> Result<Version, PgError> {
    let v = array(v, 7)?;
    if number(&v[6])? != 0 {
        return Err(fault());
    }
    let t = tenant(&v[0])?;
    data(Version::new(
        data(PolicyId::new(t, text(&v[1])?))?,
        number(&v[2])?,
        data(PayloadRef::new(
            data(PayloadId::new(t, text(&v[3])?))?,
            number(&v[4])?,
            data(serde_json::from_value(v[5].clone()))?,
        ))?,
        RemovalRule::CancelOutstandingRetainEffects,
    ))
}
pub(crate) fn policy(p: &Policy) -> Value {
    json!([
        p.key().tenant().to_string(),
        p.key().value(),
        p.revision(),
        match p.status() {
            Status::Draft => 0,
            Status::Active => 1,
            Status::Paused => 2,
            Status::Archived => 3,
        },
        p.version().map(version)
    ])
}
pub(crate) fn read_policy(v: &Value) -> Result<Policy, PgError> {
    let v = array(v, 5)?;
    let status = match number(&v[3])? {
        0 => Status::Draft,
        1 => Status::Active,
        2 => Status::Paused,
        3 => Status::Archived,
        _ => return Err(fault()),
    };
    data(Policy::restore(
        data(PolicyId::new(tenant(&v[0])?, text(&v[1])?))?,
        number(&v[2])?,
        status,
        if v[4].is_null() {
            None
        } else {
            Some(read_version(&v[4])?)
        },
    ))
}
pub(crate) fn targets(t: &TargetSnapshot) -> Value {
    json!([
        t.key().tenant().to_string(),
        t.key().value(),
        t.revision(),
        t.members().iter().map(DeviceId::value).collect::<Vec<_>>()
    ])
}
pub(crate) fn read_targets(v: &Value) -> Result<TargetSnapshot, PgError> {
    let v = array(v, 4)?;
    let t = tenant(&v[0])?;
    let members = v[3].as_array().ok_or_else(fault)?;
    if members.len() > crate::MAX_FACTS {
        return Err(fault());
    }
    let values = members
        .iter()
        .map(|m| data(DeviceId::new(t, text(m)?)))
        .collect::<Result<Vec<_>, _>>()?;
    let result = data(TargetSnapshot::new(
        data(TargetSnapshotId::new(t, text(&v[1])?))?,
        number(&v[2])?,
        SnapshotCompleteness::Complete,
        values,
    ))?;
    if result.members().len() != members.len() {
        return Err(fault());
    }
    Ok(result)
}
pub(crate) fn fact(f: &ExecutionRecord) -> Value {
    json!([
        version(f.version()),
        f.device().value(),
        match f.progress() {
            Progress::Planned => 0,
            Progress::Running => 1,
            Progress::Unknown => 2,
            Progress::Succeeded => 3,
            Progress::Failed => 4,
            Progress::Cancelled => 5,
        },
        match f.effect() {
            Effect::Unverified => 0,
            Effect::Unknown => 1,
            Effect::VerifiedPresent => 2,
            Effect::VerifiedAbsent => 3,
        }
    ])
}
pub(crate) fn read_fact(v: &Value) -> Result<ExecutionRecord, PgError> {
    let v = array(v, 4)?;
    let version = read_version(&v[0])?;
    let device = data(DeviceId::new(version.policy().tenant(), text(&v[1])?))?;
    let progress = match number(&v[2])? {
        0 => Progress::Planned,
        1 => Progress::Running,
        2 => Progress::Unknown,
        3 => Progress::Succeeded,
        4 => Progress::Failed,
        5 => Progress::Cancelled,
        _ => return Err(fault()),
    };
    let effect = match number(&v[3])? {
        0 => Effect::Unverified,
        1 => Effect::Unknown,
        2 => Effect::VerifiedPresent,
        3 => Effect::VerifiedAbsent,
        _ => return Err(fault()),
    };
    data(ExecutionRecord::new(version, device, progress, effect))
}
pub(crate) fn key(f: &ExecutionRecord) -> String {
    format!("{}/{}", f.key().version(), f.key().device().value())
}
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
pub(crate) fn plan_id(s: &str) -> Result<PlanId, PgError> {
    if s.len() != 64 || !s.is_ascii() {
        return Err(fault());
    }
    let mut b = [0; 32];
    for (i, v) in b.iter_mut().enumerate() {
        *v = data(u8::from_str_radix(&s[i * 2..i * 2 + 2], 16))?;
    }
    Ok(PlanId::from_bytes(b))
}
