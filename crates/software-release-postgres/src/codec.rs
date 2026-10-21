//! Direct publication storage projection.
use crate::{STORAGE, core::*};
use rss_contract::Timepoint;
use rss_mdm_backend_postgres_support::digest;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgError;
use serde_json::{Value, json};
pub(crate) fn array(v: &Value, n: usize) -> Result<&[Value], PgError> {
    v.as_array()
        .filter(|a| a.len() == n)
        .map(Vec::as_slice)
        .ok_or_else(|| STORAGE.fault("codec::array"))
}
pub(crate) fn s(v: &Value) -> Result<&str, PgError> {
    v.as_str().ok_or_else(|| STORAGE.fault("codec::s"))
}
pub(crate) fn n(v: &Value) -> Result<u64, PgError> {
    v.as_u64().ok_or_else(|| STORAGE.fault("codec::n"))
}
fn time(v: &Value) -> Result<Timepoint, PgError> {
    STORAGE.invalid(
        "codec::time",
        Timepoint::try_from(v.as_i64().ok_or_else(|| STORAGE.fault("codec::time"))?),
    )
}
fn hash(v: &Value) -> Result<Digest, PgError> {
    Ok(Digest::from_bytes(
        STORAGE.json("codec::hash", serde_json::from_value(v.clone()))?,
    ))
}
fn object(t: TenantId, v: &str) -> Value {
    json!([t.to_string(), v])
}
fn fields(v: &Value) -> Result<(TenantId, &str), PgError> {
    let a = array(v, 2)?;
    Ok((
        STORAGE.invalid("codec::fields", TenantId::parse(s(&a[0])?))?,
        s(&a[1])?,
    ))
}
fn actor(v: &ActorId) -> Value {
    object(v.tenant(), v.value())
}
fn read_actor(v: &Value) -> Result<ActorId, PgError> {
    let (t, v) = fields(v)?;
    crate::error::decode_domain("codec::read_actor", ActorId::new(t, v))
}
fn publication_key(v: &PublicationKey) -> Value {
    object(v.tenant(), v.value())
}
pub(crate) fn read_publication_key(v: &Value) -> Result<PublicationKey, PgError> {
    let (t, v) = fields(v)?;
    crate::error::decode_domain("codec::read_publication_key", PublicationKey::new(t, v))
}
fn request_id(v: &RequestId) -> Value {
    object(v.tenant(), v.value())
}
pub(crate) fn read_request_id(v: &Value) -> Result<RequestId, PgError> {
    let (t, v) = fields(v)?;
    crate::error::decode_domain("codec::read_request_id", RequestId::new(t, v))
}
pub(crate) fn content(c: &Content) -> Value {
    let s = c.software().fields();
    json!([
        [s.source, s.package, s.version, s.platform],
        c.description().bytes(),
        c.source_snapshot().bytes(),
        c.manifest().bytes(),
        c.variants()
            .iter()
            .map(|v| json!([
                v.architecture(),
                v.variant(),
                v.artifacts()
                    .iter()
                    .map(|a| json!([a.key(), a.digest().bytes()]))
                    .collect::<Vec<_>>()
            ]))
            .collect::<Vec<_>>()
    ])
}
fn read_content(v: &Value) -> Result<Content, PgError> {
    let a = array(v, 5)?;
    let identity = array(&a[0], 4)?;
    let software = crate::error::decode_domain(
        "codec::read_content",
        SoftwareIdentity::new(SoftwareIdentityFields {
            source: s(&identity[0])?.into(),
            package: s(&identity[1])?.into(),
            version: s(&identity[2])?.into(),
            platform: s(&identity[3])?.into(),
        }),
    )?;
    let raw = a[4]
        .as_array()
        .ok_or_else(|| STORAGE.fault("codec::read_content"))?;
    if raw.len() > 64 {
        return Err(STORAGE.fault("codec::read_content"));
    }
    let variants = raw
        .iter()
        .map(|v| {
            let a = array(v, 3)?;
            let raw = a[2]
                .as_array()
                .ok_or_else(|| STORAGE.fault("codec::read_content"))?;
            if raw.len() > 256 {
                return Err(STORAGE.fault("codec::read_content"));
            }
            let artifacts = raw
                .iter()
                .map(|v| {
                    let a = array(v, 2)?;
                    crate::error::decode_domain(
                        "codec::read_content",
                        Artifact::new(s(&a[0])?, hash(&a[1])?),
                    )
                })
                .collect::<Result<Vec<_>, PgError>>()?;
            crate::error::decode_domain(
                "codec::read_content",
                VariantContent::new(s(&a[0])?, s(&a[1])?, artifacts),
            )
        })
        .collect::<Result<Vec<_>, PgError>>()?;
    crate::error::decode_domain(
        "codec::read_content",
        Content::new(software, hash(&a[1])?, hash(&a[2])?, hash(&a[3])?, variants),
    )
}
fn evidence(e: &Evidence) -> Value {
    json!([actor(&e.actor), e.digest.bytes(), e.at.unix_seconds()])
}
fn read_evidence(v: &Value) -> Result<Evidence, PgError> {
    let a = array(v, 3)?;
    Ok(Evidence {
        actor: read_actor(&a[0])?,
        digest: hash(&a[1])?,
        at: time(&a[2])?,
    })
}
fn binding(b: &PublicationBinding) -> Value {
    json!([
        publication_key(&b.publication),
        b.content.bytes(),
        object(b.target.tenant(), b.target.value()),
        b.target_digest.bytes(),
        evidence(&b.evidence),
        b.lifecycle.bytes(),
        actor(&b.actor),
        b.at.unix_seconds()
    ])
}
fn read_binding(v: &Value) -> Result<PublicationBinding, PgError> {
    let a = array(v, 8)?;
    let (tenant, target) = fields(&a[2])?;
    Ok(PublicationBinding {
        publication: read_publication_key(&a[0])?,
        content: hash(&a[1])?,
        target: crate::error::decode_domain("codec::target", TargetId::new(tenant, target))?,
        target_digest: hash(&a[3])?,
        evidence: read_evidence(&a[4])?,
        lifecycle: hash(&a[5])?,
        actor: read_actor(&a[6])?,
        at: time(&a[7])?,
    })
}
fn outcome(p: &PublicationResult) -> Value {
    match p {
        PublicationResult::Unknown(e) => json!([0, evidence(e)]),
        PublicationResult::NotApplied(e) => json!([1, evidence(e)]),
        PublicationResult::Applied(e) => json!([2, evidence(e)]),
    }
}
fn read_outcome(v: &Value) -> Result<PublicationResult, PgError> {
    let a = array(v, 2)?;
    let e = read_evidence(&a[1])?;
    match n(&a[0])? {
        0 => Ok(PublicationResult::Unknown(e)),
        1 => Ok(PublicationResult::NotApplied(e)),
        2 => Ok(PublicationResult::Applied(e)),
        _ => Err(STORAGE.fault("codec::outcome")),
    }
}
pub(crate) fn attempt(p: &Attempt) -> Value {
    json!([
        binding(&p.binding),
        p.attempt,
        p.requested_at.unix_seconds(),
        match &p.outcome {
            PublicationOutcome::Pending => Value::Null,
            PublicationOutcome::Reported(r) => outcome(r),
        }
    ])
}
pub(crate) fn read_attempt(v: &Value) -> Result<Attempt, PgError> {
    let a = array(v, 4)?;
    Ok(Attempt {
        binding: read_binding(&a[0])?,
        attempt: n(&a[1])?,
        requested_at: time(&a[2])?,
        outcome: if a[3].is_null() {
            PublicationOutcome::Pending
        } else {
            PublicationOutcome::Reported(read_outcome(&a[3])?)
        },
    })
}
pub(crate) fn snapshot(p: &Publication) -> Result<Vec<u8>, PgError> {
    let s = p.snapshot();
    STORAGE.encode(&json!([
        1,
        publication_key(&s.id),
        s.revision,
        s.at.unix_seconds(),
        content(&s.content),
        s.withdrawn,
        attempt(&s.attempt)
    ]))
}
pub(crate) fn read_snapshot(bytes: &[u8]) -> Result<Publication, PgError> {
    let v: Value = STORAGE.decode(bytes)?;
    let a = array(&v, 7)?;
    if n(&a[0])? != 1 {
        return Err(STORAGE.fault("codec::snapshot"));
    }
    crate::error::decode_domain(
        "codec::snapshot",
        Publication::restore(Snapshot {
            id: read_publication_key(&a[1])?,
            revision: n(&a[2])?,
            at: time(&a[3])?,
            content: read_content(&a[4])?,
            withdrawn: a[5]
                .as_bool()
                .ok_or_else(|| STORAGE.fault("codec::withdrawn"))?,
            attempt: read_attempt(&a[6])?,
        }),
    )
}
pub(crate) fn request(p: &PublicationKey, r: &Request) -> Result<Vec<u8>, PgError> {
    let op = match &r.operation {
        Operation::Retry {
            publication,
            attempt,
        } => json!([0, publication.digest().bytes(), attempt]),
        Operation::Record {
            publication,
            attempt,
            outcome: o,
        } => json!([1, publication.digest().bytes(), attempt, outcome(o)]),
        Operation::Withdraw => json!([2]),
    };
    STORAGE.encode(&json!([
        1,
        publication_key(p),
        request_id(&r.id),
        actor(&r.actor),
        r.expected_revision,
        r.as_of.unix_seconds(),
        op
    ]))
}
pub(crate) fn receipt(r: &Receipt) -> Value {
    json!([
        1,
        publication_key(&r.publication),
        request_id(&r.request),
        r.fingerprint.bytes(),
        r.before_revision,
        r.revision,
        r.at.unix_seconds()
    ])
}
pub(crate) fn read_receipt(v: &Value) -> Result<Receipt, PgError> {
    let a = array(v, 7)?;
    if n(&a[0])? != 1 {
        return Err(STORAGE.fault("codec::receipt"));
    }
    Ok(Receipt {
        publication: read_publication_key(&a[1])?,
        request: read_request_id(&a[2])?,
        fingerprint: hash(&a[3])?,
        before_revision: n(&a[4])?,
        revision: n(&a[5])?,
        at: time(&a[6])?,
    })
}
pub(crate) fn material(c: &Content) -> Result<(String, Vec<u8>), PgError> {
    let mut doc = content(c);
    doc[2] = Value::Null;
    let key = crate::hex(&digest(&STORAGE.encode(&doc[0])?));
    Ok((key, STORAGE.encode(&doc)?))
}
pub(crate) fn read_request(bytes: &[u8]) -> Result<Option<(PublicationKey, Request)>, PgError> {
    let v: Value = STORAGE.decode(bytes)?;
    if v.as_array().and_then(|a| a.first()).and_then(Value::as_str) == Some("publish-v1") {
        return Ok(None);
    }
    let a = array(&v, 7)?;
    if n(&a[0])? != 1 {
        return Err(STORAGE.fault("codec::request"));
    }
    let o = a[6]
        .as_array()
        .ok_or_else(|| STORAGE.fault("codec::request"))?;
    let operation = match n(o.first().ok_or_else(|| STORAGE.fault("codec::request"))?)? {
        0 => {
            array(&a[6], 3)?;
            Operation::Retry {
                publication: PublicationId::from_digest(hash(&o[1])?),
                attempt: n(&o[2])?,
            }
        }
        1 => {
            array(&a[6], 4)?;
            Operation::Record {
                publication: PublicationId::from_digest(hash(&o[1])?),
                attempt: n(&o[2])?,
                outcome: read_outcome(&o[3])?,
            }
        }
        2 => {
            array(&a[6], 1)?;
            Operation::Withdraw
        }
        _ => return Err(STORAGE.fault("codec::request")),
    };
    Ok(Some((
        read_publication_key(&a[1])?,
        Request {
            id: read_request_id(&a[2])?,
            actor: read_actor(&a[3])?,
            expected_revision: n(&a[4])?,
            as_of: time(&a[5])?,
            operation,
        },
    )))
}
