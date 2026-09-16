//! V2 core projection in a single V1 storage envelope; no legacy decoder.
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
fn candidate(v: &CandidateId) -> Value {
    object(v.tenant(), v.value())
}
pub(crate) fn read_candidate(v: &Value) -> Result<CandidateId, PgError> {
    let (t, v) = fields(v)?;
    crate::error::decode_domain("codec::read_candidate", CandidateId::new(t, v))
}
fn request_id(v: &RequestId) -> Value {
    object(v.tenant(), v.value())
}
pub(crate) fn read_request_id(v: &Value) -> Result<RequestId, PgError> {
    let (t, v) = fields(v)?;
    crate::error::decode_domain("codec::read_request_id", RequestId::new(t, v))
}
pub(crate) fn ring(r: Ring) -> u8 {
    match r {
        Ring::Test => 0,
        Ring::Pilot => 1,
        Ring::Production => 2,
    }
}
fn read_ring(v: &Value) -> Result<Ring, PgError> {
    match n(v)? {
        0 => Ok(Ring::Test),
        1 => Ok(Ring::Pilot),
        2 => Ok(Ring::Production),
        _ => Err(STORAGE.fault("codec::read_ring")),
    }
}
fn policy(p: ActorPolicy) -> u8 {
    match p {
        ActorPolicy::Separate => 0,
        ActorPolicy::AllowSameActor => 1,
    }
}
fn read_policy(v: &Value) -> Result<ActorPolicy, PgError> {
    match n(v)? {
        0 => Ok(ActorPolicy::Separate),
        1 => Ok(ActorPolicy::AllowSameActor),
        _ => Err(STORAGE.fault("codec::read_policy")),
    }
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
fn validation(v: &Validation) -> Value {
    json!([
        candidate(&v.candidate),
        v.content.bytes(),
        ring(v.ring),
        evidence(&v.evidence),
        match v.verdict {
            Verdict::Passed => 0,
            Verdict::Failed => 1,
            Verdict::Unknown => 2,
        }
    ])
}
fn read_validation(v: &Value) -> Result<Validation, PgError> {
    let a = array(v, 5)?;
    Ok(Validation {
        candidate: read_candidate(&a[0])?,
        content: hash(&a[1])?,
        ring: read_ring(&a[2])?,
        evidence: read_evidence(&a[3])?,
        verdict: match n(&a[4])? {
            0 => Verdict::Passed,
            1 => Verdict::Failed,
            2 => Verdict::Unknown,
            _ => return Err(STORAGE.fault("codec::read_validation")),
        },
    })
}
fn approval(a: &Approval) -> Value {
    json!([
        validation(&a.validation),
        actor(&a.publisher),
        actor(&a.approver),
        policy(a.policy),
        a.at.unix_seconds(),
        a.predecessor.map(|p| p.digest().bytes())
    ])
}
fn read_approval(v: &Value) -> Result<Approval, PgError> {
    let a = array(v, 6)?;
    Ok(Approval {
        validation: read_validation(&a[0])?,
        publisher: read_actor(&a[1])?,
        approver: read_actor(&a[2])?,
        policy: read_policy(&a[3])?,
        at: time(&a[4])?,
        predecessor: if a[5].is_null() {
            None
        } else {
            Some(PublicationId::from_digest(hash(&a[5])?))
        },
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
        _ => Err(STORAGE.fault("codec::read_outcome")),
    }
}
pub(crate) fn publication(p: &Publication) -> Value {
    json!([
        approval(&p.approval),
        p.attempt,
        p.authorized_at.unix_seconds(),
        match &p.outcome {
            PublicationOutcome::Pending => Value::Null,
            PublicationOutcome::Reported(r) => outcome(r),
        }
    ])
}
pub(crate) fn read_publication(v: &Value) -> Result<Publication, PgError> {
    let a = array(v, 4)?;
    Ok(Publication {
        approval: read_approval(&a[0])?,
        attempt: n(&a[1])?,
        authorized_at: time(&a[2])?,
        outcome: if a[3].is_null() {
            PublicationOutcome::Pending
        } else {
            PublicationOutcome::Reported(read_outcome(&a[3])?)
        },
    })
}
fn ring_state(r: &RingState) -> Value {
    match r {
        RingState::NotStarted => json!([0]),
        RingState::Candidate => json!([1]),
        RingState::Validated(v) => json!([2, validation(v)]),
        RingState::Approved(v) => json!([3, approval(v)]),
        RingState::Publication(v) => json!([4, publication(v)]),
    }
}
fn read_ring_state(v: &Value) -> Result<RingState, PgError> {
    let a = v
        .as_array()
        .ok_or_else(|| STORAGE.fault("codec::read_ring_state"))?;
    let tag = n(a
        .first()
        .ok_or_else(|| STORAGE.fault("codec::read_ring_state"))?)?;
    if tag < 2 {
        array(v, 1)?;
        return Ok(if tag == 0 {
            RingState::NotStarted
        } else {
            RingState::Candidate
        });
    }
    let a = array(v, 2)?;
    match tag {
        2 => Ok(RingState::Validated(read_validation(&a[1])?)),
        3 => Ok(RingState::Approved(read_approval(&a[1])?)),
        4 => Ok(RingState::Publication(read_publication(&a[1])?)),
        _ => Err(STORAGE.fault("codec::read_ring_state")),
    }
}
pub(crate) fn snapshot(c: &Candidate) -> Result<Vec<u8>, PgError> {
    let s = c.snapshot();
    STORAGE.encode(&json!([
        2,
        candidate(&s.id),
        s.revision,
        s.at.unix_seconds(),
        s.content_at.unix_seconds(),
        content(&s.content),
        match s.disposition {
            Disposition::Active => 0,
            Disposition::Quarantined => 1,
            Disposition::Deprecated => 2,
        },
        s.rings.iter().map(ring_state).collect::<Vec<_>>()
    ]))
}
pub(crate) fn read_snapshot(bytes: &[u8]) -> Result<Candidate, PgError> {
    let v: Value = STORAGE.decode(bytes)?;
    let a = array(&v, 8)?;
    if n(&a[0])? != 2 {
        return Err(STORAGE.fault("codec::read_snapshot"));
    }
    let rings = array(&a[7], 3)?;
    crate::error::decode_domain(
        "codec::read_snapshot",
        Candidate::restore(Snapshot {
            id: read_candidate(&a[1])?,
            revision: n(&a[2])?,
            at: time(&a[3])?,
            content_at: time(&a[4])?,
            content: read_content(&a[5])?,
            disposition: match n(&a[6])? {
                0 => Disposition::Active,
                1 => Disposition::Quarantined,
                2 => Disposition::Deprecated,
                _ => return Err(STORAGE.fault("codec::read_snapshot")),
            },
            rings: [
                read_ring_state(&rings[0])?,
                read_ring_state(&rings[1])?,
                read_ring_state(&rings[2])?,
            ],
        }),
    )
}
pub(crate) fn request(c: &CandidateId, r: &Request) -> Result<Vec<u8>, PgError> {
    let operation = match &r.operation {
        Operation::Replace(c) => json!([0, content(c)]),
        Operation::Validate(v) => json!([1, validation(v)]),
        Operation::Approve {
            ring: r,
            publisher,
            policy: p,
        } => json!([2, ring(*r), actor(publisher), policy(*p)]),
        Operation::Authorize { ring: r, approval } => json!([3, ring(*r), approval.bytes()]),
        Operation::Retry {
            ring: r,
            publication,
            attempt,
        } => json!([4, ring(*r), publication.digest().bytes(), attempt]),
        Operation::Record {
            ring: r,
            publication,
            attempt,
            outcome: o,
        } => json!([
            5,
            ring(*r),
            publication.digest().bytes(),
            attempt,
            outcome(o)
        ]),
        Operation::Quarantine => json!([6]),
        Operation::Deprecate => json!([7]),
    };
    STORAGE.encode(&json!([
        2,
        candidate(c),
        request_id(&r.id),
        actor(&r.actor),
        r.expected_revision,
        r.as_of.unix_seconds(),
        operation
    ]))
}
pub(crate) fn receipt(r: &Receipt) -> Value {
    json!([
        2,
        candidate(&r.candidate),
        request_id(&r.request),
        r.fingerprint.bytes(),
        r.before_revision,
        r.revision,
        r.at.unix_seconds()
    ])
}
pub(crate) fn read_receipt(v: &Value) -> Result<Receipt, PgError> {
    let a = array(v, 7)?;
    if n(&a[0])? != 2 {
        return Err(STORAGE.fault("codec::read_receipt"));
    }
    Ok(Receipt {
        candidate: read_candidate(&a[1])?,
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
pub(crate) fn read_request(bytes: &[u8]) -> Result<Option<(CandidateId, Request)>, PgError> {
    let v: Value = STORAGE.decode(bytes)?;
    if v.as_array().and_then(|a| a.first()).and_then(Value::as_str) == Some("create-v2") {
        return Ok(None);
    }
    let a = array(&v, 7)?;
    if n(&a[0])? != 2 {
        return Err(STORAGE.fault("codec::read_request"));
    }
    let o = a[6]
        .as_array()
        .ok_or_else(|| STORAGE.fault("codec::read_request"))?;
    let tag = n(o
        .first()
        .ok_or_else(|| STORAGE.fault("codec::read_request"))?)?;
    let operation = match tag {
        0 => {
            array(&a[6], 2)?;
            Operation::Replace(read_content(&o[1])?)
        }
        1 => {
            array(&a[6], 2)?;
            Operation::Validate(read_validation(&o[1])?)
        }
        2 => {
            array(&a[6], 4)?;
            Operation::Approve {
                ring: read_ring(&o[1])?,
                publisher: read_actor(&o[2])?,
                policy: read_policy(&o[3])?,
            }
        }
        3 => {
            array(&a[6], 3)?;
            Operation::Authorize {
                ring: read_ring(&o[1])?,
                approval: hash(&o[2])?,
            }
        }
        4 => {
            array(&a[6], 4)?;
            Operation::Retry {
                ring: read_ring(&o[1])?,
                publication: PublicationId::from_digest(hash(&o[2])?),
                attempt: n(&o[3])?,
            }
        }
        5 => {
            array(&a[6], 5)?;
            Operation::Record {
                ring: read_ring(&o[1])?,
                publication: PublicationId::from_digest(hash(&o[2])?),
                attempt: n(&o[3])?,
                outcome: read_outcome(&o[4])?,
            }
        }
        6 => {
            array(&a[6], 1)?;
            Operation::Quarantine
        }
        7 => {
            array(&a[6], 1)?;
            Operation::Deprecate
        }
        _ => return Err(STORAGE.fault("codec::read_request")),
    };
    Ok(Some((
        read_candidate(&a[1])?,
        Request {
            id: read_request_id(&a[2])?,
            actor: read_actor(&a[3])?,
            expected_revision: n(&a[4])?,
            as_of: time(&a[5])?,
            operation,
        },
    )))
}
