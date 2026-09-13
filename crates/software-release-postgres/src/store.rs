use crate::error::Error;
use crate::{
    codec,
    core::*,
    db::{self, *},
    error::*,
    event,
};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::{PgError, PgOutboxWriter, PgRuntime, PgTransaction};
use serde_json::{Value, json};
use sqlx::Row;
use std::sync::Arc;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationReceipt {
    pub candidate: CandidateId,
    pub request: RequestId,
    pub revision: u64,
    pub transition: Option<Receipt>,
}
#[derive(Clone, Debug)]
pub struct HistoricalAttempt {
    pub cursor: String,
    pub publication: Publication,
}
pub struct ReleaseStore {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    writer: PgOutboxWriter,
}
impl ReleaseStore {
    pub async fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        d: OperationDeadline,
    ) -> Result<Self, Error> {
        settle(
            runtime
                .local_tx(tenant, d, |tx| {
                    Box::pin(async move {
                        verify(tx).await?;
                        Ok(Ok(()))
                    })
                })
                .await,
        )?;
        Ok(Self {
            writer: PgOutboxWriter::new(runtime.clone(), event::domain()),
            runtime,
            tenant,
        })
    }
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    fn check(&self, tx: &PgTransaction<'_>) -> InTransaction<()> {
        self.writer.validate_transaction(tx)?;
        Ok(if tx.tenant_id() == self.tenant {
            Ok(())
        } else {
            Err(Rejection::TenantMismatch)
        })
    }
    pub async fn get(
        &self,
        id: &CandidateId,
        d: OperationDeadline,
    ) -> Result<Option<Candidate>, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, d, (self, id), |(s, id), tx| {
                    Box::pin(async move { s.get_in(tx, id).await })
                })
                .await,
        )
    }
    pub async fn get_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &CandidateId,
    ) -> InTransaction<Option<Candidate>> {
        input!(self.check(tx)?);
        if id.tenant() != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        let c = db::read(tx, id.value())
            .await?
            .map(|(rev, b)| {
                let c = codec::read_snapshot(&b)?;
                if c.snapshot().id != *id || rev != c.snapshot().revision {
                    return Err(fault());
                }
                Ok(c)
            })
            .transpose()?;
        Ok(Ok(c))
    }
    pub async fn lock_candidate_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &CandidateId,
    ) -> InTransaction<Candidate> {
        input!(self.check(tx)?);
        if id.tenant() != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        lock(tx, "candidate", id.value()).await?;
        Ok(input!(self.get_in(tx, id).await?).ok_or(Rejection::NotFound))
    }
    pub async fn create(
        &self,
        id: &RequestId,
        c: &Candidate,
        d: OperationDeadline,
    ) -> Result<OperationReceipt, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, d, (self, id, c), |(s, id, c), tx| {
                    Box::pin(async move { s.create_in(tx, id, c).await })
                })
                .await,
        )
    }
    pub async fn create_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &RequestId,
        c: &Candidate,
    ) -> InTransaction<OperationReceipt> {
        input!(self.check(tx)?);
        if id.tenant() != self.tenant || c.snapshot().id.tenant() != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        if c.snapshot().revision != 0
            || c.snapshot().disposition != Disposition::Active
            || c.snapshot().at != c.snapshot().content_at
            || c.snapshot().rings
                != [
                    RingState::Candidate,
                    RingState::NotStarted,
                    RingState::NotStarted,
                ]
        {
            return Ok(Err(Rejection::InvalidInput));
        }
        let document = codec::snapshot(c)?;
        let request = encode(&json!([
            "create-v2",
            id.tenant().to_string(),
            id.value(),
            decode::<Value>(&document)?
        ]))?;
        let hash = digest(&request);
        lock(tx, "candidate", c.snapshot().id.value()).await?;
        lock(tx, "request", id.value()).await?;
        if let Some((owner, old, b)) = db::receipt(tx, id.value()).await? {
            if owner != c.snapshot().id.value() || hash != old {
                return Ok(Err(Rejection::IdentityConflict));
            }
            return Ok(Ok(operation_receipt(&b)?));
        }
        lock(tx, "candidate", c.snapshot().id.value()).await?;
        if input!(self.get_in(tx, &c.snapshot().id).await?).is_some() {
            return Ok(Err(Rejection::Conflict));
        }
        input!(material_compatible(tx, &c.snapshot().content).await?);
        let result = OperationReceipt {
            candidate: c.snapshot().id.clone(),
            request: id.clone(),
            revision: 0,
            transition: None,
        };
        db::write(tx, c.snapshot().id.value(), None, 0, document).await?;
        freeze_material(tx, &c.snapshot().content).await?;
        db::save_receipt(
            tx,
            id.value(),
            c.snapshot().id.value(),
            hash,
            request,
            encode(&json!([
                0,
                [self.tenant.to_string(), c.snapshot().id.value()],
                [self.tenant.to_string(), id.value()]
            ]))?,
        )
        .await?;
        event::append(
            &self.writer,
            tx,
            self.tenant,
            c.snapshot().at,
            c.snapshot().id.value(),
            id.value(),
            0,
        )
        .await?;
        Ok(Ok(result))
    }
    pub async fn transition(
        &self,
        id: &CandidateId,
        r: &Request,
        d: OperationDeadline,
    ) -> Result<Transition, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, d, (self, id, r), |(s, id, r), tx| {
                    Box::pin(async move { s.transition_in(tx, id, r).await })
                })
                .await,
        )
    }
    pub async fn transition_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &CandidateId,
        r: &Request,
    ) -> InTransaction<Transition> {
        input!(self.check(tx)?);
        if id.tenant() != self.tenant
            || r.id.tenant() != self.tenant
            || r.actor.tenant() != self.tenant
        {
            return Ok(Err(Rejection::TenantMismatch));
        }
        let request = codec::request(id, r)?;
        let hash = digest(&request);
        lock(tx, "candidate", id.value()).await?;
        lock(tx, "request", r.id.value()).await?;
        let previous = if let Some((owner, old, b)) = db::receipt(tx, r.id.value()).await? {
            if owner != id.value() || hash != old {
                return Ok(Err(Rejection::IdentityConflict));
            }
            Some(operation_receipt(&b)?.transition.ok_or_else(fault)?)
        } else {
            None
        };
        let c = input!(self.lock_candidate_in(tx, id).await?);
        let result = input!(
            c.transition(r.clone(), previous.as_ref())
                .map_err(|e| match e {
                    crate::core::Error::TenantMismatch => Rejection::TenantMismatch,
                    crate::core::Error::RequestConflict => Rejection::IdentityConflict,
                    _ => Rejection::Conflict,
                })
        );
        let Transition::Applied { next, receipt, .. } = &result else {
            return Ok(Ok(result));
        };
        input!(material_compatible(tx, &next.snapshot().content).await?);
        db::write(
            tx,
            id.value(),
            Some(c.snapshot().revision),
            next.snapshot().revision,
            codec::snapshot(next)?,
        )
        .await?;
        freeze_material(tx, &next.snapshot().content).await?;
        for ring in &next.snapshot().rings {
            if let RingState::Publication(p) = ring {
                let key = format!(
                    "{}/{}/{:020}",
                    crate::hex(&p.id().digest().bytes()),
                    p.attempt,
                    next.snapshot().revision
                );
                freeze(
                    tx,
                    id.value(),
                    "attempt",
                    &key,
                    encode(&codec::publication(p))?,
                )
                .await?;
            }
        }
        db::save_receipt(
            tx,
            r.id.value(),
            id.value(),
            hash,
            request,
            encode(&json!([1, codec::receipt(receipt)]))?,
        )
        .await?;
        event::append(
            &self.writer,
            tx,
            self.tenant,
            r.as_of,
            id.value(),
            r.id.value(),
            next.snapshot().revision,
        )
        .await?;
        Ok(Ok(result))
    }
    pub async fn original_request(
        &self,
        id: &RequestId,
        d: OperationDeadline,
    ) -> Result<Option<(CandidateId, Request)>, Error> {
        if id.tenant() != self.tenant {
            return Err(Rejection::TenantMismatch.into());
        }
        let key = id.value().to_owned();
        settle(self.runtime.local_tx(self.tenant,d,move|tx|Box::pin(async move{let t=tx.tenant_id().to_string();let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT request,fingerprint FROM mdm_software_release.requests WHERE tenant_id=$1::uuid AND id=$2").bind(t).bind(key).fetch_optional(c).await})).await?;let result=row.map(|r|codec::read_request(&checked(r.try_get("request")?,r.try_get("fingerprint")?)?)).transpose()?.flatten();Ok(Ok(result))})).await)
    }
    pub async fn operation_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &RequestId,
    ) -> InTransaction<Option<OperationReceipt>> {
        input!(self.check(tx)?);
        if id.tenant() != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        Ok(Ok(db::receipt(tx, id.value())
            .await?
            .map(|(_, _, b)| operation_receipt(&b))
            .transpose()?))
    }
    pub async fn operation(
        &self,
        id: &RequestId,
        d: OperationDeadline,
    ) -> Result<Option<OperationReceipt>, Error> {
        if id.tenant() != self.tenant {
            return Err(Rejection::TenantMismatch.into());
        }
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, d, id, |id, tx| {
                    Box::pin(async move {
                        Ok(Ok(db::receipt(tx, id.value())
                            .await?
                            .map(|(_, _, b)| operation_receipt(&b))
                            .transpose()?))
                    })
                })
                .await,
        )
    }
    pub async fn attempt_history(
        &self,
        id: &CandidateId,
        after: Option<String>,
        limit: usize,
        d: OperationDeadline,
    ) -> Result<Vec<HistoricalAttempt>, Error> {
        if id.tenant() != self.tenant
            || limit == 0
            || limit > 1000
            || after.as_ref().is_some_and(|s| s.len() > 512)
        {
            return Err(Rejection::InvalidInput.into());
        }
        let owner = id.value().to_owned();
        settle(self.runtime.local_tx(self.tenant,d,move|tx|Box::pin(async move{let t=tx.tenant_id();let tenant=t.to_string();let rows=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT key,document,digest FROM mdm_software_release.immutable WHERE tenant_id=$1::uuid AND owner=$2 AND kind='attempt' AND ($3::text IS NULL OR key COLLATE \"C\">$3 COLLATE \"C\") ORDER BY key COLLATE \"C\" LIMIT $4").bind(tenant).bind(&owner).bind(after).bind(limit as i64).fetch_all(c).await.map(|rows|(owner,rows))})).await?;
 let mut result=Vec::new();for row in rows.1{let b=checked(row.try_get("document")?,row.try_get("digest")?)?;let p=codec::read_publication(&decode::<Value>(&b)?)?;if p.approval.validation.candidate.tenant()!=t||p.approval.validation.candidate.value()!=rows.0||p.attempt==0{return Err(fault());}result.push(HistoricalAttempt{cursor:row.try_get("key")?,publication:p});}Ok(Ok(result))})).await)
    }
}
async fn material_compatible(tx: &mut PgTransaction<'_>, c: &Content) -> InTransaction<()> {
    let (key, bytes) = codec::material(c)?;
    if db::immutable(tx, "", "version", &key)
        .await?
        .is_some_and(|b| b != bytes)
    {
        Ok(Err(Rejection::IdentityConflict))
    } else {
        Ok(Ok(()))
    }
}
async fn freeze_material(tx: &mut PgTransaction<'_>, c: &Content) -> Result<(), PgError> {
    let (k, b) = codec::material(c)?;
    freeze(tx, "", "version", &k, b).await
}
fn operation_receipt(bytes: &[u8]) -> Result<OperationReceipt, PgError> {
    let v: Value = decode(bytes)?;
    let a = v.as_array().ok_or_else(fault)?;
    match codec::n(a.first().ok_or_else(fault)?)? {
        0 => {
            let a = codec::array(&v, 3)?;
            Ok(OperationReceipt {
                candidate: codec::read_candidate(&a[1])?,
                request: codec::read_request_id(&a[2])?,
                revision: 0,
                transition: None,
            })
        }
        1 => {
            let a = codec::array(&v, 2)?;
            let r = codec::read_receipt(&a[1])?;
            Ok(OperationReceipt {
                candidate: r.candidate.clone(),
                request: r.request.clone(),
                revision: r.revision,
                transition: Some(r),
            })
        }
        _ => Err(fault()),
    }
}
