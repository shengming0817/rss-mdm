use crate::error::Error;
use crate::{STORAGE, codec, core::*, error::*, event};
use rss_mdm_backend_postgres_support::digest;
use rss_mdm_backend_postgres_support::{AggregateRecord, RequestRecord};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::{PgError, PgOutboxWriter, PgRuntime, PgTransaction};
use serde_json::{Value, json};
use sqlx::Row;
use std::sync::Arc;
/// Immutable candidate request receipt; distinct from mutable current candidate state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationReceipt {
    /// Tenant-scoped candidate identity.
    pub candidate: CandidateId,
    /// Original request identity associated with this receipt.
    pub request: RequestId,
    /// Version or lifecycle revision recorded in this value.
    pub revision: u64,
    /// Core lifecycle mutation or original receipt; creation has no transition receipt.
    pub transition: Option<Receipt>,
}
/// An immutable publication attempt together with its pagination identity.
#[derive(Clone, Debug)]
pub struct HistoricalAttempt {
    /// Opaque continuation identity; pass unchanged to the next history query.
    pub cursor: String,
    /// Immutable publication attempt, including its original approval and result.
    pub publication: Publication,
}
/// Tenant-bound sole persistence owner of candidates, approvals, attempts and publication results.
pub struct ReleaseStore {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    writer: PgOutboxWriter,
}
impl ReleaseStore {
    /// Identify this tenant's ordered event partition for a canonical aggregate ID.
    /// The outer transaction declares every partition once, before any business locks.
    pub fn partition(
        &self,
        id: &str,
    ) -> Result<rss_transactional_messaging::message::PartitionIdentity, PgError> {
        use rss_transactional_messaging::message::{PartitionIdentity, PartitionKey};
        Ok(PartitionIdentity::new(
            self.tenant,
            event::domain(),
            STORAGE.invalid("store::partition", PartitionKey::parse(id))?,
        ))
    }

    /// Admit the exact schema and effective runtime privileges, then borrow the host runtime.
    /// Returns a settlement error on admission failure; never migrates or closes the runtime.
    pub async fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        d: OperationDeadline,
    ) -> Result<Self, Error> {
        settle(
            runtime
                .local_tx(tenant, d, |tx| {
                    Box::pin(async move {
                        STORAGE.verify(tx, crate::ADMISSION).await?;
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
    /// Return the tenant permanently bound to this store.
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
    /// Read and validate the current aggregate for this store tenant. Missing identities return `None`.
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
    /// Read through a borrowed transaction after runtime-owner and tenant validation.
    /// Never commits; propagate outer errors to the transaction owner.
    pub async fn get_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &CandidateId,
    ) -> InTransaction<Option<Candidate>> {
        input!(self.check(tx)?);
        if id.tenant() != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        let c = STORAGE
            .read(tx, id.value())
            .await?
            .map(
                |AggregateRecord {
                     revision: rev,
                     document: b,
                 }| {
                    let c = codec::read_snapshot(&b)?;
                    if c.snapshot().id != *id || rev != c.snapshot().revision {
                        return Err(STORAGE.fault("store::get_in"));
                    }
                    Ok(c)
                },
            )
            .transpose()?;
        Ok(Ok(c))
    }
    /// Lock and restore a candidate for companion app decisions. The caller retains the transaction lock.
    pub async fn lock_candidate_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &CandidateId,
    ) -> InTransaction<Candidate> {
        input!(self.check(tx)?);
        if id.tenant() != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        STORAGE.lock(tx, "candidate", id.value()).await?;
        Ok(input!(self.get_in(tx, id).await?).ok_or(Rejection::NotFound))
    }
    /// Persist a new immutable candidate and its original creation receipt in one transaction.
    /// Reuse the identical request after an unconfirmed commit; changed content under an existing identity is rejected.
    pub async fn create(
        &self,
        id: &RequestId,
        c: &Candidate,
        d: OperationDeadline,
    ) -> Result<OperationReceipt, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, d, (self, id, c), |(s, id, c), tx| {
                    Box::pin(async move {
                        tx.prepare_outbox_partitions(&[s.partition(c.snapshot().id.value())?])
                            .await?;
                        s.create_in(tx, id, c).await
                    })
                })
                .await,
        )
    }
    /// Create within the caller transaction, including immutable-version checks and the request receipt.
    /// The caller owns commit/rollback and must propagate outer storage errors.
    /// The caller must declare the complete Outbox partition set before business locks.
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
        let request = STORAGE.encode(&json!([
            "create-v2",
            id.tenant().to_string(),
            id.value(),
            STORAGE.decode::<Value>(&document)?
        ]))?;
        let hash = digest(&request);
        STORAGE
            .lock(tx, "candidate", c.snapshot().id.value())
            .await?;
        STORAGE.lock(tx, "request", id.value()).await?;
        if let Some(RequestRecord {
            owner,
            fingerprint: old,
            receipt: b,
            ..
        }) = STORAGE.receipt(tx, id.value()).await?
        {
            if owner != c.snapshot().id.value() || hash != old {
                return Ok(Err(Rejection::IdentityConflict));
            }
            return Ok(Ok(operation_receipt(&b)?));
        }
        STORAGE
            .lock(tx, "candidate", c.snapshot().id.value())
            .await?;
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
        STORAGE
            .write(tx, c.snapshot().id.value(), None, 0, document)
            .await?;
        freeze_material(tx, &c.snapshot().content).await?;
        STORAGE
            .save_receipt(
                tx,
                id.value(),
                c.snapshot().id.value(),
                request,
                STORAGE.encode(&json!([
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
    /// Apply a core request with immutable attempt history, its receipt and RSS Outbox atomically.
    /// Replays return the original receipt rather than a new external Publish decision.
    pub async fn transition(
        &self,
        id: &CandidateId,
        r: &Request,
        d: OperationDeadline,
    ) -> Result<Transition, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, d, (self, id, r), |(s, id, r), tx| {
                    Box::pin(async move {
                        tx.prepare_outbox_partitions(&[s.partition(id.value())?])
                            .await?;
                        s.transition_in(tx, id, r).await
                    })
                })
                .await,
        )
    }
    /// Apply a core request in the borrowed transaction; never performs external source I/O.
    /// Propagate outer PG errors and let the host settle commit/rollback.
    /// The caller must declare the complete Outbox partition set before business locks.
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
        STORAGE.lock(tx, "candidate", id.value()).await?;
        STORAGE.lock(tx, "request", r.id.value()).await?;
        let previous = if let Some(RequestRecord {
            owner,
            fingerprint: old,
            receipt: b,
            ..
        }) = STORAGE.receipt(tx, r.id.value()).await?
        {
            if owner != id.value() || hash != old {
                return Ok(Err(Rejection::IdentityConflict));
            }
            Some(
                operation_receipt(&b)?
                    .transition
                    .ok_or_else(|| STORAGE.fault("store::transition_in"))?,
            )
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
        STORAGE
            .write(
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
                STORAGE
                    .freeze(
                        tx,
                        id.value(),
                        "attempt",
                        &key,
                        STORAGE.encode(&codec::publication(p))?,
                    )
                    .await?;
            }
        }
        STORAGE
            .save_receipt(
                tx,
                r.id.value(),
                id.value(),
                request,
                STORAGE.encode(&json!([1, codec::receipt(receipt)]))?,
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
    /// Recover the complete original core request by identity for exact service-level replay.
    pub async fn original_request(
        &self,
        id: &RequestId,
        d: OperationDeadline,
    ) -> Result<Option<(CandidateId, Request)>, Error> {
        if id.tenant() != self.tenant {
            return Err(Rejection::TenantMismatch.into());
        }
        let key = id.value().to_owned();
        settle(
            self.runtime
                .local_tx(self.tenant, d, move |tx| {
                    Box::pin(async move {
                        let t = tx.tenant_id().to_string();
                        let row = tx
                            .with_connection(move |c| {
                                Box::pin(async move {
                                    sqlx::query(ORIGINAL_REQUEST_SQL)
                                        .bind(t)
                                        .bind(key)
                                        .fetch_optional(c)
                                        .await
                                })
                            })
                            .await?;
                        let result = row
                            .map(|r| {
                                codec::read_request(
                                    &STORAGE.checked(
                                        r.try_get("request")?,
                                        r.try_get("fingerprint")?,
                                    )?,
                                )
                            })
                            .transpose()?
                            .flatten();
                        Ok(Ok(result))
                    })
                })
                .await,
        )
    }
    /// Read the original request receipt in the caller transaction after owner and tenant checks.
    pub async fn operation_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &RequestId,
    ) -> InTransaction<Option<OperationReceipt>> {
        input!(self.check(tx)?);
        if id.tenant() != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        Ok(Ok(STORAGE
            .receipt(tx, id.value())
            .await?
            .map(|RequestRecord { receipt: b, .. }| operation_receipt(&b))
            .transpose()?))
    }
    /// Read the original durable request receipt without changing current aggregate state.
    /// Use this after an unconfirmed commit; absence alone is not permission to invent another request identity.
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
                        Ok(Ok(STORAGE
                            .receipt(tx, id.value())
                            .await?
                            .map(|record| operation_receipt(&record.receipt))
                            .transpose()?))
                    })
                })
                .await,
        )
    }
    /// Read immutable publication attempts in bounded cursor order. Pass the last item cursor as `after`.
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
        settle(
            self.runtime
                .local_tx(self.tenant, d, move |tx| {
                    Box::pin(async move {
                        let rows = query_attempts(tx, &owner, after, limit).await?;
                        let attempts = rows
                            .into_iter()
                            .map(|row| decode_attempt(row, tx.tenant_id(), &owner))
                            .collect::<Result<Vec<_>, _>>()?;
                        Ok(Ok(attempts))
                    })
                })
                .await,
        )
    }
}
async fn material_compatible(tx: &mut PgTransaction<'_>, c: &Content) -> InTransaction<()> {
    let (key, bytes) = codec::material(c)?;
    if STORAGE
        .immutable(tx, "", "version", &key)
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
    STORAGE.freeze(tx, "", "version", &k, b).await
}
fn operation_receipt(bytes: &[u8]) -> Result<OperationReceipt, PgError> {
    let v: Value = STORAGE.decode(bytes)?;
    let a = v
        .as_array()
        .ok_or_else(|| STORAGE.fault("store::operation_receipt"))?;
    match codec::n(
        a.first()
            .ok_or_else(|| STORAGE.fault("store::operation_receipt"))?,
    )? {
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
        _ => Err(STORAGE.fault("store::operation_receipt")),
    }
}

const ORIGINAL_REQUEST_SQL: &str = "SELECT request,fingerprint FROM mdm_software_release.requests WHERE tenant_id=$1::uuid AND id=$2";
const ATTEMPT_HISTORY_SQL: &str = "SELECT key,document,digest FROM mdm_software_release.immutable WHERE tenant_id=$1::uuid AND owner=$2 AND kind='attempt' AND ($3::text IS NULL OR key COLLATE \"C\">$3 COLLATE \"C\") ORDER BY key COLLATE \"C\" LIMIT $4";

async fn query_attempts(
    tx: &mut PgTransaction<'_>,
    owner: &str,
    after: Option<String>,
    limit: usize,
) -> Result<Vec<sqlx::postgres::PgRow>, PgError> {
    let (tenant, owner) = (tx.tenant_id().to_string(), owner.to_owned());
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(ATTEMPT_HISTORY_SQL)
                .bind(tenant)
                .bind(owner)
                .bind(after)
                .bind(limit as i64)
                .fetch_all(c)
                .await
        })
    })
    .await
}
fn decode_attempt(
    row: sqlx::postgres::PgRow,
    tenant: TenantId,
    owner: &str,
) -> Result<HistoricalAttempt, PgError> {
    let bytes = STORAGE.checked(row.try_get("document")?, row.try_get("digest")?)?;
    let publication = codec::read_publication(&STORAGE.decode::<Value>(&bytes)?)?;
    let candidate = &publication.approval.validation.candidate;
    if candidate.tenant() != tenant || candidate.value() != owner || publication.attempt == 0 {
        return Err(STORAGE.fault("store::attempt_history"));
    }
    Ok(HistoricalAttempt {
        cursor: row.try_get("key")?,
        publication,
    })
}
