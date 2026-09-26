use crate::{Fact, InvalidFact};
use rss_audit_core::PreparedAuditV1;
use rss_audit_postgres::{AuditTransaction, Control, Integrity, PgAudit, Record};
use rss_contract::Timepoint;
use rss_request_context::ExecutionTimer;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sqlx::{PgConnection, PgPool, Row};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Audit(#[from] rss_audit_postgres::Error),
    #[error(transparent)]
    Fact(#[from] InvalidFact),
    #[error("audit recovery receipt conflicts with durable record")]
    Receipt,
    #[error("audit recovery requires READ COMMITTED isolation")]
    Isolation,
    #[error("audit receipt admission failed")]
    Admission,
    #[error("audit commit result is unconfirmed")]
    CommitUnknown,
    #[error("audit rollback is unconfirmed")]
    RollbackFailed,
}
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Self::Audit(e.into())
    }
}
impl From<Error> for PgError {
    fn from(e: Error) -> Self {
        match e {
            Error::Audit(e) => e.into(),
            Error::Fact(_) => rss_audit_postgres::Error::InvalidBound.into(),
            Error::Receipt
            | Error::Isolation
            | Error::Admission
            | Error::CommitUnknown
            | Error::RollbackFailed => rss_audit_postgres::Error::StorageContract.into(),
        }
    }
}
#[derive(Clone)]
pub struct AuditStore {
    adapter: PgAudit,
    ledger: bool,
}
impl AuditStore {
    #[cfg(feature = "integration")]
    pub fn inject_next_fault(&self, fault: rss_audit_postgres::PgFault) {
        self.adapter.inject_next_fault(fault);
    }
    /// Admit the host-owned pool and explicit integrity mode. Does not close the pool.
    /// Rejects unsafe receipt privileges/schema and non-READ-COMMITTED isolation.
    pub async fn new<T: ExecutionTimer>(
        pool: PgPool,
        integrity: Integrity,
        control: &Control<'_, T>,
    ) -> Result<Self, Error> {
        let mut connection = tokio::time::timeout(control.remaining(), pool.acquire())
            .await
            .map_err(|_| {
                rss_audit_postgres::Error::Deadline(
                    rss_transactional_messaging::transaction::LocalTxDeadlineStage::Acquire,
                )
            })??;
        let isolation =
            tokio::time::timeout(control.remaining(), admit_receipts(&mut connection)).await;
        match isolation {
            Ok(result) => result?,
            Err(_) => {
                connection.close_on_drop();
                return Err(rss_audit_postgres::Error::Deadline(
                    rss_transactional_messaging::transaction::LocalTxDeadlineStage::Operation,
                )
                .into());
            }
        }
        drop(connection);
        let ledger = matches!(integrity, Integrity::Ledger(_));
        Ok(Self {
            adapter: PgAudit::new(pool, integrity, control).await?,
            ledger,
        })
    }
    /// Admit the configured tenant before serving requests. Verify a bounded authenticated
    /// record when present so a wrong secret fails startup, even with the same key ID.
    /// Validate this tenant's stored integrity mode and, for Ledger, authenticate an existing window.
    /// This uses the same bounded owner transaction and never repairs or downgrades stored data.
    pub async fn validate_tenant<T: ExecutionTimer>(
        &self,
        tenant: rss_request_context::TenantId,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let ledger = self.ledger;
        self.execute(tenant, control, (), move |_, tx| {
            Box::pin(async move {
                let page = tx
                    .read_page(
                        rss_audit_postgres::Cursor::start(tenant),
                        rss_audit_postgres::ReadLimit::new(
                            1,
                            rss_audit_core::MAX_RECORD_BYTES as u64,
                        )?,
                    )
                    .await?;
                if page
                    .records()
                    .iter()
                    .any(|r| r.ledger_sequence().is_some() != ledger)
                {
                    return Err(Error::Receipt);
                }
                Ok(())
            })
        })
        .await
        .fold(
            |_| Ok(()),
            |error| Err(transaction_error(error)),
            |error| Err(transaction_error(error)),
            |_| Err(Error::RollbackFailed),
            |_| Err(Error::CommitUnknown),
            |error| Err(transaction_error(error)),
        )?;
        if ledger {
            self.adapter
                .read_verified(
                    tenant,
                    rss_ledger::Sequence::new(0),
                    rss_ledger_postgres::ReadLimit::new(1, 262144)
                        .map_err(rss_audit_postgres::Error::from)?,
                    control,
                )
                .await
                .fold(
                    |_| Ok(()),
                    |e| Err(Error::Audit(e)),
                    |e| Err(Error::Audit(e)),
                    |_| Err(Error::RollbackFailed),
                    |_| Err(Error::CommitUnknown),
                    |e| Err(Error::Audit(e)),
                )?;
        }
        Ok(())
    }
    /// Run product SQL under Audit then optional Ledger locks, using the component owner.
    pub async fn execute<T: ExecutionTimer, C: Send, R: Send, E: Send + From<Error>, F>(
        &self,
        tenant: rss_request_context::TenantId,
        control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> rss_transactional_messaging::transaction::LocalTxAttempt<
        rss_audit_postgres::Committed<R>,
        rss_audit_postgres::TransactionError<E>,
    >
    where
        F: for<'a> FnOnce(
                &'a mut C,
                &'a mut AuditTransaction<'_, '_, '_, T>,
            ) -> futures::future::BoxFuture<'a, Result<R, E>>
            + Send,
    {
        measure(
            "owner_total",
            self.adapter.local_tx_with_context(
                tenant,
                control,
                (context, Some(operation)),
                |(context, operation), tx| {
                    Box::pin(async move {
                        tx.with_connection(|c| Box::pin(admit_receipts(c)))
                            .await
                            .map_err(E::from)?;
                        measure("lock_head", tx.lock_head())
                            .await
                            .map_err(Error::from)
                            .map_err(E::from)?;
                        let operation = operation
                            .take()
                            .expect("component invokes its transaction callback once");
                        measure("product_callback", operation(context, tx)).await
                    })
                },
            ),
        )
        .await
    }
    /// End product work before the owner's total cutoff, then await the owner's settlement.
    /// Only cancels the borrowed callback, never the enclosing transaction future. Provider
    /// acquisition/setup remain subject to its total cutoff and may have an unconfirmed rollback.
    pub async fn execute_with_operation<
        T: ExecutionTimer,
        C: Send,
        R: Send,
        E: Send + From<Error>,
        F,
    >(
        &self,
        tenant: rss_request_context::TenantId,
        total: &Control<'_, T>,
        operation_control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> rss_transactional_messaging::transaction::LocalTxAttempt<
        rss_audit_postgres::Committed<R>,
        rss_audit_postgres::TransactionError<E>,
    >
    where
        F: for<'a> FnOnce(
                &'a mut C,
                &'a mut AuditTransaction<'_, '_, '_, T>,
            ) -> futures::future::BoxFuture<'a, Result<R, E>>
            + Send,
    {
        measure(
            "owner_total",
            self.adapter.local_tx_with_context(
                tenant,
                total,
                (context, Some(operation), operation_control, total),
                |(context, operation, operation_control, total), tx| {
                    Box::pin(async move {
                        let expired = || {
                            E::from(Error::Audit(rss_audit_postgres::Error::Deadline(
                        rss_transactional_messaging::transaction::LocalTxDeadlineStage::Operation)))
                        };
                        let remaining = operation_control.remaining().min(total.remaining());
                        if remaining.is_zero() {
                            return Err(expired());
                        }
                        let work = async {
                            tx.with_connection(|c| Box::pin(admit_receipts(c)))
                                .await
                                .map_err(E::from)?;
                            measure("lock_head", tx.lock_head())
                                .await
                                .map_err(Error::from)
                                .map_err(E::from)?;
                            let value = measure(
                                "product_callback",
                                operation.take().expect("one owner callback")(context, tx),
                            )
                            .await?;
                            if operation_control.remaining().is_zero() {
                                return Err(expired());
                            }
                            Ok(value)
                        };
                        tokio::time::timeout(remaining, work)
                            .await
                            .map_err(|_| expired())?
                    })
                },
            ),
        )
        .await
    }
    /// First operation in an RSS transaction: validate isolation/receipts, then lock Audit and Ledger.
    /// Must precede business and outbox locks. Reuses the owner's connection and remaining budget;
    /// errors must propagate to that owner. This method neither commits nor proves prior rollback.
    pub async fn lock_in(&self, tx: &mut PgTransaction<'_>) -> Result<(), Error> {
        tx.with_connection(|c| Box::pin(async move { Ok(admit_receipts(c).await) }))
            .await
            .map_err(rss_audit_postgres::Error::from)??;
        self.adapter.lock_head_in(tx).await?;
        Ok(())
    }
    /// Persist the independent request outcome using the component's settlement result.
    /// This never overwrites the recorded outcome of the business transaction.
    pub async fn settle_request<T: ExecutionTimer>(
        &self,
        request: &crate::RequestAudit,
        status: u16,
        result: &str,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.record(Fact::request(request, status, result)?, control)
            .await
            .fold(
                |_| Ok(()),
                |error| Err(transaction_error(error)),
                |error| Err(transaction_error(error)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |error| Err(transaction_error(error)),
            )
    }
    /// Settle a standalone request fact before returning its protected response.
    async fn record<T: ExecutionTimer>(
        &self,
        fact: Fact,
        control: &Control<'_, T>,
    ) -> rss_transactional_messaging::transaction::LocalTxAttempt<
        rss_audit_postgres::Committed<()>,
        rss_audit_postgres::TransactionError<Error>,
    > {
        self.execute(
            fact.identity().tenant(),
            control,
            (self, fact),
            |(store, fact), tx| Box::pin(async move { store.append_checked(tx, fact, None).await }),
        )
        .await
    }

    /// Stage a request fact under an Audit-owned transaction for a final known response.
    /// Request tenant must match the transaction. The owner must propagate errors and settle;
    /// use `settle_request` instead after a separate business transaction has ended.
    pub async fn append_request<T: ExecutionTimer>(
        &self,
        tx: &mut AuditTransaction<'_, '_, '_, T>,
        request: &crate::RequestAudit,
        status: u16,
        result: &str,
    ) -> Result<(), Error> {
        let fact = Fact::request(request, status, result)?;
        self.append_checked(tx, &fact, None).await
    }
    /// Stage a business fact inside `execute`; head locks must already precede business locks.
    /// `replayed` must reflect the producer's actual locked business receipt. A mismatched pair
    /// is an integrity failure, never permission to reconstruct or overwrite an event.
    /// Return errors to the original owner; this result is not a commit receipt.
    pub async fn append<T: ExecutionTimer>(
        &self,
        tx: &mut AuditTransaction<'_, '_, '_, T>,
        fact: &Fact,
        replayed: bool,
    ) -> Result<(), Error> {
        self.append_checked(tx, fact, Some(replayed)).await
    }
    // These two carrier adapters share restore/read_receipt/save_receipt and the component's
    // append implementation. Keep transaction ownership explicit rather than introducing an
    // erased writer/transaction trait that could expose a second settlement path.
    async fn append_checked<T: ExecutionTimer>(
        &self,
        tx: &mut AuditTransaction<'_, '_, '_, T>,
        fact: &Fact,
        existing: Option<bool>,
    ) -> Result<(), Error> {
        if fact.identity().tenant() != tx.tenant_id() {
            return Err(rss_audit_postgres::Error::ScopeMismatch.into());
        }
        let identity = fact.identity().clone();
        let receipt = measure(
            "receipt_read",
            tx.with_connection(move |c| Box::pin(async move { read_receipt(c, &identity).await })),
        )
        .await?;
        let record = measure("record_find", tx.find(fact.identity())).await?;
        if let Some(prepared) = restore(fact, receipt, record, self.ledger, existing)? {
            measure("append_replay", tx.append(&prepared)).await?;
            return Ok(());
        }
        let at = measure("timestamp", tx.with_connection(|c| Box::pin(now(c)))).await?;
        let prepared = measure("prepare", tx.prepare(fact.event(at)?)).await?;
        let save = prepared.clone();
        let fingerprint = *fact.fingerprint();
        measure(
            "receipt_write",
            tx.with_connection(move |c| {
                Box::pin(async move { save_receipt(c, &save, fingerprint).await })
            }),
        )
        .await?;
        measure("append", tx.append(&prepared)).await?;
        Ok(())
    }
    /// Stage a business fact in the existing RSS owner after `lock_in`.
    /// `replayed` is the producer's locked business-receipt result, not a guessed HTTP property.
    /// Pairing, fingerprint and canonical bytes must agree; success remains staged until owner commit.
    pub async fn append_in(
        &self,
        tx: &mut PgTransaction<'_>,
        fact: &Fact,
        replayed: bool,
    ) -> Result<(), Error> {
        self.append_checked_in(tx, fact, Some(replayed)).await
    }
    /// Stage an independent request identity in the RSS owner's transaction after `lock_in`.
    /// Only use after the final response facts are known; this does not settle or release a response.
    pub async fn append_request_in(
        &self,
        tx: &mut PgTransaction<'_>,
        request: &crate::RequestAudit,
        status: u16,
        result: &str,
    ) -> Result<(), Error> {
        let fact = Fact::request(request, status, result)?;
        self.append_checked_in(tx, &fact, None).await
    }
    async fn append_checked_in(
        &self,
        tx: &mut PgTransaction<'_>,
        fact: &Fact,
        existing: Option<bool>,
    ) -> Result<(), Error> {
        if fact.identity().tenant() != tx.tenant_id() {
            return Err(rss_audit_postgres::Error::ScopeMismatch.into());
        }
        let identity = fact.identity().clone();
        let receipt = tx
            .with_connection(move |c| Box::pin(async move { Ok(read_receipt(c, &identity).await) }))
            .await
            .map_err(rss_audit_postgres::Error::from)??;
        let record = self.adapter.find_in(tx, fact.identity()).await?;
        if let Some(prepared) = restore(fact, receipt, record, self.ledger, existing)? {
            self.adapter.append_in(tx, &prepared).await?;
            return Ok(());
        }
        let at = tx
            .with_connection(|c| Box::pin(async move { Ok(now(c).await) }))
            .await
            .map_err(rss_audit_postgres::Error::from)??;
        let prepared = self.adapter.prepare_in(tx, fact.event(at)?).await?;
        let save = prepared.clone();
        let fingerprint = *fact.fingerprint();
        tx.with_connection(move |c| {
            Box::pin(async move { Ok(save_receipt(c, &save, fingerprint).await) })
        })
        .await
        .map_err(rss_audit_postgres::Error::from)??;
        self.adapter.append_in(tx, &prepared).await?;
        Ok(())
    }
}
struct Receipt {
    fingerprint: Vec<u8>,
    canonical: Vec<u8>,
}
fn restore(
    fact: &Fact,
    receipt: Option<Receipt>,
    record: Option<Record>,
    ledger: bool,
    existing: Option<bool>,
) -> Result<Option<PreparedAuditV1>, Error> {
    match (receipt, record) {
        (None, None) if existing != Some(true) => Ok(None),
        (Some(receipt), Some(record))
            if existing != Some(false)
                && receipt.fingerprint == fact.fingerprint()
                && receipt.canonical == record.prepared().canonical_bytes()
                && record.ledger_sequence().is_some() == ledger =>
        {
            Ok(Some(record.prepared().clone()))
        }
        _ => Err(Error::Receipt),
    }
}
async fn now(c: &mut PgConnection) -> Result<Timepoint, Error> {
    let at: i64 = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(c)
        .await?;
    Timepoint::try_from(at).map_err(|_| rss_audit_postgres::Error::StorageContract.into())
}
async fn read_receipt(
    c: &mut PgConnection,
    id: &rss_audit_core::RecordIdentity,
) -> Result<Option<Receipt>, Error> {
    let row = sqlx::query("SELECT fingerprint,canonical FROM mdm_audit.receipts WHERE tenant_id=$1::uuid AND source_id=$2 AND event_id=$3")
        .bind(id.tenant().to_string()).bind(id.source().source_id().as_str()).bind(id.event_id().as_str()).fetch_optional(c).await?;
    row.map(|r| {
        Ok(Receipt {
            fingerprint: r.try_get("fingerprint")?,
            canonical: r.try_get("canonical")?,
        })
    })
    .transpose()
}
async fn save_receipt(
    c: &mut PgConnection,
    prepared: &PreparedAuditV1,
    fingerprint: [u8; 32],
) -> Result<(), Error> {
    let decoded = rss_audit_core::decode_untrusted(prepared.canonical_bytes())
        .map_err(rss_audit_postgres::Error::from)?;
    let id = decoded.event().identity();
    sqlx::query("INSERT INTO mdm_audit.receipts(tenant_id,source_id,event_id,fingerprint,canonical) VALUES($1::uuid,$2,$3,$4,$5)")
        .bind(id.tenant().to_string()).bind(id.source().source_id().as_str()).bind(id.event_id().as_str())
        .bind(fingerprint.as_slice()).bind(prepared.canonical_bytes()).execute(c).await?;
    Ok(())
}

async fn admit_receipts(c: &mut PgConnection) -> Result<(), Error> {
    let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
        .fetch_one(&mut *c)
        .await?;
    if isolation != "read committed" {
        return Err(Error::Isolation);
    }
    let valid: Option<bool> = sqlx::query_scalar(include_str!("admission.sql"))
        .fetch_one(c)
        .await?;
    if valid != Some(true) {
        return Err(Error::Admission);
    }
    Ok(())
}

fn transaction_error(error: rss_audit_postgres::TransactionError<Error>) -> Error {
    match error {
        rss_audit_postgres::TransactionError::Operation(error) => error,
        rss_audit_postgres::TransactionError::Audit(error) => Error::Audit(error),
        rss_audit_postgres::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}

// Fixture-only phase timing; production has no environment switch or diagnostic payload.
async fn measure<F: std::future::Future>(phase: &'static str, future: F) -> F::Output {
    #[cfg(feature = "integration")]
    let started =
        (std::env::var_os("MDM_AUDIT_DIAGNOSTIC").is_some()).then(tokio::time::Instant::now);
    #[cfg(not(feature = "integration"))]
    let _ = phase;
    let value = future.await;
    #[cfg(feature = "integration")]
    if let Some(started) = started {
        eprintln!(
            "{}",
            serde_json::json!({"audit_phase":phase,"elapsed_micros":started.elapsed().as_micros()})
        );
    }
    value
}
