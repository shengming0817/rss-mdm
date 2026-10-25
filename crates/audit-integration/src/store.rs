use crate::{
    AuditReadStore, BacklogLimits, Fact, InvalidFact, RequestAudit, SourceTransaction,
    TransactionError,
};
use crate::{budget::SourceControl, queue::StagedFact, source::FrozenFact};
use rss_audit_postgres::{Control, Integrity};
use rss_request_context::{ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    message::PartitionIdentity, policy::OperationDeadline, transaction::LocalTxAttempt,
};
use rss_transactional_messaging_postgres::{PgError, PgOutboxWriter, PgRuntime, PgTransaction};
use sqlx::{PgConnection, PgPool};
use std::sync::Arc;

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
    #[error("audit source backlog is full")]
    BacklogFull,
    #[error("audit failure-fact reserve is exhausted")]
    ReserveExhausted,
}
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        // A real SQL permission denial retains the permission diagnosis after startup probes
        // leave the hot path. Other storage failures (including closed pools) stay distinct.
        if e.as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("42501")
        {
            Self::Admission
        } else {
            Self::Audit(e.into())
        }
    }
}
impl From<Error> for PgError {
    fn from(e: Error) -> Self {
        match e {
            Error::Audit(e) => e.into(),
            Error::Fact(_) => rss_audit_postgres::Error::InvalidBound.into(),
            Error::BacklogFull | Error::ReserveExhausted => sqlx::Error::PoolTimedOut.into(),
            Error::Receipt
            | Error::Isolation
            | Error::Admission
            | Error::CommitUnknown
            | Error::RollbackFailed => rss_audit_postgres::Error::StorageContract.into(),
        }
    }
}

/// Source production and final-history reading use separate admitted capabilities.
#[derive(Clone)]
pub struct AuditStore {
    accepted_requests: Arc<crate::AcceptedRequests>,
    read: AuditReadStore,
    pub(crate) runtime: Arc<PgRuntime>,
    writer: Arc<PgOutboxWriter>,
    pub(crate) limits: BacklogLimits,
}
impl std::ops::Deref for AuditStore {
    type Target = AuditReadStore;
    fn deref(&self) -> &Self::Target {
        &self.read
    }
}
impl AuditStore {
    /// Host supplies the producer runtime and read pool for the same configured database.
    /// The host owns both resources and must rebuild them after controlled configuration changes.
    pub async fn new<T: ExecutionTimer>(
        pool: PgPool,
        integrity: Integrity,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        limits: BacklogLimits,
        control: &Control<'_, T>,
    ) -> Result<Self, Error> {
        let read = AuditReadStore::new(pool, integrity, control).await?;
        let store = Self {
            accepted_requests: Arc::default(),
            read,
            writer: Arc::new(PgOutboxWriter::new(runtime.clone(), FrozenFact::domain()?)),
            runtime,
            limits,
        };
        store.admit(tenant, control).await?;
        Ok(store)
    }
    /// Construct a separate immutable producer capability for another admitted same-database owner.
    pub async fn on_runtime<T: ExecutionTimer>(
        &self,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        control: &Control<'_, T>,
    ) -> Result<Self, Error> {
        let store = Self {
            accepted_requests: self.accepted_requests.clone(),
            read: self.read.clone(),
            writer: Arc::new(PgOutboxWriter::new(runtime.clone(), FrozenFact::domain()?)),
            runtime,
            limits: self.limits,
        };
        store.admit(tenant, control).await?;
        Ok(store)
    }
    /// Native ingresses borrowing this source share one host-managed handoff owner.
    pub fn accepted_requests(&self) -> Arc<crate::AcceptedRequests> {
        self.accepted_requests.clone()
    }
    async fn admit<T: ExecutionTimer>(
        &self,
        tenant: TenantId,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.runtime
            .local_tx_with_context(
                tenant,
                OperationDeadline::from_remaining(control.total_remaining()),
                self,
                |store, tx| {
                    Box::pin(async move { store.validate_in(tx).await.map_err(Into::into) })
                },
            )
            .await
            .fold(
                |_| Ok(()),
                |e| Err(Error::Audit(e.into())),
                |e| Err(Error::Audit(e.into())),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |e| Err(Error::Audit(e.into())),
            )
    }
    #[cfg(feature = "integration")]
    pub fn inject_next_fault(
        &self,
        fault: rss_transactional_messaging_postgres::PgTransactionFault,
    ) {
        self.runtime.inject_next_transaction_fault(fault);
    }
    /// Validate the actual runtime connection once at assembly; no full scan runs on requests.
    pub async fn validate_in(&self, tx: &mut PgTransaction<'_>) -> Result<(), Error> {
        self.writer
            .validate_transaction(tx)
            .map_err(rss_audit_postgres::Error::from)?;
        let budget = crate::budget::AuditBudget::new(tx.deadline().timeout());
        let control = budget.control();
        tx.with_connection_context(
            &mut (&self.read.adapter, &control),
            |(reader, control), connection| {
                Box::pin(async move {
                    let result = async {
                        admit_receipts(connection).await?;
                        reader.validate_connection(connection, control).await?;
                        Ok::<_, Error>(())
                    }
                    .await;
                    Ok(result)
                })
            },
        )
        .await
        .map_err(rss_audit_postgres::Error::from)??;
        Ok(())
    }
    /// Runtime provenance and isolation only; never obtains an Audit/Ledger head lock.
    pub async fn bind_in(&self, tx: &mut PgTransaction<'_>) -> Result<(), Error> {
        self.writer
            .validate_transaction(tx)
            .map_err(rss_audit_postgres::Error::from)?;
        tx.with_connection(|c| Box::pin(async move { Ok(check_isolation(c).await) }))
            .await
            .map_err(rss_audit_postgres::Error::from)??;
        Ok(())
    }
    /// Declare audit and business partitions together before ordered appends in an existing RSS owner.
    pub async fn prepare_in(
        &self,
        tx: &mut PgTransaction<'_>,
        request: &RequestAudit,
        business: &[PartitionIdentity],
    ) -> Result<(), Error> {
        self.bind_in(tx).await?;
        if request.tenant() != tx.tenant_id().to_string() {
            return Err(Error::Receipt);
        }
        let snapshot = request.snapshot();
        let mut partitions = business.to_vec();
        partitions.push(crate::source::partition(
            tx.tenant_id(),
            snapshot.target_type,
            snapshot.target.as_deref().unwrap_or("request"),
        )?);
        tx.prepare_outbox_partitions(&partitions)
            .await
            .map_err(rss_audit_postgres::Error::from)?;
        Ok(())
    }
    /// Business SQL, frozen facts and source receipts share the RSS owner's one commit.
    /// Audit-owned reads remain a separate read-only capability.
    pub async fn write<T: ExecutionTimer, C: Send, R: Send, E: Send + From<Error>, F>(
        &self,
        tenant: TenantId,
        control: &SourceControl<'_, T>,
        context: C,
        operation: F,
    ) -> LocalTxAttempt<R, TransactionError<E>>
    where
        F: for<'a> FnOnce(
                &'a mut C,
                &'a mut SourceTransaction<'_, '_>,
            ) -> futures::future::BoxFuture<'a, Result<R, E>>
            + Send,
    {
        crate::source_transaction::write(
            &self.runtime,
            tenant,
            control,
            (self, context, Some(operation)),
            |(store, context, operation), tx| {
                Box::pin(async move {
                    store.bind_in(tx.inner).await.map_err(E::from)?;
                    let operation = operation.take().expect("source operation is invoked once");
                    let value = operation(context, tx).await?;
                    store.flush(tx).await.map_err(E::from)?;
                    Ok(value)
                })
            },
        )
        .await
    }
    async fn flush(&self, tx: &mut SourceTransaction<'_, '_>) -> Result<(), Error> {
        let facts = std::mem::take(&mut tx.facts);
        let partitions = facts
            .iter()
            .map(|fact| fact.frozen.partition())
            .collect::<Result<Vec<_>, _>>()?;
        tx.inner
            .prepare_outbox_partitions(&partitions)
            .await
            .map_err(rss_audit_postgres::Error::from)?;
        for fact in facts {
            crate::queue::append(
                tx.inner,
                &self.writer,
                &fact.frozen,
                fact.existing,
                self.limits,
            )
            .await?;
        }
        Ok(())
    }
    pub async fn append(
        &self,
        tx: &mut SourceTransaction<'_, '_>,
        fact: &Fact,
        replayed: bool,
    ) -> Result<(), Error> {
        self.stage(tx, fact, Some(replayed)).await
    }
    async fn stage(
        &self,
        tx: &mut SourceTransaction<'_, '_>,
        fact: &Fact,
        existing: Option<bool>,
    ) -> Result<(), Error> {
        self.writer
            .validate_transaction(tx.inner)
            .map_err(rss_audit_postgres::Error::from)?;
        if tx.tenant_id() != fact.identity().tenant() {
            return Err(Error::Receipt);
        }
        let now = source_time(tx.inner).await?;
        tx.facts.push(StagedFact {
            frozen: FrozenFact::freeze(fact, now)?,
            existing,
        });
        Ok(())
    }
    /// Native RSS owners prepare the complete partition set before business appends.
    pub async fn append_in(
        &self,
        tx: &mut PgTransaction<'_>,
        fact: &Fact,
        replayed: bool,
    ) -> Result<(), Error> {
        self.enqueue_in(tx, fact, Some(replayed)).await
    }
    async fn enqueue_in(
        &self,
        tx: &mut PgTransaction<'_>,
        fact: &Fact,
        existing: Option<bool>,
    ) -> Result<(), Error> {
        self.writer
            .validate_transaction(tx)
            .map_err(rss_audit_postgres::Error::from)?;
        if tx.tenant_id() != fact.identity().tenant() {
            return Err(Error::Receipt);
        }
        let frozen = FrozenFact::freeze(fact, source_time(tx).await?)?;
        crate::queue::append(tx, &self.writer, &frozen, existing, self.limits).await
    }
    /// Queue a final request outcome before releasing its response; this does not wait for projection.
    pub async fn settle_request<T: ExecutionTimer>(
        &self,
        request: &RequestAudit,
        status: u16,
        result: &str,
        control: &SourceControl<'_, T>,
    ) -> Result<(), Error> {
        let fact = Fact::request(request, status, result)?;
        self.write(
            fact.identity().tenant(),
            control,
            (self, fact),
            |(store, fact), tx| Box::pin(async move { store.stage(tx, fact, None).await }),
        )
        .await
        .fold(
            |_| Ok(()),
            |e| Err(transaction_error(e)),
            |e| Err(transaction_error(e)),
            |_| Err(Error::RollbackFailed),
            |_| Err(Error::CommitUnknown),
            |e| Err(transaction_error(e)),
        )
    }
}
async fn source_time(tx: &mut PgTransaction<'_>) -> Result<rss_contract::Timepoint, Error> {
    let now: i64 = tx
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .map_err(rss_audit_postgres::Error::from)?;
    rss_contract::Timepoint::try_from(now).map_err(|_| Error::Receipt)
}
async fn check_isolation(c: &mut PgConnection) -> Result<(), Error> {
    let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
        .fetch_one(c)
        .await?;
    if isolation != "read committed" {
        return Err(Error::Isolation);
    }
    Ok(())
}
async fn admit_receipts(c: &mut PgConnection) -> Result<(), Error> {
    check_isolation(c).await?;
    let valid: Option<bool> = sqlx::query_scalar(include_str!("admission.sql"))
        .fetch_one(c)
        .await?;
    if valid != Some(true) {
        return Err(Error::Admission);
    }
    Ok(())
}
fn transaction_error(error: TransactionError<Error>) -> Error {
    match error {
        TransactionError::Operation(error) | TransactionError::Storage(error) => error,
        TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}

/// Sanitized closed audit diagnosis; carries no provider messages or request input.
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    CommitUnknown,
    RollbackFailed,
    RequestDeadline,
    AuditIntegrity,
    AuditAdmission,
    AuditIsolation,
    AuditContract,
    AuditBackpressure,
    AuditReserveExhausted,
    Audit,
}
impl Error {
    pub fn class(&self) -> ErrorClass {
        let error = self;
        match error {
            Error::CommitUnknown => ErrorClass::CommitUnknown,
            Error::RollbackFailed => ErrorClass::RollbackFailed,
            Error::Audit(error) if error.is_interrupted() => ErrorClass::RequestDeadline,
            Error::Receipt => ErrorClass::AuditIntegrity,
            Error::Admission => ErrorClass::AuditAdmission,
            Error::Isolation => ErrorClass::AuditIsolation,
            Error::Fact(_) => ErrorClass::AuditContract,
            Error::BacklogFull => ErrorClass::AuditBackpressure,
            Error::ReserveExhausted => ErrorClass::AuditReserveExhausted,
            Error::Audit(error) => {
                use rss_audit_postgres::Error as Audit;
                match error {
                    Audit::Admission(_) => ErrorClass::AuditAdmission,
                    Audit::Conflict | Audit::StorageContract | Audit::IntegrityRequired => {
                        ErrorClass::AuditIntegrity
                    }
                    Audit::Ledger(error) => match error {
                        rss_ledger_postgres::Error::Storage(_)
                        | rss_ledger_postgres::Error::Messaging(_) => ErrorClass::Audit,
                        rss_ledger_postgres::Error::Admission(_) => ErrorClass::AuditAdmission,
                        _ => ErrorClass::AuditIntegrity,
                    },
                    Audit::InvalidBound
                    | Audit::ScopeMismatch
                    | Audit::Protocol(_)
                    | Audit::ReadBudgetExceeded => ErrorClass::AuditContract,
                    _ => ErrorClass::Audit,
                }
            }
        }
    }
}
