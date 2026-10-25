use crate::budget::SourceControl;
use crate::{AuditReadStore, Fact, InvalidFact, RequestAudit, SourceTransaction, TransactionError};
use rss_audit_postgres::{Control, Integrity};
use rss_request_context::{ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    message::PartitionIdentity, policy::OperationDeadline, transaction::LocalTxAttempt,
};
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use sqlx::PgPool;
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
    read: AuditReadStore,
    pub(crate) runtime: Arc<PgRuntime>,
    integrity: Integrity,
}
impl std::ops::Deref for AuditStore {
    type Target = AuditReadStore;
    fn deref(&self) -> &Self::Target {
        &self.read
    }
}
impl AuditStore {
    pub fn integrity(&self) -> &Integrity {
        &self.integrity
    }
    /// Host supplies the producer runtime and read pool for the same configured database.
    /// The host owns both resources and must rebuild them after controlled configuration changes.
    pub async fn new<T: ExecutionTimer>(
        pool: PgPool,
        integrity: Integrity,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        control: &Control<'_, T>,
    ) -> Result<Self, Error> {
        let read = AuditReadStore::new(pool, integrity.clone(), control).await?;
        let store = Self {
            read,
            integrity,
            runtime,
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
            read: self.read.clone(),
            integrity: self.integrity.clone(),
            runtime,
        };
        store.admit(tenant, control).await?;
        Ok(store)
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
    /// Admit the actual writer connection once at startup.
    pub async fn validate_in(&self, tx: &mut PgTransaction<'_>) -> Result<(), Error> {
        self.runtime
            .validate_transaction(tx)
            .map_err(rss_audit_postgres::Error::from)?;
        let isolation: String = tx
            .with_connection(|c| {
                Box::pin(async move {
                    sqlx::query_scalar("SHOW transaction_isolation")
                        .fetch_one(c)
                        .await
                })
            })
            .await
            .map_err(rss_audit_postgres::Error::from)?;
        if isolation != "read committed" {
            return Err(Error::Isolation);
        }
        rss_audit_postgres::validate_in(tx, &self.integrity).await?;
        Ok(())
    }
    /// Borrow the original owner; acquire an optional Ledger chain before business locks.
    pub async fn bind_in(&self, tx: &mut PgTransaction<'_>) -> Result<(), Error> {
        self.runtime
            .validate_transaction(tx)
            .map_err(rss_audit_postgres::Error::from)?;
        if matches!(self.integrity, Integrity::Ledger(_)) {
            rss_audit_postgres::lock_head_in(tx, &self.integrity).await?;
        }
        Ok(())
    }
    /// Prepare only the caller's real business partitions after optional Ledger locking.
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
        if !business.is_empty() {
            tx.prepare_outbox_partitions(business)
                .await
                .map_err(rss_audit_postgres::Error::from)?;
        }
        Ok(())
    }
    /// Business SQL and final Audit records share the RSS owner's one commit.
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
        for appended in
            rss_audit_postgres::append_batch_in(tx.inner, &self.integrity, &tx.facts).await?
        {
            require_new_business_fact(&appended)?;
        }
        Ok(())
    }
    pub async fn append(
        &self,
        tx: &mut SourceTransaction<'_, '_>,
        fact: &Fact,
    ) -> Result<(), Error> {
        self.runtime
            .validate_transaction(tx.inner)
            .map_err(rss_audit_postgres::Error::from)?;
        if tx.tenant_id() != fact.identity().tenant() {
            return Err(Error::Receipt);
        }
        let now = source_time(tx.inner).await?;
        tx.facts.push(
            rss_audit_core::prepare(fact.event(now)?, now)
                .map_err(rss_audit_postgres::Error::from)?,
        );
        Ok(())
    }
    /// Stage on the caller's already-bound business transaction; the caller alone settles.
    pub async fn append_in(&self, tx: &mut PgTransaction<'_>, fact: &Fact) -> Result<(), Error> {
        self.append_batch_in(tx, std::slice::from_ref(fact)).await
    }
    /// Append a prepared group of business facts on the original owner’s connection.
    pub async fn append_batch_in(
        &self,
        tx: &mut PgTransaction<'_>,
        facts: &[Fact],
    ) -> Result<(), Error> {
        self.runtime
            .validate_transaction(tx)
            .map_err(rss_audit_postgres::Error::from)?;
        if facts.is_empty() {
            return Ok(());
        }
        let now = source_time(tx).await?;
        let prepared = facts
            .iter()
            .map(|fact| {
                if tx.tenant_id() != fact.identity().tenant() {
                    return Err(Error::Receipt);
                }
                Ok(rss_audit_core::prepare(fact.event(now)?, now)
                    .map_err(rss_audit_postgres::Error::from)?)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        for appended in rss_audit_postgres::append_batch_in(tx, &self.integrity, &prepared).await? {
            require_new_business_fact(&appended)?;
        }
        Ok(())
    }
    /// Commit a necessary final request outcome before releasing its response.
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
            |(store, fact), tx| Box::pin(async move { store.append(tx, fact).await }),
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
// Business replay belongs to the operation owner and never reaches append. Accepting an
// existing business fact here would let a new mutation commit without its own audit fact.
fn require_new_business_fact(appended: &rss_audit_postgres::StagedAppend) -> Result<(), Error> {
    if !appended.inserted()
        && appended
            .record()
            .prepared()
            .identity()
            .source()
            .source_id()
            .as_str()
            == "mdm.business"
    {
        return Err(Error::Receipt);
    }
    Ok(())
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
