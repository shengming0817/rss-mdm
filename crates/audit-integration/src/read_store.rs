//! Read-only transactions over the host-owned Audit writer pool; this facade exposes no writes.
use crate::Error;
use rss_audit_postgres::{Control, Integrity, PgAudit, ReadAuditTransaction};
use rss_request_context::ExecutionTimer;
use sqlx::{PgConnection, PgPool};

#[derive(Clone)]
pub struct AuditReadStore {
    pub(crate) adapter: PgAudit,
    ledger: bool,
}
impl AuditReadStore {
    /// Public installation mode; never exposes the integrity key.
    pub fn uses_ledger(&self) -> bool {
        self.ledger
    }

    /// 停写转交/恢复时逐页验证至已捕获的链头；同库链头本身不是外部防截断证明。
    pub async fn verify_history_to(
        &self,
        tenant: rss_request_context::TenantId,
        last: Option<u64>,
        tag: &[u8; 32],
    ) -> Result<u64, Error> {
        if !self.ledger {
            return Err(Error::Admission);
        }
        let mut start = 0u64;
        loop {
            let budget = crate::budget::AuditBudget::new(std::time::Duration::from_secs(10));
            let window = self
                .adapter
                .read_verified(
                    tenant,
                    rss_ledger::Sequence::new(start),
                    rss_ledger_postgres::ReadLimit::new(64, 4 * 1024 * 1024)
                        .map_err(rss_audit_postgres::Error::from)?,
                    &budget.control(),
                )
                .await
                .fold(
                    |v| Ok(v.into_value()),
                    |e| Err(Error::Audit(e)),
                    |e| Err(Error::Audit(e)),
                    |_| Err(Error::RollbackFailed),
                    |_| Err(Error::CommitUnknown),
                    |e| Err(Error::Audit(e)),
                )?;
            let verified = window.ledger_verification();
            let Some(expected) = last else {
                return if verified.count() == 0 && tag == &[0u8; 32] {
                    Ok(0)
                } else {
                    Err(Error::Receipt)
                };
            };
            let end = verified.last().ok_or(Error::Receipt)?.get();
            if verified.first().map(|v| v.get()) != Some(start) || end > expected {
                return Err(Error::Receipt);
            }
            if end == expected {
                if verified.tail_tag().as_ref().map(|v| v.as_bytes()) != Some(tag) {
                    return Err(Error::Receipt);
                }
                return expected.checked_add(1).ok_or(Error::Receipt);
            }
            start = end.checked_add(1).ok_or(Error::Receipt)?;
        }
    }
    /// Admit the host-owned pool and explicit integrity mode. Does not close the pool.
    /// Source production and its receipt admission belong to AuditStore.
    pub async fn new<T: ExecutionTimer>(
        pool: PgPool,
        integrity: Integrity,
        control: &Control<'_, T>,
    ) -> Result<Self, Error> {
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
        self.read(tenant, control, (), move |_, tx| {
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
    /// Read under the Audit owner without creating or locking Audit/Ledger heads.
    pub async fn read<T: ExecutionTimer, C: Send, R: Send, E: Send + From<Error>, F>(
        &self,
        tenant: rss_request_context::TenantId,
        control: &Control<'_, T>,
        context: C,
        operation: F,
    ) -> rss_transactional_messaging::transaction::LocalTxAttempt<R, crate::TransactionError<E>>
    where
        F: for<'a> FnOnce(
                &'a mut C,
                &'a mut ReadAuditTransaction<'_, '_, '_, T>,
            ) -> futures::future::BoxFuture<'a, Result<R, E>>
            + Send,
    {
        self.adapter
            .read_tx_with_context(
                tenant,
                control,
                (context, Some(operation)),
                |(context, operation), tx| {
                    Box::pin(async move {
                        tx.with_connection(|c| Box::pin(check_isolation(c)))
                            .await
                            .map_err(E::from)?;
                        let operation = operation
                            .take()
                            .expect("component invokes its transaction callback once");
                        operation(context, tx).await
                    })
                },
            )
            .await
            .fold(
                |value| {
                    rss_transactional_messaging::transaction::LocalTxAttempt::committed(
                        value.into_value(),
                    )
                },
                |error| {
                    rss_transactional_messaging::transaction::LocalTxAttempt::not_started(
                        map_error(error),
                    )
                },
                |error| {
                    rss_transactional_messaging::transaction::LocalTxAttempt::rolled_back(
                        map_error(error),
                    )
                },
                |error| {
                    rss_transactional_messaging::transaction::LocalTxAttempt::rollback_failed(
                        map_error(error),
                    )
                },
                |error| {
                    rss_transactional_messaging::transaction::LocalTxAttempt::commit_unknown(
                        map_error(error),
                    )
                },
                |error| {
                    rss_transactional_messaging::transaction::LocalTxAttempt::fenced(map_error(
                        error,
                    ))
                },
            )
    }
}

async fn check_isolation(connection: &mut PgConnection) -> Result<(), Error> {
    let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
        .fetch_one(connection)
        .await?;
    if isolation != "read committed" {
        return Err(Error::Isolation);
    }
    Ok(())
}
fn map_error<E>(error: rss_audit_postgres::TransactionError<E>) -> crate::TransactionError<E> {
    match error {
        rss_audit_postgres::TransactionError::Operation(error) => {
            crate::TransactionError::Operation(error)
        }
        rss_audit_postgres::TransactionError::Audit(error) => {
            crate::TransactionError::Storage(Error::Audit(error))
        }
        rss_audit_postgres::TransactionError::Rollback {
            operation,
            settlement,
        } => crate::TransactionError::Rollback {
            operation: Box::new(map_error(*operation)),
            settlement: Error::Audit(settlement),
        },
    }
}
fn transaction_error(error: crate::TransactionError<Error>) -> Error {
    match error {
        crate::TransactionError::Operation(error) | crate::TransactionError::Storage(error) => {
            error
        }
        crate::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
