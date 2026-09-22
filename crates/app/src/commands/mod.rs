//! Product operation composition; RSS remains the command, messaging and recovery owner.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
mod config;
mod http;
mod model;
pub(crate) mod native;
mod plans;
mod protocol;
mod recovery;
mod service;
mod storage;
use crate::{Error, Failure, audit::Audit};
pub(crate) use config::Resource;
pub(crate) use http::routes;
use model::*;
use rss_device_command as dc;
use rss_device_command::Store;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgOutboxStore, PgRuntime, PgTransaction};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

const DOMAIN: &str = "mdm.commands.v1";
fn messaging_domain() -> rss_transactional_messaging::message::MessagingDomain {
    rss_transactional_messaging::message::MessagingDomain::parse(DOMAIN).expect("fixed domain")
}
fn recovery_scope(tenant: TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, DOMAIN).expect("fixed scope")
}

pub(crate) struct Commands {
    runtime: Arc<PgRuntime>,
    outbox: Arc<PgOutboxStore<()>>,
    store: rss_device_command_postgres::PgStore<()>,
    reconcile: rss_reconcile_postgres::PgStore,
    tenant: TenantId,
    instance: String,
}
#[derive(Debug, thiserror::Error)]
pub(crate) enum Fault {
    #[error(transparent)]
    Request(#[from] Error),
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}
type Result<T> = std::result::Result<T, Fault>;
fn invalid<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|_| Error::Malformed.into())
}
fn corrupt<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|_| Error::Unavailable(Failure::CommandInvariant).into())
}
pub(crate) fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(6))
}
fn rejection(error: Fault, failure: &Mutex<Option<Error>>) -> PgError {
    let (reason, db) = match error {
        Fault::Request(e) => (e, sqlx::Error::Protocol("command rejected".into()).into()),
        Fault::Storage(e) => {
            use rss_transactional_messaging::error::MessagingErrorKind;
            let reason = match e.kind() {
                MessagingErrorKind::OwnershipLost | MessagingErrorKind::Conflict => Error::Conflict,
                MessagingErrorKind::Permanent | MessagingErrorKind::Invariant => {
                    Error::Unavailable(Failure::CommandInvariant)
                }
                _ => Error::Unavailable(Failure::CommandStorage),
            };
            (reason, e)
        }
        Fault::Sql(e) => (Error::Unavailable(Failure::CommandStorage), e.into()),
    };
    *failure.lock().expect("request result") = Some(reason);
    db
}
fn settle<T>(
    attempt: rss_transactional_messaging::transaction::LocalTxAttempt<T, PgError>,
    audit: &Audit,
    failure: Mutex<Option<Error>>,
) -> std::result::Result<T, Error> {
    attempt.fold(
        |v| {
            audit.mark_committed();
            Ok(v)
        },
        |_| Err(Error::Unavailable(Failure::CommandStorage)),
        |_| {
            Err(failure
                .into_inner()
                .expect("request result")
                .unwrap_or(Error::Unavailable(Failure::CommandStorage)))
        },
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(Failure::CommandStorage)),
    )
}
impl Commands {
    async fn required_command(
        &self,
        tx: &mut PgTransaction<'_>,
        op: &storage::Operation,
    ) -> Result<dc::Command> {
        self.store
            .load(tx, op.scope, &op.command_id()?)
            .await?
            .ok_or_else(|| Error::Unavailable(Failure::CommandInvariant).into())
    }

    pub(crate) async fn transact<C: Send, R: Send, F>(
        &self,
        context: C,
        audit: &Audit,
        operation: F,
    ) -> std::result::Result<R, Error>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgTransaction<'_>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<R>> + Send + 'c>,
            > + Send,
    {
        let failure = Mutex::new(None);
        let attempt = self
            .runtime
            .local_tx_with_context(
                self.tenant,
                deadline(),
                (context, Some(operation), audit, &failure),
                |state, tx| {
                    Box::pin(async move {
                        let (context, operation, audit, failure) = state;
                        if let Err(e) = storage::admit(tx).await {
                            return Err(rejection(e, failure));
                        }
                        let f = operation.take().expect("one callback");
                        match f(context, tx).await {
                            Ok(v) => {
                                audit.mark_commit_started();
                                Ok(v)
                            }
                            Err(e) => Err(rejection(e, failure)),
                        }
                    })
                },
            )
            .await;
        settle(attempt, audit, failure)
    }
}

#[cfg(all(test, feature = "integration"))]
impl Commands {
    pub(crate) fn inject_fault(
        &self,
        fault: rss_transactional_messaging_postgres::PgTransactionFault,
    ) {
        self.runtime.inject_next_transaction_fault(fault);
    }
}

#[cfg(test)]
pub(crate) mod tests;
