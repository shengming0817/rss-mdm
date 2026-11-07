//! DA transactions borrow the original Audit/Identity PostgreSQL transaction.
use crate::{Error, Pending};
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_install_support::StorageProfile;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
pub struct Assembly {
    pub report_limits: crate::reports::Limits,
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub tenant: TenantId,
    pub instance: Uuid,
    pub store: Arc<rss_mdm_registration_service::Store>,
    pub audit: Arc<AuditStore>,
    pub access_audit: Arc<AuditStore>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
}
pub struct Service {
    pub(crate) report_limits: crate::reports::Limits,
    pub(crate) cursor: rss_mdm_query::cursor::CursorCodec,
    pub(crate) tenant: TenantId,
    instance: Uuid,
    pub(crate) store: Arc<rss_mdm_registration_service::Store>,
    pub(crate) audit: Arc<AuditStore>,
    pub(crate) access_audit: Arc<AuditStore>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
}
pub(crate) struct Change<R> {
    pub(crate) value: R,
    pub(crate) replay: bool,
}
impl Service {
    pub fn new(a: Assembly) -> Result<Self, Error> {
        if a.store.profile() != StorageProfile::Da || a.instance.is_nil() {
            return Err(Error::Configuration);
        }
        a.report_limits.validate()?;
        Ok(Self {
            report_limits: a.report_limits,
            cursor: a.cursor,
            tenant: a.tenant,
            instance: a.instance,
            store: a.store,
            access_audit: a.access_audit,
            audit: a.audit,
            protection: a.protection,
        })
    }
    pub const fn profile(&self) -> StorageProfile {
        StorageProfile::Da
    }
    pub fn service_id(&self) -> Result<Uuid, Error> {
        Ok(self.instance)
    }
    pub(crate) fn proof(&self, p: &AuthorizedPrincipal, a: &RequestAudit) -> Result<(), Error> {
        if p.profile() != StorageProfile::Da
            || p.tenant_id() != self.tenant.to_string()
            || a.tenant() != p.tenant_id()
        {
            return Err(Error::Forbidden);
        }
        p.check_live()?;
        p.bind_audit(a).map_err(Into::into)
    }
    pub(crate) async fn write<C: Send, R: Send>(
        &self,
        a: &RequestAudit,
        context: C,
        f: impl for<'a> FnOnce(&'a mut C, &'a mut PgConnection) -> Pending<'a, Change<R>> + Send,
    ) -> Result<R, Error> {
        self.write_admitted(
            &self.audit,
            a,
            context,
            |_, _| Box::pin(async { Ok(()) }),
            f,
        )
        .await
    }
    /// Session revocation and the receipt/permission snapshot use the Identity runtime's
    /// original transaction. A replay lookup never consumes the one-use step-up proof.
    pub(crate) async fn read_with_session<C: Send, R: Send>(
        &self,
        actor: &AuthorizedPrincipal,
        context: C,
        f: impl for<'a> FnOnce(&'a mut C, &'a mut PgConnection) -> Pending<'a, R> + Send,
    ) -> Result<R, Error> {
        if actor.profile() != StorageProfile::Da || actor.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(6));
        let attempt = self
            .access_audit
            .write(
                self.tenant,
                &budget.source_control(),
                (actor, context, Some(f)),
                |ctx, tx| {
                    Box::pin(async move {
                        tx.with_connection_context(ctx, |ctx, c| {
                            Box::pin(async move {
                                crate::device_access::service::admit_session(c, ctx.0).await?;
                                let f = ctx.2.take().ok_or(Error::Corrupt)?;
                                f(&mut ctx.1, c).await
                            })
                        })
                        .await
                    })
                },
            )
            .await;
        attempt.fold(
            Ok,
            |e| Err(transaction_error(e)),
            |e| Err(transaction_error(e)),
            |_| Err(Error::Storage),
            |_| Err(Error::Storage),
            |e| Err(transaction_error(e)),
        )
    }
    /// One settlement implementation. Identity admission precedes every product lock.
    pub(crate) async fn write_admitted<C: Send, R: Send>(
        &self,
        source: &AuditStore,
        a: &RequestAudit,
        context: C,
        before: impl for<'a> FnOnce(&'a mut C, &'a mut PgConnection) -> Pending<'a, ()> + Send,
        f: impl for<'a> FnOnce(&'a mut C, &'a mut PgConnection) -> Pending<'a, Change<R>> + Send,
    ) -> Result<R, Error> {
        let profile = self.profile();
        let installation = self.service_id()?;

        if a.tenant() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(6));
        let out = source
            .write(
                self.tenant,
                &budget.source_control(),
                (
                    source,
                    a,
                    (self.tenant.to_string(), context, Some(f), Some(before)),
                ),
                |ctx, tx| {
                    Box::pin(async move {
                        let (store, a, context) = ctx;
                        let change = tx
                            .with_connection_context(context, |ctx, c| {
                                Box::pin(async move {
                                    let before = ctx.3.take().ok_or(Error::Corrupt)?;
                                    before(&mut ctx.1, c).await?;
                                    if rss_mdm_registration_service::device::installation_in(
                                        profile, c,
                                    )
                                    .await?
                                        != installation
                                    {
                                        return Err(Error::Forbidden);
                                    }
                                    rss_mdm_registration_service::admission::lock_in(
                                        profile, c, &ctx.0,
                                    )
                                    .await?;
                                    let f = ctx.2.take().ok_or(Error::Corrupt)?;
                                    f(&mut ctx.1, c).await
                                })
                            })
                            .await?;
                        let snapshot = a.snapshot();
                        if snapshot.intent != rss_mdm_audit_integration::AuditIntent::Routine {
                            let op = snapshot.operation_id.ok_or(Error::Malformed)?;
                            let key = format!("device-access:{}:{op}", snapshot.action);
                            let fact = match snapshot.operation_owner {
                                Some(owner) => Fact::business(a, owner, &key, 200, "success", None),
                                None => Fact::observation(a, &key, 200, "success", None),
                            }?;
                            (if change.replay {
                                Ok(())
                            } else {
                                store.append(tx, &fact).await
                            })
                            .map_err(Error::from)?;
                        }
                        if change.replay {
                            a.management_result(
                                rss_mdm_audit_integration::ManagementResult::Replayed,
                            )
                        }
                        a.mark_commit_started();
                        Ok(change.value)
                    })
                },
            )
            .await;
        settle(out, a)
    }
}
pub(crate) fn settle<R>(
    attempt: rss_transactional_messaging::transaction::LocalTxAttempt<
        R,
        rss_mdm_audit_integration::TransactionError<Error>,
    >,
    audit: &RequestAudit,
) -> Result<R, Error> {
    attempt.fold(
        |value| {
            // Optional protocol branches can commit only admission reads and return
            // control to another producer. Only that producer's marked write phase
            // changes the request's business outcome.
            if audit.snapshot().write_outcome == rss_mdm_audit_integration::WriteOutcome::Unknown {
                audit.mark_committed();
            }
            Ok(value)
        },
        |error| Err(transaction_error(error)),
        |error| {
            audit.mark_rolled_back();
            Err(transaction_error(error))
        },
        |_| {
            audit.mark_rollback_failed();
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |error| Err(transaction_error(error)),
    )
}

fn transaction_error(error: rss_mdm_audit_integration::TransactionError<Error>) -> Error {
    match error {
        rss_mdm_audit_integration::TransactionError::Operation(error) => error,
        rss_mdm_audit_integration::TransactionError::Storage(error) => error.into(),
        rss_mdm_audit_integration::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
