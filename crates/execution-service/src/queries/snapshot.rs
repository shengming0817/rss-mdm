//! One bounded fact snapshot followed by current authority validation.
//! ref: sqlx sqlx-postgres/src/transaction.rs (BEGIN before the first SELECT).
use super::*;
use rss_mdm_registration_service::device::endpoints::PrimaryRegistration;
use sqlx::{Acquire, PgConnection};

/// Page-local authority and time from a single read-only snapshot.
pub struct Basis {
    pub grant: authorization::Snapshot,
    pub now: i64,
    pub registration: Option<(String, Option<PrimaryRegistration>)>,
}
fn failure(e: crate::transaction::Fault) -> Error {
    match e {
        crate::transaction::Fault::Request(e) => e,
        crate::transaction::Fault::Sql(e)
            if e.as_database_error()
                .and_then(|e| e.code())
                .is_some_and(|c| c == "40001" || c == "40P01") =>
        {
            Error::ReadConflict
        }
        crate::transaction::Fault::Sql(_) | crate::transaction::Fault::Storage(_) => {
            Error::Unavailable(Failure::CommandStorage)
        }
    }
}
impl Queries {
    /// Run a bounded product page in one snapshot, then revalidate current authority.
    pub async fn snapshot<C: Send, R: Send, F>(
        &self,
        proof: &AuthorizedPrincipal,
        mut context: C,
        operation: F,
    ) -> std::result::Result<R, Error>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut PgConnection,
                &'c mut Basis,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = crate::Result<R>> + Send + 'c>,
            > + Send,
    {
        proof.check_live()?;
        let started = self.clock.now();
        let remaining = || {
            crate::transaction::TRANSACTION_BUDGET
                .saturating_sub(self.clock.now().saturating_duration_since(started))
        };
        let deadline = || Error::Unavailable(Failure::RequestDeadline);
        let mut connection = tokio::time::timeout(remaining(), self.read_pool.acquire())
            .await
            .map_err(|_| deadline())?
            .map_err(|_| Error::Unavailable(Failure::CommandStorage))?;
        let read = tokio::time::timeout(remaining(), async {
            let mut tx = connection.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(&mut *tx).await?;
            let timeout = remaining().as_millis().max(1).to_string();
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)").bind(self.tenant.to_string()).bind(timeout).execute(&mut *tx).await?;
            let grant = authorization::snapshot_on(&mut tx, proof.tenant_id(), proof.instance_id()).await?;
            let binding = grant.query_binding(proof)?;
            let now = sqlx::query_scalar("SELECT floor(extract(epoch FROM transaction_timestamp()))::bigint").fetch_one(&mut *tx).await?;
            let mut basis = Basis { grant, now, registration: None };
            #[cfg(feature = "integration")]
            self.read_checkpoint(super::ReadPhase::Facts).await?;
            let value = operation(&mut context, &mut tx, &mut basis).await?;
            tx.rollback().await?;
            Ok::<_, crate::transaction::Fault>((value, binding, basis.registration))
        }).await;
        let (value, binding, registration) = match read {
            Ok(Ok(value)) => value,
            other => {
                connection.close_on_drop();
                return Err(match other {
                    Ok(Err(e)) => failure(e),
                    Err(_) => deadline(),
                    Ok(Ok(_)) => unreachable!(),
                });
            }
        };
        // Never wait for the runtime pool while retaining a snapshot connection.
        drop(connection);
        #[cfg(feature = "integration")]
        self.read_checkpoint(super::ReadPhase::Authority).await?;
        if remaining().is_zero() {
            return Err(deadline());
        }
        crate::transaction::inspect_budget(
            &self.runtime,
            self.tenant,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(remaining()),
            (proof, binding, registration),
            |state, tx| {
                Box::pin(async move {
                    let (proof, binding, registration) = state;
                    let current = crate::action_admission::current(tx, proof).await?;
                    if current.query_binding(proof)? != *binding {
                        return Err(Error::ReadConflict.into());
                    }
                    if let Some((device, expected)) = registration {
                        let tenant = proof.tenant_id().to_owned();
                        tx.with_connection_context(
                            &mut (device, expected),
                            |(device, expected), c| {
                                Box::pin(async move {
                                    use rss_mdm_registration_service::device::endpoints;
                                    Ok::<_, sqlx::Error>(
                                        async {
                                            endpoints::lock_in(
                                                c,
                                                &tenant,
                                                device,
                                                rss_mdm_inventory::Channel::Mdm,
                                            )
                                            .await?;
                                            let actual = endpoints::current_in(
                                                c,
                                                &tenant,
                                                device,
                                                rss_mdm_inventory::Channel::Mdm,
                                            )
                                            .await?;
                                            Ok::<_, rss_mdm_registration_service::Error>(
                                                actual == **expected,
                                            )
                                        }
                                        .await,
                                    )
                                })
                            },
                        )
                        .await??
                        .then_some(())
                        .ok_or(Error::ReadConflict)?;
                    }
                    proof.check_live()?;
                    Ok(())
                })
            },
        )
        .await?;
        Ok(value)
    }
}
