//! One read transaction per page; release it before checking authority again.
//! ref: sqlx v0.8.6 sqlx-core/src/transaction.rs
use super::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
impl Scopes {
    #[cfg(feature = "integration")]
    pub fn pause_page(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (reached, wait) = tokio::sync::oneshot::channel();
        let (resume, release) = tokio::sync::oneshot::channel();
        assert!(
            self.page_gate
                .lock()
                .expect("page gate")
                .replace((reached, release))
                .is_none()
        );
        (wait, resume)
    }
    #[cfg(feature = "integration")]
    pub(super) async fn page_boundary(&self) {
        let gate = self.page_gate.lock().expect("page gate").take();
        if let Some((reached, release)) = gate {
            let _ = reached.send(());
            let _ = release.await;
        }
    }
    pub async fn page(
        &self,
        proof: &AuthorizedPrincipal,
        request: &PageRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        request
            .query
            .page
            .require_schema(&SCHEMA)
            .map_err(|_| Error::Malformed)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        proof.manage(Permission::ScopeRead)?;
        proof.require_all_devices(Permission::InventoryRead)?;
        let authority = proof.authorization()?.query_binding(proof)?;
        audit.resource_target(
            rss_mdm_audit_integration::TargetKind::Scope,
            &request.scope.to_string(),
        );
        audit.set_action(
            "management_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let budget =
            rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(6));
        let mut connection =
            tokio::time::timeout(budget.control().total_remaining(), self.read_pool.acquire())
                .await
                .map_err(|_| Error::Unavailable(Failure::Storage))?
                .map_err(|_| Error::Unavailable(Failure::Storage))?;
        let read=tokio::time::timeout(budget.control().total_remaining(),async {
            use sqlx::Acquire;
            let mut tx=connection.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(&mut *tx).await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true)")
                .bind(self.tenant.to_string()).bind(budget.control().total_remaining().as_millis().max(1).to_string()).execute(&mut *tx).await?;
            let current=rss_mdm_authorization_service::snapshot_on(&mut tx,proof.tenant_id(),proof.instance_id()).await?;
            current.require(proof,Permission::ScopeRead,None)?;
            current.require_all_devices(proof,Permission::InventoryRead)?;
            if current.query_binding(proof)?!=authority {return Err(Error::Conflict.into());}
            let result=self.page_on(&mut tx,request,&authority).await?;
            tx.rollback().await?;
            Ok::<_,crate::transaction::Fault>(result)
        }).await;
        let result = match read {
            Ok(Ok(result)) => result,
            other => {
                connection.close_on_drop();
                return Err(match other {
                    Ok(Err(crate::transaction::Fault::Request(e))) => e,
                    _ => Error::Unavailable(Failure::Storage),
                });
            }
        };
        drop(connection);
        // Release the page connection before revalidating current authority.
        self.audit_store
            .read(
                self.tenant,
                &budget.control(),
                (proof, &authority),
                |ctx, tx| {
                    Box::pin(async move {
                        let (proof, expected) = *ctx;
                        tx.with_connection_context(
                            &mut (proof, expected),
                            |(proof, expected), c| {
                                Box::pin(async move {
                                    let current = rss_mdm_authorization_service::snapshot_on(
                                        c,
                                        proof.tenant_id(),
                                        proof.instance_id(),
                                    )
                                    .await
                                    .map_err(|_| {
                                        sqlx::Error::Protocol("authorization read".into())
                                    })?;
                                    Ok::<_, sqlx::Error>(
                                        current
                                            .query_binding(proof)
                                            .is_ok_and(|binding| binding == **expected),
                                    )
                                })
                            },
                        )
                        .await
                        .map_err(rss_mdm_audit_integration::Error::from)
                    })
                },
            )
            .await
            .fold(
                |same| if same { Ok(()) } else { Err(Error::Conflict) },
                |_| Err(Error::Unavailable(Failure::Storage)),
                |_| Err(Error::Unavailable(Failure::Storage)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::Unavailable(Failure::Storage)),
                |_| Err(Error::Unavailable(Failure::Storage)),
            )?;
        proof.check_live()?;
        Ok(result)
    }
}
