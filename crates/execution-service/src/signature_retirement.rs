//! Execution-owned pending signature references; the trust owner controls retirement.
pub struct PendingSignatures;
impl rss_mdm_task_trust::RetirementGuard for PendingSignatures {
    fn pending<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        key_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<bool, rss_mdm_task_trust::Error>> + Send + 'a>,
    > {
        Box::pin(async move {
            let pending: bool =
                sqlx::query_scalar("SELECT mdm_commands.pending_task_signatures($1::uuid,$2)")
                    .bind(tenant.to_string())
                    .bind(key_id)
                    .fetch_one(&mut *c)
                    .await
                    .map_err(|_| {
                        rss_mdm_task_trust::Error::Unavailable(
                            rss_mdm_task_trust::Failure::Database,
                        )
                    })?;
            Ok(pending)
        })
    }
}
