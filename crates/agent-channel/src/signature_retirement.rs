//! Agent-owned pending signature references; the trust owner controls retirement.
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
                sqlx::query_scalar("SELECT mdm_agent.pending_task_signatures($1::uuid,$2)")
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

/// Verify the exact Agent-owned privileged predicate before exposing Task Trust.
pub async fn verify_authority(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let body = include_str!("../schema/relations.sql")
        .split_once("CREATE FUNCTION mdm_agent.pending_task_signatures(")
        .expect("Agent predicate")
        .1
        .split("$$")
        .nth(1)
        .expect("predicate body");
    let rejected: Option<String> = sqlx::query_scalar(include_str!("authority-admission.sql"))
        .bind(body)
        .fetch_optional(c)
        .await?;
    if rejected.is_some() {
        return Err(sqlx::Error::Protocol(
            "Agent signature authority rejected".into(),
        ));
    }
    Ok(())
}
