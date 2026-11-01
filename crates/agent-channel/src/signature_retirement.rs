//! Agent-owned pending signature references; the trust owner controls retirement.
pub struct PendingSignatures {
    profile: rss_mdm_install_support::StorageProfile,
}
impl PendingSignatures {
    pub const fn new(profile: rss_mdm_install_support::StorageProfile) -> Self {
        Self { profile }
    }
    pub const fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
}
impl rss_mdm_task_trust::RetirementGuard for PendingSignatures {
    fn pending<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        key_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<bool, rss_mdm_task_trust::Error>> + Send + 'a>,
    > {
        let profile = self.profile();

        Box::pin(async move {
            let pending: bool = sqlx::query_scalar(
                crate::storage_profile::sql(profile).signature_retirement_pending_1,
            )
            .bind(tenant.to_string())
            .bind(key_id)
            .fetch_one(&mut *c)
            .await
            .map_err(|_| {
                rss_mdm_task_trust::Error::Unavailable(rss_mdm_task_trust::Failure::Database)
            })?;
            Ok(pending)
        })
    }
}

/// Verify the exact Agent-owned privileged predicate before exposing Task Trust.
pub async fn verify_authority(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    let body = crate::storage_profile::sql(profile)
        .relations
        .split("$$")
        .nth(1)
        .expect("Agent predicate body");
    let rejected: Option<String> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).authority_admission)
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
