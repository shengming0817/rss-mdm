//! Task trust and native material loading, independent of business service assembly.
use std::sync::Arc;
pub(crate) async fn signing(
    config: &crate::config::Config,
    tenant: rss_request_context::TenantId,
    protection: Arc<rss_mdm_native_protection::Protector>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    channels: &crate::channel_status::Channels,
) -> Result<
    (
        Arc<rss_mdm_task_trust::Signing>,
        Arc<rss_mdm_task_trust::Service>,
    ),
    crate::Error,
> {
    let loaded_signing = crate::task_signing::prepare(
        config.task_signing.as_ref(),
        &config.access_database,
        tenant,
        &protection,
        channels,
    )
    .await?;
    let signing = Arc::new(rss_mdm_task_trust::Signing::new(tenant, loaded_signing)?);
    let task_trust = Arc::new(rss_mdm_task_trust::Service::new(
        tenant,
        signing.clone(),
        protection.clone(),
        audit,
        Arc::new(rss_mdm_agent_channel::signature_retirement::PendingSignatures),
    )?);
    Ok((signing, task_trust))
}
