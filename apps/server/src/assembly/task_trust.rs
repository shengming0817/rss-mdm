//! Task trust and native material loading, independent of business service assembly.
use std::sync::Arc;
pub(crate) fn signing(
    protection: Arc<rss_mdm_native_protection::Protector>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
) -> Result<
    (
        Arc<rss_mdm_task_trust::Signing>,
        Arc<rss_mdm_task_trust::Service>,
    ),
    crate::Error,
> {
    let signing = Arc::new(rss_mdm_task_trust::Signing::new(
        rss_mdm_install_support::StorageProfile::Mdm,
        rss_mdm_task_trust::Use::AgentTask,
        protection.clone(),
    )?);
    let task_trust = Arc::new(rss_mdm_task_trust::Service::new(
        signing.clone(),
        protection.clone(),
        audit,
        Arc::new(
            rss_mdm_agent_channel::signature_retirement::PendingSignatures::new(
                rss_mdm_install_support::StorageProfile::Mdm,
            ),
        ),
    )?);
    Ok((signing, task_trust))
}
