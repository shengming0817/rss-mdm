//! Minimal command service; no full application or platform material preparation.
use super::runtime::case_tenant;
use std::sync::Arc;

pub(crate) async fn command_service(
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    command_clock: rss_device_command_postgres::CommandClock,
) -> anyhow::Result<(
    Arc<rss_mdm_execution_service::ExecutionService>,
    Arc<rss_mdm_execution_service::queries::Queries>,
    Arc<rss_transactional_messaging_postgres::PgRuntime>,
)> {
    let config = crate::test_support::identity::config(case_tenant())?;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let protection = config.native_protector()?;
    let content = None;
    let runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    let channels = Arc::new(crate::channel_status::Channels::new(&config));
    let built = crate::execution_assembly::assemble(
        &config,
        protection,
        audit,
        content,
        Default::default(),
        runtime.clone(),
        channels,
        None,
        None,
        sessions,
        None,
        command_clock,
    )
    .await;
    let (service, _, queries) = match built {
        Ok(value) => value,
        Err(error) => {
            runtime.close().await;
            return Err(error.into());
        }
    };
    Ok((service, queries, runtime))
}
