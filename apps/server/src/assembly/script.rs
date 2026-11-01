//! Explicit script owner composition over shared host resources.
use super::host_storage::Storage;
use crate::Error;
use std::sync::Arc;
pub(crate) async fn assemble(
    config: &crate::config::Config,
    storage: &Storage,
    source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
) -> Result<
    (
        Arc<rss_mdm_script_service::ScriptService>,
        Arc<rss_mdm_script_service::worker::Worker>,
    ),
    Error,
> {
    let scripts = Arc::new(rss_mdm_script_service::ScriptService::new(
        rss_mdm_script_service::Transactions::bind(
            storage.runtime.clone(),
            storage.tenant,
            storage.audit.clone(),
            Arc::new(rss_mdm_script_service::Materials {
                agent_store: Arc::new(super::agent_facts::AgentFacts),
                source: source.clone(),
                capacity: Arc::new(super::capacity::Capacity),
                instance: config.identity.instance_id.clone(),
            }),
        )
        .await
        .map_err(|_| Error::Configuration(crate::ConfigIssue::CommandStorage))?,
        sessions.clone(),
    ));
    let script_work = Arc::new(
        rss_mdm_script_service::worker::Worker::new(
            scripts.clone(),
            storage.reconcile.clone(),
            storage.worker_budget.clone(),
            config.background.device_concurrency,
        )
        .map_err(|_| Error::Configuration(crate::ConfigIssue::CommandStorage))?,
    );
    Ok((scripts, script_work))
}
