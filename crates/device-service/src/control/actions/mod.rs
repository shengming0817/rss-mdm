//! Product-owned side-effect runs, deliberately separate from desired-state execution.
pub(crate) mod activity;
pub mod agent;

pub mod production;
pub mod recovery;

pub mod storage;

pub(crate) mod run_recovery;

pub mod poll;

pub mod history;

pub mod result;

pub async fn event_parent_current_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    device: rss_mdm_agent_wire::DeviceId,
    id: uuid::Uuid,
) -> super::transaction::Result<bool> {
    let run = storage::load_run(tx, id).await?;
    Ok(run.target.device == device
        && run.state.execution == rss_mdm_task_state::Execution::Running
        && run.state.started_at.is_some())
}
pub async fn event_progress_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    id: uuid::Uuid,
) -> super::transaction::Result<rss_mdm_task_state::RunState> {
    Ok(storage::read_run(tx, id).await?.state)
}
