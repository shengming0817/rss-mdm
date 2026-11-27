use super::{storage as db, *};
use rss_mdm_audit_integration::Fact;
use rss_mdm_task_state::{Cancellation, Execution};
pub async fn audit_recovery(
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    service: &Service,
    tx: &mut PgTransaction<'_>,
    run: &db::Run,
    previous: &rss_mdm_task_state::RunState,
) -> Result<()> {
    if *previous != run.state {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Da,
            binding,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("command-recovery");
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::DeviceAccessTask,
            run.id,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.plan(run.policy_version);
        audit.target_device(&run.target.device);
        let bytes = checked_input(serde_json::to_vec(&(&previous, &run.state)))?;
        use sha2::Digest;
        let fact = Fact::business(
            &audit,
            rss_mdm_audit_integration::operation::OperationOwner::DeviceAccessTask,
            &format!(
                "action:{}:recover:{:x}",
                run.id,
                sha2::Sha256::digest(&bytes)
            ),
            200,
            "success",
            None,
        )?
        .with_details(serde_json::json!({"before":previous,"after":run.state}))?
        .with_activity(&super::activity::run(
            run,
            rss_mdm_audit_integration::activity::ActivityPhase::Reconciled,
        ))?;
        audit.finalize(None);
        service
            .transactions
            .audit_store
            .append_in(tx, &fact)
            .await?;
    }
    Ok(())
}
impl Service {
    pub async fn project_action_in(
        tx: &mut PgTransaction<'_>,
        dispatch: &rss_mdm_work_page::relay::Dispatch,
        store: &rss_mdm_audit_integration::AuditStore,
    ) -> Result<bool> {
        use rss_mdm_audit_integration::operation::OperationOwner;
        let id = dispatch.id;
        let audit = rss_mdm_audit_integration::command_transaction::dispatch_audit(
            rss_mdm_audit_integration::StorageProfile::Da,
            dispatch.binding,
            OperationOwner::DeviceAccessTask,
            id,
            "command-dispatch",
        );
        audit.target(&id.to_string());
        store.bind_in(tx).await?;
        if !dispatch.accept_in(tx, "UPDATE rss_da.access_runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_fingerprint=$3 AND expected_epoch=current_setting('rss.execution_epoch')::bigint AND da_target IS NULL AND NOT gateway_accepted").await? {
            audit.finalize(None);
            return Ok(false);
        }
        let run = match super::storage::read_run(tx, id).await {
            Err(crate::device_access::execution::transaction::Fault::Request(crate::device_access::execution::Error::Invariant)) => return Ok(false),
            other => other?,
        };
        let activity = super::activity::run(
            &run,
            rss_mdm_audit_integration::activity::ActivityPhase::Dispatched,
        );
        let fact = Fact::business(
            &audit,
            OperationOwner::DeviceAccessTask,
            &format!("action:{id}:dispatch"),
            200,
            "success",
            None,
        )?
        .with_activity(&activity)?;
        store.append_in(tx, &fact).await?;
        audit.finalize(None);
        Ok(true)
    }
}

pub(super) async fn stale_registration(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    target: &Target,
) -> Result<bool> {
    // Runs belong to DA, but their transport coordinates belong to the actual Agent store.
    let profile = service.agent_store.storage_profile();
    let tenant = tx.tenant_id().to_string();
    let target = target.clone();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(rss_mdm_registration_service::device::read::inactive_in(
                profile,
                c,
                tenant,
                target.device,
            ))
        })
        .await?)
}

pub async fn recover_one(
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    service: &Service,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    let now = storage::now(tx).await?;
    let mut run = db::load_run(tx, id).await?;
    let plan = admission::load(tx, run.id).await?;
    let previous = run.state.clone();
    let stale = stale_registration(&service.transactions, tx, &run.target).await?;
    if !service.accepts_new_work()
        || stale
        || !plan
            .allowed_in(&service.transactions, tx, &run.target)
            .await?
    {
        run.state.cancel();
    }

    // A sealed protocol result is durable execution evidence, even after worker downtime.
    run.state.expire(now);
    if run.state.execution == Execution::NotStarted
        && run.state.cancellation == Cancellation::Requested
    {
        run.state.cancel();
    }
    db::save_run(&service.transactions.reconcile_messaging, tx, &run).await?;
    audit_recovery(binding, service, tx, &run, &previous).await?;
    Ok(())
}
