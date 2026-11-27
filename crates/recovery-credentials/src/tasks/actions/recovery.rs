use crate::tasks::{storage as db, *};
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
            service.profile(),
            binding,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("command-recovery");
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::CredentialTask,
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
            rss_mdm_audit_integration::operation::OperationOwner::CredentialTask,
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
        dispatch: &rss_mdm_work_page::relay::Dispatch<'_>,
        store: &rss_mdm_audit_integration::AuditStore,
        profile: rss_mdm_audit_integration::StorageProfile,
    ) -> Result<bool> {
        use rss_mdm_audit_integration::operation::OperationOwner;
        let id = dispatch.id;
        let audit = rss_mdm_audit_integration::command_transaction::dispatch_audit(
            profile,
            dispatch.binding,
            OperationOwner::CredentialTask,
            id,
            "command-dispatch",
        );
        audit.target(&id.to_string());
        store.bind_in(tx).await?;
        if !dispatch.accept_in(tx, match profile { rss_mdm_audit_integration::StorageProfile::Mdm => "UPDATE mdm_recovery_tasks.runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_fingerprint=$3 AND expected_epoch=current_setting('rss.execution_epoch')::bigint AND NOT gateway_accepted", rss_mdm_audit_integration::StorageProfile::Da => "UPDATE rss_da.credential_runs SET gateway_accepted=true WHERE da_execution IS NULL AND tenant_id=$1::uuid AND id=$2 AND dispatch_fingerprint=$3 AND expected_epoch=current_setting('rss.execution_epoch')::bigint AND NOT gateway_accepted", }).await? {
            audit.finalize(None);
            return Ok(false);
        }
        let run = match super::storage::read_run(profile, tx, id).await {
            Err(crate::tasks::transaction::Fault::Request(crate::tasks::Error::Invariant)) => {
                return Ok(false);
            }
            other => other?,
        };
        let activity = super::activity::run(
            &run,
            rss_mdm_audit_integration::activity::ActivityPhase::Dispatched,
        );
        let fact = Fact::business(
            &audit,
            OperationOwner::CredentialTask,
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
    // Credential storage can belong to DA while the execution target remains an Agent.
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
    profile: rss_mdm_install_support::StorageProfile,
    service: &Service,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    let now = storage::now(tx).await?;
    let mut run = db::load_run(profile, tx, id).await?;
    let plan =
        crate::tasks::policy::read_in(&service.transactions.policy_reader, tx, run.policy_version)
            .await?;
    let previous = run.state.clone();
    let stale = stale_registration(&service.transactions, tx, &run.target).await?;
    if !service.accepts_new_work()
        || stale
        || plan
            .withdrawn_in(&service.transactions, tx, &run.target, now)
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
    db::save_run(profile, &service.transactions.reconcile_messaging, tx, &run).await?;
    audit_recovery(binding, service, tx, &run, &previous).await?;
    Ok(())
}
