//! Durable Script recovery retains uncertainty until original-attempt evidence arrives.
use crate::{Result, ScriptService, runs::Run, storage};
use rss_mdm_audit_integration::Fact;
use rss_mdm_task_state::{Cancellation, Execution};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
pub async fn audit_recovery(
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    service: &ScriptService,
    tx: &mut PgTransaction<'_>,
    run: &Run,
    previous: &rss_mdm_task_state::RunState,
) -> Result<()> {
    if (run.state.cancellation != Cancellation::None || run.state.execution == Execution::Unknown)
        && let Some(attempt) = run.state.attempt()
    {
        service
            .abandon_in(
                binding,
                tx,
                attempt,
                if run.state.cancellation != Cancellation::None {
                    "revoked"
                } else {
                    "timeout"
                },
            )
            .await?;
    }
    if *previous != run.state {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            binding,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("script-recovery");
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Script,
            run.id,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.plan(run.policy_version);
        audit.target_device(&run.target.device.clone());

        let bytes = crate::checked_input(serde_json::to_vec(&(&previous, &run.state)))?;
        use sha2::Digest;
        let fact = Fact::business(
            &audit,
            rss_mdm_audit_integration::operation::OperationOwner::Script,
            &format!(
                "script:{}:recover:{:x}",
                run.id,
                sha2::Sha256::digest(&bytes)
            ),
            200,
            "success",
            None,
        )?
        .with_details(serde_json::json!({"before":previous,"after":run.state}))?
        .with_activity(&crate::activity::run(
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
impl ScriptService {
    pub async fn project_action_in(
        tx: &mut PgTransaction<'_>,
        dispatch: &rss_mdm_work_page::relay::Dispatch<'_>,
        store: &rss_mdm_audit_integration::AuditStore,
    ) -> Result<bool> {
        use rss_mdm_audit_integration::operation::OperationOwner;
        let id = dispatch.id;
        store.bind_in(tx).await?;
        if !dispatch.accept_in(tx, "UPDATE mdm_script.runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_fingerprint=$3 AND expected_epoch=current_setting('rss.execution_epoch')::bigint AND NOT gateway_accepted").await? {
            return Ok(false);
        }
        let run = match storage::read_run(tx, id).await {
            Err(crate::transaction::Fault::Request(crate::Error::Invariant)) => return Ok(false),
            other => other?,
        };
        let activity = crate::activity::run(
            &run,
            rss_mdm_audit_integration::activity::ActivityPhase::Dispatched,
        );
        let audit = rss_mdm_audit_integration::command_transaction::dispatch_audit(
            rss_mdm_audit_integration::StorageProfile::Mdm,
            dispatch.binding,
            OperationOwner::Script,
            id,
            "script-dispatch",
        );
        audit.target(&id.to_string());
        let fact = Fact::business(
            &audit,
            OperationOwner::Script,
            &format!("script:{id}:dispatch"),
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

pub async fn recover_one(
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    service: &ScriptService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    service.transactions.validate_in(tx)?;
    let target = storage::read_run(tx, id).await?.target;
    let tenant = tx.tenant_id().to_string();
    let device = target.device;
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(
                rss_mdm_registration_service::lifecycle::lock_recovery_in(c, &tenant, &device)
                    .await,
            )
        })
    })
    .await??;
    let now = storage::now(tx).await?;
    let mut run = storage::load_run(tx, id).await?;
    let plan = crate::policy::read_in(&service.transactions, tx, run.policy_version).await?;
    let tenant = tx.tenant_id().to_string();
    let stale = tx
        .with_connection(move |c| {
            Box::pin(rss_mdm_registration_service::device::read::inactive_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                tenant,
                target.device,
            ))
        })
        .await?;
    let previous = run.state.clone();
    if stale || !plan.active {
        run.state.cancel();
    }
    run.state.expire(now);
    if run.state.execution == Execution::NotStarted
        && run.state.cancellation == Cancellation::Requested
    {
        run.state.cancel();
    }
    storage::save_run(&service.transactions, tx, &run).await?;
    audit_recovery(binding, service, tx, &run, &previous).await
}
