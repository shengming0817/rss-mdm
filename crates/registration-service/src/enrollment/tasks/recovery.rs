//! Durable Enrollment recovery retains uncertainty until original-attempt evidence arrives.
use crate::enrollment::tasks::{Result, Service, runs::Run, storage};
use rss_mdm_audit_integration::Fact;
use rss_mdm_task_state::{Cancellation, Execution};

use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
pub async fn audit_recovery(
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    service: &Service,
    tx: &mut PgTransaction<'_>,
    run: &Run,
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
        audit.identify_service("enrollment-recovery");
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::EnrollmentTask,
            run.id,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.plan(run.policy_version);
        audit.target_device(&run.target.device);
        let bytes =
            crate::enrollment::tasks::checked_input(serde_json::to_vec(&(&previous, &run.state)))?;
        use sha2::Digest;
        let fact = Fact::business(
            &audit,
            rss_mdm_audit_integration::operation::OperationOwner::EnrollmentTask,
            &format!(
                "enrollment:{}:recover:{:x}",
                run.id,
                sha2::Sha256::digest(&bytes)
            ),
            200,
            "success",
            None,
        )?
        .with_details(serde_json::json!({"before":previous,"after":run.state}))?
        .with_activity(&crate::enrollment::tasks::activity::run(
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
        profile: rss_mdm_audit_integration::StorageProfile,
    ) -> Result<bool> {
        use rss_mdm_audit_integration::operation::OperationOwner;
        let id = dispatch.id;
        let audit = rss_mdm_audit_integration::command_transaction::dispatch_audit(
            profile,
            dispatch.binding,
            OperationOwner::EnrollmentTask,
            id,
            "enrollment-dispatch",
        );
        audit.target(&id.to_string());
        store.bind_in(tx).await?;
        if !dispatch.accept_in(tx, match profile { rss_mdm_audit_integration::StorageProfile::Mdm => "UPDATE mdm_registration_tasks.runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_fingerprint=$3 AND expected_epoch=current_setting('rss.execution_epoch')::bigint AND NOT gateway_accepted", rss_mdm_audit_integration::StorageProfile::Da => "UPDATE rss_da.enrollment_runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_fingerprint=$3 AND expected_epoch=current_setting('rss.execution_epoch')::bigint AND NOT gateway_accepted", }).await? {
            audit.finalize(None);
            return Ok(false);
        }
        let run = match storage::read_run(profile, tx, id).await {
            Err(crate::enrollment::tasks::transaction::Fault::Request(
                crate::enrollment::tasks::Error::Invariant,
            )) => return Ok(false),
            other => other?,
        };
        let activity = crate::enrollment::tasks::activity::run(
            &run,
            rss_mdm_audit_integration::activity::ActivityPhase::Dispatched,
        );
        let fact = Fact::business(
            &audit,
            OperationOwner::EnrollmentTask,
            &format!("enrollment:{id}:dispatch"),
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
    profile: rss_mdm_install_support::StorageProfile,
    service: &Service,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    service.transactions.validate_in(tx)?;
    let target = storage::read_run(profile, tx, id).await?.target;
    storage::lock_device(profile, tx, &target.device).await?;
    let now = storage::now(tx).await?;
    let mut run = storage::load_run(profile, tx, id).await?;
    let plan =
        crate::enrollment::tasks::policy::read_in(&service.transactions, tx, run.policy_version)
            .await?;
    let tenant = tx.tenant_id().to_string();
    let stale = tx
        .with_connection(move |c| {
            Box::pin(crate::device::read::inactive_in(
                profile,
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
    storage::save_run(profile, &service.transactions, tx, &run).await?;
    audit_recovery(binding, service, tx, &run, &previous).await
}
