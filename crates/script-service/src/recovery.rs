//! Durable Script recovery retains uncertainty until original-attempt evidence arrives.
use crate::{Result, ScriptService, runs::Run, storage};
use rss_mdm_audit_integration::Fact;
use rss_mdm_task_state::{Cancellation, Execution};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
pub async fn audit_recovery(
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
            tx.tenant_id().to_string(),
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
    pub async fn accept_action_dispatch(
        &self,
        id: Uuid,
        fingerprint: Vec<u8>,
    ) -> std::result::Result<(), crate::Error> {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            self.transactions.tenant.to_string(),
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Script,
            id,
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target(&id.to_string());
        audit.identify_service("script-dispatch");
        let result=crate::transaction::run(&self.transactions.audit_store,&self.transactions.runtime,self.transactions.tenant,&audit,(self,id,fingerprint,&audit),|ctx,tx|Box::pin(async move{
            let (service,id,fingerprint,audit)=ctx;
            crate::transaction::prepare_audit_in(&service.transactions.audit_store,tx,audit,&[]).await?;
            let run=storage::read_run(tx,*id).await?;
            let fact=Fact::business(audit, rss_mdm_audit_integration::operation::OperationOwner::Script, &format!("script:{id}:dispatch"), 200, "success", None)?
                .with_activity(&crate::activity::run(&run,rss_mdm_audit_integration::activity::ActivityPhase::Dispatched))?;
            let tenant=tx.tenant_id().to_string();let id=id.to_string();let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move{
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_script.runs WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(&id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false){sqlx::query("UPDATE mdm_script.runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(crate::Error::Invariant)?;
            if old{audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            (if old { Ok(()) } else { service.transactions.audit_store.append_in(tx, &fact).await })?;Ok(())
        })).await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}

pub async fn recover_one(
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
    audit_recovery(service, tx, &run, &previous).await
}
