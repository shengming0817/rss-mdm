use super::{
    state::{Cancellation, Execution},
    storage as db,
};
use crate::{ExecutionService, Result, storage};
use rss_mdm_audit_integration::Fact;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub fn policy_id(entity: &str) -> Option<Uuid> {
    entity
        .strip_prefix("policy.")
        .and_then(|v| Uuid::parse_str(v).ok())
}
pub async fn active(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 AND input_revision>input_consumed) OR EXISTS(SELECT 1 FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$2 AND state='enabled' AND definition->'action'->>'kind'='software')")
            .bind(tenant).bind(id).fetch_one(c).await
    })).await?)
}

pub(crate) async fn backlog_in(tx: &mut PgTransaction<'_>, policy: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_commands.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 AND input_revision>input_consumed) OR EXISTS(SELECT FROM mdm_commands.software_stage_stats s JOIN mdm_policy.policies p ON(p.tenant_id,p.current_version)=(s.tenant_id,s.version) WHERE p.tenant_id=$1::uuid AND p.id=$2 AND p.state='enabled' AND (NOT s.membership_complete OR NOT s.ready))").bind(tenant).bind(policy).fetch_one(c).await
    })).await?)
}

pub(crate) async fn discover_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    super::scheduled::discover_in(service, tx, id).await?;
    if let Some(policy) = crate::sources::storage::read_in(&service.policy_reader, tx, id).await?
        && policy.definition.action.kind() == rss_mdm_policy::ActionKind::Software
    {
        let software =
            crate::sources::software::read_in(&service.policy_reader, tx, policy.version).await?;
        software
            .assignment
            .advance_stats_in(&service.admission(), tx, id)
            .await?;
        if software.assignment.release_gates_in(tx).await? {
            crate::sources::storage::wake_execution_in(&service.reconcile_messaging, tx, id)
                .await?;
        }
    }
    Ok(())
}

pub async fn audit_recovery(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    run: &db::Run,
    previous: &super::state::RunState,
) -> Result<()> {
    if (run.state.cancellation != Cancellation::None || run.state.execution == Execution::Unknown)
        && let Some(attempt) = run.state.attempt()
    {
        super::collection::abandon(
            service,
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
            tx.tenant_id().to_string(),
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("command-recovery");
        audit.operation(
            run.id,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        run.source.audit(&audit);
        audit.target_device(&run.target.device);
        audit.registration(run.target.registration);
        let bytes = crate::checked_input(serde_json::to_vec(&(&previous, &run.state)))?;
        use sha2::Digest;
        let fact = Fact::business(
            &audit,
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
        service.audit_store.append_in(tx, &fact).await?;
    }
    Ok(())
}
impl ExecutionService {
    pub async fn accept_action_dispatch(
        &self,
        id: Uuid,
        fingerprint: Vec<u8>,
    ) -> std::result::Result<(), crate::Error> {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            self.tenant.to_string(),
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.operation(
            id,
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target(&id.to_string());
        audit.identify_service("command-dispatch");
        let result=crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,&audit,(self,id,fingerprint,&audit),|ctx,tx|Box::pin(async move{
            let (service,id,fingerprint,audit)=ctx;
            crate::transaction::prepare_audit_in(&service.audit_store,tx,audit,&[]).await?;
            let run=super::storage::read_run(tx,*id).await?;
            let fact=Fact::business(audit, &format!("action:{id}:dispatch"), 200, "success", None)?
                .with_activity(&super::activity::run(&run,rss_mdm_audit_integration::activity::ActivityPhase::Dispatched))?;
            let tenant=tx.tenant_id().to_string();let id=id.to_string();let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move{
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(&id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false){sqlx::query("UPDATE mdm_commands.action_runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(crate::Error::Unavailable(crate::Failure::CommandInvariant))?;
            if old{audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            (if old { Ok(()) } else { service.audit_store.append_in(tx, &fact).await })?;Ok(())
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

#[cfg(feature = "integration")]
impl ExecutionService {
    /// Exercise the production recovery transaction through the same action funnel as the worker.
    pub async fn recover_action_fixture(&self, id: Uuid) -> std::result::Result<(), crate::Error> {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            self.tenant.to_string(),
            "management_write",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let result = crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            &audit,
            (self, id),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, id) = *ctx;
                    let audit = rss_mdm_audit_integration::RequestAudit::new(
                        tx.tenant_id().to_string(),
                        "management_write",
                        rss_mdm_audit_integration::AuditIntent::Management,
                    );
                    let prepared =
                        crate::recovery::prepare(service, tx, &format!("policy.{id}"), &audit)
                            .await?;
                    crate::recovery::apply_prepared(service, tx, prepared, &audit).await?;
                    Ok(())
                })
            },
        )
        .await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}

async fn stale_registration(tx: &mut PgTransaction<'_>, target: &crate::Target) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let target = target.clone();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(crate::device::read::stale_registration_in(
                c,
                tenant,
                target.registration,
                target.device,
                target.generation,
            ))
        })
        .await?)
}

pub async fn recover_one(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    let now = storage::now(tx).await?;
    let mut run = db::load_run(tx, id).await?;
    let plan = db::load_source(&service.policy_reader, tx, run.source).await?;
    let previous = run.state.clone();
    let stale = stale_registration(tx, &run.target).await?;
    if stale || plan.withdrawn_in(service, tx, &run.target, now).await? {
        run.state.cancel();
    }
    if !stale
        && run.state.cancellation == Cancellation::None
        && run.state.execution != Execution::Unknown
        && let db::ScheduledPolicy::Native(native) = &plan
    {
        super::native_collection::advance_run(service, tx, &mut run, native, now).await?;
    }
    if let db::ScheduledPolicy::Software(software) = &plan
        && software.assignment.channel() == rss_mdm_inventory::Channel::Mdm
    {
        super::native_software::advance_run(service, tx, &mut run, software, now).await?;
    }
    // A sealed protocol result is durable execution evidence, even after worker downtime.
    run.state.expire(now);
    if run.state.execution == Execution::NotStarted
        && run.state.cancellation == Cancellation::Requested
    {
        run.state.cancel();
    }
    if matches!(plan, db::ScheduledPolicy::Native(_))
        && run.state.cancellation == Cancellation::Requested
    {
        run.state.cancelled(run.id)?;
    }
    db::save_run(&service.reconcile_messaging, tx, &run).await?;
    audit_recovery(service, tx, &run, &previous).await?;
    Ok(())
}
