use super::storage as db;
use crate::deployment::{Result, SoftwareService, storage};
use rss_mdm_audit_integration::Fact;
use rss_mdm_task_state::{Cancellation, Execution};
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
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_software_deployment.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 AND (input_revision>input_consumed OR dispatch_revision>dispatch_consumed)) OR EXISTS(SELECT 1 FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$2 AND state='enabled' AND definition->'action'->>'kind'='software')")
            .bind(tenant).bind(id).fetch_one(c).await
    })).await?)
}

pub(crate) async fn backlog_in(tx: &mut PgTransaction<'_>, policy: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_software_deployment.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 AND (input_revision>input_consumed OR dispatch_revision>dispatch_consumed)) OR EXISTS(SELECT FROM mdm_software_deployment.software_stage_stats s JOIN mdm_policy.policies p ON(p.tenant_id,p.current_version)=(s.tenant_id,s.version) WHERE p.tenant_id=$1::uuid AND p.id=$2 AND p.state='enabled' AND s.stage < jsonb_array_length(coalesce(p.definition#>'{action,rollout,stages}','[]'::jsonb)) AND (NOT s.membership_complete OR NOT s.ready))").bind(tenant).bind(policy).fetch_one(c).await
    })).await?)
}

pub(crate) async fn discover_in(
    service: &SoftwareService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    recover_runs_in(service, tx, id).await?;
    if let Some(policy) =
        crate::deployment::sources::storage::read_in(&service.transactions.policy_reader, tx, id)
            .await?
        && policy.definition.action.kind() == rss_mdm_policy::ActionKind::Software
    {
        let software = crate::deployment::sources::software::read_in(
            &service.transactions.policy_reader,
            tx,
            policy.version,
        )
        .await?;
        software
            .assignment
            .advance_stats_in(&service.transactions.admission(), tx, id)
            .await?;
        if software
            .assignment
            .release_gates_in(&service.transactions.admission().source, tx)
            .await?
        {
            crate::deployment::sources::storage::wake_dispatch_in(
                &service.transactions.reconcile_messaging,
                tx,
                id,
            )
            .await?;
        }
    }
    super::scheduled::dispatch_in(service, tx, id).await
}

/// Policy changes revisit accepted runs without rediscovering assignment targets.
async fn recover_runs_in(
    service: &SoftwareService,
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
) -> Result<()> {
    crate::deployment::sources::storage::read_in(&service.transactions.policy_reader, tx, policy)
        .await?
        .ok_or(crate::deployment::Error::NotFound)?;
    let tenant = tx.tenant_id().to_string();
    let (revision, consumed, mut window, mut after): (i64, i64, i64, Option<Uuid>) = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as("SELECT input_revision,input_consumed,input_window,recovery_after FROM mdm_software_deployment.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE").bind(tenant).bind(policy).fetch_one(c).await
    })).await?;
    if consumed == window {
        window = revision;
        after = None;
    }
    if consumed == window {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let rows: Vec<Uuid> = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT r.id FROM mdm_software_deployment.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::uuid IS NULL OR r.id>$3) ORDER BY r.id LIMIT 33").bind(tenant).bind(policy).bind(after).fetch_all(c).await
    })).await?;
    for id in rows.iter().take(32) {
        super::run_recovery::wake_run(&service.transactions.reconcile_messaging, tx, *id).await?;
    }
    let more = rows.len() > 32;
    let after = if more { Some(rows[31]) } else { None };
    let consumed = if more { consumed } else { window };
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_software_deployment.policy_recovery SET input_consumed=$3,input_window=$4,recovery_after=$5 WHERE tenant_id=$1::uuid AND policy=$2").bind(tenant).bind(policy).bind(consumed).bind(window).bind(after).execute(c).await?; Ok(())
    })).await?;
    Ok(())
}

pub async fn audit_recovery(
    service: &SoftwareService,
    tx: &mut PgTransaction<'_>,
    run: &db::Run,
    previous: &rss_mdm_task_state::RunState,
) -> Result<()> {
    if *previous != run.state {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            tx.tenant_id().to_string(),
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("command-recovery");
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::SoftwareAction,
            run.id,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        run.source.audit(&audit);
        audit.target_device(&run.target.device);
        audit.registration(run.target.registration);
        let bytes = crate::deployment::checked_input(serde_json::to_vec(&(&previous, &run.state)))?;
        use sha2::Digest;
        let fact = Fact::business(
            &audit,
            rss_mdm_audit_integration::operation::OperationOwner::SoftwareAction,
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
impl SoftwareService {
    pub async fn accept_action_dispatch(
        &self,
        id: Uuid,
        fingerprint: Vec<u8>,
    ) -> std::result::Result<(), crate::deployment::Error> {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            self.transactions.tenant.to_string(),
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::SoftwareAction,
            id,
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target(&id.to_string());
        audit.identify_service("command-dispatch");
        let result=crate::deployment::transaction::run(&self.transactions.audit_store,&self.transactions.runtime,self.transactions.tenant,&audit,(self,id,fingerprint,&audit),|ctx,tx|Box::pin(async move{
            let (service,id,fingerprint,audit)=ctx;
            crate::deployment::transaction::prepare_audit_in(&service.transactions.audit_store,tx,audit,&[]).await?;
            let run=super::storage::read_run(tx,*id).await?;
            let fact=Fact::business(audit, rss_mdm_audit_integration::operation::OperationOwner::SoftwareAction, &format!("action:{id}:dispatch"), 200, "success", None)?
                .with_activity(&super::activity::run(&run,rss_mdm_audit_integration::activity::ActivityPhase::Dispatched))?;
            let tenant=tx.tenant_id().to_string();let id=id.to_string();let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move{
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(&id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false){sqlx::query("UPDATE mdm_software_deployment.action_runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(crate::deployment::Error::Unavailable(crate::deployment::Failure::CommandInvariant))?;
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

pub(super) async fn stale_registration(
    tx: &mut PgTransaction<'_>,
    target: &crate::deployment::Target,
) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let target = target.clone();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(crate::deployment::device::read::stale_registration_in(
                rss_mdm_install_support::StorageProfile::Mdm,
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
    service: &SoftwareService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    let now = storage::now(tx).await?;
    let mut run = db::load_run(tx, id).await?;
    let plan = db::load_source(&service.transactions, tx, run.source).await?;
    let previous = run.state.clone();
    let stale = stale_registration(tx, &run.target).await?;
    if stale
        || plan
            .withdrawn_in(&service.transactions, tx, &run.target, now)
            .await?
    {
        run.state.cancel();
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
    db::save_run(
        &service.transactions.policy_reader,
        &service.transactions.reconcile_messaging,
        tx,
        &run,
    )
    .await?;
    audit_recovery(service, tx, &run, &previous).await?;
    Ok(())
}
