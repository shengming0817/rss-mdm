use super::storage as db;
use crate::control::{Result, Service, storage};
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
    Ok(tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.unmanage_policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 AND input_revision>input_consumed)").bind(tenant).bind(id).fetch_one(c).await})).await?)
}

pub(crate) async fn backlog_in(tx: &mut PgTransaction<'_>, policy: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.unmanage_policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 AND input_revision>input_consumed)").bind(tenant).bind(policy).fetch_one(c).await})).await?)
}

pub(crate) async fn discover_in(
    service: &Service,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    use sqlx::Row;
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT input_revision,input_consumed,input_window,recovery_after FROM mdm_devices.unmanage_policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE").bind(tenant).bind(id).fetch_optional(c).await})).await?;
    let Some(row) = row else {
        return Ok(());
    };
    let revision: i64 = row.try_get("input_revision")?;
    let consumed: i64 = row.try_get("input_consumed")?;
    let mut window: i64 = row.try_get("input_window")?;
    let mut after: Option<Uuid> = row.try_get("recovery_after")?;
    if window == consumed {
        window = revision;
        after = None;
    }
    if window == consumed {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let mut ids=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Uuid>("SELECT r.id FROM mdm_devices.unmanage_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::uuid IS NULL OR r.id>$3) ORDER BY r.id LIMIT 33").bind(tenant).bind(id).bind(after).fetch_all(c).await})).await?;
    let done = ids.len() <= 32;
    ids.truncate(32);
    let after = ids.last().copied();
    for run in ids {
        super::run_recovery::wake_run(&service.transactions.reconcile_messaging, tx, run).await?;
    }
    let tenant = tx.tenant_id().to_string();
    let consumed = if done { window } else { consumed };
    tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_devices.unmanage_policy_recovery SET input_consumed=$3,input_window=$4,recovery_after=$5 WHERE tenant_id=$1::uuid AND policy=$2").bind(tenant).bind(id).bind(consumed).bind(window).bind(after).execute(c).await?;Ok(())})).await?;
    Ok(())
}

pub async fn audit_recovery(
    service: &Service,
    tx: &mut PgTransaction<'_>,
    run: &db::Run,
    previous: &rss_mdm_task_state::RunState,
) -> Result<()> {
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
        let bytes = crate::control::checked_input(serde_json::to_vec(&(&previous, &run.state)))?;
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
        service
            .transactions
            .audit_store
            .append_in(tx, &fact)
            .await?;
    }
    Ok(())
}
impl Service {
    pub async fn accept_action_dispatch(
        &self,
        id: Uuid,
        fingerprint: Vec<u8>,
    ) -> std::result::Result<(), crate::control::Error> {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            self.transactions.tenant.to_string(),
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
        let result=crate::control::transaction::run(&self.transactions.audit_store,&self.transactions.runtime,self.transactions.tenant,&audit,(self,id,fingerprint,&audit),|ctx,tx|Box::pin(async move{
            let (service,id,fingerprint,audit)=ctx;
            crate::control::transaction::prepare_audit_in(&service.transactions.audit_store,tx,audit,&[]).await?;
            let run=super::storage::read_run(tx,*id).await?;
            let fact=Fact::business(audit, &format!("action:{id}:dispatch"), 200, "success", None)?
                .with_activity(&super::activity::run(&run,rss_mdm_audit_integration::activity::ActivityPhase::Dispatched))?;
            let tenant=tx.tenant_id().to_string();let id=id.to_string();let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move{
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_devices.unmanage_runs WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(&id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false){sqlx::query("UPDATE mdm_devices.unmanage_runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(crate::control::Error::Unavailable(crate::control::Failure::CommandInvariant))?;
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
    target: &crate::control::Target,
) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let target = target.clone();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(crate::control::device::read::stale_registration_in(
                c,
                tenant,
                target.registration,
                target.device,
                target.generation,
            ))
        })
        .await?)
}

pub async fn recover_one(service: &Service, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
    let now = storage::now(tx).await?;
    let mut run = db::load_run(tx, id).await?;
    let plan = db::load_source(&service.transactions.policy_reader, tx, run.source).await?;
    let previous = run.state.clone();
    let stale = stale_registration(tx, &run.target).await?;
    if stale
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
    db::save_run(&service.transactions.reconcile_messaging, tx, &run).await?;
    audit_recovery(service, tx, &run, &previous).await?;
    Ok(())
}
