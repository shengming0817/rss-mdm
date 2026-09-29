use super::{
    state::{Cancellation, Execution},
    storage as db,
};
use crate::execution::{ExecutionService, Result, storage};
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
    Ok(tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) WHERE r.tenant_id=$1::uuid AND v.policy=$2::uuid AND ((r.state->>'execution'='not_started' AND r.state->>'cancellation'<>'confirmed') OR r.state->>'execution'='running' OR (r.state->>'execution'='unknown' AND r.state->>'cancellation'='none' AND (NOT p.enabled OR p.current_version<>v.id))))").bind(tenant).bind(id.to_string()).fetch_one(c).await
    })).await?)
}
pub async fn recover(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    crate::planning::policies::storage::lock(tx, id).await?;
    let tenant = tx.tenant_id().to_string();
    let runs=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.policy_recovery(tenant_id,policy) VALUES($1::uuid,$2::uuid) ON CONFLICT DO NOTHING").bind(&tenant).bind(id.to_string()).execute(&mut *c).await?;
        sqlx::query_as::<_,(Uuid,Option<Uuid>)>("SELECT r.id,(SELECT recovery_after FROM mdm_commands.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2::uuid) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) WHERE r.tenant_id=$1::uuid AND v.policy=$2::uuid AND ((r.state->>'execution'='not_started' AND r.state->>'cancellation'<>'confirmed') OR r.state->>'execution' IN('running','unknown')) AND r.id>coalesce((SELECT recovery_after FROM mdm_commands.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2::uuid),'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY r.id LIMIT 128").bind(tenant).bind(id.to_string()).fetch_all(c).await
    })).await?;
    let total = runs.len();
    let mut last = runs.first().and_then(|(_, previous)| *previous);
    let mut processed = 0;
    for (id, _) in runs {
        if tx.deadline().timeout() < std::time::Duration::from_secs(3) {
            break;
        }
        recover_one(service, tx, id).await?;
        last = Some(id);
        processed += 1;
    }
    let next = if processed < total || total == 128 {
        last
    } else {
        None
    };
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.policy_recovery SET recovery_after=$3::uuid WHERE tenant_id=$1::uuid AND policy=$2::uuid").bind(tenant).bind(id.to_string()).bind(next).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub async fn audit_recovery(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    run: &db::Run,
    previous: &super::state::RunState,
) -> Result<()> {
    if *previous != run.state {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            tx.tenant_id().to_string(),
            "command_reconcile",
        );
        audit.identify_service("command-recovery");
        audit.operation(run.id, "command_reconcile");
        run.source.audit(&audit);
        audit.target(&run.target.device);
        audit.registration(run.target.registration);
        let bytes = crate::execution::checked_input(serde_json::to_vec(&(&previous, &run.state)))?;
        use sha2::Digest;
        let fact = Fact::business(
            &audit,
            &format!(
                "action:{}:recover:{:x}",
                run.id,
                sha2::Sha256::digest(&bytes)
            ),
            &bytes,
            200,
            "success",
            None,
        )?
        .with_details(serde_json::json!({"before":previous,"after":run.state}))?;
        audit.finalize(None);
        service.audit_store.append_in(tx, &fact, false).await?;
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
        );
        audit.operation(id, "command_dispatch");
        audit.identify_service("command-dispatch");
        let result=crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,&audit,(self,id,fingerprint,&audit),|ctx,tx|Box::pin(async move{
            let (service,id,fingerprint,audit)=ctx;
            let fact=Fact::business(audit,&format!("action:{id}:dispatch"),fingerprint,200,"success",None)?;
            let tenant=tx.tenant_id().to_string();let id=id.to_string();let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move{
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(&id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false){sqlx::query("UPDATE mdm_commands.action_runs SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(crate::Error::Unavailable(crate::Failure::CommandInvariant))?;
            if old{audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            service.audit_store.append_in(tx,&fact,old).await?;Ok(())
        }),crate::transaction::TransactionOwner::Execution).await;
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
                    recover(service, tx, id).await
                })
            },
            crate::transaction::TransactionOwner::Execution,
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

async fn stale_registration(
    tx: &mut PgTransaction<'_>,
    target: &super::model::Target,
) -> Result<bool> {
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
    run.state.expire(now, plan.timeout_seconds());
    if run.state.execution == Execution::NotStarted
        && run.state.cancellation == Cancellation::Requested
    {
        run.state.cancel();
    }
    db::save_run(tx, &run).await?;
    audit_recovery(service, tx, &run, &previous).await?;
    Ok(())
}
