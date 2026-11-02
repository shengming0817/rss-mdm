use crate::tasks::{storage as db, *};
use rss_mdm_audit_integration::Fact;
use rss_mdm_task_state::{Cancellation, Execution};
pub async fn audit_recovery(
    service: &Service,
    tx: &mut PgTransaction<'_>,
    run: &db::Run,
    previous: &rss_mdm_task_state::RunState,
) -> Result<()> {
    if *previous != run.state {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            service.profile(),
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
        audit.plan(run.policy_version);
        audit.target_device(&run.target.device);
        audit.registration(run.target.registration);
        let bytes = checked_input(serde_json::to_vec(&(&previous, &run.state)))?;
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
    ) -> std::result::Result<(), Error> {
        let profile = self.profile();

        let audit = rss_mdm_audit_integration::RequestAudit::new(
            profile,
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
        let result = transaction::run(
            &self.transactions.audit_store,
            &self.transactions.runtime,
            self.transactions.tenant,
            &audit,
            (self, id, fingerprint, &audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, id, fingerprint, audit) = ctx;
                    transaction::prepare_audit_in(
                        &service.transactions.audit_store,
                        tx,
                        audit,
                        &[],
                    )
                    .await?;
                    let run = super::storage::read_run(profile, tx, *id).await?;
                    let fact = Fact::business(
                        audit,
                        &format!("action:{id}:dispatch"),
                        200,
                        "success",
                        None,
                    )?
                    .with_activity(&super::activity::run(
                        &run,
                        rss_mdm_audit_integration::activity::ActivityPhase::Dispatched,
                    ))?;
                    let tenant = tx.tenant_id().to_string();
                    let id = id.to_string();
                    let fingerprint = fingerprint.clone();
                    let old = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                let old = sqlx::query_scalar::<_, bool>(
                                    crate::storage_profile::sql(profile)
                                        .tasks_actions_recovery_accept_action_dispatch_1,
                                )
                                .bind(&tenant)
                                .bind(&id)
                                .bind(&fingerprint)
                                .fetch_optional(&mut *c)
                                .await?;
                                if old == Some(false) {
                                    sqlx::query(
                                        crate::storage_profile::sql(profile)
                                            .tasks_actions_recovery_accept_action_dispatch_2,
                                    )
                                    .bind(tenant)
                                    .bind(id)
                                    .execute(c)
                                    .await?;
                                }
                                Ok(old)
                            })
                        })
                        .await?
                        .ok_or(Error::Invariant)?;
                    if old {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    (if old {
                        Ok(())
                    } else {
                        service.transactions.audit_store.append_in(tx, &fact).await
                    })?;
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
            Box::pin(
                rss_mdm_registration_service::device::read::stale_registration_in(
                    profile,
                    c,
                    tenant,
                    target.registration,
                    target.device,
                    target.generation,
                ),
            )
        })
        .await?)
}

pub async fn recover_one(
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
    db::save_run(profile, &service.transactions.reconcile_messaging, tx, &run).await?;
    audit_recovery(service, tx, &run, &previous).await?;
    Ok(())
}
