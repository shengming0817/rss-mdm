use super::storage as db;
use crate::control::{Error, device::DevicePrincipal};
use crate::control::{Result, Service, storage};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::Fact;
use rss_mdm_task_state::{Cancellation, Execution};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub(crate) async fn principal(
    service: &crate::control::transactions::Transactions,
    tx: &mut PgTransaction<'_>,
    principal: &DevicePrincipal,
) -> Result<()> {
    if tx.tenant_id() != principal.tenant() {
        return Err(Error::Unauthorized.into());
    }
    let principal = principal.clone();
    let checked = principal.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::control::device::store::revalidate_source(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                &checked,
                rss_mdm_inventory::ReportSource::AgentBuiltin,
            )
            .await)
        })
    })
    .await??;
    let enabled = crate::control::agent_facts::agent_binding_in(
        tx,
        service.agent_store.clone(),
        principal.registration(),
    )
    .await?
    .is_some_and(|b| b.inventory() && b.task());
    if !enabled {
        return Err(Error::Forbidden.into());
    }
    Ok(())
}
pub(crate) fn belongs(run: &db::Run, p: &DevicePrincipal) -> Result<()> {
    if run.target.device != p.device()
        || run.target.registration != p.registration()
        || run.target.generation != p.generation()
    {
        return Err(Error::Unauthorized.into());
    }
    Ok(())
}

/// Business effects of one correlated Agent event. Protocol persistence and signing are external.
pub struct EventEffects {
    pub start: Option<wire::TaskPayload>,
    pub cancelled: bool,
    pub credentials: Vec<wire::CredentialReceipt>,
    pub fact: Fact,
}
impl Service {
    pub async fn agent_prepare_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        super::run_recovery::lock_device(tx, p.device()).await?;
        principal(&self.transactions, tx, p).await
    }

    pub async fn agent_offer_one_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        input: &wire::TaskClaimRequest,
        id: Uuid,
        attempt: Uuid,
        audit: &RequestAudit,
    ) -> Result<Option<(wire::TaskPayload, Fact, i64)>> {
        self.agent_prepare_in(tx, p).await?;
        let service = self;
        let now = storage::now(tx).await?;
        let event_key = format!("agent:{}:offer:{}", p.registration(), input.operation_id());
        let binding = crate::control::agent_facts::agent_binding_in(
            tx,
            self.transactions.agent_store.clone(),
            p.registration(),
        )
        .await?
        .ok_or(Error::Forbidden)?;
        let mut offer = None;
        let mut offer_activity = None;
        let mut run = db::load_run(tx, id).await?;
        belongs(&run, p)?;
        let plan = db::load_source(&service.transactions.policy_reader, tx, run.source).await?;
        let previous = run.state.clone();
        run.state.expire(now);
        let capable = binding
            .capabilities
            .contains(&wire::Capability::DeviceUnmanageV1);
        let allowed = capable
            && plan
                .authorized_run_in(&service.transactions, tx, &run, now)
                .await?;
        if plan
            .withdrawn_in(&service.transactions, tx, &run.target, now)
            .await?
        {
            run.state.cancel();
        }
        super::recovery::audit_recovery(service, tx, &run, &previous).await?;
        if run.state.cancellation == Cancellation::None
            && run.available_at <= now
            && allowed
            && run.state.claim(attempt, now).is_ok()
        {
            let payload = plan
                .task(
                    &service.transactions,
                    tx,
                    &run.target,
                    db::TaskIssue {
                        run: run.id,
                        attempt,
                        permit: wire::TaskPermit::Offer,
                        expiry: (now + 60).min(run.deadline),
                    },
                )
                .await?;
            run.source.audit(audit);
            audit.target(&run.id.to_string());
            let activity = super::activity::run(
                &run,
                rss_mdm_audit_integration::activity::ActivityPhase::Offered,
            );

            offer_activity = Some(activity);
            offer = Some(payload);
        }
        db::save_run(&service.transactions.reconcile_messaging, tx, &run).await?;
        crate::control::unmanage::wake_device_in(
            &service.transactions.reconcile_messaging,
            tx,
            &run.target.device,
        )
        .await?;
        offer
            .map(|payload| {
                let fact = Fact::business(audit, &event_key, 200, "success", None)?
                    .with_activity(offer_activity.as_ref().ok_or(Error::Conflict)?)?;
                Ok((payload, fact, run.deadline))
            })
            .transpose()
    }
    pub async fn agent_replay_offer_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        signed: &wire::SignedTask,
        audit: &RequestAudit,
    ) -> Result<()> {
        let run = db::load_run(tx, signed.payload.task_id()).await?;
        belongs(&run, p)?;
        run.source.audit(audit);
        audit.target(&run.id.to_string());
        let plan = db::load_source(&self.transactions.policy_reader, tx, run.source).await?;
        let now = storage::now(tx).await?;
        if run.state.cancellation != Cancellation::None
            || run.state.execution != Execution::NotStarted
            || run.state.attempt() != Some(signed.payload.attempt_id())
            || signed.payload.expires_at() <= now
            || !plan
                .authorized_run_in(&self.transactions, tx, &run, now)
                .await?
        {
            return Err(Error::Conflict.into());
        }
        crate::control::transaction::prepare_audit_in(
            &self.transactions.audit_store,
            tx,
            audit,
            &[],
        )
        .await?;
        Ok(())
    }
    pub async fn agent_replay_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        id: Uuid,
        input: &wire::TaskEventRequest,
        audit: &RequestAudit,
    ) -> Result<()> {
        let run = db::load_run(tx, id).await?;
        belongs(&run, p)?;
        run.source.audit(audit);
        audit.target(&id.to_string());
        let plan = db::load_source(&self.transactions.policy_reader, tx, run.source).await?;
        crate::control::transaction::prepare_audit_in(
            &self.transactions.audit_store,
            tx,
            audit,
            &[],
        )
        .await?;

        if matches!(input.event(), wire::TaskEvent::Start) {
            let now = storage::now(tx).await?;
            if now >= run.deadline
                || run.state.cancellation != Cancellation::None
                || run.state.attempt() != Some(input.attempt_id())
                || run.state.execution != Execution::Running
            {
                return Err(Error::Conflict.into());
            }
            if plan
                .withdrawn_in(&self.transactions, tx, &run.target, now)
                .await?
                || !plan
                    .authorized_run_in(&self.transactions, tx, &run, now)
                    .await?
            {
                return Err(Error::Forbidden.into());
            }
        }
        Ok(())
    }
    pub async fn agent_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        id: Uuid,
        input: &wire::TaskEventRequest,
        audit: &RequestAudit,
    ) -> Result<EventEffects> {
        let service = self;
        let mut run = db::load_run(tx, id).await?;
        belongs(&run, p)?;
        crate::control::transaction::prepare_audit_in(
            &service.transactions.audit_store,
            tx,
            audit,
            &[],
        )
        .await?;
        run.source.audit(audit);
        audit.target(&id.to_string());
        let plan = db::load_source(&service.transactions.policy_reader, tx, run.source).await?;

        let now = storage::now(tx).await?;
        let event_key = format!(
            "agent:{}:task:{id}:event:{}",
            p.registration(),
            input.operation_id()
        );
        let requires_start_authority = matches!(
            input.event(),
            wire::TaskEvent::Start | wire::TaskEvent::Received
        ) || run.state.started_at.is_none();
        let allowed = if requires_start_authority {
            plan.authorized_run_in(&service.transactions, tx, &run, now)
                .await?
        } else {
            plan.completion_authorized_in(&service.transactions, tx, &run.target, now)
                .await?
        };
        if matches!(
            input.event(),
            wire::TaskEvent::Start | wire::TaskEvent::Received
        ) && !allowed
        {
            return Err(Error::Forbidden.into());
        }
        if run.state.attempt() != Some(input.attempt_id()) {
            return Err(Error::Conflict.into());
        }
        let mut permit = None;
        let credentials = Vec::new();
        match input.event() {
            wire::TaskEvent::SoftwareResult(_)
            | wire::TaskEvent::EnrollmentResult { .. }
            | wire::TaskEvent::Result(_)
            | wire::TaskEvent::CollectionResult(_)
            | wire::TaskEvent::ChunkedCollectionResult { .. }
            | wire::TaskEvent::OutputChunk(_)
            | wire::TaskEvent::ChunkedResult(_) => return Err(Error::Malformed.into()),
            wire::TaskEvent::DeviceAccessPrepared(_)
            | wire::TaskEvent::DeviceAccessResult(_)
            | wire::TaskEvent::CredentialEscrow(_)
            | wire::TaskEvent::CredentialResult(_) => return Err(Error::Unsupported.into()),
            wire::TaskEvent::UnmanageResult { outcome } => {
                if !matches!(plan, db::ScheduledPolicy::Retirement(_)) {
                    return Err(Error::Malformed.into());
                }
                if *outcome == wire::UnmanageOutcome::Unknown {
                    run.state.uncertain_result(input.attempt_id())?;
                } else {
                    run.state.result(
                        input.attempt_id(),
                        *outcome == wire::UnmanageOutcome::Completed,
                    )?;
                }
                run.result = Some(super::result::RunResult::Unmanage(
                    super::result::Unmanage {
                        unmanage_outcome: *outcome,
                    },
                ));
            }

            wire::TaskEvent::Received => {
                run.state.received(input.attempt_id(), now)?;
            }
            wire::TaskEvent::Start => {
                if run.state.execution != Execution::NotStarted {
                    return Err(Error::Conflict.into());
                }

                run.state.start(input.attempt_id(), now)?;
                let expiry = run.deadline;
                let payload = plan
                    .task(
                        &service.transactions,
                        tx,
                        &run.target,
                        db::TaskIssue {
                            run: id,
                            attempt: input.attempt_id(),
                            permit: wire::TaskPermit::Start,
                            expiry,
                        },
                    )
                    .await?;
                permit = Some(payload);
            }
            wire::TaskEvent::Cancelled => {
                run.state.cancel();
                run.state.cancelled(input.attempt_id())?;
            }
        }
        db::save_run(&service.transactions.reconcile_messaging, tx, &run).await?;
        crate::control::unmanage::wake_device_in(
            &service.transactions.reconcile_messaging,
            tx,
            &run.target.device,
        )
        .await?;
        let fact = Fact::business(audit, &event_key, 200, "success", None)?;
        let fact = fact.with_activity(&super::activity::run(
            &run,
            super::activity::phase(input.event()),
        ))?;

        Ok(EventEffects {
            start: permit,
            cancelled: !allowed || run.state.cancellation != Cancellation::None,
            credentials,
            fact,
        })
    }
    pub async fn agent_cancellations_in(
        &self,
        tx: &mut PgTransaction<'_>,
        registration: Uuid,
        after: Option<Uuid>,
    ) -> Result<Vec<wire::TaskCancellation>> {
        self.transactions.runtime.validate_transaction(tx)?;
        super::poll::cancellations(tx, registration, after).await
    }
}
use rss_mdm_audit_integration::RequestAudit;
