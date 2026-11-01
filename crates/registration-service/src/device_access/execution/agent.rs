use super::Error;
use super::storage as db;
use super::{
    Result, Service, admission, agent_facts, checked_input, provisioning, storage, transaction,
};
use crate::DevicePrincipal;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::Fact;
use rss_mdm_task_state::{Cancellation, Execution};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub(crate) async fn principal(
    service: &super::Transactions,
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
            Ok(crate::device::store::revalidate_source(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                &checked,
                rss_mdm_inventory::ReportSource::AgentBuiltin,
            )
            .await)
        })
    })
    .await??;
    let enabled =
        agent_facts::agent_binding_in(tx, service.agent_store.clone(), principal.registration())
            .await?
            .is_some_and(|b| {
                b.inventory() && b.capabilities.contains(&wire::Capability::DeviceAccessV1)
            });
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
        lock_device(tx, p.device()).await?;
        principal(&self.transactions, tx, p).await
    }
    pub async fn agent_admit_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        _input: &wire::TaskClaimRequest,
        audit: &RequestAudit,
    ) -> Result<()> {
        let service = self;
        let now = storage::now(tx).await?;
        let binding = agent_facts::agent_binding_in(
            tx,
            service.transactions.agent_store.clone(),
            p.registration(),
        )
        .await?
        .ok_or(Error::Forbidden)?;
        let partitions = [];
        let access = if binding
            .capabilities
            .contains(&wire::Capability::DeviceAccessV1)
        {
            let prepared =
                admission::prepare_reconciliation_in(&service.transactions, tx, p).await?;
            Some(prepared)
        } else {
            None
        };
        transaction::prepare_audit_in(&service.transactions.audit_store, tx, audit, &partitions)
            .await?;
        if let Some(prepared) = access {
            admission::reconcile_in(
                &service.transactions,
                tx,
                prepared,
                now,
                rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
                audit,
            )
            .await?;
        }
        Ok(())
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
        let binding = agent_facts::agent_binding_in(
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
        let plan = admission::load(tx, run.id).await?;
        let previous = run.state.clone();
        run.state.expire(now);
        let capable = admission::capable(&binding, &plan.binding.configuration.windows);
        let authorized = plan
            .allowed_in(&service.transactions, tx, &run.target)
            .await?;
        let allowed = capable && authorized;
        if !authorized {
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
            audit.plan(run.policy_version);
            audit.target(&run.id.to_string());
            let activity = super::activity::run(
                &run,
                rss_mdm_audit_integration::activity::ActivityPhase::Offered,
            );

            offer_activity = Some(activity);
            offer = Some(payload);
        }
        db::save_run(&service.transactions.reconcile_messaging, tx, &run).await?;
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
        audit.plan(run.policy_version);
        audit.target(&run.id.to_string());
        let plan = admission::load(tx, run.id).await?;
        let now = storage::now(tx).await?;
        if run.state.cancellation != Cancellation::None
            || run.state.execution != Execution::NotStarted
            || run.state.attempt() != Some(signed.payload.attempt_id())
            || signed.payload.expires_at() <= now
            || !plan.allowed_in(&self.transactions, tx, &run.target).await?
        {
            return Err(Error::Conflict.into());
        }
        transaction::prepare_audit_in(&self.transactions.audit_store, tx, audit, &[]).await?;
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
        audit.plan(run.policy_version);
        audit.target(&id.to_string());
        let plan = admission::load(tx, run.id).await?;
        transaction::prepare_audit_in(&self.transactions.audit_store, tx, audit, &[]).await?;

        if matches!(input.event(), wire::TaskEvent::Start) {
            let now = storage::now(tx).await?;
            if now >= run.deadline
                || run.state.cancellation != Cancellation::None
                || run.state.attempt() != Some(input.attempt_id())
                || run.state.execution != Execution::Running
            {
                return Err(Error::Conflict.into());
            }
            if !plan.allowed_in(&self.transactions, tx, &run.target).await? {
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
        transaction::prepare_audit_in(&service.transactions.audit_store, tx, audit, &[]).await?;
        audit.plan(run.policy_version);
        audit.target(&id.to_string());
        let plan = admission::load(tx, run.id).await?;

        let now = storage::now(tx).await?;
        let event_key = format!(
            "agent:{}:task:{id}:event:{}",
            p.registration(),
            input.operation_id()
        );
        let allowed = plan
            .allowed_in(&service.transactions, tx, &run.target)
            .await?;
        let effect_allowed = allowed && run.state.cancellation == Cancellation::None;
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
        let mut credentials = Vec::new();
        match input.event() {
            wire::TaskEvent::SoftwareResult(_)
            | wire::TaskEvent::EnrollmentResult { .. }
            | wire::TaskEvent::Result(_)
            | wire::TaskEvent::CollectionResult(_)
            | wire::TaskEvent::ChunkedCollectionResult { .. }
            | wire::TaskEvent::OutputChunk(_)
            | wire::TaskEvent::ChunkedResult(_) => return Err(Error::Malformed.into()),
            wire::TaskEvent::DeviceAccessPrepared(value) => {
                if !matches!(run.state.execution, Execution::Running | Execution::Unknown)
                    || run.state.started_at.is_none()
                {
                    return Err(Error::Forbidden.into());
                }
                provisioning::prepared(&service.transactions, tx, &run, input, value).await?;
            }
            wire::TaskEvent::DeviceAccessResult(value) => {
                let access_complete = value
                    .effect
                    .complete(&plan.binding.configuration, plan.binding.intent.platform());
                if !matches!(run.state.execution, Execution::Running | Execution::Unknown)
                    || run.state.started_at.is_none()
                {
                    return Err(Error::Forbidden.into());
                }
                admission::finish_in(
                    &service.transactions,
                    tx,
                    &run,
                    input,
                    value,
                    effect_allowed,
                )
                .await?;
                if provisioning::unresolved(
                    &service.transactions,
                    tx,
                    &run,
                    input.attempt_id(),
                    !matches!(value.effect, wire::AccessEffect::Unknown)
                        && (!matches!(
                            value.effect,
                            wire::AccessEffect::Applied { .. }
                                | wire::AccessEffect::WhfbRetired { .. }
                        ) || access_complete),
                )
                .await?
                    || matches!(value.effect, wire::AccessEffect::Unknown)
                    || matches!(
                        value.effect,
                        wire::AccessEffect::Applied { .. } | wire::AccessEffect::WhfbRetired { .. }
                    ) && !access_complete
                {
                    run.state.uncertain_result(input.attempt_id())?;
                } else {
                    run.state.result(input.attempt_id(), access_complete)?;
                }
                run.result = Some(value.clone());
            }
            wire::TaskEvent::CredentialEscrow(value) => {
                if !effect_allowed
                    || !matches!(run.state.execution, Execution::Running | Execution::Unknown)
                    || run.state.started_at.is_none()
                {
                    return Err(Error::Forbidden.into());
                }
                credentials = provisioning::escrow(
                    &service.transactions,
                    tx,
                    &run,
                    input.attempt_id(),
                    value,
                )
                .await?;
                if !run.state.trusts_result(now) {
                    run.state.uncertain_result(input.attempt_id())?;
                    let tenant =
                        checked_input(Uuid::parse_str(&service.transactions.tenant.to_string()))?;
                    let recovery = service
                        .transactions
                        .recovery
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move { Ok(recovery.unknown(c, tenant, id).await) })
                    })
                    .await??;
                }
            }
            wire::TaskEvent::CredentialResult(_) | wire::TaskEvent::UnmanageResult { .. } => {
                return Err(Error::Malformed.into());
            }
            wire::TaskEvent::Received => {
                run.state.received(input.attempt_id(), now)?;
                admission::received_in(tx, &run).await?;
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
                if run.state.started_at.is_some()
                    && provisioning::unresolved(
                        &service.transactions,
                        tx,
                        &run,
                        input.attempt_id(),
                        true,
                    )
                    .await?
                {
                    run.state.uncertain_result(input.attempt_id())?;
                } else {
                    run.state.cancelled(input.attempt_id())?;
                }
            }
        }
        db::save_run(&service.transactions.reconcile_messaging, tx, &run).await?;
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

pub(crate) async fn lock_device(tx: &mut PgTransaction<'_>, device: &str) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::lifecycle::lock_devices_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                &tenant,
                &[device],
            )
            .await)
        })
    })
    .await??;
    Ok(())
}
