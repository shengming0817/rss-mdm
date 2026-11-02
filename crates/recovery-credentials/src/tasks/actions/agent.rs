use super::storage as db;
use crate::tasks::Error;
use crate::tasks::{Result, Service, checked_input, storage};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::Fact;
use rss_mdm_registration_service::DevicePrincipal;
use rss_mdm_task_state::{Cancellation, Execution};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub(crate) async fn principal(
    _profile: rss_mdm_install_support::StorageProfile,
    service: &crate::tasks::Transactions,
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
            Ok(
                rss_mdm_registration_service::device::store::revalidate_source(
                    checked.profile(),
                    c,
                    &checked,
                    rss_mdm_inventory::ReportSource::AgentBuiltin,
                )
                .await,
            )
        })
    })
    .await??;
    let enabled = crate::tasks::agent_facts::agent_binding_in(
        tx,
        service.agent_store.clone(),
        principal.registration(),
    )
    .await?
    .is_some_and(|b| {
        b.inventory()
            && b.capabilities
                .contains(&wire::Capability::CredentialsWindowsV1)
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
        let profile = self.profile();

        self.transactions.runtime.validate_transaction(tx)?;
        lock_device(profile, tx, p.device()).await?;
        principal(profile, &self.transactions, tx, p).await
    }
    pub async fn agent_admit_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        input: &wire::TaskClaimRequest,
        audit: &RequestAudit,
    ) -> Result<()> {
        if !self.accepts_new_work() {
            return Ok(());
        }
        let owner_audit = audit.product_fact_copy(self.profile());
        let audit = &owner_audit;
        let profile = self.profile();

        let service = self;
        let now = storage::now(tx).await?;
        let binding = crate::tasks::agent_facts::agent_binding_in(
            tx,
            service.transactions.agent_store.clone(),
            p.registration(),
        )
        .await?
        .ok_or(Error::Forbidden)?;
        let versions = crate::tasks::policy::agent_versions_in(profile, tx, p.registration())
            .await?
            .into_iter()
            .map(|version| (version, Uuid::new_v4()))
            .collect::<Vec<_>>();
        let partitions = [];

        crate::tasks::transaction::prepare_audit_in(
            &service.transactions.audit_store,
            tx,
            audit,
            &partitions,
        )
        .await?;
        for (id, run_id) in versions {
            let policy =
                db::load_policy_version(&service.transactions.policy_reader, tx, id).await?;
            let target = crate::tasks::Target {
                device: p.device().into(),
                registration: p.registration(),
                generation: p.generation(),
            };
            if crate::tasks::credential_tasks::capable(&binding, policy.frozen.input.architecture) {
                super::production::accept_for_device(
                    profile,
                    &service.transactions,
                    tx,
                    &policy,
                    &target,
                    super::production::AdmissionTrigger::Agent(input.operation_id()),
                    now,
                    run_id,
                )
                .await?;
            }
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
        if !self.accepts_new_work() {
            return Ok(None);
        }
        let owner_audit = audit.product_fact_copy(self.profile());
        let audit = &owner_audit;
        let profile = self.profile();

        self.agent_prepare_in(tx, p).await?;
        let service = self;
        let now = storage::now(tx).await?;
        let event_key = format!("agent:{}:offer:{}", p.registration(), input.operation_id());
        let binding = crate::tasks::agent_facts::agent_binding_in(
            tx,
            self.transactions.agent_store.clone(),
            p.registration(),
        )
        .await?
        .ok_or(Error::Forbidden)?;
        let mut offer = None;
        let mut offer_activity = None;
        let mut run = db::load_run(profile, tx, id).await?;
        belongs(&run, p)?;
        let plan =
            db::load_policy_version(&service.transactions.policy_reader, tx, run.policy_version)
                .await?;
        let previous = run.state.clone();
        run.state.expire(now);
        let capable =
            crate::tasks::credential_tasks::capable(&binding, plan.frozen.input.architecture);
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
            audit.plan(run.policy_version);
            audit.target(&run.id.to_string());
            let activity = super::activity::run(
                &run,
                rss_mdm_audit_integration::activity::ActivityPhase::Offered,
            );

            offer_activity = Some(activity);
            offer = Some(payload);
        }
        db::save_run(profile, &service.transactions.reconcile_messaging, tx, &run).await?;
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
        if !self.accepts_new_work() {
            return Err(Error::Forbidden.into());
        }
        let owner_audit = audit.product_fact_copy(self.profile());
        let audit = &owner_audit;
        let profile = self.profile();

        let run = db::load_run(profile, tx, signed.payload.task_id()).await?;
        belongs(&run, p)?;
        audit.plan(run.policy_version);
        audit.target(&run.id.to_string());
        let plan =
            db::load_policy_version(&self.transactions.policy_reader, tx, run.policy_version)
                .await?;
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
        crate::tasks::transaction::prepare_audit_in(&self.transactions.audit_store, tx, audit, &[])
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
        if !self.accepts_new_work()
            && matches!(
                input.event(),
                wire::TaskEvent::Start | wire::TaskEvent::Received
            )
        {
            return Err(Error::Forbidden.into());
        }
        let owner_audit = audit.product_fact_copy(self.profile());
        let audit = &owner_audit;
        let profile = self.profile();

        let run = db::load_run(profile, tx, id).await?;
        belongs(&run, p)?;
        audit.plan(run.policy_version);
        audit.target(&id.to_string());
        let plan =
            db::load_policy_version(&self.transactions.policy_reader, tx, run.policy_version)
                .await?;
        crate::tasks::transaction::prepare_audit_in(&self.transactions.audit_store, tx, audit, &[])
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
        if !self.accepts_new_work()
            && matches!(
                input.event(),
                wire::TaskEvent::Start | wire::TaskEvent::Received
            )
        {
            return Err(Error::Forbidden.into());
        }
        let owner_audit = audit.product_fact_copy(self.profile());
        let audit = &owner_audit;
        let profile = self.profile();

        let service = self;
        let mut run = db::load_run(profile, tx, id).await?;
        belongs(&run, p)?;
        crate::tasks::transaction::prepare_audit_in(
            &service.transactions.audit_store,
            tx,
            audit,
            &[],
        )
        .await?;
        audit.plan(run.policy_version);
        audit.target(&id.to_string());
        let plan =
            db::load_policy_version(&service.transactions.policy_reader, tx, run.policy_version)
                .await?;

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
        let effect_allowed = allowed
            && (run.state.cancellation == Cancellation::None
                || !self.accepts_new_work() && run.state.started_at.is_some());
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
            wire::TaskEvent::DeviceAccessPrepared(_) | wire::TaskEvent::DeviceAccessResult(_) => {
                return Err(Error::Malformed.into());
            }
            wire::TaskEvent::CredentialEscrow(value) => {
                if !effect_allowed
                    || !matches!(run.state.execution, Execution::Running | Execution::Unknown)
                    || run.state.started_at.is_none()
                {
                    return Err(Error::Forbidden.into());
                }
                credentials = crate::tasks::credential_tasks::escrow(
                    profile,
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
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::storage::unknown_in(
                                crate::Custody::new(profile, None),
                                c,
                                tenant,
                                id,
                            )
                            .await)
                        })
                    })
                    .await?
                    .map_err(Error::from)?;
                }
            }
            wire::TaskEvent::CredentialResult(value) => {
                if !effect_allowed
                    || !matches!(run.state.execution, Execution::Running | Execution::Unknown)
                    || run.state.started_at.is_none()
                {
                    return Err(Error::Forbidden.into());
                }
                match crate::tasks::credential_tasks::finish(
                    profile,
                    &service.transactions,
                    tx,
                    &run,
                    input.attempt_id(),
                    value,
                )
                .await?
                {
                    Execution::Unknown => run.state.uncertain_result(input.attempt_id())?,
                    Execution::Succeeded => run.state.result(input.attempt_id(), true)?,
                    Execution::Failed => run.state.result(input.attempt_id(), false)?,
                    _ => return Err(Error::Conflict.into()),
                }
                run.result = Some(super::result::RunResult::Credential(value.clone()));
            }
            wire::TaskEvent::UnmanageResult { .. } => return Err(Error::Malformed.into()),
            wire::TaskEvent::Received => {
                run.state.received(input.attempt_id(), now)?;
            }
            wire::TaskEvent::Start => {
                if run.state.execution != Execution::NotStarted {
                    return Err(Error::Conflict.into());
                }
                {
                    crate::tasks::credential_tasks::start(
                        profile,
                        &service.transactions,
                        tx,
                        &run,
                        input.attempt_id(),
                    )
                    .await?;
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
        db::save_run(profile, &service.transactions.reconcile_messaging, tx, &run).await?;
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
        let profile = self.profile();

        self.transactions.runtime.validate_transaction(tx)?;
        super::poll::cancellations(profile, tx, registration, after).await
    }
}
use rss_mdm_audit_integration::RequestAudit;

pub(crate) async fn lock_device(
    _profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(rss_mdm_registration_service::lifecycle::lock_devices_in(
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
