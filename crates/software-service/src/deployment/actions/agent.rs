use super::storage as db;
use crate::deployment::{Error, device::DevicePrincipal};
use crate::deployment::{Result, SoftwareService, storage, stored};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::Fact;
use rss_mdm_audit_integration::activity::ActivityReporting;
use rss_mdm_task_state::{Cancellation, Execution};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::json;
use uuid::Uuid;

pub(crate) async fn principal(
    service: &crate::deployment::transactions::Transactions,
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
            Ok(crate::deployment::device::store::revalidate_source(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                &checked,
                rss_mdm_inventory::ReportSource::AgentBuiltin,
            )
            .await)
        })
    })
    .await??;
    let enabled = crate::deployment::agent_facts::agent_binding_in(
        tx,
        service.agent_store.clone(),
        *principal.device(),
    )
    .await?
    .is_some_and(|b| b.inventory() && b.task());
    if !enabled {
        return Err(Error::Forbidden.into());
    }
    Ok(())
}
pub(crate) fn belongs(run: &db::Run, p: &DevicePrincipal) -> Result<()> {
    if run.target.device != *p.device() {
        return Err(Error::Unauthorized.into());
    }
    Ok(())
}

/// Business effects of one correlated Agent event. Protocol persistence and signing are external.
pub struct EventEffects {
    pub start: Option<wire::TaskPayload>,
    pub cancelled: bool,
    pub fact: Fact,
}
impl SoftwareService {
    pub async fn agent_prepare_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        super::run_recovery::lock_device(tx, p.device()).await?;
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
        let binding = crate::deployment::agent_facts::agent_binding_in(
            tx,
            service.transactions.agent_store.clone(),
            *p.device(),
        )
        .await?
        .ok_or(Error::Forbidden)?;
        let software_capable = binding.software();
        let versions = crate::deployment::sources::admission::agent_versions_in(tx, *p.device())
            .await?
            .into_iter()
            .map(|version| (version, Uuid::new_v4()))
            .collect::<Vec<_>>();
        let partitions = [];

        crate::deployment::transaction::prepare_audit_in(
            &service.transactions.audit_store,
            tx,
            audit,
            &partitions,
        )
        .await?;
        for (id, run_id) in versions {
            let policy =
                db::load_policy_version(&service.transactions.policy_reader, tx, id).await?;
            let target = crate::deployment::Target {
                device: *p.device(),
            };
            match &policy {
                db::ScheduledPolicy::Software(software) if software_capable => {
                    super::software::accept_for_device(
                        &service.transactions,
                        tx,
                        software,
                        &target,
                        now,
                        run_id,
                    )
                    .await?
                }
                _ => (),
            }
        }
        Ok(())
    }
    #[expect(
        clippy::cognitive_complexity,
        reason = "offer admission checks current device, capability and original task state in one transaction"
    )]
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
        let event_key = format!("agent:{}:offer:{}", p.device(), input.operation_id());
        let binding = crate::deployment::agent_facts::agent_binding_in(
            tx,
            self.transactions.agent_store.clone(),
            *p.device(),
        )
        .await?
        .ok_or(Error::Forbidden)?;
        let mut offer = None;
        let mut offer_activity = None;
        let mut run = db::load_run(tx, id).await?;
        belongs(&run, p)?;
        let plan = db::load_source(&service.transactions, tx, run.source).await?;
        let previous = run.state.clone();
        run.state.expire(now);
        let capable = match &plan {
            db::ScheduledPolicy::Software(software) => {
                software
                    .assignment
                    .supported_in(&service.transactions.admission(), tx, &binding)
                    .await?
            }
        };
        let waiting_ready = if run.state.execution == Execution::NotStarted
            && run.state.cancellation == Cancellation::None
            && now < run.deadline
        {
            crate::deployment::self_service::advance_waiting_in(service, tx, &mut run, &plan, now)
                .await?
        } else {
            true
        };
        let allowed = capable
            && waiting_ready
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
            let mut activity = super::activity::run(
                &run,
                rss_mdm_audit_integration::activity::ActivityPhase::Offered,
            );
            if let wire::TaskPayload::Software(spec) = &payload {
                activity.links.steps = spec
                    .steps
                    .iter()
                    .map(|s| super::activity::step_id(&s.step_id))
                    .collect();
            }
            offer_activity = Some(activity);
            offer = Some(payload);
        }
        db::save_run(
            &service.transactions.policy_reader,
            &service.transactions.reconcile_messaging,
            tx,
            &run,
        )
        .await?;
        self.transactions
            .lifecycle
            .wake_in(
                &service.transactions.reconcile_messaging,
                tx,
                &run.target.device,
            )
            .await?;
        offer
            .map(|payload| {
                if let wire::TaskPayload::Software(task) = &payload {
                    crate::preparation::execution::validate_task_admission(task)
                        .map_err(|_| Error::Forbidden)?;
                }
                let fact = Fact::business(
                    audit,
                    rss_mdm_audit_integration::operation::OperationOwner::SoftwareAction,
                    &event_key,
                    200,
                    "success",
                    None,
                )?
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
        let plan = db::load_source(&self.transactions, tx, run.source).await?;
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
        crate::deployment::transaction::prepare_audit_in(
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
        let plan = db::load_source(&self.transactions, tx, run.source).await?;
        crate::deployment::transaction::prepare_audit_in(
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
    #[expect(
        clippy::cognitive_complexity,
        reason = "event handling keeps original attempt, replay, result and audit branches together"
    )]
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
        crate::deployment::transaction::prepare_audit_in(
            &service.transactions.audit_store,
            tx,
            audit,
            &[],
        )
        .await?;
        run.source.audit(audit);
        audit.target(&id.to_string());
        let plan = db::load_source(&service.transactions, tx, run.source).await?;

        let now = storage::now(tx).await?;
        let event_key = format!(
            "agent:{}:task:{id}:event:{}",
            p.device(),
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

        let mut software_audit = None;
        match input.event() {
            wire::TaskEvent::Result(_)
            | wire::TaskEvent::CollectionResult(_)
            | wire::TaskEvent::ChunkedCollectionResult { .. }
            | wire::TaskEvent::OutputChunk(_)
            | wire::TaskEvent::ChunkedResult(_) => return Err(Error::Malformed.into()),

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
            }
            wire::TaskEvent::SoftwareResult(result) => {
                let db::ScheduledPolicy::Software(software) = &plan;
                let super::evidence::Material::Software {
                    platform: _,
                    intent,
                    definition_digest,
                    steps,
                } = super::evidence::load_in(
                    service.transactions.agent_store.clone(),
                    tx,
                    id,
                    input.attempt_id(),
                )
                .await?;
                let assessment = crate::preparation::evidence::assess_execution(
                    result,
                    intent,
                    definition_digest,
                    &steps,
                )
                .map_err(|_| Error::Malformed)?;
                let intended = match software.assignment.intent() {
                    rss_mdm_policy::SoftwareIntent::RequiredInstall
                    | rss_mdm_policy::SoftwareIntent::AvailableInstall => {
                        wire::SoftwareTaskIntent::Install
                    }
                    rss_mdm_policy::SoftwareIntent::ExplicitUninstall => {
                        wire::SoftwareTaskIntent::Uninstall
                    }
                };
                if intent != intended {
                    return Err(Error::Malformed.into());
                }
                let observed_at = result
                    .steps
                    .iter()
                    .filter_map(|s| match s.after {
                        wire::SoftwareDetectionObservation::Present { observed_at, .. }
                        | wire::SoftwareDetectionObservation::Absent { observed_at, .. } => {
                            Some(observed_at)
                        }
                        wire::SoftwareDetectionObservation::Unknown { .. } => None,
                    })
                    .max();
                if observed_at.is_some_and(|at| {
                    at > now || run.state.started_at.is_none_or(|start| at < start)
                }) {
                    return Err(Error::Malformed.into());
                }
                let trusted = run.state.started_at.is_some()
                    && matches!(
                        run.state.execution,
                        Execution::Running | Execution::Unknown | Execution::WaitingReboot
                    );
                use crate::preparation::evidence::SoftwareEvidenceAssessment as Assessment;
                let effect = match (trusted, assessment) {
                    (false, _) | (_, Assessment::Unknown) => {
                        run.state.uncertain_result(input.attempt_id())?;
                        "unknown"
                    }
                    (true, Assessment::RebootPending) => {
                        run.state.waiting_reboot(input.attempt_id())?;
                        "waiting_reboot"
                    }
                    (true, Assessment::Satisfied) => {
                        run.state.result(input.attempt_id(), true)?;
                        "verified"
                    }
                    (true, Assessment::Unsatisfied) => {
                        run.state.result(input.attempt_id(), false)?;
                        "failed"
                    }
                };
                let previous_effect = run
                    .result
                    .as_ref()
                    .and_then(super::result::RunResult::effect)
                    .map(str::to_owned);
                let evidence = result.clone();
                software_audit = Some(
                    json!({"taskId":id,"attemptId":input.attempt_id(),"previousEffect":previous_effect,
                        "effect":effect,"definitionDigest":result.definition_digest,"steps":result.steps}),
                );
                let observed_at = observed_at
                    .map(|at| at.checked_mul(1_000_000).ok_or(Error::Malformed))
                    .transpose()?;
                let received_at = super::software::effect_received_at(tx).await?;
                run.result = Some(super::result::RunResult::Software(
                    super::result::Software {
                        intent: result.intent,
                        definition_digest: result.definition_digest,
                        evidence,
                        effect: stored(serde_json::from_value(json!(effect)))?,
                        effect_observed_at: observed_at,
                        effect_received_at: received_at,
                        received_at: now,
                    },
                ));
            }
            _ => return Err(Error::Malformed.into()),
        }
        db::save_run(
            &service.transactions.policy_reader,
            &service.transactions.reconcile_messaging,
            tx,
            &run,
        )
        .await?;
        self.transactions
            .lifecycle
            .wake_in(
                &service.transactions.reconcile_messaging,
                tx,
                &run.target.device,
            )
            .await?;
        let fact = Fact::business(
            audit,
            rss_mdm_audit_integration::operation::OperationOwner::SoftwareAction,
            &event_key,
            200,
            "success",
            None,
        )?;
        let fact = if let Some(details) = software_audit.clone() {
            fact.with_details(details)?
        } else {
            fact
        };
        let mut activity = super::activity::run(&run, super::activity::phase(input.event()));
        activity.links.request.get_or_insert(input.operation_id());
        activity.reporting = match activity.phase {
            rss_mdm_audit_integration::activity::ActivityPhase::Reporting => {
                Some(ActivityReporting::Partial)
            }
            rss_mdm_audit_integration::activity::ActivityPhase::Result => {
                Some(ActivityReporting::Acknowledged)
            }
            _ => None,
        };
        if let wire::TaskEvent::SoftwareResult(result) = input.event() {
            activity.links.steps = result
                .steps
                .iter()
                .map(|s| super::activity::step_id(&s.step_id))
                .collect();
        }
        let fact = fact.with_activity(&activity)?;
        if let Some(wire::TaskPayload::Software(task)) = &permit {
            crate::preparation::execution::validate_task_admission(task)
                .map_err(|_| Error::Forbidden)?;
        }
        Ok(EventEffects {
            start: permit,
            cancelled: !allowed || run.state.cancellation != Cancellation::None,
            fact,
        })
    }
    pub async fn agent_content_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        id: Uuid,
        attempt: Uuid,
        key: Option<&str>,
        audit: &RequestAudit,
    ) -> Result<rss_mdm_resource::Artifact> {
        self.transactions.runtime.validate_transaction(tx)?;
        let service = self;
        super::run_recovery::lock_device(tx, p.device()).await?;
        principal(&service.transactions, tx, p).await?;
        let run = db::load_run(tx, id).await?;
        belongs(&run, p)?;
        run.source.audit(audit);
        audit.target(&id.to_string());
        let plan = db::load_source(&service.transactions, tx, run.source).await?;

        let now = storage::now(tx).await?;
        let allowed = if run.state.started_at.is_some() {
            plan.completion_authorized_in(&service.transactions, tx, &run.target, now)
                .await?
        } else {
            plan.authorized_run_in(&service.transactions, tx, &run, now)
                .await?
        };
        if run.state.attempt() != Some(attempt)
            || run.deadline <= now
            || run.state.cancellation != Cancellation::None
            || !matches!(
                run.state.execution,
                Execution::NotStarted | Execution::Running
            )
            || !allowed
        {
            return Err(Error::Forbidden.into());
        }
        match plan {
            db::ScheduledPolicy::Software(software) => {
                let key = key.ok_or(Error::Malformed)?;
                let (index, local_key) = key.split_once('/').ok_or(Error::Malformed)?;
                let index: usize = index.parse().map_err(|_| Error::Malformed)?;
                let (platform, architecture) =
                    db::agent_profile_in(&service.transactions, tx, run.target.device)
                        .await?
                        .ok_or(Error::Forbidden)?;
                let artifact = software
                    .assignment
                    .artifact_in(
                        &service.transactions.admission(),
                        tx,
                        platform,
                        architecture,
                        index,
                        local_key,
                    )
                    .await?;
                let super::evidence::Material::Software { steps, .. } = super::evidence::load_in(
                    service.transactions.agent_store.clone(),
                    tx,
                    id,
                    attempt,
                )
                .await?;
                let offered = steps
                    .get(index)
                    .and_then(|s| s.artifacts.iter().find(|a| a.key == key))
                    .ok_or(Error::Forbidden)?;
                if offered.length != artifact.length()
                    || offered.sha256 != artifact.digest().bytes()
                {
                    return Err(Error::Forbidden.into());
                }
                Ok(artifact)
            }
        }
    }
    pub async fn agent_cancellations_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: rss_mdm_agent_wire::DeviceId,
        after: Option<Uuid>,
    ) -> Result<Vec<wire::TaskCancellation>> {
        self.transactions.runtime.validate_transaction(tx)?;
        super::poll::cancellations(tx, device, after).await
    }
}
use rss_mdm_audit_integration::RequestAudit;
