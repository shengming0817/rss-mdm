//! Enrollment participates in Agent requests; Agent owns signatures and protocol receipts.
use crate::DevicePrincipal;
use crate::enrollment::tasks::{Error, Result, Service, Target, policy, runs::Run, storage};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::{
    Fact, RequestAudit,
    activity::{ActivityPhase, ActivityReporting},
};
use rss_mdm_task_state::{Cancellation, Execution};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;

pub struct EventEffects {
    pub start: Option<wire::TaskPayload>,
    pub cancelled: bool,
    pub fact: Fact,
}
pub(crate) fn belongs(run: &Run, p: &DevicePrincipal) -> Result<()> {
    if run.target.device != p.device()
        || run.target.registration != p.registration()
        || run.target.generation != p.generation()
    {
        return Err(Error::Unauthorized.into());
    }
    Ok(())
}
impl Service {
    pub async fn agent_prepare_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
    ) -> Result<()> {
        let profile = self.profile();

        self.transactions.validate_in(tx)?;
        if self.profile() != p.profile() || tx.tenant_id() != p.tenant() {
            return Err(Error::Unauthorized.into());
        }
        storage::lock_device(profile, tx, p.device()).await?;
        let checked = p.clone();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(crate::device::store::revalidate_source(
                    profile,
                    c,
                    &checked,
                    rss_mdm_inventory::ReportSource::AgentBuiltin,
                )
                .await)
            })
        })
        .await??;
        if !crate::enrollment::tasks::agent_facts::agent_binding_in(
            profile,
            tx,
            self.transactions.agent_store.clone(),
            p.registration(),
        )
        .await?
        .is_some_and(|b| b.inventory() && b.enrollment())
        {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }

    /// Admission is separate from candidate capture so App can retain one global poll budget.
    pub async fn agent_admit_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        input: &wire::TaskClaimRequest,
    ) -> Result<()> {
        let profile = self.profile();

        self.agent_prepare_in(tx, p).await?;
        let tenant = tx.tenant_id().to_string();
        let registration = p.registration();
        let versions = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(
                        crate::storage_profile::sql(profile)
                            .enrollment_tasks_agent_agent_admit_in_1,
                    )
                    .bind(&tenant)
                    .bind(registration)
                    .execute(&mut *c)
                    .await?;
                    let after: Option<Uuid> = sqlx::query_scalar(
                        crate::storage_profile::sql(profile)
                            .enrollment_tasks_agent_agent_admit_in_2,
                    )
                    .bind(&tenant)
                    .bind(registration)
                    .fetch_one(&mut *c)
                    .await?;
                    let rows = sqlx::query(
                        crate::storage_profile::sql(profile)
                            .enrollment_tasks_agent_agent_admit_in_3,
                    )
                    .bind(&tenant)
                    .bind(after)
                    .fetch_all(&mut *c)
                    .await?;
                    let next = if rows.len() == 64 {
                        rows.last()
                            .map(|r| r.try_get::<Uuid, _>("id"))
                            .transpose()?
                    } else {
                        None
                    };
                    sqlx::query(
                        crate::storage_profile::sql(profile)
                            .enrollment_tasks_agent_agent_admit_in_4,
                    )
                    .bind(tenant)
                    .bind(registration)
                    .bind(next)
                    .execute(c)
                    .await?;
                    rows.into_iter()
                        .map(|r| r.try_get::<Uuid, _>("current_version"))
                        .collect::<std::result::Result<Vec<_>, sqlx::Error>>()
                })
            })
            .await?;
        let now = storage::now(tx).await?;
        let target = Target {
            device: p.device().into(),
            registration: p.registration(),
            generation: p.generation(),
        };
        for version in versions {
            let plan = policy::read_in(&self.transactions, tx, version).await?;
            crate::enrollment::tasks::admission::accept_for_device(
                profile,
                &self.transactions,
                tx,
                &plan,
                &target,
                crate::enrollment::tasks::admission::TriggerInput::Agent(input.operation_id()),
                now,
                Uuid::new_v4(),
            )
            .await?;
        }
        Ok(())
    }

    /// Inspect one candidate from App's captured, globally bounded ordered page.
    pub async fn agent_offer_one_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        id: Uuid,
        attempt: Uuid,
        audit: &RequestAudit,
    ) -> Result<Option<(wire::TaskPayload, Fact, i64)>> {
        let profile = self.profile();

        self.agent_prepare_in(tx, p).await?;
        self.transactions
            .audit_store
            .prepare_in(tx, audit, &[])
            .await?;
        let now = storage::now(tx).await?;
        let mut run = storage::load_run(profile, tx, id).await?;
        belongs(&run, p)?;
        let plan = policy::read_in(&self.transactions, tx, run.policy_version).await?;
        let previous = run.state.clone();
        run.state.expire(now);
        if !plan.active {
            run.state.cancel();
        }
        let waiting_ready = if run.state.execution == Execution::NotStarted
            && run.state.cancellation == Cancellation::None
            && now < run.deadline
        {
            crate::enrollment::tasks::self_service::advance_waiting_in(
                profile, self, tx, &mut run, &plan, now,
            )
            .await?
        } else {
            true
        };
        crate::enrollment::tasks::recovery::audit_recovery(self, tx, &run, &previous).await?;
        let offer = if waiting_ready
            && run.state.cancellation == Cancellation::None
            && run.available_at <= now
            && plan.authorized_run_in(&self.transactions, tx, &run).await?
        {
            if run.state.claim(attempt, now).is_ok() {
                let payload = plan
                    .task(
                        &self.transactions,
                        tx,
                        &run,
                        attempt,
                        wire::TaskPermit::Offer,
                        (now + 60).min(run.deadline),
                    )
                    .await?;
                audit.plan(run.policy_version);
                audit.target(&run.id.to_string());
                let fact = Fact::business(
                    audit,
                    &format!("enrollment:{id}:offer:{attempt}"),
                    200,
                    "success",
                    None,
                )?
                .with_activity(&crate::enrollment::tasks::activity::run(
                    &run,
                    ActivityPhase::Offered,
                ))?;
                Some((payload, fact, run.deadline))
            } else {
                None
            }
        } else {
            None
        };
        storage::save_run(profile, &self.transactions, tx, &run).await?;
        Ok(offer)
    }
    pub async fn agent_replay_offer_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        signed: &wire::SignedTask,
        audit: &RequestAudit,
    ) -> Result<()> {
        let profile = self.profile();

        self.agent_prepare_in(tx, p).await?;
        let run = storage::load_run(profile, tx, signed.payload.task_id()).await?;
        belongs(&run, p)?;
        audit.plan(run.policy_version);
        audit.target(&run.id.to_string());
        let plan = policy::read_in(&self.transactions, tx, run.policy_version).await?;
        let now = storage::now(tx).await?;
        if run.state.cancellation != Cancellation::None
            || run.state.execution != Execution::NotStarted
            || run.state.attempt() != Some(signed.payload.attempt_id())
            || signed.payload.expires_at() <= now
            || !plan.authorized_run_in(&self.transactions, tx, &run).await?
        {
            return Err(Error::Conflict.into());
        }
        self.transactions
            .audit_store
            .prepare_in(tx, audit, &[])
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
        let profile = self.profile();

        self.agent_prepare_in(tx, p).await?;
        let run = storage::load_run(profile, tx, id).await?;
        belongs(&run, p)?;
        audit.plan(run.policy_version);
        audit.target(&id.to_string());
        self.transactions
            .audit_store
            .prepare_in(tx, audit, &[])
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
            let plan = policy::read_in(&self.transactions, tx, run.policy_version).await?;
            if !plan.authorized_run_in(&self.transactions, tx, &run).await? {
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
        let profile = self.profile();

        self.agent_prepare_in(tx, p).await?;
        let mut run = storage::load_run(profile, tx, id).await?;
        belongs(&run, p)?;
        self.transactions
            .audit_store
            .prepare_in(tx, audit, &[])
            .await?;
        audit.plan(run.policy_version);
        audit.target(&id.to_string());
        let plan = policy::read_in(&self.transactions, tx, run.policy_version).await?;
        let now = storage::now(tx).await?;
        let requires_start_authority = matches!(
            input.event(),
            wire::TaskEvent::Start | wire::TaskEvent::Received
        ) || run.state.started_at.is_none();
        let allowed = if requires_start_authority {
            plan.authorized_run_in(&self.transactions, tx, &run).await?
        } else {
            plan.active
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
        let _effect_allowed = allowed && run.state.cancellation == Cancellation::None;
        let mut permit = None;
        match input.event() {
            wire::TaskEvent::Received => run.state.received(input.attempt_id(), now)?,
            wire::TaskEvent::Start => {
                if run.state.execution != Execution::NotStarted {
                    return Err(Error::Conflict.into());
                }
                run.state.start(input.attempt_id(), now)?;
                permit = Some(
                    plan.task(
                        &self.transactions,
                        tx,
                        &run,
                        input.attempt_id(),
                        wire::TaskPermit::Start,
                        run.deadline,
                    )
                    .await?,
                );
            }
            wire::TaskEvent::Cancelled => {
                run.state.cancel();
                run.state.cancelled(input.attempt_id())?;
            }

            wire::TaskEvent::EnrollmentResult { outcome } => {
                if *outcome == wire::EnrollmentEntryOutcome::Unknown {
                    run.state.uncertain_result(input.attempt_id())?;
                } else {
                    run.state.result(
                        input.attempt_id(),
                        *outcome == wire::EnrollmentEntryOutcome::Opened,
                    )?;
                }
                run.result = Some(*outcome);
            }
            _ => return Err(Error::Malformed.into()),
        }
        storage::save_run(profile, &self.transactions, tx, &run).await?;
        let mut activity = crate::enrollment::tasks::activity::run(
            &run,
            crate::enrollment::tasks::activity::phase(input.event()),
        );
        activity.links.request.get_or_insert(input.operation_id());
        activity.reporting = match activity.phase {
            ActivityPhase::Reporting => Some(ActivityReporting::Partial),
            ActivityPhase::Result => Some(ActivityReporting::Acknowledged),
            _ => None,
        };
        let fact = Fact::business(
            audit,
            &format!("enrollment:{id}:event:{}", input.operation_id()),
            200,
            "success",
            None,
        )?
        .with_activity(&activity)?;
        Ok(EventEffects {
            start: permit,
            cancelled: !allowed || run.state.cancellation != Cancellation::None,
            fact,
        })
    }
}
