//! Durable native admission sweeps and individually fenced run recovery.
//! ref: rss_reconcile_postgres::messaging::{wake_in, protect_in};
//! Kubernetes sample-controller/controller.go (one queued object per reconciliation).
use super::{production::AdmissionTrigger, storage as db};
use crate::{Error, ExecutionService, Result, storage};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) enum Work {
    CheckIn { registration: Uuid, generation: i64 },
    Run(Uuid),
}
impl Work {
    pub(crate) fn parse(entity: &str) -> Option<Self> {
        if let Some(id) = entity.strip_prefix("native-run:") {
            return Uuid::parse_str(id).ok().map(Self::Run);
        }
        let (id, generation) = entity.strip_prefix("native-checkin:")?.split_once(':')?;
        Some(Self::CheckIn {
            registration: Uuid::parse_str(id).ok()?,
            generation: generation.parse().ok()?,
        })
    }
    fn entity(self) -> String {
        match self {
            Self::Run(id) => format!("native-run:{id}"),
            Self::CheckIn {
                registration,
                generation,
            } => format!("native-checkin:{registration}:{generation}"),
        }
    }
}
async fn wake(tx: &mut PgTransaction<'_>, work: Work) -> Result<()> {
    let target = rss_reconcile::Target::new(crate::recovery_scope(tx.tenant_id()), work.entity())
        .map_err(|_| Error::Malformed)?;
    rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| Box::pin(async { Ok(()) }))
        .await?;
    crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
    Ok(())
}
pub(crate) async fn wake_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
    wake(tx, Work::Run(id)).await
}
/// Only an accepted, authenticated protocol request records a new check-in.
pub(crate) async fn record(
    tx: &mut PgTransaction<'_>,
    p: &crate::device::DevicePrincipal,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    if p.tenant() != tx.tenant_id() {
        return Err(Error::Unauthorized.into());
    }
    let registration = p.registration();
    let generation = p.generation();
    let event = Uuid::new_v4();
    let at = storage::now(tx).await?;
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.native_checkins(tenant_id,registration,generation,pending_event,pending_at) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT(tenant_id,registration,generation) DO UPDATE SET pending_event=excluded.pending_event,pending_at=excluded.pending_at")
            .bind(tenant).bind(registration).bind(generation).bind(event).bind(at).execute(c).await?;
        Ok(())
    })).await?;
    wake(
        tx,
        Work::CheckIn {
            registration,
            generation,
        },
    )
    .await
}
pub(crate) async fn active(tx: &mut PgTransaction<'_>, work: Work) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        match work {
            Work::CheckIn { registration, generation } => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.native_checkins WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND (active_event IS NOT NULL OR pending_event IS NOT NULL))")
                .bind(tenant).bind(registration).bind(generation).fetch_one(c).await,
            Work::Run(id) => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2 AND state->>'execution' IN('not_started','running','unknown') AND state->>'cancellation'<>'confirmed')")
                .bind(tenant).bind(id).fetch_one(c).await,
        }
    })).await?)
}
pub(crate) async fn step(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    work: Work,
) -> Result<bool> {
    match work {
        Work::Run(id) => {
            let tenant = tx.tenant_id().to_string();
            let device: String = tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar("SELECT device FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
                    .bind(tenant).bind(id).fetch_one(c).await
            })).await?;
            storage::lock(tx, &device).await?;
            super::recovery::recover_one(service, tx, id).await?;
            Ok(false)
        }
        Work::CheckIn {
            registration,
            generation,
        } => checkin_step(service, tx, registration, generation).await,
    }
}
async fn checkin_step(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    generation: i64,
) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let state = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_commands.native_checkins SET active_event=pending_event,active_at=pending_at,pending_event=NULL,pending_at=NULL,policy_after=NULL WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND active_event IS NULL AND pending_event IS NOT NULL")
            .bind(&tenant).bind(registration).bind(generation).execute(&mut *c).await?;
        sqlx::query("SELECT s.active_event,s.active_at,s.policy_after,r.device,(r.state='active' AND r.generation=s.generation) AS current FROM mdm_commands.native_checkins s JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(s.tenant_id,s.registration) WHERE s.tenant_id=$1::uuid AND s.registration=$2 AND s.generation=$3 FOR UPDATE OF s")
            .bind(tenant).bind(registration).bind(generation).fetch_optional(c).await
    })).await?;
    let Some(state) = state else { return Ok(false) };
    let current: bool = state.try_get("current")?;
    let event: Option<Uuid> = state.try_get("active_event")?;
    if !current || event.is_none() {
        clear(tx, registration, generation, !current).await?;
        return Ok(false);
    }
    let event = event.ok_or(Error::Malformed)?;
    let at: i64 = state.try_get("active_at")?;
    let after: Option<Uuid> = state.try_get("policy_after")?;
    let device: String = state.try_get("device")?;
    storage::lock(tx, &device).await?;
    let tenant = tx.tenant_id().to_string();
    let next: Option<(Uuid, Uuid)> = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as("SELECT id,current_version FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND state='enabled' AND definition->'action'->>'kind'='native_collection' AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 1")
            .bind(tenant).bind(after).fetch_optional(c).await
    })).await?;
    let Some((policy, version)) = next else {
        clear(tx, registration, generation, false).await?;
        // A subsequent claim promotes the latest event; never restart this sweep in-place.
        return Ok(false);
    };
    let plan = db::load_policy_version(&service.policy_reader, tx, version).await?;
    if let db::ScheduledPolicy::Native(native) = &plan {
        use rss_mdm_policy::schedule::Trigger;
        let trigger = match native.frozen.input.schedule.trigger {
            Trigger::CheckIn { .. } => Some(AdmissionTrigger::CheckIn { event, at }),
            Trigger::Registration => Some(AdmissionTrigger::Registration { at }),
            _ => None,
        };
        if let Some(trigger) = trigger {
            let target = crate::Target {
                device,
                registration,
                generation,
            };
            let now = storage::now(tx).await?;
            super::production::accept_for_device(service, tx, &plan, &target, trigger, now).await?;
        }
    }
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_commands.native_checkins SET policy_after=$4 WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
            .bind(tenant).bind(registration).bind(generation).bind(policy).execute(c).await?;
        Ok(())
    })).await?;
    Ok(true)
}
async fn clear(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    generation: i64,
    stale: bool,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_commands.native_checkins SET active_event=NULL,active_at=NULL,policy_after=NULL,pending_event=CASE WHEN $4 THEN NULL ELSE pending_event END,pending_at=CASE WHEN $4 THEN NULL ELSE pending_at END WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
            .bind(tenant).bind(registration).bind(generation).bind(stale).execute(c).await?;
        Ok(())
    })).await?;
    Ok(())
}

#[cfg(feature = "integration")]
impl ExecutionService {
    /// Fault-test one real run transaction, without a device-wide recovery scan.
    pub async fn recover_native_run_fixture(&self, id: Uuid) -> std::result::Result<(), Error> {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            self.tenant.to_string(),
            "command_reconcile",
        );
        let result = crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            &audit,
            (self, id),
            |ctx, tx| Box::pin(async move { step(ctx.0, tx, Work::Run(ctx.1)).await.map(|_| ()) }),
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
