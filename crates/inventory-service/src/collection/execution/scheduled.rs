//! Policy discovery creates device targets; admission never holds a page of device locks.
use super::{CollectionService, admission as production, model::Target, policy, storage};
use crate::{Error, transaction::Result};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) struct Work {
    pub version: Uuid,
    pub registration: Uuid,
    pub generation: i64,
}
impl Work {
    pub(crate) fn parse(entity: &str) -> Option<Self> {
        let mut fields = entity.strip_prefix("scheduled:")?.split(':');
        let value = Self {
            version: fields.next()?.parse().ok()?,
            registration: fields.next()?.parse().ok()?,
            generation: fields.next()?.parse().ok()?,
        };
        (fields.next().is_none() && value.generation > 0).then_some(value)
    }
    fn entity(self) -> String {
        format!(
            "scheduled:{}:{}:{}",
            self.version, self.registration, self.generation
        )
    }
}

pub(crate) async fn wake_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    work: Work,
) -> Result<()> {
    let target = rss_reconcile::Target::new(super::wake::scope(tx.tenant_id()), work.entity())
        .map_err(|_| Error::Malformed)?;
    reconcile
        .wake_in(
            tx,
            &target,
            &rss_reconcile::ResourceSet::empty(target.scope().tenant()),
            (),
            |_, _| Box::pin(async { Ok(()) }),
        )
        .await?;
    Ok(())
}

pub(crate) async fn device_in(tx: &mut PgTransaction<'_>, work: Work) -> Result<Option<String>> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        // The existing Policy kernel holds a shared barrier without granting
        // Execution UPDATE privilege on authored policies. Re-read after that lock.
        sqlx::query("SELECT mdm_policy.lock_policy(policy) FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2")
            .bind(&tenant).bind(work.version).execute(&mut *c).await?;
        sqlx::query_scalar("SELECT r.device FROM mdm_access.registrations r JOIN mdm_policy.policies p ON p.tenant_id=r.tenant_id AND p.current_version=$2 AND p.state='enabled' WHERE r.tenant_id=$1::uuid AND r.id=$3 AND r.generation=$4 AND r.state='active'")
            .bind(tenant).bind(work.version).bind(work.registration).bind(work.generation).fetch_optional(c).await
    })).await?)
}

pub(crate) async fn advance_in(
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    work: Work,
    run: Uuid,
) -> Result<()> {
    let Some(device) = device_in(tx, work).await? else {
        return Ok(());
    };
    let plan = policy::read_in(&service.transactions, tx, work.version).await?;
    let target = Target {
        device,
        registration: work.registration,
        generation: work.generation,
    };
    let now = storage::now(tx).await?;
    production::accept_for_device(
        &service.transactions,
        tx,
        &plan,
        &target,
        production::TriggerInput::Scheduled,
        now,
        run,
    )
    .await
}

/// Calendar work sleeps until useful again; a retired version/registration converges.
pub(crate) async fn delay_in(
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    work: Work,
) -> Result<Option<std::time::Duration>> {
    let Some(device) = device_in(tx, work).await? else {
        return Ok(None);
    };
    let plan = policy::read_in(&service.transactions, tx, work.version).await?;
    let now = storage::now(tx).await?;
    let seconds = match plan.frozen {
        super::frozen::Published::NativeCollection { action: native, .. } => {
            let target = Target {
                device,
                registration: work.registration,
                generation: work.generation,
            };
            let last = storage::last_started_in(tx, work.version, &target).await?;
            if now >= native.input.schedule.ends_at() {
                return Ok(None);
            }
            match (&native.input.schedule.trigger, last) {
                (rss_mdm_policy::schedule::Trigger::Interval { seconds, .. }, Some(last)) => last
                    .saturating_add(i64::from(*seconds))
                    .saturating_sub(now)
                    .max(5),
                (rss_mdm_policy::schedule::Trigger::Once { .. }, Some(_)) => return Ok(None),
                (
                    rss_mdm_policy::schedule::Trigger::Manual
                    | rss_mdm_policy::schedule::Trigger::CheckIn { .. }
                    | rss_mdm_policy::schedule::Trigger::Registration,
                    _,
                ) => return Ok(None),
                _ => match native
                    .frozen
                    .input
                    .schedule
                    .next_after(now, target.device.as_bytes())?
                {
                    Some(next) => next.available_at.saturating_sub(now).max(1),
                    None => return Ok(None),
                },
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(bounded_delay(std::time::Duration::from_secs(
        seconds as u64,
    ))))
}

fn bounded_delay(delay: std::time::Duration) -> std::time::Duration {
    delay.clamp(
        std::time::Duration::from_millis(1),
        std::time::Duration::from_secs(86400),
    )
}

/// Assignment updates wake their exact immutable registration generation.
pub async fn wake_assignment_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let native:bool=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2 AND frozen->>'kind'='native_collection')").bind(tenant).bind(version).fetch_one(c).await})).await?;
    if native {
        wake_in(
            reconcile,
            tx,
            Work {
                version,
                registration: target.registration_id,
                generation: target.generation,
            },
        )
        .await?;
    }
    Ok(())
}
