//! Policy discovery creates device targets; admission never holds a page of device locks.
use super::{CollectionService, admission as production, model::Target, policy, storage};
use crate::{Error, transaction::Result};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

/// Ephemeral proof of a current, enabled version owned by this scheduler.
/// Private fields and no deserialization prevent persisted work from becoming authority.
pub struct VerifiedNativeCollectionVersion<'a> {
    reader: &'a rss_mdm_policy_postgres::PolicyReader,
    version: Uuid,
}
impl<'a> VerifiedNativeCollectionVersion<'a> {
    pub async fn verify_in(
        reader: &'a rss_mdm_policy_postgres::PolicyReader,
        tx: &mut PgTransaction<'_>,
        version: Uuid,
    ) -> Result<Option<Self>> {
        let stored_version = crate::transaction::checked(reader.version_in(tx, version).await?)?
            .ok_or(crate::Error::Unavailable(crate::Failure::PlanningStorage))?;
        if stored_version.action_kind != rss_mdm_policy::ActionKind::NativeCollection {
            return Ok(None);
        }
        let frozen: super::frozen::Published =
            crate::transaction::stored(serde_json::from_value(stored_version.frozen))?;
        if !matches!(frozen, super::frozen::Published::NativeCollection { .. }) {
            return Err((crate::Error::Unavailable(crate::Failure::PlanningStorage)).into());
        }
        let policy =
            crate::transaction::checked(reader.locked_in(tx, stored_version.policy).await?)?
                .ok_or(crate::Error::Unavailable(crate::Failure::PlanningStorage))?;
        if policy.version != version {
            return Ok(None);
        }
        if policy.definition.action.kind() != rss_mdm_policy::ActionKind::NativeCollection {
            return Err((crate::Error::Unavailable(crate::Failure::PlanningStorage)).into());
        }
        if !policy.state.is_enabled() {
            return Ok(None);
        }
        Ok(Some(Self { reader, version }))
    }
    /// Revalidate on the borrowing transaction; a proof cannot act as a cached authorization lease.
    pub async fn wake_assignment_in(
        &self,
        reconcile: &rss_reconcile_postgres::PgMessagingStore,
        tx: &mut PgTransaction<'_>,
        target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
    ) -> Result<()> {
        if target.channel.as_str() != "mdm" {
            return Ok(());
        }
        let work = Work {
            version: self.version,
            device: target.device.clone(),
        };
        if let Some(device) = device_in(self.reader, tx, &work).await?
            && device != target.device
        {
            return Err(Error::Unavailable(crate::Failure::PlanningStorage).into());
        }
        wake_in(
            reconcile,
            tx,
            self,
            &Work {
                version: self.version,
                device: target.device.clone(),
            },
        )
        .await
    }
}

#[derive(Clone)]
pub(crate) struct Work {
    pub version: Uuid,
    pub device: String,
}
impl Work {
    pub(crate) fn parse(entity: &str) -> Option<Self> {
        let mut fields = entity.strip_prefix("scheduled:")?.split(':');
        let value = Self {
            version: fields.next()?.parse().ok()?,
            device: fields.next()?.to_owned(),
        };
        (fields.next().is_none() && !value.device.is_empty()).then_some(value)
    }
    fn entity(&self) -> String {
        format!("scheduled:{}:{}", self.version, self.device)
    }
}

pub(crate) async fn wake_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    verified: &VerifiedNativeCollectionVersion<'_>,
    work: &Work,
) -> Result<()> {
    if verified.version != work.version {
        return Err((crate::Error::Unavailable(crate::Failure::PlanningStorage)).into());
    }
    if device_in(verified.reader, tx, &work).await?.is_none() {
        return Ok(());
    }
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

pub(crate) async fn device_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    work: &Work,
) -> Result<Option<String>> {
    if VerifiedNativeCollectionVersion::verify_in(reader, tx, work.version)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    if work.device.is_empty() {
        return Err((crate::Error::Unavailable(crate::Failure::PlanningStorage)).into());
    }
    let tenant = tx.tenant_id().to_string();
    let device = work.device.clone();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT id AS device FROM mdm_access.devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND state = 'active' AND purpose = 'primary' AND channel = 'mdm'")
            .bind(tenant).bind(device).fetch_optional(c).await
    })).await?)
}

pub(crate) async fn advance_in(
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    work: &Work,
    run: Uuid,
) -> Result<()> {
    let Some(device) = device_in(&service.transactions.policy_reader, tx, &work).await? else {
        return Ok(());
    };
    let plan = policy::read_in(&service.transactions, tx, work.version).await?;
    let target = Target { device };
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

/// Calendar work sleeps until useful again; a retired version/device converges.
pub(crate) async fn delay_in(
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    work: &Work,
) -> Result<Option<std::time::Duration>> {
    let Some(device) = device_in(&service.transactions.policy_reader, tx, &work).await? else {
        return Ok(None);
    };
    let plan = policy::read_in(&service.transactions, tx, work.version).await?;
    let now = storage::now(tx).await?;
    let seconds = match plan.frozen {
        super::frozen::Published::NativeCollection { action: native, .. } => {
            let target = Target { device };
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
