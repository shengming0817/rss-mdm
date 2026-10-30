//! Policy discovery creates device targets; admission never holds a page of device locks.
use super::{production, storage as db};
use crate::{Error, ExecutionService, Result, Target, storage};
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
    let target = rss_reconcile::Target::new(crate::recovery_scope(tx.tenant_id()), work.entity())
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

/// Called under the Policy discovery claim. Its fixed window does not acknowledge a later wake.
pub(crate) async fn discover_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
) -> Result<()> {
    let Some(current) =
        crate::sources::storage::read_in(&service.transactions.policy_reader, tx, policy).await?
    else {
        return Ok(());
    };
    let tenant = tx.tenant_id().to_string();
    let (revision,consumed,mut window,mut after) = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.policy_recovery(tenant_id,policy) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(&tenant).bind(policy).execute(&mut *c).await?;
        sqlx::query_as::<_,(i64,i64,i64,Option<String>)>("SELECT input_revision,input_consumed,input_window,target_after FROM mdm_commands.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE").bind(tenant).bind(policy).fetch_one(c).await
    })).await?;
    if consumed == window {
        window = revision;
        after = None;
    }
    if consumed == window {
        return Ok(());
    }
    let kind = current.definition.action.kind();
    let enabled = current.state.is_enabled();
    let supported = kind == rss_mdm_policy::ActionKind::NativeCollection
        || kind == rss_mdm_policy::ActionKind::Software;
    let tenant = tx.tenant_id().to_string();
    let version = current.version;
    let rows = if enabled && supported {
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT DISTINCT r.device COLLATE \"C\" AS device,r.id,r.generation FROM mdm_policy.assignments a JOIN mdm_access.registrations r ON r.tenant_id=a.tenant_id AND r.device=a.target->>'device' AND r.channel=a.channel AND r.state='active' AND r.purpose='primary' WHERE a.tenant_id=$1::uuid AND a.policy=$2 AND a.version=$3 AND a.availability='ready' AND r.device>coalesce($4,'') COLLATE \"C\" ORDER BY r.device COLLATE \"C\",r.id LIMIT 33")
                .bind(tenant).bind(policy).bind(version).bind(after).fetch_all(c).await
        })).await?
    } else {
        Vec::new()
    };
    for row in rows.iter().take(32) {
        wake_in(
            &service.transactions.reconcile_messaging,
            tx,
            Work {
                version,
                registration: row.try_get("id")?,
                generation: row.try_get("generation")?,
            },
        )
        .await?;
    }
    let more = rows.len() > 32;
    let after = if more {
        Some(rows[31].try_get::<String, _>("device")?)
    } else {
        None
    };
    let consumed = if more { consumed } else { window };
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_commands.policy_recovery SET input_consumed=$3,input_window=$4,target_after=$5 WHERE tenant_id=$1::uuid AND policy=$2").bind(tenant).bind(policy).bind(consumed).bind(window).bind(after).execute(c).await?;
        Ok(())
    })).await?;
    Ok(())
}

pub(crate) async fn advance_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    work: Work,
    run: Uuid,
) -> Result<()> {
    let Some(device) = device_in(tx, work).await? else {
        return Ok(());
    };
    let plan =
        db::load_policy_version(&service.transactions.policy_reader, tx, work.version).await?;
    let target = Target {
        device,
        registration: work.registration,
        generation: work.generation,
    };
    let now = storage::now(tx).await?;
    match &plan {
        db::ScheduledPolicy::Native(_) => {
            production::accept_for_device(
                &service.transactions,
                tx,
                &plan,
                &target,
                production::AdmissionTrigger::Scheduled,
                now,
                run,
            )
            .await
        }
        db::ScheduledPolicy::Software(software) => {
            super::software::accept_for_device(
                &service.transactions,
                tx,
                software,
                &target,
                now,
                run,
            )
            .await
        }
        _ => Ok(()),
    }
}

/// Calendar work sleeps until useful again; a retired version/registration converges.
pub(crate) async fn delay_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    work: Work,
) -> Result<Option<std::time::Duration>> {
    let Some(device) = device_in(tx, work).await? else {
        return Ok(None);
    };
    let plan =
        db::load_policy_version(&service.transactions.policy_reader, tx, work.version).await?;
    let now = storage::now(tx).await?;
    let seconds = match plan {
        db::ScheduledPolicy::Native(native) => {
            let target = Target {
                device,
                registration: work.registration,
                generation: work.generation,
            };
            let last = production::collection_started_in(tx, work.version, &target).await?;
            if now >= native.frozen.input.schedule.ends_at() {
                return Ok(None);
            }
            match (&native.frozen.input.schedule.trigger, last) {
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
        db::ScheduledPolicy::Software(software) => {
            if now >= software.assignment.frozen.schedule.ends_at() {
                return Ok(None);
            }
            let tenant = tx.tenant_id().to_string();
            let pending:bool=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND policy_version=$2 AND registration=$3 AND generation=$4 AND state->>'execution' IN('not_started','running','waiting_reboot','unknown') AND state->>'cancellation'<>'confirmed')").bind(tenant).bind(work.version).bind(work.registration).bind(work.generation).fetch_one(c).await})).await?;
            if pending {
                return Ok(None);
            }
            let target = Target {
                device,
                registration: work.registration,
                generation: work.generation,
            };
            let schedule = &software.assignment.frozen.schedule;
            if schedule.not_before > now {
                return Ok(Some(bounded_delay(std::time::Duration::from_secs(
                    (schedule.not_before - now) as u64,
                ))));
            }
            if software
                .assignment
                .entry_in(&service.transactions.source, tx, &target.device, now)
                .await?
                .is_none()
            {
                return Ok(None);
            }
            match super::software::slot_in(
                &service.transactions,
                tx,
                &software,
                &target,
                None,
                now,
                None,
            )
            .await?
            {
                super::software::Preparation::Satisfied => return Ok(None),
                super::software::Preparation::Waiting(delay) => {
                    return Ok(Some(bounded_delay(delay)));
                }
                super::software::Preparation::NotEligible => {
                    match schedule.next_after(now, target.device.as_bytes())? {
                        Some(next) => next.available_at.saturating_sub(now).max(1),
                        None => return Ok(None),
                    }
                }
                super::software::Preparation::Ready(_) => 5,
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

#[cfg(feature = "integration")]
impl ExecutionService {
    pub async fn recover_scheduled_fixture(
        &self,
        version: Uuid,
        registration: Uuid,
        generation: i64,
    ) -> std::result::Result<(), Error> {
        self.recover_entity_fixture(
            Work {
                version,
                registration,
                generation,
            }
            .entity(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maximum_generation_keeps_a_bounded_durable_identity() {
        let work = Work {
            version: Uuid::from_u128(1),
            registration: Uuid::from_u128(2),
            generation: i64::MAX,
        };
        let entity = work.entity();
        let tenant =
            rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000003").unwrap();
        assert!(rss_reconcile::Target::new(crate::recovery_scope(tenant), entity.clone()).is_ok());
        assert_eq!(Work::parse(&entity).unwrap().generation, i64::MAX);
    }
}
