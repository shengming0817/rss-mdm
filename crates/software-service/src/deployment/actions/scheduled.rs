//! Policy discovery creates device targets; admission never holds a page of device locks.
use super::storage as db;
use crate::deployment::{Error, Result, SoftwareService, Target, storage};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;

/// Ephemeral proof of a current, enabled version owned by this scheduler.
/// Private fields and no deserialization prevent persisted work from becoming authority.
pub struct VerifiedSoftwareVersion<'a> {
    reader: &'a rss_mdm_policy_postgres::PolicyReader,
    version: Uuid,
    channel: rss_mdm_policy::SoftwareChannel,
}
impl<'a> VerifiedSoftwareVersion<'a> {
    pub async fn verify_in(
        reader: &'a rss_mdm_policy_postgres::PolicyReader,
        tx: &mut PgTransaction<'_>,
        version: Uuid,
    ) -> Result<Option<Self>> {
        let stored_version =
            crate::deployment::transaction::checked(reader.version_in(tx, version).await?)?.ok_or(
                crate::deployment::Error::Unavailable(crate::deployment::Failure::CommandInvariant),
            )?;
        if stored_version.action_kind != rss_mdm_policy::ActionKind::Software {
            return Ok(None);
        }
        let frozen: crate::deployment::frozen::Published =
            crate::deployment::stored(serde_json::from_value(stored_version.frozen))?;
        let crate::deployment::frozen::Published::Software { action } = frozen else {
            return Err(crate::deployment::Error::Unavailable(
                crate::deployment::Failure::CommandInvariant,
            )
            .into());
        };
        let channel = action.channel;
        let policy = crate::deployment::transaction::checked(
            reader.locked_in(tx, stored_version.policy).await?,
        )?
        .ok_or(crate::deployment::Error::Unavailable(
            crate::deployment::Failure::CommandInvariant,
        ))?;
        if policy.version != version {
            return Ok(None);
        }
        if policy.definition.action.kind() != rss_mdm_policy::ActionKind::Software {
            return Err((crate::deployment::Error::Unavailable(
                crate::deployment::Failure::CommandInvariant,
            ))
            .into());
        }
        if !policy.state.is_enabled() {
            return Ok(None);
        }
        Ok(Some(Self {
            reader,
            version,
            channel,
        }))
    }
    /// Revalidate on the borrowing transaction; a proof cannot act as a cached authorization lease.
    pub async fn wake_assignment_in(
        &self,
        reconcile: &rss_reconcile_postgres::PgMessagingStore,
        tx: &mut PgTransaction<'_>,
        target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
    ) -> Result<()> {
        if target.channel.as_str() != self.channel.as_str() {
            return Ok(());
        }
        let work = Work {
            version: self.version,
            device: target.device.clone(),
        };
        if let Some(device) = device_in(self.reader, tx, &work).await?
            && device != target.device
        {
            return Err(Error::Unavailable(crate::deployment::Failure::CommandInvariant).into());
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
    verified: &VerifiedSoftwareVersion<'_>,
    work: &Work,
) -> Result<()> {
    if verified.version != work.version {
        return Err((crate::deployment::Error::Unavailable(
            crate::deployment::Failure::CommandInvariant,
        ))
        .into());
    }
    if device_in(verified.reader, tx, &work).await?.is_none() {
        return Ok(());
    }
    let target = rss_reconcile::Target::new(
        crate::deployment::recovery_scope(tx.tenant_id()),
        work.entity(),
    )
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
    let Some(proof) = VerifiedSoftwareVersion::verify_in(reader, tx, work.version).await? else {
        return Ok(None);
    };
    let channel = proof.channel.as_str();
    if work.device.is_empty() {
        return Err((crate::deployment::Error::Unavailable(
            crate::deployment::Failure::CommandInvariant,
        ))
        .into());
    }
    let tenant = tx.tenant_id().to_string();
    let device = work.device.clone();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT id AS device FROM mdm_access.devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND state = 'active' AND purpose = 'primary' AND channel = $3")
            .bind(tenant).bind(device).bind(channel).fetch_optional(c).await
    })).await?)
}

/// Only rollout gate transitions reopen this bounded dispatch window. Policy owns initial discovery.
pub(crate) async fn dispatch_in(
    service: &SoftwareService,
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
) -> Result<()> {
    let current = crate::deployment::sources::storage::read_in(
        &service.transactions.policy_reader,
        tx,
        policy,
    )
    .await?
    .ok_or(Error::Unavailable(
        crate::deployment::Failure::CommandInvariant,
    ))?;
    let tenant = tx.tenant_id().to_string();
    let (revision, consumed, mut window, mut after): (i64, i64, i64, Option<String>) = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as("SELECT dispatch_revision,dispatch_consumed,dispatch_window,dispatch_after FROM mdm_software_deployment.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE").bind(tenant).bind(policy).fetch_one(c).await
    })).await?;
    if consumed == window {
        window = revision;
        after = None;
    }
    if consumed == window {
        return Ok(());
    }
    let version = current.version;
    let verified =
        VerifiedSoftwareVersion::verify_in(&service.transactions.policy_reader, tx, version)
            .await?;
    let rows = if verified.is_some() {
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT DISTINCT r.id COLLATE \"C\" AS device, r.id FROM mdm_policy.assignments AS a INNER JOIN mdm_access.devices AS r ON r.tenant_id = a.tenant_id AND r.id = a.target ->> 'device' AND r.channel = a.channel AND r.state = 'active' AND r.purpose = 'primary' WHERE a.tenant_id = CAST($1 AS uuid) AND a.policy = $2 AND a.version = $3 AND a.availability = 'ready' AND r.id > COALESCE($4, '') COLLATE \"C\" ORDER BY r.id COLLATE \"C\", r.id LIMIT 33").bind(tenant).bind(policy).bind(version).bind(after).fetch_all(c).await
        })).await?
    } else {
        Vec::new()
    };
    if let Some(verified) = &verified {
        for row in rows.iter().take(32) {
            wake_in(
                &service.transactions.reconcile_messaging,
                tx,
                verified,
                &Work {
                    version,
                    device: row.try_get("id")?,
                },
            )
            .await?;
        }
    }
    let more = rows.len() > 32;
    let after: Option<String> = if more {
        Some(rows[31].try_get("device")?)
    } else {
        None
    };
    let consumed = if more { consumed } else { window };
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_software_deployment.policy_recovery SET dispatch_consumed=$3,dispatch_window=$4,dispatch_after=$5 WHERE tenant_id=$1::uuid AND policy=$2").bind(tenant).bind(policy).bind(consumed).bind(window).bind(after).execute(c).await?; Ok(())
    })).await?;
    Ok(())
}

pub(crate) async fn advance_in(
    service: &SoftwareService,
    tx: &mut PgTransaction<'_>,
    work: &Work,
    run: Uuid,
) -> Result<()> {
    let Some(device) = device_in(&service.transactions.policy_reader, tx, &work).await? else {
        return Ok(());
    };
    let plan =
        db::load_policy_version(&service.transactions.policy_reader, tx, work.version).await?;
    let target = Target { device };
    let now = storage::now(tx).await?;
    match &plan {
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
    }
}

/// Calendar work sleeps until useful again; a retired version/device converges.
pub(crate) async fn delay_in(
    service: &SoftwareService,
    tx: &mut PgTransaction<'_>,
    work: &Work,
) -> Result<Option<std::time::Duration>> {
    let Some(device) = device_in(&service.transactions.policy_reader, tx, &work).await? else {
        return Ok(None);
    };
    let plan =
        db::load_policy_version(&service.transactions.policy_reader, tx, work.version).await?;
    let now = storage::now(tx).await?;
    let seconds = match plan {
        db::ScheduledPolicy::Software(software) => {
            if now >= software.assignment.frozen.schedule.ends_at() {
                return Ok(None);
            }
            let tenant = tx.tenant_id().to_string();
            let work = work.clone();
            let pending:bool=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT EXISTS (SELECT FROM mdm_software_deployment.action_runs WHERE tenant_id = CAST($1 AS uuid) AND policy_version = $2 AND device = $3 AND state ->> 'execution' IN ('not_started', 'running', 'waiting_reboot', 'unknown') AND state ->> 'cancellation' <> 'confirmed')").bind(tenant).bind(work.version).bind(&work.device).fetch_one(c).await})).await?;
            if pending {
                return Ok(None);
            }
            let target = Target { device };
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
