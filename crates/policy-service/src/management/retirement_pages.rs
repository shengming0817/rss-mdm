//! Occurrence dispatch, Scope publication catch-up, and one protected device page.
use super::*;
use crate::worker::{Work, jobs};
use rss_mdm_agent_wire::ObjectRef;
use rss_mdm_install_support::StorageProfile;
use rss_mdm_policy::schedule::Schedule;
use rss_mdm_policy_postgres::{
    schedules,
    work::{self, RetirementOccurrence, TriggerPage},
};
use rss_mdm_scope_service::channels::ScopeAdmission;
use rss_reconcile_postgres::{PgMessagingStore, ProtectedStep};
use rss_transactional_messaging::fence::ExecutionBinding;
use sha2::{Digest, Sha256};
use std::time::Duration;

const DEVICE_PAGE: usize = 64;
const TRIGGER_PAGE: u16 = 64;

fn work_id(domain: &[u8], key: &impl Serialize) -> Result<Uuid> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(stored(serde_json::to_vec(key))?);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    Ok(Uuid::from_bytes(bytes))
}

pub(super) async fn enqueue_occurrence_in(
    profile: StorageProfile,
    reconcile: &PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
    version: Uuid,
    occurrence: RetirementOccurrence,
    publication: Option<Uuid>,
) -> Result<()> {
    let id = work_id(
        b"retirement-occurrence/v1",
        &(
            tx.tenant_id().octets(),
            policy,
            version,
            occurrence,
            publication,
        ),
    )?;
    jobs::enqueue_job_in(
        profile,
        reconcile,
        tx,
        id,
        &Work::RetirementPage {
            policy,
            version,
            occurrence,
        },
    )
    .await?;
    Ok(())
}

impl crate::application::Application {
    pub(crate) async fn retirement_policy_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: Uuid,
        version: Uuid,
    ) -> Result<Option<Policy>> {
        let reader =
            rss_mdm_policy_postgres::PolicyReader::bind(self.profile(), self.runtime.clone());
        Ok(storage::read_in(&reader, tx, policy)
            .await?
            .filter(|p| p.state.is_enabled() && p.version == version))
    }

    pub(crate) async fn finish_retirement_in(
        &self,
        binding: ExecutionBinding,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        result: Value,
    ) -> Result<()> {
        work::retirement_result_in(self.profile(), tx, task, result).await?;
        jobs::finish_job_in(binding, self.profile(), tx, &self.audit_store, task, None).await
    }

    /// One fixed Scope publication enumerates active triggers through its original upper bound.
    pub(crate) async fn refresh_retirement_in(
        &self,
        binding: ExecutionBinding,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        policy: &Policy,
        continuation: Option<TriggerPage>,
    ) -> Result<()> {
        let profile = self.profile();
        let now = crate::action_admission::now(tx).await?;
        let page = match continuation {
            Some(page) => Some(page),
            None => {
                let Action::UnmanageDevice { schedule, .. } = &policy.definition.action else {
                    return Err(Error::Malformed.into());
                };
                self.enqueue_calendar_in(tx, policy.id, policy.version, schedule, now, Some(task))
                    .await?;
                schedules::trigger_bound_in(profile, tx, policy.version, now)
                    .await?
                    .map(|through| TriggerPage {
                        publication: task,
                        after: Uuid::nil(),
                        through,
                    })
            }
        };
        if let Some(page) = page {
            let rows =
                schedules::trigger_page_in(profile, tx, policy.version, now, page, TRIGGER_PAGE)
                    .await?;
            for &(trigger, created_at, deadline) in rows.iter().take(usize::from(TRIGGER_PAGE)) {
                enqueue_occurrence_in(
                    profile,
                    &self.reconcile_messaging,
                    tx,
                    policy.id,
                    policy.version,
                    RetirementOccurrence::Explicit {
                        trigger,
                        created_at,
                        deadline,
                    },
                    Some(page.publication),
                )
                .await?;
            }
            if rows.len() > usize::from(TRIGGER_PAGE) {
                let page = TriggerPage {
                    after: rows[usize::from(TRIGGER_PAGE) - 1].0,
                    ..page
                };
                let id = work_id(
                    b"retirement-refresh/v1",
                    &(tx.tenant_id().octets(), policy.version, page),
                )?;
                jobs::enqueue_job_in(
                    profile,
                    &self.reconcile_messaging,
                    tx,
                    id,
                    &Work::RetirementRefresh {
                        policy: policy.id,
                        version: policy.version,
                        page,
                    },
                )
                .await?;
            }
        }
        jobs::finish_job_in(binding, profile, tx, &self.audit_store, task, None).await
    }

    async fn enqueue_calendar_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: Uuid,
        version: Uuid,
        schedule: &Schedule,
        now: i64,
        publication: Option<Uuid>,
    ) -> Result<()> {
        if let Some(slot) = schedule.due(-1, now, version.as_bytes())?
            && slot.available_at <= now
            && now < schedule.ends_at()
            && slot.window_end.is_none_or(|end| now < end)
        {
            enqueue_occurrence_in(
                self.profile(),
                &self.reconcile_messaging,
                tx,
                policy,
                version,
                RetirementOccurrence::Calendar {
                    at: slot.coordinate,
                },
                publication,
            )
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn advance_retirement_page_in(
        &self,
        binding: ExecutionBinding,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        policy: &Policy,
        occurrence: RetirementOccurrence,
        after: Option<ObjectRef>,
    ) -> Result<ProtectedStep<()>> {
        let Action::UnmanageDevice {
            schedule,
            run_lifetime_seconds,
        } = &policy.definition.action
        else {
            return Err(Error::Malformed.into());
        };
        let (coordinate, expiry) = match occurrence {
            RetirementOccurrence::Explicit {
                created_at,
                deadline,
                ..
            } => (created_at, deadline),
            RetirementOccurrence::Calendar { at } => (at, schedule.ends_at()),
        };
        let version = policy.version;
        let now = crate::action_admission::now(tx).await?;
        let slot = schedule.occurrence(coordinate, version.as_bytes())?;
        let end = expiry
            .min(schedule.ends_at())
            .min(slot.and_then(|s| s.window_end).unwrap_or(i64::MAX));
        let Some(slot) = slot.filter(|s| now < end && s.available_at < end) else {
            self.finish_retirement_in(binding, tx, task, json!({"state":"expired"}))
                .await?;
            return Ok(ProtectedStep::Ready(()));
        };
        if now < slot.available_at {
            return Ok(ProtectedStep::Deferred(Duration::from_secs(
                (slot.available_at - now) as u64,
            )));
        }
        let profile = self.profile();
        let tenant = tx.tenant_id();
        let scope = policy.definition.scope;
        if !super::reconcile::lock_assignment_scope(profile, tx, scope).await? {
            return Ok(ProtectedStep::Deferred(
                crate::worker_wake::RECOVERY.min(Duration::from_secs((end - now) as u64)),
            ));
        }
        let reader = self.objects.clone();
        let mut objects = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        rss_mdm_scope_service::channels::targets::lifecycle_objects_on(
                            profile,
                            Some(reader.as_ref()),
                            c,
                            tenant,
                            scope,
                            after,
                            DEVICE_PAGE,
                        )
                        .await,
                    )
                })
            })
            .await?
            .map_err(Error::from)?;
        let more = objects.len() > DEVICE_PAGE;
        objects.truncate(DEVICE_PAGE);
        let next = objects.last().map(|o| o.cursor);
        let occurrence = occurrence.identity();
        let deadline = end.min(now.saturating_add(i64::from(*run_lifetime_seconds)));
        let mut eligible = 0_i64;
        let mut pending = 0_i64;
        for item in objects {
            if item.admission == ScopeAdmission::Pending {
                pending += 1;
            }
            if matches!(item.admission, ScopeAdmission::Eligible { .. }) {
                eligible += 1;
                let object = stored(serde_json::to_value(&item.object))?;
                // A later Scope result can reconsider the same object after withdrawal.
                // Device execution deduplicates by the original occurrence and registration.
                let id = work_id(
                    b"retirement-device/v1",
                    &(policy.id, version, &occurrence, item.scope_result, &object),
                )?;
                jobs::enqueue_job_in(
                    profile,
                    &self.reconcile_messaging,
                    tx,
                    id,
                    &Work::Lifecycle {
                        policy: policy.id,
                        version,
                        object,
                        occurrence: occurrence.clone(),
                        deadline,
                    },
                )
                .await?;
            }
        }
        work::record_retirement_page_in(profile, tx, task, eligible, pending, more).await?;
        if more {
            work::cursor_in(profile, tx, task, next).await?;
        } else {
            jobs::finish_job_in(binding, profile, tx, &self.audit_store, task, None).await?;
        }
        Ok(ProtectedStep::Ready(()))
    }

    /// Calendar discovery advances only the Policy cursor. Explicit work is born at admission.
    pub(crate) async fn advance_lifecycle_schedules_in(
        &self,
        tx: &mut PgTransaction<'_>,
    ) -> Result<()> {
        let profile = self.profile();
        let after = schedules::scan_cursor_in(profile, tx).await?;
        let now = crate::action_admission::now(tx).await?;
        let rows = schedules::retirement_in(profile, tx, after).await?;
        let next = (rows.len() == 64).then(|| rows.last().expect("full page").0);
        for (policy, version, frozen) in rows {
            let rss_mdm_device_service::control::frozen::Frozen::UnmanageDevice {
                schedule, ..
            } = stored(serde_json::from_value(frozen))?;
            self.enqueue_calendar_in(tx, policy, version, &schedule, now, None)
                .await?;
        }
        schedules::complete_scan_in(
            profile,
            tx,
            next,
            if next.is_some() {
                now
            } else {
                now.saturating_add(5)
            },
        )
        .await?;
        Ok(())
    }
}
