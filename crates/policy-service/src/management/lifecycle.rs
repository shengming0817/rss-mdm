//! Scope qualification and ordinary Policy triggers feed the device lifecycle owner.
use super::*;
use rss_mdm_device_service::lifecycle::{self, Acceptance};
use rss_mdm_execution_service::source_authority::ScopeAdmission;

pub(crate) struct PreparedLifecycle {
    policy: Policy,
    frozen: Frozen,
    objects: Vec<rss_mdm_execution_service::source_authority::DeviceAssignment>,
    triggers: Vec<(Uuid, i64)>,
    more: bool,
    next: Option<String>,
    now: i64,
}

impl crate::application::Application {
    pub(crate) async fn prepare_lifecycle_assignment_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        after: Option<String>,
    ) -> Result<Option<PreparedLifecycle>> {
        if !policy.state.is_enabled() {
            return Ok(None);
        }
        let published = checked(
            rss_mdm_policy_postgres::PolicyReader::bind(self.runtime.clone(), self.tenant)
                .version_in(tx, policy.version)
                .await?,
        )?
        .ok_or(Error::NotFound)?;
        let frozen: Frozen = stored(serde_json::from_value(published.frozen))?;
        let Frozen::UnmanageDevice {
            schedule,
            run_lifetime_seconds,
            actor,
        } = frozen
        else {
            return Err(Error::Malformed.into());
        };
        let tenant = tx.tenant_id();
        let version = policy.version;
        let now = crate::action_admission::now(tx).await?;
        let triggers = rss_mdm_policy_postgres::schedules::triggers_in(tx, version, now).await?;
        let reader = self.objects.clone();
        let scope = policy.definition.scope;
        let mut objects = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        rss_mdm_execution_service::scope::targets::lifecycle_objects_on(
                            reader.as_ref(),
                            c,
                            tenant,
                            scope,
                            after.as_deref(),
                            64,
                        )
                        .await,
                    )
                })
            })
            .await?
            .map_err(rss_mdm_execution_service::Error::from)?;
        let more = objects.len() > 64;
        objects.truncate(64);
        let next = objects.last().map(|o| o.cursor.clone());
        Ok(Some(PreparedLifecycle {
            policy: policy.clone(),
            frozen: Frozen::UnmanageDevice {
                schedule,
                run_lifetime_seconds,
                actor,
            },
            objects,
            triggers,
            more,
            next,
            now,
        }))
    }
    pub(crate) async fn advance_lifecycle_assignment_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        prepared: PreparedLifecycle,
    ) -> Result<()> {
        let PreparedLifecycle {
            policy,
            frozen,
            objects,
            triggers,
            more,
            next,
            now,
        } = prepared;
        let Frozen::UnmanageDevice {
            schedule,
            run_lifetime_seconds,
            actor: _,
        } = frozen
        else {
            return Err(Error::Malformed.into());
        };
        let tenant = tx.tenant_id();
        let version = policy.version;
        for item in objects {
            if !matches!(item.admission, ScopeAdmission::Eligible { .. }) {
                continue;
            }
            let key = item.object.object.key();
            let mut occurrences = Vec::new();
            for (trigger, at) in &triggers {
                if let Some(slot) = schedule.occurrence(*at, version.as_bytes())?
                    && slot.available_at <= now
                    && slot.window_end.is_none_or(|end| now < end)
                {
                    occurrences.push((
                        format!("explicit:{trigger}"),
                        slot.window_end.unwrap_or(i64::MAX),
                    ));
                }
            }
            if let Some(slot) = schedule.due(-1, now, version.as_bytes())?
                && slot.available_at <= now
            {
                occurrences.push((
                    format!("calendar:{}", slot.coordinate),
                    slot.window_end.unwrap_or(i64::MAX),
                ));
            }
            let object = stored(serde_json::to_value(&item.object))?;
            for (occurrence, end) in occurrences {
                use sha2::{Digest, Sha256};
                // An occurrence keeps its identity while newer registration/member
                // evidence receives a successor work item instead of colliding with
                // a superseded frozen input. Device acceptance remains idempotent.
                let encoded = stored(serde_json::to_vec(&(
                    policy.id,
                    version,
                    &key,
                    &occurrence,
                    &object,
                )))?;
                let digest =
                    Sha256::digest([b"device-lifecycle-work/v1".as_slice(), &encoded].concat());
                let mut id = [0; 16];
                id.copy_from_slice(&digest[..16]);
                let id = Uuid::from_bytes(id);
                if rss_mdm_policy_postgres::work::exists_in(tx, id, false).await? {
                    continue;
                }
                let input = crate::worker::Work::Lifecycle {
                    policy: policy.id,
                    version,
                    object: object.clone(),
                    occurrence,
                    deadline: end.min(now.saturating_add(i64::from(run_lifetime_seconds))),
                };
                crate::worker::jobs::enqueue_job_in(tx, id, &input).await?;
                self.reconcile_messaging
                    .wake_in(
                        tx,
                        &crate::worker::jobs::job_target(tenant, id),
                        &rss_reconcile::ResourceSet::empty(tenant),
                        (),
                        move |_, tx| {
                            Box::pin(async move {
                                rss_mdm_policy_postgres::work::forwarded_in(tx, id).await?;
                                Ok(())
                            })
                        },
                    )
                    .await?;
            }
        }
        if more {
            rss_mdm_policy_postgres::work::cursor_in(tx, task, next).await?;
            Ok(())
        } else {
            crate::worker::jobs::finish_job_in(tx, &self.audit_store, task, None).await
        }
    }
}

impl crate::application::Application {
    pub(crate) async fn advance_lifecycle_work_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        input: &crate::worker::Work,
    ) -> Result<()> {
        let crate::worker::Work::Lifecycle {
            policy,
            version,
            object,
            occurrence,
            deadline,
        } = input
        else {
            return Err(Error::Malformed.into());
        };
        let policy_id = *policy;
        let tenant = tx.tenant_id();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("SELECT mdm_policy.lock_policy($1)")
                    .bind(policy_id)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        let current = storage::read_in(
            &rss_mdm_policy_postgres::PolicyReader::bind(self.runtime.clone(), self.tenant),
            tx,
            *policy,
        )
        .await?;
        let now = crate::action_admission::now(tx).await?;
        if current
            .as_ref()
            .is_none_or(|p| !p.state.is_enabled() || p.version != *version)
            || now >= *deadline
        {
            return crate::worker::jobs::finish_job_in(
                tx,
                &self.audit_store,
                task,
                Some("superseded"),
            )
            .await;
        }
        let published = checked(
            rss_mdm_policy_postgres::PolicyReader::bind(self.runtime.clone(), self.tenant)
                .version_in(tx, *version)
                .await?,
        )?
        .ok_or(Error::NotFound)?;
        let Frozen::UnmanageDevice {
            run_lifetime_seconds,
            actor,
            ..
        } = stored(serde_json::from_value(published.frozen))?
        else {
            return Err(Error::Malformed.into());
        };
        let object: rss_mdm_inventory_service::objects::DeviceObject =
            stored(serde_json::from_value(object.clone()))?;
        let key = object.object.key();
        let version = *version;
        let occurrence = occurrence.clone();
        let reader = self.objects.clone();
        let accepted = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(lifecycle::accept_in(
                        c,
                        tenant,
                        reader.as_ref(),
                        &Acceptance {
                            origin: rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
                            policy: policy_id,
                            version,
                            occurrence: &occurrence,
                            target: &object,
                            actor: &actor,
                            delivery_seconds: run_lifetime_seconds,
                            now,
                        },
                    )
                    .await)
                })
            })
            .await?
            .map_err(Error::from)?;
        rss_mdm_execution_service::unmanage::wake_in(&self.reconcile_messaging, tx, accepted.0)
            .await?;
        if !accepted.1 {
            let audit = RequestAudit::new(
                tenant.to_string(),
                "device_retirement_accepted",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            audit.identify_service("device-lifecycle");
            audit.target(&key);
            audit.operation(
                accepted.0,
                "device_retirement_accepted",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            let fact = Fact::business(
                &audit,
                &format!(
                    "retirement:{}:policy:{policy_id}:{version}:accepted",
                    accepted.0
                ),
                200,
                "success",
                None,
            )?;
            self.audit_store
                .append_in(tx, &fact)
                .await
                .map_err(Error::from)?;
            audit.finalize(None);
        }
        crate::worker::jobs::finish_job_in(tx, &self.audit_store, task, None).await
    }
}

impl crate::application::Application {
    /// One claimed calendar page; occurrence identities and the page cursor commit together.
    pub(crate) async fn advance_lifecycle_schedules_in(
        &self,
        tx: &mut PgTransaction<'_>,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let after = rss_mdm_policy_postgres::schedules::scan_cursor_in(tx).await?;
        let now = crate::action_admission::now(tx).await?;
        let rows = rss_mdm_policy_postgres::schedules::retirement_in(tx, after).await?;
        let next = if rows.len() == 64 {
            rows.last().map(|r| r.0)
        } else {
            None
        };
        for (policy, version, value) in rows {
            let Frozen::UnmanageDevice { schedule, .. } = stored(serde_json::from_value(value))?
            else {
                return Err(Error::Malformed.into());
            };
            let mut occurrences = Vec::new();
            if let Some(slot) = schedule.due(-1, now, version.as_bytes())?
                && slot.available_at <= now
            {
                occurrences.push(format!("calendar:{}", slot.coordinate));
            }
            let triggers =
                rss_mdm_policy_postgres::schedules::triggers_in(tx, version, now).await?;
            for (trigger, at) in triggers {
                if let Some(slot) = schedule.occurrence(at, version.as_bytes())?
                    && slot.available_at <= now
                    && slot.window_end.is_none_or(|end| now < end)
                {
                    occurrences.push(format!("explicit:{trigger}"));
                }
            }
            for occurrence in occurrences {
                let digest = Sha256::digest(
                    serde_json::to_vec(&(
                        "unmanage-scheduled",
                        self.tenant.to_string(),
                        version,
                        occurrence,
                    ))
                    .map_err(|_| Error::Malformed)?,
                );
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&digest[..16]);
                let id = Uuid::from_bytes(bytes);

                let exists = rss_mdm_policy_postgres::work::exists_in(tx, id, false).await?;
                if !exists {
                    crate::worker::jobs::enqueue_job_in(
                        tx,
                        id,
                        &crate::worker::Work::PolicyReconcile { policy },
                    )
                    .await?;
                }
            }
        }
        // Finishing a cycle yields to ordinary work; an unfinished cycle resumes promptly.
        rss_mdm_policy_postgres::schedules::complete_scan_in(
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
