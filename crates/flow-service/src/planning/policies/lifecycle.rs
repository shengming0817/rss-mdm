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

impl super::super::Planning {
    pub(crate) async fn prepare_lifecycle_assignment_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        after: Option<String>,
    ) -> Result<Option<PreparedLifecycle>> {
        let terminal_partition = rss_mdm_audit_integration::source_partition(
            tx.tenant_id(),
            "policy",
            &policy.id.to_string(),
        )
        .map_err(Error::from)?;
        if !policy.state.is_enabled() {
            tx.prepare_outbox_partitions(&[terminal_partition]).await?;
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
            grant,
        } = frozen
        else {
            return Err(Error::Malformed.into());
        };
        let tenant = tx.tenant_id();
        let t = tenant.to_string();
        let version = policy.version;
        let now = crate::action_admission::now(tx).await?;
        let authority = grant.clone();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(authority
                    .valid(c, crate::authorization::Permission::DeviceUnmanage, now)
                    .await)
            })
        })
        .await?
        .map_err(Error::from)?
        .then_some(())
        .ok_or(Error::Forbidden)?;
        let triggers=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_as::<_,(Uuid,i64)>("SELECT id,created_at FROM mdm_policy.triggers WHERE tenant_id=$1::uuid AND version=$2 AND deadline>$3 ORDER BY created_at DESC,id DESC LIMIT 64")
                .bind(t).bind(version).bind(now).fetch_all(c).await
        })).await?;
        let reader = self.objects.clone();
        let scope = policy.definition.scope;
        let mut objects = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(super::super::targets::lifecycle_objects_on(
                        reader.as_ref(),
                        c,
                        tenant,
                        scope,
                        after.as_deref(),
                    )
                    .await)
                })
            })
            .await?
            .map_err(rss_mdm_execution_service::Error::from)?;
        let more = objects.len() > 64;
        objects.truncate(64);
        let next = objects.last().map(|o| o.cursor.clone());
        let mut partitions = vec![terminal_partition];
        for item in &objects {
            partitions.push(
                rss_mdm_audit_integration::source_partition(
                    tenant,
                    "mdm",
                    &item.object.object.key(),
                )
                .map_err(Error::from)?,
            );
        }
        tx.prepare_outbox_partitions(&partitions).await?;
        Ok(Some(PreparedLifecycle {
            policy: policy.clone(),
            frozen: Frozen::UnmanageDevice {
                schedule,
                run_lifetime_seconds,
                grant,
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
            grant,
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
            let explicit = triggers.iter().find_map(|(id, at)| {
                schedule
                    .occurrence(*at, version.as_bytes())
                    .ok()
                    .flatten()
                    .filter(|s| s.available_at <= now && s.window_end.is_none_or(|end| now < end))
                    .map(|_| format!("explicit:{id}"))
            });
            let occurrence = if let Some(explicit) = explicit {
                Some(explicit)
            } else {
                schedule
                    .due(-1, now, version.as_bytes())?
                    .filter(|s| s.available_at <= now)
                    .map(|s| format!("calendar:{}", s.coordinate))
            };
            let Some(occurrence) = occurrence else {
                continue;
            };
            let reader = self.objects.clone();
            let policy_id = policy.id;
            let grant = grant.clone();
            let accepted = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(lifecycle::accept_in(
                            c,
                            tenant,
                            reader.as_ref(),
                            &Acceptance {
                                policy: policy_id,
                                version,
                                occurrence: &occurrence,
                                target: &item.object,
                                authority: &grant,
                                delivery_seconds: run_lifetime_seconds,
                                now,
                            },
                        )
                        .await)
                    })
                })
                .await?
                .map_err(Error::from)?;
            rss_mdm_execution_service::unmanage::wake_in(tx, accepted.0).await?;
            if !accepted.1 {
                let audit = RequestAudit::new(tenant.to_string(), "device_retirement_accepted");
                audit.identify_service("device-lifecycle");
                audit.operation(accepted.0, "device_retirement_accepted");
                audit.target(&key);
                let bytes = serde_json::to_vec(&(policy.id, version, &key, accepted.0))
                    .map_err(|_| Error::Malformed)?;
                let fact = Fact::business(
                    &audit,
                    &format!(
                        "retirement:{}:policy:{}:{version}:accepted",
                        accepted.0, policy.id
                    ),
                    &bytes,
                    200,
                    "success",
                    None,
                )?;
                let appended = self.audit_store.append_in(tx, &fact, false).await;
                audit.finalize(
                    appended
                        .as_ref()
                        .err()
                        .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
                );
                appended.map_err(Error::from)?;
            }
        }
        if more {
            let t = tenant.to_string();
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("UPDATE mdm_automation.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2")
                    .bind(t).bind(task).bind(next).execute(c).await?;Ok(())
            })).await?;
            Ok(())
        } else {
            crate::automation::jobs::finish_job_in(tx, &self.audit_store, task, None).await
        }
    }
}

impl super::super::Planning {
    /// Feed calendar occurrences into the existing durable Policy job queue.
    /// The job ID is derived from the published version and occurrence: restart
    /// does not create another scheduler checkpoint or another execution.
    pub async fn forward_lifecycle_schedules(&self) -> std::result::Result<u64, Error> {
        use sha2::{Digest, Sha256};
        let mut after = None;
        let mut count = 0;
        loop {
            let audit = RequestAudit::new(self.tenant.to_string(), "device_retirement_schedule");
            audit.identify_service("device-lifecycle");
            let outcome=run(&self.audit_store,&self.runtime,self.tenant,&audit,(self,after),|ctx,tx|Box::pin(async move {
                let (s,after)=*ctx;
                let now=crate::action_admission::now(tx).await?;
                let tenant=tx.tenant_id().to_string();
                let rows=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query_as::<_,(Uuid,Uuid,Value)>("SELECT p.id,v.id,v.frozen FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.state='enabled' AND v.action_kind='unmanage_device' AND ($2::uuid IS NULL OR p.id>$2) ORDER BY p.id LIMIT 64")
                        .bind(tenant).bind(after).fetch_all(c).await
                })).await?;
                let next=if rows.len()==64{rows.last().map(|r|r.0)}else{None};
                let mut added=0;
                for (policy,version,value) in rows {
                    let Frozen::UnmanageDevice {schedule,..}=stored(serde_json::from_value(value))? else {return Err(Error::Malformed.into());};
                    let mut occurrences=Vec::new();
                    if let Some(slot)=schedule.due(-1,now,version.as_bytes())? && slot.available_at<=now {
                        occurrences.push(format!("calendar:{}",slot.coordinate));
                    }
                    let t=tx.tenant_id().to_string();
                    let triggers=tx.with_connection(move|c|Box::pin(async move {
                        sqlx::query_as::<_,(Uuid,i64)>("SELECT id,created_at FROM mdm_policy.triggers WHERE tenant_id=$1::uuid AND version=$2 AND deadline>$3 ORDER BY created_at DESC,id DESC LIMIT 64")
                            .bind(t).bind(version).bind(now).fetch_all(c).await
                    })).await?;
                    for (trigger,at) in triggers {
                        if let Some(slot)=schedule.occurrence(at,version.as_bytes())? && slot.available_at<=now && slot.window_end.is_none_or(|end|now<end) {
                            occurrences.push(format!("explicit:{trigger}"));
                        }
                    }
                    for occurrence in occurrences {
                    let digest=Sha256::digest(serde_json::to_vec(&("unmanage-scheduled",s.tenant.to_string(),version,occurrence)).map_err(|_|Error::Malformed)?);
                    let mut bytes=[0u8;16];bytes.copy_from_slice(&digest[..16]);let id=Uuid::from_bytes(bytes);
                    crate::transaction::lock(tx).await?;
                    let t=tx.tenant_id().to_string();
                    let exists=tx.with_connection(move|c|Box::pin(async move {
                        sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND id=$2)").bind(t).bind(id).fetch_one(c).await
                    })).await?;
                    if !exists {
                        crate::automation::jobs::enqueue_job_in(tx,id,&crate::automation::JobInput::PolicyReconcile{policy}).await?;
                        added+=1;
                    }
                    }
                }
                Ok((next,added))
            }),TransactionOwner::Planning).await;
            audit.finalize(
                outcome
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
            let (next, added) = outcome?;
            count += added;
            if next.is_none() {
                break;
            }
            after = next;
        }
        Ok(count)
    }
}
