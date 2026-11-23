//! Accept one frozen retirement target under current Policy and complete-object Scope evidence.
use super::*;
use rss_mdm_device_service::control::frozen::Frozen;
use rss_mdm_device_service::lifecycle::{self, Acceptance};
use rss_mdm_scope_service::channels::ScopeAdmission;

impl crate::application::Application {
    pub(crate) async fn advance_lifecycle_work_in(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        input: &crate::worker::Work,
    ) -> Result<rss_reconcile_postgres::ProtectedStep<()>> {
        let profile = self.profile();

        let crate::worker::Work::Lifecycle {
            policy,
            version,
            object,
            occurrence,
            scope_result,
            deadline,
        } = input
        else {
            return Err(Error::Malformed.into());
        };
        let tenant = tx.tenant_id();
        let Some(current) = self.retirement_policy_in(tx, *policy, *version).await? else {
            return self
                .finish_retirement_in(binding, tx, task, json!({"state":"superseded"}))
                .await
                .map(rss_reconcile_postgres::ProtectedStep::Ready);
        };
        if crate::action_admission::now(tx).await? >= *deadline {
            return self
                .finish_retirement_in(binding, tx, task, json!({"state":"expired"}))
                .await
                .map(rss_reconcile_postgres::ProtectedStep::Ready);
        }
        let published = checked(
            rss_mdm_policy_postgres::PolicyReader::bind(profile, self.runtime.clone())
                .version_in(tx, *version)
                .await?,
        )?
        .ok_or(Error::NotFound)?;
        let Frozen::UnmanageDevice {
            run_lifetime_seconds,
            actor,
            ..
        } = stored(serde_json::from_value(published.frozen))?;
        let object: rss_mdm_inventory_service::objects::DeviceObject =
            stored(serde_json::from_value(object.clone()))?;
        let key = object.object;
        // Association writers use these same member locks. Keep them through the
        // complete-object Scope check and the Device owner's acceptance.
        let members: Vec<_> = object.members.iter().map(|m| m.device).collect();
        let locked = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        rss_mdm_registration_service::lifecycle::try_lock_devices_in(
                            profile,
                            c,
                            &tenant.to_string(),
                            &members,
                        )
                        .await,
                    )
                })
            })
            .await??;
        if !locked {
            return Ok(rss_reconcile_postgres::ProtectedStep::Deferred(
                std::time::Duration::from_millis(50),
            ));
        }
        let fresh =
            super::reconcile::lock_assignment_scope(profile, tx, current.definition.scope).await?;
        let scope = current.definition.scope;
        let reader = self.objects.clone();
        let frozen_object = object.clone();
        let assignment = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        rss_mdm_scope_service::channels::targets::lifecycle_object_on(
                            profile,
                            reader.as_ref(),
                            c,
                            tenant,
                            scope,
                            &frozen_object,
                        )
                        .await,
                    )
                })
            })
            .await?
            .map_err(Error::from)?;
        let now = crate::action_admission::now(tx).await?;
        if now >= *deadline {
            return self
                .finish_retirement_in(binding, tx, task, json!({"state":"expired"}))
                .await
                .map(rss_reconcile_postgres::ProtectedStep::Ready);
        }
        let eligible = fresh
            && assignment.as_ref().is_some_and(|item| {
                matches!(item.admission, ScopeAdmission::Eligible { .. }) && item.object == object
            });
        if !eligible {
            let old = object.clone();
            let policy_id = *policy;
            let version_id = *version;
            let admitted_scope = *scope_result;
            let (prior, same_scope) = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        let published =
                            rss_mdm_scope_service::results::published_on(profile, c, tenant, scope)
                                .await?;
                        Ok((
                            lifecycle::linked_target_in(c, tenant, policy_id, version_id, &old)
                                .await,
                            published.is_some_and(|(run, _, _)| run == admitted_scope),
                        ))
                    })
                })
                .await?;
            let pending = !fresh
                || assignment
                    .as_ref()
                    .is_some_and(|item| item.admission == ScopeAdmission::Pending);
            let prior = prior?;
            if fresh
                && same_scope
                && pending
                && let Some(operation) = prior
            {
                return self
                    .finish_retirement_in(
                        binding,
                        tx,
                        task,
                        json!({"state":"reused","operation":operation}),
                    )
                    .await
                    .map(rss_reconcile_postgres::ProtectedStep::Ready);
            }
            if pending {
                let remaining = std::time::Duration::from_secs((*deadline - now) as u64);
                return Ok(rss_reconcile_postgres::ProtectedStep::Deferred(
                    crate::worker_wake::RECOVERY.min(remaining),
                ));
            }
            let mut result = json!({"state":"ineligible"});
            if let Some(operation) = prior {
                result["previousOperation"] = json!(operation);
            }
            return self
                .finish_retirement_in(binding, tx, task, result)
                .await
                .map(rss_reconcile_postgres::ProtectedStep::Ready);
        }
        let policy_id = *policy;
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
                            execution: binding,
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
        self.changes.retirement_accepted_in(tx, accepted.0).await?;
        if !accepted.1 {
            let audit = RequestAudit::new(
                rss_mdm_audit_integration::Origin::Background,
                self.profile(),
                binding,
                "device_retirement_accepted",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            audit.identify_service("device-lifecycle");
            audit.target(&stored(serde_json::to_string(&key))?);
            audit.owned_operation(
                rss_mdm_audit_integration::operation::OperationOwner::Policy,
                accepted.0,
                "device_retirement_accepted",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            let fact = Fact::business(
                &audit,
                rss_mdm_audit_integration::operation::OperationOwner::Policy,
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
        self.finish_retirement_in(
            binding,
            tx,
            task,
            json!({"state":if accepted.1 { "reused" } else { "accepted" },"operation":accepted.0}),
        )
        .await
        .map(rss_reconcile_postgres::ProtectedStep::Ready)
    }
}
