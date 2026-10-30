use super::*;
pub(crate) enum PreparedAssignment {
    Empty,
    Lifecycle(Box<super::lifecycle::PreparedLifecycle>),
    Ordinary {
        policy: Box<Policy>,
        assignments: Vec<rss_mdm_execution_service::source_authority::AssignmentObject>,
        more: bool,
        channel: rss_mdm_inventory::Channel,
    },
}
impl crate::application::Application {
    pub(crate) async fn prepare_assignment_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: Uuid,
        after: Option<String>,
    ) -> Result<PreparedAssignment> {
        let Some(p) = storage::read_in(
            &rss_mdm_policy_postgres::PolicyReader::bind(self.runtime.clone(), self.tenant),
            tx,
            policy,
        )
        .await?
        else {
            return Ok(PreparedAssignment::Empty);
        };
        if matches!(p.definition.action, Action::UnmanageDevice { .. }) {
            return Ok(
                match self.prepare_lifecycle_assignment_in(tx, &p, after).await? {
                    Some(prepared) => PreparedAssignment::Lifecycle(Box::new(prepared)),
                    None => PreparedAssignment::Empty,
                },
            );
        }
        use rss_mdm_execution_service::source_authority::SourceAuthority;
        let channel =
            rss_mdm_execution_service::source_authority::action_channel(&p.definition.action)?;
        let source = crate::management::source::execution(self.objects.clone());
        let scope = p.definition.scope;
        let tenant = tx.tenant_id();
        let mut assignments = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_scope_postgres::admission_on(c, tenant, scope).await?;
                    Ok(source
                        .assignment_objects_on(c, tenant, scope, channel, after.as_deref(), 64)
                        .await)
                })
            })
            .await?
            .map_err(rss_mdm_execution_service::Error::from)?;
        let more = assignments.len() > 64;
        assignments.truncate(64);

        Ok(PreparedAssignment::Ordinary {
            policy: Box::new(p),
            assignments,
            more,
            channel,
        })
    }
    pub(crate) async fn advance_assignment_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        prepared: PreparedAssignment,
    ) -> Result<()> {
        use rss_mdm_execution_service::source_authority::Availability;
        let (p, assignments, more, channel) = match prepared {
            PreparedAssignment::Empty => {
                return crate::worker::jobs::finish_job_in(tx, &self.audit_store, task, None).await;
            }
            PreparedAssignment::Lifecycle(batch) => {
                return self.advance_lifecycle_assignment_in(tx, task, *batch).await;
            }
            PreparedAssignment::Ordinary {
                policy,
                assignments,
                more,
                channel,
            } => (policy, assignments, more, channel),
        };
        let mut devices = Vec::new();
        let mut keys = Vec::new();
        for mut assignment in assignments {
            keys.push(assignment.object.key());

            if !p.state.is_enabled() {
                assignment.availability = Availability::Unavailable;
                assignment.reason = Some("policy_disabled".into());
            }
            let input = checked_input(serde_json::to_value(&assignment))?;
            let policy = p.id;
            let version = p.version;
            let key = assignment.object.key();
            let channel = channel.as_str();
            let reason = assignment.reason.clone();
            let available = assignment.availability == Availability::Ready;
            let target = assignment
                .target
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| Error::Malformed)?;
            let run = assignment.scope_result;
            let entry = match assignment.admission {
                rss_mdm_execution_service::source_authority::ScopeAdmission::Eligible { entry } => {
                    entry
                }
                _ => 0,
            };
            let fact_key = format!("assignment:{task}:{policy}:{version}:{key}:{channel}");
            let changed = rss_mdm_policy_postgres::assignments::upsert_in(
                tx,
                rss_mdm_policy_postgres::assignments::Assignment {
                    policy,
                    version,
                    object: key,
                    channel: channel.to_owned(),
                    input,
                    available,
                    reason,
                    target,
                    scope_result: run,
                    entry_revision: entry,
                },
            )
            .await?;
            if changed {
                self.assignment_fact_in(tx, &fact_key, &p, assignment.target.as_ref(), available)
                    .await?;
                if available
                    && matches!(
                        p.definition.action.kind(),
                        rss_mdm_policy::ActionKind::NativeCollection
                            | rss_mdm_policy::ActionKind::Software
                    )
                    && let Some(target) = &assignment.target
                {
                    rss_mdm_execution_service::wake::wake_policy_device_in(
                        &self.reconcile_messaging,
                        tx,
                        version,
                        target,
                    )
                    .await?;
                }
            }
            if let Some(target) = assignment.target {
                devices.push(target.device);
            }
        }
        devices.sort();
        devices.dedup();
        rss_mdm_execution_service::wake::wake_native_batch_in(
            &self.reconcile_messaging,
            std::sync::Arc::new(crate::management::source::execution(self.objects.clone())),
            tx,
            &devices,
        )
        .await?;
        // Removed source objects remain inspectable as unavailable; existing operation targets are immutable.
        let policy = p.id;
        let version = p.version;
        let scope = p.definition.scope;
        let previous =
            rss_mdm_policy_postgres::assignments::objects_in(tx, policy, version).await?;
        let targets = previous
            .iter()
            .map(|(_, object)| object.clone())
            .collect::<Vec<_>>();
        let retained = rss_mdm_scope_postgres::ScopeBinding::new(self.runtime.clone(), self.tenant)
            .target_members_in(tx, scope, targets)
            .await?;
        let missing = previous
            .into_iter()
            .filter(|(_, object)| !retained.contains(object))
            .map(|(key, _)| key)
            .collect();
        let removed =
            rss_mdm_policy_postgres::assignments::withdraw_in(tx, policy, version, missing).await?;

        for (object, value) in removed {
            let target: Option<
                rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
            > = value
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| Error::Malformed)?;
            self.assignment_fact_in(
                tx,
                &format!("assignment:{task}:{policy}:{version}:{object}:removed"),
                &p,
                target.as_ref(),
                false,
            )
            .await?;
            let Some(target) = target else {
                continue;
            };
            let device = target.device;
            rss_mdm_execution_service::wake::wake_native_in(
                &self.reconcile_messaging,
                std::sync::Arc::new(crate::management::source::execution(self.objects.clone())),
                tx,
                &device,
            )
            .await?;
        }
        if more {
            {
                let next = keys.last().cloned();
                rss_mdm_policy_postgres::work::cursor_in(tx, task, next).await?;
                Ok(())
            }
        } else {
            crate::worker::jobs::finish_job_in(tx, &self.audit_store, task, None).await
        }
    }
}

impl crate::application::Application {
    async fn assignment_fact_in(
        &self,
        tx: &mut PgTransaction<'_>,
        key: &str,
        p: &Policy,
        target: Option<&rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
        available: bool,
    ) -> Result<()> {
        use rss_mdm_audit_integration::{AuditIntent, Fact, RequestAudit, activity::*};
        let audit = RequestAudit::new(
            tx.tenant_id().to_string(),
            "policy_assignment",
            AuditIntent::Management,
        );
        audit.identify_service("policy-assignment");
        audit.plan(p.version);
        audit.target(&p.id.to_string());
        let mut activity = Activity::new(
            ActivityKind::Assignment,
            if available {
                ActivityPhase::Assigned
            } else {
                ActivityPhase::Withdrawn
            },
        );
        activity.links.policy = Some(p.id);
        activity.links.version = Some(p.version);
        activity.origin = ActivityOrigin::Policy;
        activity.decision = Some(if available {
            ActivityDecision::Assigned
        } else {
            ActivityDecision::Unavailable
        });
        activity.target = target.map(|t| ActivityTarget {
            device: t.device.clone(),
            registration: t.registration_id,
            generation: t.generation,
        });
        if let Some(t) = target {
            audit.registration(t.registration_id);
        }
        self.audit_store.prepare_in(tx, &audit, &[]).await?;
        let fact = Fact::business(&audit, key, 200, "success", None)?.with_activity(&activity)?;
        let result = self.audit_store.append_in(tx, &fact).await;
        audit.finalize(None);
        result?;
        Ok(())
    }
}
