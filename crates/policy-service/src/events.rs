//! Policy event batches own acceptance identities and references, never execution state.
//! ref: meilisearch crates/index-scheduler/src/queue/batches.rs (atomic batch/member references).
use crate::application::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use crate::management as policies;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::activity::{ActivityDecision, ActivityOrigin};
use rss_mdm_authorization_service::OperationAuthority;
use rss_mdm_execution_service::{ExecutionService, Target};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

pub mod queries;

pub struct Events {
    pub application: Arc<Application>,
    pub execution: Arc<ExecutionService>,
}
#[derive(Clone, Copy)]
enum Requester<'a> {
    Management(&'a AuthorizedPrincipal),
    Agent(&'a rss_mdm_registration_service::device::DevicePrincipal),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Caller {
    Management { actor: crate::authorization::Actor },
    Agent { target: Target },
}
impl Caller {
    fn key(&self) -> std::result::Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::Malformed)
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct MemberAuthority {
    permissions: Vec<(Permission, OperationAuthority)>,
    retirement_target: Option<rss_mdm_inventory_service::objects::DeviceObject>,
}
struct Dispatch<'a> {
    policy: &'a rss_mdm_policy::Policy,
    target: &'a Target,
    member: Uuid,
    deadline: i64,
    input: &'a wire::PolicyEventRequest,
    audit: &'a RequestAudit,
    retirement_target: Option<&'a rss_mdm_inventory_service::objects::DeviceObject>,
}
const MAX_MEMBERS: usize = 1000;
impl Events {
    pub async fn invoke_management(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        input: &wire::PolicyEventRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<wire::PolicyEventAccepted, Error> {
        proof.manage(Permission::PolicyRead)?;
        if input.execution_context.is_some()
            || !matches!(
                input.source,
                wire::PolicyEventSource::Human | wire::PolicyEventSource::Ai
            )
        {
            return Err(Error::Malformed);
        }
        self.invoke(Requester::Management(proof), device, input, audit)
            .await
    }
    pub async fn invoke_agent(
        &self,
        principal: &rss_mdm_registration_service::device::DevicePrincipal,
        input: &wire::PolicyEventRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<wire::PolicyEventAccepted, Error> {
        self.invoke(
            Requester::Agent(principal),
            principal.device(),
            input,
            audit,
        )
        .await
    }
    async fn invoke(
        &self,
        requester: Requester<'_>,
        device: &str,
        input: &wire::PolicyEventRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<wire::PolicyEventAccepted, Error> {
        if input.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        let p = &self.application;
        let (caller, proof) = match requester {
            Requester::Management(proof) => (
                Caller::Management {
                    actor: proof.actor(),
                },
                Some(proof),
            ),
            Requester::Agent(principal) => (
                Caller::Agent {
                    target: Target {
                        device: principal.device().into(),
                        registration: principal.registration(),
                        generation: principal.generation(),
                    },
                },
                None,
            ),
        };
        audit.operation(
            input.operation_id,
            "policy_event",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let audit_store = &p.audit_store;
        run(
            audit_store,
            &p.runtime,
            p.tenant,
            audit,
            (self, &caller, requester, proof, device, input, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, caller, requester, proof, device, input, audit) = *ctx;
                    s.execution.validate_policy_transaction_in(tx)?;
                    crate::transaction::lock(tx).await?;
                    if let Requester::Agent(principal) = requester {
                        s.execution
                            .verify_event_device_in(tx, principal, Some(input))
                            .await?;
                    }
                    let snapshot = match proof {
                        Some(p) => {
                            let snapshot = crate::action_admission::current(tx, p).await?;
                            snapshot.require(p, Permission::PolicyRead, None)?;
                            Some(snapshot)
                        }
                        None => None,
                    };
                    let audit_store = &s.application.audit_store;
                    audit_store.prepare_in(tx, audit, &[]).await?;
                    if let Caller::Agent { target } = caller
                        && !s.execution.event_device_current_in(tx, target).await?
                    {
                        return Err(Error::Forbidden.into());
                    }
                    let actor = caller.key()?;
                    let hash = fingerprint(&(caller, device, input))?;
                    let operation = input.operation_id;
                    let actor_query = actor.clone();
                    let old: Option<(Vec<u8>, Uuid, i64)> =
                        rss_mdm_policy_postgres::events::replay_in(tx, actor_query, operation)
                            .await?;
                    if let Some((prior, batch, members)) = old {
                        if prior != hash {
                            return Err(Error::Conflict.into());
                        }
                        return Ok(wire::PolicyEventAccepted {
                            operation_id: operation,
                            batch_id: batch,
                            members: members as u32,
                        });
                    }
                    if let Caller::Agent { target } = caller
                        && !s
                            .execution
                            .event_parent_current_in(tx, target, &input.source)
                            .await?
                    {
                        return Err(Error::Forbidden.into());
                    }
                    if let Caller::Agent { target } = caller {
                        s.execution
                            .apply_event_context_in(
                                tx,
                                target,
                                input.execution_context.as_ref().ok_or(Error::Malformed)?,
                            )
                            .await?;
                    }
                    let name = input.event.as_str().to_owned();
                    let ids: Vec<Uuid> =
                        rss_mdm_policy_postgres::events::matching_policies_in(tx, name).await?;
                    if ids.len() > MAX_MEMBERS {
                        return Err(Error::Malformed.into());
                    }
                    let now = crate::action_admission::now(tx).await?;
                    let batch = Uuid::new_v4();
                    let mut member_count = 0;
                    let document = json(input)?;
                    let caller_document = json(caller)?;
                    let device_owned = device.to_owned();
                    rss_mdm_policy_postgres::events::insert_batch_in(
                        tx,
                        batch,
                        operation,
                        actor,
                        caller_document,
                        device_owned,
                        document,
                        hash,
                        now,
                        now.saturating_add(604800),
                    )
                    .await?;
                    let management_reader = rss_mdm_policy_postgres::PolicyReader::bind(
                        s.application.runtime.clone(),
                        s.application.tenant,
                    );
                    let reader = &management_reader;
                    for id in ids {
                        let policy =
                            checked(reader.read_in(tx, id).await?)?.ok_or(Error::NotFound)?;
                        let permission =
                            rss_mdm_execution_service::action_permission(&policy.definition.action);
                        let mut permissions = Vec::new();
                        let mut decision = wire::PolicyEventDecision::Pending;
                        let retirement_target = if matches!(
                            policy.definition.action,
                            rss_mdm_policy::Action::UnmanageDevice { .. }
                        ) {
                            let tenant = tx.tenant_id();
                            let reader = s.application.objects.clone();
                            let device = device.to_owned();
                            let object = tx
                                .with_connection(move |c| {
                                    Box::pin(
                                        async move { reader.endpoint(c, tenant, &device).await },
                                    )
                                })
                                .await?;
                            Some(
                                tx.with_connection(move |c| {
                                    Box::pin(async move {
                                        Ok(rss_mdm_device_service::lifecycle::complete_target_in(
                                            c, tenant, &object,
                                        )
                                        .await)
                                    })
                                })
                                .await?
                                .map_err(Error::from)?,
                            )
                        } else {
                            None
                        };
                        if let (Some(snapshot), Some(proof)) = (&snapshot, proof) {
                            let mut required = vec![permission];
                            if matches!(
                                policy.definition.action,
                                rss_mdm_policy::Action::EnsureAgentInstalled { .. }
                            ) {
                                required.push(Permission::Enrollment);
                            }
                            let devices = retirement_target.as_ref().map_or_else(
                                || vec![device.to_owned()],
                                |object| object.members.iter().map(|m| m.device.clone()).collect(),
                            );
                            for device in devices {
                                for p in &required {
                                    match OperationAuthority::from_proof(
                                        snapshot, proof, &device, *p,
                                    ) {
                                        Ok(a) => permissions.push((*p, a)),
                                        Err(_) => {
                                            decision = wire::PolicyEventDecision::Rejected {
                                                reason: "permission_denied".into(),
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        let channel = policy.definition.action.target_channel().map_or(
                            "agent",
                            |c| match c {
                                rss_mdm_policy::SoftwareChannel::Agent => "agent",
                                rss_mdm_policy::SoftwareChannel::Mdm => "mdm",
                            },
                        );
                        let mut target = rss_mdm_execution_service::policy_events::target_in(
                            tx, device, channel,
                        )
                        .await?;
                        if target.is_none()
                            && matches!(
                                policy.definition.action,
                                rss_mdm_policy::Action::UnmanageDevice { .. }
                            )
                        {
                            target = rss_mdm_execution_service::policy_events::target_in(
                                tx, device, "mdm",
                            )
                            .await?;
                        }
                        if matches!(caller, Caller::Agent { .. }) {
                            let Some(ref target) = target else {
                                continue;
                            };
                            if !s.execution.event_scope_in(tx, &policy, target).await? {
                                continue;
                            }
                        }
                        member_count += 1;
                        if target.is_none() {
                            decision = wire::PolicyEventDecision::Rejected {
                                reason: "registration_unavailable".into(),
                            };
                        }
                        let member = Uuid::new_v4();
                        if !matches!(decision, wire::PolicyEventDecision::Pending) {
                            let mut activity = rss_mdm_audit_integration::activity::Activity::new(
                                rss_mdm_audit_integration::activity::ActivityKind::Batch,
                                rss_mdm_audit_integration::activity::ActivityPhase::Decided,
                            );
                            let visible_target = match &target {
                                Some(t) => Some(t.clone()),
                                None => match caller {
                                    Caller::Agent { target } => Some(target.clone()),
                                    _ => {
                                        rss_mdm_execution_service::policy_events::target_in(
                                            tx, device, "mdm",
                                        )
                                        .await?
                                    }
                                },
                            };
                            activity.target = visible_target.map(|t| {
                                rss_mdm_audit_integration::activity::ActivityTarget {
                                    device: t.device,
                                    registration: t.registration,
                                    generation: t.generation,
                                }
                            });
                            activity.links.batch = Some(batch);
                            activity.links.member = Some(member);
                            activity.links.policy = Some(policy.id);
                            activity.links.version = Some(policy.version);
                            activity.links.request = Some(operation);
                            activity.decision = Some(ActivityDecision::Rejected);
                            activity.origin = match input.source {
                                wire::PolicyEventSource::Human => ActivityOrigin::Human,
                                wire::PolicyEventSource::Ai => ActivityOrigin::Ai,
                                wire::PolicyEventSource::Policy { .. } => ActivityOrigin::Policy,
                            };
                            audit_store
                                .append_in(
                                    tx,
                                    &rss_mdm_audit_integration::Fact::business(
                                        audit,
                                        &format!("policy-event:{batch}:{member}"),
                                        200,
                                        "rejected",
                                        None,
                                    )?
                                    .with_activity(&activity)?,
                                )
                                .await?;
                        }
                        let target = json(&target)?;
                        let authority = json(&MemberAuthority {
                            permissions,
                            retirement_target,
                        })?;
                        let decision = json(&decision)?;
                        rss_mdm_policy_postgres::events::insert_member_in(
                            tx,
                            batch,
                            member,
                            policy.id,
                            policy.revision,
                            policy.version,
                            target,
                            authority,
                            decision,
                        )
                        .await?;
                    }
                    crate::worker::jobs::enqueue_job_in(
                        tx,
                        batch,
                        &crate::worker::Work::PolicyEvent { batch },
                    )
                    .await?;
                    let mut activity = rss_mdm_audit_integration::activity::Activity::new(
                        rss_mdm_audit_integration::activity::ActivityKind::Batch,
                        rss_mdm_audit_integration::activity::ActivityPhase::Accepted,
                    );
                    activity.links.batch = Some(batch);
                    activity.links.request = Some(operation);
                    activity.origin = match input.source {
                        wire::PolicyEventSource::Human => ActivityOrigin::Human,
                        wire::PolicyEventSource::Ai => ActivityOrigin::Ai,
                        wire::PolicyEventSource::Policy { .. } => ActivityOrigin::Policy,
                    };
                    let target = if let Caller::Agent { target } = caller {
                        Some(target.clone())
                    } else {
                        rss_mdm_execution_service::policy_events::target_in(tx, device, "agent")
                            .await?
                    };
                    let target = match target {
                        Some(t) => Some(t),
                        None => {
                            rss_mdm_execution_service::policy_events::target_in(tx, device, "mdm")
                                .await?
                        }
                    };
                    activity.target =
                        target.map(|t| rss_mdm_audit_integration::activity::ActivityTarget {
                            device: t.device,
                            registration: t.registration,
                            generation: t.generation,
                        });
                    audit_store
                        .append_in(
                            tx,
                            &rss_mdm_audit_integration::Fact::business(
                                audit,
                                &format!("policy-event:{batch}:accepted"),
                                202,
                                "success",
                                None,
                            )?
                            .with_activity(&activity)?,
                        )
                        .await?;
                    if let Some(proof) = proof {
                        proof.check_live()?;
                    }
                    Ok(wire::PolicyEventAccepted {
                        operation_id: operation,
                        batch_id: batch,
                        members: member_count,
                    })
                })
            },
        )
        .await
    }
}

impl Application {
    pub(crate) async fn advance_event_in(
        &self,
        execution: &ExecutionService,
        tx: &mut PgTransaction<'_>,
        batch: Uuid,
    ) -> Result<()> {
        execution.validate_policy_transaction_in(tx)?;
        self.runtime.validate_transaction(tx)?;
        let audit_store = &self.audit_store;
        let row = rss_mdm_policy_postgres::events::pending_member_in(tx, batch).await?;
        let Some(row) = row else {
            return crate::worker::jobs::finish_job_in(tx, audit_store, batch, None).await;
        };
        let member: Uuid = row.try_get("id")?;
        let id: Uuid = row.try_get("policy")?;
        let version: Uuid = row.try_get("version")?;
        let deadline: i64 = row.try_get("deadline")?;
        let target: Target = stored(serde_json::from_value(row.try_get("target")?))?;
        let caller: Caller = stored(serde_json::from_value(row.try_get("caller")?))?;
        let authority: MemberAuthority = stored(serde_json::from_value(row.try_get("authority")?))?;
        let input: wire::PolicyEventRequest =
            stored(serde_json::from_value(row.try_get("input")?))?;
        let audit = RequestAudit::new(
            self.tenant.to_string(),
            "policy_event_member",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("policy-event");
        audit.operation(
            member,
            "policy_event_member",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.registration(target.registration);
        audit.target(&target.device);
        audit_store.prepare_in(tx, &audit, &[]).await?;
        let now = crate::action_admission::now(tx).await?;
        let reader = rss_mdm_policy_postgres::PolicyReader::bind(self.runtime.clone(), self.tenant);
        let policy = policies::storage::read_in(&reader, tx, id).await?;
        let mut valid = execution.event_device_current_in(tx, &target).await?;
        for (permission, proof) in authority.permissions {
            valid &= tx
                .with_connection(move |c| {
                    Box::pin(async move { Ok(proof.valid(c, permission, now).await) })
                })
                .await??;
        }
        if let Caller::Agent { target: ref origin } = caller {
            valid &= execution.event_device_current_in(tx, origin).await?;
        }
        let decision = if now >= deadline {
            wire::PolicyEventDecision::Expired
        } else if !valid {
            rss_mdm_execution_service::policy_events::rejected("authority_changed")
        } else if let Some(policy) = policy.filter(|p| p.version == version) {
            if !policy.state.is_enabled() {
                rss_mdm_execution_service::policy_events::rejected("policy_disabled")
            } else {
                self.dispatch_event_in(
                    execution,
                    tx,
                    Dispatch {
                        policy: &policy,
                        target: &target,
                        member,
                        deadline,
                        input: &input,
                        audit: &audit,
                        retirement_target: authority.retirement_target.as_ref(),
                    },
                )
                .await?
            }
        } else {
            rss_mdm_execution_service::policy_events::rejected("policy_changed")
        };
        let mut activity = rss_mdm_audit_integration::activity::Activity::new(
            rss_mdm_audit_integration::activity::ActivityKind::Batch,
            rss_mdm_audit_integration::activity::ActivityPhase::Decided,
        );
        activity.target = Some(rss_mdm_audit_integration::activity::ActivityTarget {
            device: target.device.clone(),
            registration: target.registration,
            generation: target.generation,
        });
        activity.links.batch = Some(batch);
        activity.links.member = Some(member);
        activity.links.policy = Some(id);
        activity.links.version = Some(version);
        activity.links.request = Some(input.operation_id);
        activity.origin = match input.source {
            wire::PolicyEventSource::Human => ActivityOrigin::Human,
            wire::PolicyEventSource::Ai => ActivityOrigin::Ai,
            wire::PolicyEventSource::Policy { .. } => ActivityOrigin::Policy,
        };
        activity.decision = Some(match &decision {
            wire::PolicyEventDecision::Pending => ActivityDecision::Pending,
            wire::PolicyEventDecision::Accepted { .. } => ActivityDecision::Accepted,
            wire::PolicyEventDecision::NoChange { .. } => ActivityDecision::NoChange,
            wire::PolicyEventDecision::Rejected { .. } => ActivityDecision::Rejected,
            wire::PolicyEventDecision::Expired => ActivityDecision::Expired,
        });
        if let wire::PolicyEventDecision::Accepted { operations } = &decision {
            activity.links.operations = operations
                .iter()
                .map(|r| {
                    use rss_mdm_audit_integration::activity::ActivityOperation as A;
                    match r {
                        wire::PolicyEventOperation::Run { id } => A::Run { id: *id },
                        wire::PolicyEventOperation::Native { id } => A::Native { id: *id },
                        wire::PolicyEventOperation::Retirement { id } => A::Retirement { id: *id },
                    }
                })
                .collect();
        }
        let decision = json(&decision)?;
        rss_mdm_policy_postgres::events::decide_member_in(tx, member, decision).await?;
        audit_store
            .append_in(
                tx,
                &rss_mdm_audit_integration::Fact::business(
                    &audit,
                    &format!("policy-event:{batch}:{member}"),
                    200,
                    "success",
                    None,
                )?
                .with_activity(&activity)?,
            )
            .await?;
        audit.finalize(None);
        Ok(())
    }
    async fn dispatch_event_in(
        &self,
        execution: &ExecutionService,
        tx: &mut PgTransaction<'_>,
        dispatch: Dispatch<'_>,
    ) -> Result<wire::PolicyEventDecision> {
        let Dispatch {
            policy,
            target,
            member,
            deadline,
            input,
            audit,
            retirement_target,
        } = dispatch;
        use rss_mdm_policy::Action;
        let origin = match input.source {
            wire::PolicyEventSource::Human => ActivityOrigin::Human,
            wire::PolicyEventSource::Ai => ActivityOrigin::Ai,
            wire::PolicyEventSource::Policy { .. } => ActivityOrigin::Policy,
        };
        if matches!(input.source, wire::PolicyEventSource::Ai)
            && matches!(policy.definition.action, Action::Execution { .. })
            && !policy.definition.self_service.as_ref().is_some_and(|s| {
                s.allow_ai == Some(true) && s.risk_level.is_some_and(|risk| risk.value() == 1)
            })
        {
            return Ok(rss_mdm_execution_service::policy_events::rejected(
                "ai_not_allowed",
            ));
        }
        match &policy.definition.action {
            Action::TelemetryProfile { .. } => {
                let device = target.device.clone();
                let id = policy.id;
                let version = policy.version;
                {
                    let tenant = self.tenant;
                    let objects = self.objects.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::telemetry::current_on(
                                tenant, objects, c, &device, id, version,
                            )
                            .await)
                        })
                    })
                }
                .await??;
                Ok(wire::PolicyEventDecision::NoChange {
                    reason: "configuration_available".into(),
                })
            }
            Action::UnmanageDevice { .. } => {
                self.accept_event_retirement_in(
                    tx,
                    policy,
                    target,
                    (member, origin),
                    retirement_target.ok_or(Error::Malformed)?,
                )
                .await
            }
            _ => Ok(execution
                .accept_policy_event_in(tx, policy, target, (member, origin), deadline, audit)
                .await?),
        }
    }
}
impl Application {
    async fn accept_event_retirement_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &rss_mdm_policy::Policy,
        target: &Target,
        cause: (Uuid, ActivityOrigin),
        frozen_target: &rss_mdm_inventory_service::objects::DeviceObject,
    ) -> Result<wire::PolicyEventDecision> {
        use rss_mdm_execution_service::source_authority::SourceAuthority;
        let (member, origin) = cause;
        let tenant = tx.tenant_id();
        let reader = self.objects.clone();
        let device = target.device.clone();
        let scope = policy.definition.scope;
        let object = tx
            .with_connection(move |c| {
                Box::pin(async move { reader.endpoint(c, tenant, &device).await })
            })
            .await?;
        let reader = self.objects.clone();
        let object = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        rss_mdm_device_service::lifecycle::complete_target_in(c, tenant, &object)
                            .await,
                    )
                })
            })
            .await?
            .map_err(Error::from)?;
        if &object != frozen_target {
            return Ok(rss_mdm_execution_service::policy_events::rejected(
                "target_changed",
            ));
        }
        for member in &object.members {
            let source = crate::management::source::execution(self.objects.clone());
            let member = member.clone();
            let eligible = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(source
                            .admission_on(c, tenant, scope, member.channel, &member.device)
                            .await)
                    })
                })
                .await?
                .map_err(rss_mdm_execution_service::Error::from)?;
            if !matches!(
                eligible,
                rss_mdm_execution_service::source_authority::ScopeAdmission::Eligible { .. }
            ) {
                return Ok(rss_mdm_execution_service::policy_events::rejected(
                    "scope_not_eligible",
                ));
            }
        }
        let published = checked(
            rss_mdm_policy_postgres::PolicyReader::bind(self.runtime.clone(), self.tenant)
                .version_in(tx, policy.version)
                .await?,
        )?
        .ok_or(Error::NotFound)?;
        let frozen: rss_mdm_execution_service::frozen::Frozen =
            stored(serde_json::from_value(published.frozen))?;
        let rss_mdm_execution_service::frozen::Frozen::UnmanageDevice {
            actor,
            run_lifetime_seconds,
            schedule,
        } = frozen
        else {
            return Err(Error::Malformed.into());
        };
        let now = crate::action_admission::now(tx).await?;
        if !schedule
            .occurrence(now, target.device.as_bytes())?
            .is_some_and(|s| s.available_at <= now && s.window_end.is_none_or(|end| now < end))
        {
            return Ok(rss_mdm_execution_service::policy_events::rejected(
                "outside_window",
            ));
        }
        let id = policy.id;
        let version = policy.version;
        let occurrence = format!("event:{member}");
        let accepted = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(rss_mdm_device_service::lifecycle::accept_in(
                        c,
                        tenant,
                        reader.as_ref(),
                        &rss_mdm_device_service::lifecycle::Acceptance {
                            origin,
                            policy: id,
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
        Ok(wire::PolicyEventDecision::Accepted {
            operations: vec![wire::PolicyEventOperation::Retirement { id: accepted.0 }],
        })
    }
    /// Called only after confirmed rollback, under the original job claim.
    pub(crate) async fn reject_event_member_in(
        &self,
        audit_store: &rss_mdm_audit_integration::AuditStore,
        tx: &mut PgTransaction<'_>,
        batch: Uuid,
        reason: &str,
    ) -> Result<()> {
        let audit = RequestAudit::new(
            self.tenant.to_string(),
            "policy_event_member",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("policy-event");
        audit_store.prepare_in(tx, &audit, &[]).await?;
        let decision = json!({"state":"rejected","reason":reason});
        let member: Option<Uuid> =
            rss_mdm_policy_postgres::events::reject_next_in(tx, batch, decision).await?;
        if let Some(member) = member {
            let row = rss_mdm_policy_postgres::events::member_fact_in(tx, member).await?;
            let target: Target = stored(serde_json::from_value(row.try_get("target")?))?;
            let input: wire::PolicyEventRequest =
                stored(serde_json::from_value(row.try_get("input")?))?;
            let mut activity = rss_mdm_audit_integration::activity::Activity::new(
                rss_mdm_audit_integration::activity::ActivityKind::Batch,
                rss_mdm_audit_integration::activity::ActivityPhase::Decided,
            );
            activity.target = Some(rss_mdm_audit_integration::activity::ActivityTarget {
                device: target.device.clone(),
                registration: target.registration,
                generation: target.generation,
            });
            activity.links.batch = Some(batch);
            activity.links.member = Some(member);
            activity.links.policy = Some(row.try_get("policy")?);
            activity.links.version = Some(row.try_get("version")?);
            activity.links.request = Some(row.try_get("request")?);
            activity.decision = Some(ActivityDecision::Rejected);
            activity.origin = match input.source {
                wire::PolicyEventSource::Human => ActivityOrigin::Human,
                wire::PolicyEventSource::Ai => ActivityOrigin::Ai,
                wire::PolicyEventSource::Policy { .. } => ActivityOrigin::Policy,
            };
            audit.registration(target.registration);
            audit.target_device(&target.device);
            audit.operation(
                member,
                "policy_event_member",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            audit_store
                .append_in(
                    tx,
                    &rss_mdm_audit_integration::Fact::business(
                        &audit,
                        &format!("policy-event:{batch}:{member}"),
                        200,
                        "rejected",
                        None,
                    )?
                    .with_activity(&activity)?,
                )
                .await?;
        }
        audit.finalize(None);
        Ok(())
    }
}
