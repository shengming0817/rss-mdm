//! Targeted self-service calls share the existing Policy version, Run reducer and admission.
mod access;
pub mod directory;
/// Validate selector coordinates at Policy publication without manufacturing grants.
pub fn validate_access(
    config: &rss_mdm_policy::SelfService,
    tenant: &str,
    instance: &str,
) -> std::result::Result<(), Error> {
    access::selectors(config, tenant, instance)
        .map(|_| ())
        .map_err(|fault| match fault {
            Fault::Request(error) => error,
            _ => Error::Malformed,
        })
}

use crate::{
    Error, ExecutionService, Result, Target,
    actions::{production, storage as db},
    authorization::{Permission, context::AuthorizedPrincipal},
    storage,
    transaction::*,
};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_registration_service::DevicePrincipal;
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    #[serde(deserialize_with = "required_activity_user")]
    pub activity_user: Option<rss_mdm_audit_integration::activity::ActivityUser>,
    pub authorization: wire::TaskAuthorization,
    pub parameters: std::collections::BTreeMap<String, Value>,
    pub execution_target: Option<wire::SoftwareExecutionTarget>,
    pub pending_scope: Option<Uuid>,
    pub pending_rollout: Option<rss_mdm_policy::SoftwareRollout>,
}
impl Invocation {
    /// Verify the accepted invocation against its immutable task and real execution target.
    pub async fn valid_in(
        &self,
        service: &ExecutionService,
        tx: &mut PgTransaction<'_>,
        plan: &db::ScheduledPolicy,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        let wire::TaskAuthorization::SelfService { policy_version, .. } = &self.authorization
        else {
            return Ok(false);
        };
        match plan {
            db::ScheduledPolicy::Script(script) if script.id == *policy_version => {
                if script
                    .frozen
                    .definition
                    .validate_parameters(&json!(self.parameters))
                    .is_err()
                {
                    return Ok(false);
                }
            }
            db::ScheduledPolicy::Software(software)
                if software.id == *policy_version
                    && software.assignment.intent()
                        == rss_mdm_policy::SoftwareIntent::AvailableInstall
                    && self.parameters.is_empty() => {}
            db::ScheduledPolicy::Enrollment(enrollment)
                if enrollment.id == *policy_version
                    && self.parameters.is_empty()
                    && self.execution_target.is_none() => {}
            _ => return Ok(false),
        }
        if self.pending_scope.is_some() {
            return Ok(false);
        }
        if let Some(expected) = &self.execution_target
            && execution_target_in(service, tx, plan, target)
                .await?
                .as_ref()
                != Some(expected)
        {
            return Ok(false);
        }
        plan.run_admission_in(service, tx, target, now).await
    }
}
fn effective_risk(policy: &rss_mdm_policy::Policy) -> u8 {
    policy
        .definition
        .self_service
        .as_ref()
        .and_then(|s| s.risk_level)
        .map_or(2, |r| r.value())
}
struct Prepared {
    task: Option<wire::SelfServiceTask>,
    parameters: std::collections::BTreeMap<String, Value>,
    slot: InvocationSlot,
    effect: Option<Value>,
    execution_target: Option<wire::SoftwareExecutionTarget>,
}
async fn prepare_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    plan: &db::ScheduledPolicy,
    target: &Target,
    request: Uuid,
    input: Option<&std::collections::BTreeMap<String, Value>>,
    now: i64,
) -> Result<Option<Prepared>> {
    if input.is_none() && !plan.authorized_in(service, tx, target, now).await? {
        return Ok(None);
    }
    match plan {
        db::ScheduledPolicy::Script(script) => {
            let entry = match script
                .entry_in(&service.source, tx, &target.device, now)
                .await?
            {
                Some(entry) => entry,
                None if input.is_some() => 0,
                None => return Ok(None),
            };
            let Some(slot) = invocation_slot_in(tx, script, target, entry, request, now).await?
            else {
                return Ok(None);
            };
            let parameters = match input {
                Some(input) => {
                    let values = script.frozen.parameters.resolve(&json!(input))?;
                    script
                        .frozen
                        .definition
                        .validate_parameters(&values)
                        .map_err(|_| Error::Malformed)?;
                    checked_input(serde_json::from_value(values))?
                }
                None => Default::default(),
            };
            let task = wire::SelfServiceTask::Script {
                resource: script.frozen.resource.clone(),
                run_as: script.frozen.execution_identity(),
                parameter_sources: parameter_sources(&script.frozen.parameters),
                parameter_schema: script.frozen.definition.spec().parameters.clone(),
            };
            Ok(Some(Prepared {
                task: Some(task),
                parameters,
                slot,
                effect: None,
                execution_target: execution_target_in(service, tx, plan, target).await?,
            }))
        }
        db::ScheduledPolicy::Software(software)
            if software.assignment.intent() == rss_mdm_policy::SoftwareIntent::AvailableInstall =>
        {
            if input.is_some_and(|input| !input.is_empty()) {
                return Err(Error::Malformed.into());
            }
            let binding = crate::channels::agent_binding_in(
                tx,
                service.agent_store.clone(),
                target.registration,
            )
            .await?
            .ok_or(Error::Forbidden)?;
            let (platform, architecture) = db::agent_profile_in(service, tx, target.registration)
                .await?
                .ok_or(Error::Forbidden)?;
            if input.is_some()
                && !software
                    .assignment
                    .supported_in(&service.admission(), tx, &binding)
                    .await?
            {
                if software
                    .assignment
                    .admitted_in(&service.admission(), tx, platform, architecture)
                    .await?
                    .is_none()
                {
                    return Err(Error::Forbidden.into());
                }
                let occurrence = format!("self-service:{request}");
                if !production::occurrence_available_in(tx, software.id, target, &occurrence, now)
                    .await?
                {
                    return Ok(None);
                }
                let schedule = &software.assignment.frozen.schedule;
                let Some(window) = schedule.occurrence(now, target.device.as_bytes())? else {
                    return Ok(None);
                };
                let available = window.available_at.max(now);
                let deadline = available
                    .checked_add(i64::from(software.assignment.frozen.run_lifetime_seconds))
                    .ok_or(Error::Malformed)?
                    .min(schedule.ends_at())
                    .min(window.window_end.unwrap_or(i64::MAX));
                if deadline <= available {
                    return Ok(None);
                }
                return Ok(Some(Prepared {
                    task: None,
                    parameters: Default::default(),
                    slot: InvocationSlot {
                        occurrence,
                        available,
                        deadline,
                    },
                    effect: None,
                    execution_target: None,
                }));
            }
            let crate::actions::software::Preparation::Ready(slot) =
                crate::actions::software::slot_in(
                    service,
                    tx,
                    software,
                    target,
                    Some(crate::actions::software::Invocation::SelfService(request)),
                    now,
                    None,
                )
                .await?
            else {
                return Ok(None);
            };
            let root = slot.steps.last().ok_or(Error::Malformed)?;
            let task = wire::SelfServiceTask::Software {
                resource: wire::TaskResource {
                    id: software.assignment.frozen.resource.clone(),
                    version: software.assignment.frozen.version.clone(),
                    variant: software
                        .assignment
                        .variant(platform, architecture)
                        .ok_or(Error::Forbidden)?
                        .into(),
                },
                run_as: rss_mdm_software_service::preparation::execution::execution_identity(
                    &root.action,
                ),
                target: root.target.clone(),
            };
            Ok(Some(Prepared {
                task: Some(task),
                parameters: Default::default(),
                slot: InvocationSlot {
                    occurrence: slot.occurrence,
                    available: slot.available,
                    deadline: slot.deadline,
                },
                effect: Some(slot.effect),
                execution_target: Some(root.target.clone()),
            }))
        }
        db::ScheduledPolicy::Enrollment(enrollment) => {
            if input.is_some_and(|input| !input.is_empty()) {
                return Err(Error::Malformed.into());
            }
            let (pending, last) = production::policy_pending_in(
                tx,
                enrollment.owner,
                enrollment.id,
                target,
                now,
                true,
            )
            .await?;
            let occurrence = format!("self-service:{request}");
            if !production::occurrence_available_in(tx, enrollment.id, target, &occurrence, now)
                .await?
            {
                return Ok(None);
            }
            let schedule = &enrollment.frozen.schedule;
            if pending || !production::check_in_interval_elapsed(&schedule.trigger, last, now) {
                return Ok(None);
            }
            let Some(slot) = schedule.occurrence(now, target.device.as_bytes())? else {
                return Ok(None);
            };
            let available = slot.available_at.max(now);
            let deadline = available
                .checked_add(i64::from(enrollment.frozen.run_lifetime_seconds))
                .ok_or(Error::Malformed)?
                .min(schedule.ends_at())
                .min(slot.window_end.unwrap_or(i64::MAX));
            if deadline <= available {
                return Ok(None);
            }
            let (platform, _) = db::agent_profile_in(service, tx, target.registration)
                .await?
                .ok_or(Error::Forbidden)?;
            Ok(Some(Prepared {
                task: Some(wire::SelfServiceTask::Enrollment {
                    organization: enrollment.frozen.organization,
                    entry: enrollment
                        .frozen
                        .entries
                        .for_platform(platform)
                        .ok_or(Error::Unsupported)?,
                }),
                parameters: Default::default(),
                slot: InvocationSlot {
                    occurrence,
                    available,
                    deadline,
                },
                effect: None,
                execution_target: None,
            }))
        }
        _ => Ok(None),
    }
}
async fn execution_target_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    plan: &db::ScheduledPolicy,
    target: &Target,
) -> Result<Option<wire::SoftwareExecutionTarget>> {
    let Some(binding) =
        crate::channels::agent_binding_in(tx, service.agent_store.clone(), target.registration)
            .await?
    else {
        return Ok(None);
    };
    let Some((platform, architecture)) =
        db::agent_profile_in(service, tx, target.registration).await?
    else {
        return Ok(None);
    };
    match plan {
        db::ScheduledPolicy::Script(script) => Ok(
            rss_mdm_software_service::preparation::execution::identity_target(
                script.frozen.execution_identity(),
                match platform {
                    rss_mdm_policy::Platform::Windows => wire::TaskPlatform::Windows,
                    rss_mdm_policy::Platform::Macos => wire::TaskPlatform::Macos,
                },
                &binding.execution_context,
            )
            .ok(),
        ),
        db::ScheduledPolicy::Software(software) => Ok(software
            .assignment
            .prepared_in(
                &service.admission(),
                tx,
                platform,
                architecture,
                &binding.execution_context,
            )
            .await?
            .and_then(|steps| steps.last().map(|root| root.target.clone()))),
        _ => Ok(None),
    }
}
fn target(p: &DevicePrincipal) -> Target {
    Target {
        device: p.device().into(),
        registration: p.registration(),
        generation: p.generation(),
    }
}
fn bind(
    p: &DevicePrincipal,
    proof: Option<&AuthorizedPrincipal>,
    audit: &RequestAudit,
) -> std::result::Result<(), Error> {
    if let Some(proof) = proof {
        if proof.tenant_id() != p.tenant().to_string() {
            return Err(Error::Forbidden);
        }
        proof.check_live()?;
        proof.bind_audit(audit)?;
    }
    Ok(())
}
fn actor(p: &DevicePrincipal, subject: &wire::SelfServiceSubject) -> String {
    let subject = match subject {
        wire::SelfServiceSubject::Device {} => "device".into(),
        wire::SelfServiceSubject::User { user } => {
            format!("{}:{}", user.instance_id, user.principal_id)
        }
    };
    format!(
        "self-service:{subject}:{}:{}",
        p.registration(),
        p.generation()
    )
}
fn request_actors(p: &DevicePrincipal, proof: Option<&AuthorizedPrincipal>) -> Result<Vec<String>> {
    let mut actors = Vec::new();
    if let Some(proof) = proof {
        actors.push(actor(
            p,
            &wire::SelfServiceSubject::User {
                user: wire::SelfServiceUser {
                    tenant_id: checked_input(Uuid::parse_str(proof.tenant_id()))?,
                    instance_id: checked_input(Uuid::parse_str(proof.instance_id()))?,
                    principal_id: checked_input(Uuid::parse_str(proof.principal_id()))?,
                },
            },
        ));
    }
    actors.push(actor(p, &wire::SelfServiceSubject::Device {}));
    Ok(actors)
}
fn owns(subject: &wire::SelfServiceSubject, proof: Option<&AuthorizedPrincipal>) -> bool {
    match subject {
        wire::SelfServiceSubject::Device {} => true,
        wire::SelfServiceSubject::User { user } => proof.is_some_and(|proof| {
            proof.instance_id() == user.instance_id.to_string()
                && proof.principal_id() == user.principal_id.to_string()
                && proof.tenant_id() == user.tenant_id.to_string()
        }),
    }
}
impl ExecutionService {
    pub async fn invoke_self_service(
        &self,
        p: &DevicePrincipal,
        proof: Option<&AuthorizedPrincipal>,
        input: &wire::SelfServiceInvoke,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        bind(p, proof, audit)?;
        if input.operation_id.is_nil()
            || input.policy_id.is_nil()
            || input.parameters.len() > 32
            || serde_json::to_vec(input)
                .map_err(|_| Error::Malformed)?
                .len()
                > 131072
        {
            return Err(Error::Malformed);
        }
        audit.operation(
            input.operation_id,
            "command_accept",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let id = Uuid::new_v4();
        run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, p, proof, input, audit, id),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, p, proof, input, audit, id) = *ctx;

                    storage::lock_device(tx, p.device()).await?;
                    crate::actions::agent::principal(service, tx, p).await?;
                    let hash = fingerprint(input)?;
                    let now = storage::now(tx).await?;
                    crate::transaction::prepare_audit_in(&service.audit_store, tx, audit, &[])
                        .await?;
                    // Search the same authenticated identities as status before selecting today's access basis.
                    for actor in request_actors(p, proof)? {
                        if let Some(response) =
                            db::replay(tx, &actor, input.operation_id, &hash).await?
                        {
                            let run = db::load_run(
                                tx,
                                checked_input(Uuid::parse_str(
                                    response["runId"].as_str().ok_or(Error::Malformed)?,
                                ))?,
                            )
                            .await?;
                            crate::actions::agent::belongs(&run, p)?;

                            return Ok(response);
                        }
                    }
                    let policy = crate::sources::storage::read_in(
                        &service.policy_reader,
                        tx,
                        input.policy_id,
                    )
                    .await?
                    .ok_or(Error::NotFound)?;
                    let config = policy
                        .definition
                        .self_service
                        .as_ref()
                        .ok_or(Error::Forbidden)?;
                    let allow_ai = config.allow_ai.ok_or(Error::Forbidden)?;
                    let risk = effective_risk(&policy);
                    if !policy.state.is_enabled()
                        || !config.published
                        || (input.source == wire::SelfServiceCaller::Ai
                            && (!allow_ai || (risk == 2 && !input.confirmed)))
                    {
                        return Err(Error::Forbidden.into());
                    }
                    let basis = access::select(config, proof)?.ok_or(Error::Forbidden)?;
                    let subject = access::qualify_in(service, tx, config, &basis)
                        .await?
                        .ok_or(Error::Forbidden)?;
                    let actor = actor(p, &subject);
                    let event_key = format!("{actor}:{}", input.operation_id);
                    let plan = db::load_source(
                        &service.policy_reader,
                        tx,
                        db::Source::Policy {
                            version: policy.version,
                        },
                    )
                    .await?;
                    let target = target(p);
                    let admission = crate::sources::storage::admission_in(
                        &service.source,
                        tx,
                        policy.definition.scope,
                        crate::source_authority::Channel::Agent,
                        p.device(),
                    )
                    .await?;
                    if admission == crate::source_authority::ScopeAdmission::Excluded {
                        return Err(Error::Forbidden.into());
                    }
                    let rollout_pending = if let db::ScheduledPolicy::Software(v) = &plan {
                        v.assignment
                            .entry_in(&service.source, tx, p.device(), now)
                            .await?
                            .is_none()
                    } else {
                        false
                    };
                    let pending_scope = (admission
                        == crate::source_authority::ScopeAdmission::Pending
                        || rollout_pending)
                        .then_some(policy.definition.scope);
                    let pending_rollout = if pending_scope.is_some() {
                        match &policy.definition.action {
                            rss_mdm_policy::Action::Software { rollout, .. } => {
                                Some(rollout.clone())
                            }
                            _ => None,
                        }
                    } else {
                        None
                    };
                    let Some(prepared) = prepare_in(
                        service,
                        tx,
                        &plan,
                        &target,
                        input.operation_id,
                        Some(&input.parameters),
                        now,
                    )
                    .await?
                    else {
                        return Err(Error::Conflict.into());
                    };
                    let decision = wire::TaskAuthorization::SelfService {
                        request_id: input.operation_id,
                        subject,
                        source: input.source,
                        policy_id: policy.id,
                        policy_revision: policy.revision as u64,
                        policy_version: policy.version,
                        allow_ai,
                        risk_level: risk,
                        confirmed: input.confirmed,
                    };
                    checked_input(
                        decision.validate(checked_input(Uuid::parse_str(&p.tenant().to_string()))?),
                    )?;
                    let binding = crate::channels::agent_binding_in(
                        tx,
                        service.agent_store.clone(),
                        p.registration(),
                    )
                    .await?
                    .ok_or(Error::Forbidden)?;
                    let activity_user = match (
                        &decision,
                        binding.execution_context.interactive_user.as_ref(),
                    ) {
                        (
                            wire::TaskAuthorization::SelfService {
                                subject: wire::SelfServiceSubject::User { user },
                                ..
                            },
                            Some(os),
                        ) => Some(rss_mdm_audit_integration::activity::ActivityUser {
                            instance: user.instance_id,
                            principal: user.principal_id,
                            os_identity: os.identity.clone(),
                            generated_uid: os.generated_uid.clone(),
                            session: os.session_id,
                        }),
                        _ => None,
                    };
                    let invocation = Invocation {
                        activity_user,
                        authorization: decision,
                        parameters: prepared.parameters,
                        execution_target: prepared.execution_target,
                        pending_scope,
                        pending_rollout,
                    };
                    production::queue_run_in(
                        service,
                        tx,
                        production::RunInput {
                            origin: match input.source {
                                wire::SelfServiceCaller::Human => {
                                    rss_mdm_audit_integration::activity::ActivityOrigin::Human
                                }
                                wire::SelfServiceCaller::Ai => {
                                    rss_mdm_audit_integration::activity::ActivityOrigin::Ai
                                }
                            },
                            invocation: Some(invocation),
                            triggered_at: None,
                            source: db::Source::Policy {
                                version: policy.version,
                            },
                            target: &target,
                            id,
                            occurrence: prepared.slot.occurrence,
                            available: prepared.slot.available,
                            deadline: prepared.slot.deadline,
                            now,
                        },
                    )
                    .await?;
                    if let Some(effect) = prepared.effect {
                        crate::actions::software::persist_effect_in(tx, id, &effect).await?;
                    }
                    let response = json(&wire::SelfServiceAccepted {
                        request_id: input.operation_id,
                        run_id: id,
                        policy_id: policy.id,
                        policy_revision: policy.revision as u64,
                        policy_version: policy.version,
                    })?;
                    db::receipt(
                        tx,
                        &actor,
                        input.operation_id,
                        hash.clone(),
                        &response,
                        None,
                    )
                    .await?;
                    if let Some(proof) = proof {
                        proof.check_live()?;
                    }
                    let fact = Fact::business(audit, &event_key, 202, "success", None)?;
                    service.audit_store.append_in(tx, &fact).await?;
                    crate::sources::storage::wake_execution_in(
                        &service.reconcile_messaging,
                        tx,
                        policy.id,
                    )
                    .await?;
                    Ok(response)
                })
            },
        )
        .await
    }
    pub async fn self_service_status(
        &self,
        p: &DevicePrincipal,
        proof: Option<&AuthorizedPrincipal>,
        request: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        bind(p, proof, audit)?;
        if request.is_nil() {
            return Err(Error::Malformed);
        }
        crate::transaction::inspect(&self.runtime, self.tenant, (self, p, proof, request, audit), |ctx, tx| Box::pin(async move {
            let (service, p, proof, request, audit) = *ctx;
            storage::lock_device(tx, p.device()).await?; crate::actions::agent::principal(service, tx, p).await?;
            let actors = request_actors(p,proof)?;
            let tenant = tx.tenant_id().to_string();
            let response: Value = tx.with_connection(move |c| Box::pin(async move { sqlx::query_scalar("SELECT response FROM mdm_commands.action_receipts WHERE tenant_id=$1::uuid AND actor=ANY($2) AND id=$3 ORDER BY array_position($2,actor) LIMIT 1").bind(tenant).bind(actors).bind(request).fetch_optional(c).await })).await?.ok_or(Error::NotFound)?;
            let id = checked_input(Uuid::parse_str(response["runId"].as_str().ok_or(Error::Malformed)?))?;
            let run = db::load_run(tx, id).await?; crate::actions::agent::belongs(&run, p)?;
            let invocation = run.invocation.as_ref().ok_or(Error::Forbidden)?;
            let wire::TaskAuthorization::SelfService { subject, .. } = &invocation.authorization else { return Err(Error::Forbidden.into()); };
            if !owns(subject, proof) { return Err(Error::Forbidden.into()); }
            let plan = db::load_source(&service.policy_reader, tx, run.source).await?;
            // Current authenticated ownership and ordinary inventory permissions govern history.
            let result = match (&plan, run.result.as_ref()) {
                (db::ScheduledPolicy::Script(_), Some(result)) => {
                    let can_read = match proof {
                        Some(proof) => {
                            let auth = crate::action_admission::current(tx, proof).await?;
                            auth.require(proof, Permission::InventoryRead, Some(p.device())).is_ok()
                        }
                        None => false,
                    };
                    if can_read { Some(wire::SelfServiceResult::Script { evidence: stored(serde_json::from_value(result.clone()))? }) } else { None }
                }
                (db::ScheduledPolicy::Software(_), Some(result)) => Some(wire::SelfServiceResult::Software { effect: stored(serde_json::from_value(result["effect"].clone()))? }),
                (db::ScheduledPolicy::Enrollment(_), Some(result)) => Some(wire::SelfServiceResult::Enrollment { outcome: stored(serde_json::from_value(result["entryOutcome"].clone()))? }),
                _ => None,
            };
            if let Some(proof) = proof { proof.check_live()?; }
            audit.require_final_request();
            json(&wire::SelfServiceStatus { request_id: request, run_id: id, attempt_id: run.state.attempt(), state: public_state(&run.state), available_at: run.available_at, deadline: run.deadline, result })
        })).await
    }
}

struct InvocationSlot {
    occurrence: String,
    available: i64,
    deadline: i64,
}
// A directory probe only reads the same facts rechecked atomically by invocation.
async fn invocation_slot_in(
    tx: &mut PgTransaction<'_>,
    script: &crate::sources::admission::ExecutionPolicy,
    target: &Target,
    entry: i64,
    request: Uuid,
    now: i64,
) -> Result<Option<InvocationSlot>> {
    let (pending, last) =
        production::policy_pending_in(tx, script.owner, script.id, target, now, false).await?;
    let schedule = &script.frozen.input.schedule;
    if pending || !production::check_in_interval_elapsed(&schedule.trigger, last, now) {
        return Ok(None);
    }
    let occurrence = production::policy_occurrence(
        script.frequency,
        target,
        &script.entry_source(),
        entry,
        &format!("self-service:{request}"),
    );
    if !production::occurrence_available_in(tx, script.id, target, &occurrence, now).await? {
        return Ok(None);
    }
    let Some(slot) = schedule.occurrence(now, target.device.as_bytes())? else {
        return Ok(None);
    };
    let available = slot.available_at.max(now);
    let deadline = available
        .checked_add(i64::from(script.frozen.input.run_lifetime_seconds))
        .ok_or(Error::Malformed)?
        .min(schedule.ends_at())
        .min(slot.window_end.unwrap_or(i64::MAX));
    Ok((deadline > available).then_some(InvocationSlot {
        occurrence,
        available,
        deadline,
    }))
}

fn metadata(config: &rss_mdm_policy::SelfService) -> Result<wire::SelfServiceMetadata> {
    Ok(wire::SelfServiceMetadata {
        published: config.published,
        presentation: config.presentation.clone(),
        allow_ai: config.allow_ai.ok_or(Error::Malformed)?,
        risk_level: config.risk_level.ok_or(Error::Malformed)?.value(),
    })
}
fn parameter_sources(
    sources: &rss_mdm_policy::ParameterSources,
) -> std::collections::BTreeMap<String, wire::ScriptParameterSource> {
    sources
        .0
        .iter()
        .map(|(name, source)| {
            (
                name.clone(),
                match source {
                    rss_mdm_policy::ParameterSource::Fixed { value } => {
                        wire::ScriptParameterSource::Fixed {
                            value: value.clone(),
                        }
                    }
                    rss_mdm_policy::ParameterSource::Input {} => {
                        wire::ScriptParameterSource::Input {}
                    }
                },
            )
        })
        .collect()
}
fn public_state(state: &crate::actions::state::RunState) -> wire::TaskRunState {
    use crate::actions::state::{Cancellation, Delivery, Execution};
    wire::TaskRunState {
        delivery: match state.delivery {
            Delivery::Queued => wire::TaskDelivery::Queued,
            Delivery::Claimed {
                attempt,
                lease_until,
            } => wire::TaskDelivery::Claimed {
                attempt,
                lease_until,
            },
            Delivery::Received {
                attempt,
                lease_until,
            } => wire::TaskDelivery::Received {
                attempt,
                lease_until,
            },
        },
        execution: match state.execution {
            Execution::NotStarted => wire::TaskExecution::NotStarted,
            Execution::Running => wire::TaskExecution::Running,
            Execution::Succeeded => wire::TaskExecution::Succeeded,
            Execution::Failed => wire::TaskExecution::Failed,
            Execution::WaitingReboot => wire::TaskExecution::WaitingReboot,
            Execution::Unknown => wire::TaskExecution::Unknown,
        },
        cancellation: match state.cancellation {
            Cancellation::None => wire::RunCancellation::None,
            Cancellation::Requested => wire::RunCancellation::Requested,
            Cancellation::Confirmed => wire::RunCancellation::Confirmed,
        },
        deadline: state.deadline,
        started_at: state.started_at,
    }
}

pub(crate) async fn advance_waiting_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    run: &mut db::Run,
    plan: &db::ScheduledPolicy,
    now: i64,
) -> Result<bool> {
    let Some(invocation) = &run.invocation else {
        return Ok(true);
    };
    if let Some(scope) = invocation.pending_scope {
        if !matches!(
            crate::sources::storage::admission_in(
                &service.source,
                tx,
                scope,
                crate::source_authority::Channel::Agent,
                &run.target.device
            )
            .await?,
            crate::source_authority::ScopeAdmission::Eligible { .. }
        ) {
            return Ok(false);
        }
        if let (db::ScheduledPolicy::Software(v), Some(rollout)) =
            (plan, &invocation.pending_rollout)
        {
            let assignment = v.assignment.pending_admission(scope, rollout.clone());
            if assignment
                .entry_in(&service.source, tx, &run.target.device, now)
                .await?
                .is_none()
            {
                return Ok(false);
            }
        }
        let source = service.source.clone();
        let tenant = tx.tenant_id();
        let device = run.target.device.clone();
        let evidence = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(source
                        .evidence_on(
                            c,
                            tenant,
                            scope,
                            crate::source_authority::Channel::Agent,
                            &device,
                        )
                        .await)
                })
            })
            .await??;
        if evidence.is_empty() {
            return Ok(false);
        }
        run.source_objects = evidence;
        let invocation = run.invocation.as_mut().ok_or(Error::Malformed)?;
        invocation.pending_scope = None;
        invocation.pending_rollout = None;
    }
    if let db::ScheduledPolicy::Software(software) = plan {
        let id = run.id;
        let tenant = tx.tenant_id().to_string();
        let (missing, created): (bool, i64) = tx.with_connection(move |c| Box::pin(async move { sqlx::query_as("SELECT software_effect IS NULL,created_at FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await })).await?;
        if missing {
            let Some(binding) = crate::channels::agent_binding_in(
                tx,
                service.agent_store.clone(),
                run.target.registration,
            )
            .await?
            else {
                return Ok(false);
            };
            if !software
                .assignment
                .supported_in(&service.admission(), tx, &binding)
                .await?
            {
                return Ok(false);
            }
            let wire::TaskAuthorization::SelfService { request_id, .. } = &run
                .invocation
                .as_ref()
                .ok_or(Error::Malformed)?
                .authorization
            else {
                return Err(Error::Malformed.into());
            };
            let crate::actions::software::Preparation::Ready(slot) =
                crate::actions::software::slot_in(
                    service,
                    tx,
                    software,
                    &run.target,
                    Some(crate::actions::software::Invocation::SelfService(
                        *request_id,
                    )),
                    created,
                    Some(run.id),
                )
                .await?
            else {
                return Ok(false);
            };
            let root = slot.steps.last().ok_or(Error::Malformed)?;
            run.invocation
                .as_mut()
                .ok_or(Error::Malformed)?
                .execution_target = Some(root.target.clone());
            crate::actions::software::persist_effect_in(tx, run.id, &slot.effect).await?;
        }
    }
    let invocation = run.invocation.as_ref().ok_or(Error::Malformed)?;
    let document = json(invocation)?;
    let evidence = json(&run.source_objects)?;
    let id = run.id;
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_commands.action_runs SET invocation=$3,source_objects=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(document).bind(evidence).execute(c).await?;Ok(())})).await?;
    Ok(true)
}

fn required_activity_user<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<rss_mdm_audit_integration::activity::ActivityUser>, D::Error> {
    Option::deserialize(d)
}
