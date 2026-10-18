//! Targeted self-service calls share the existing Policy version, Run reducer and admission.
mod access;
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
    pub authorization: wire::TaskAuthorization,
    pub parameters: std::collections::BTreeMap<String, Value>,
    pub basis: access::Basis,
    pub execution_target: Option<wire::SoftwareExecutionTarget>,
}
impl Invocation {
    /// Recheck the same employee publication/qualification at Start and native authentication.
    /// The borrowed connection keeps revocation and scope checks in the caller's transaction.
    pub(crate) async fn qualified_on(
        &self,
        c: &mut sqlx::PgConnection,
        owner: Uuid,
        tenant: rss_request_context::TenantId,
        instance: &str,
        sessions: &crate::authorization::session::SessionAuthority,
    ) -> Result<Option<Uuid>> {
        use sqlx::Row;
        let wire::TaskAuthorization::SelfService {
            subject,
            source,
            policy_id,
            policy_revision,
            policy_version,
            allow_ai,
            risk_level,
            confirmed,
            ..
        } = &self.authorization
        else {
            return Ok(None);
        };
        if owner != *policy_id {
            return Ok(None);
        }
        sqlx::query("SELECT mdm_planning.policy_lock($1)")
            .bind(owner)
            .execute(&mut *c)
            .await
            .map_err(crate::database::db)?;
        let row = sqlx::query("SELECT revision,current_version,definition FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$2 AND state='enabled'")
            .bind(tenant.to_string()).bind(owner).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let definition: rss_mdm_policy::Definition = stored(serde_json::from_value(
            row.try_get("definition").map_err(crate::database::db)?,
        ))?;
        let Some(config) = &definition.self_service else {
            return Ok(None);
        };
        let risk = if matches!(definition.action, rss_mdm_policy::Action::Software { .. }) {
            2
        } else {
            config.risk_level.map_or(2, |r| r.value())
        };
        if row
            .try_get::<Uuid, _>("current_version")
            .map_err(crate::database::db)?
            != *policy_version
            || row
                .try_get::<i64, _>("revision")
                .map_err(crate::database::db)? as u64
                != *policy_revision
            || !config.published
            || config.allow_ai != Some(*allow_ai)
            || risk != *risk_level
            || (*source == wire::SelfServiceCaller::Ai
                && (!*allow_ai || (risk == 2 && !*confirmed)))
        {
            return Ok(None);
        }
        if access::qualify_on(c, config, &self.basis, tenant, instance, sessions)
            .await?
            .as_ref()
            != Some(subject)
        {
            return Ok(None);
        }
        Ok(Some(definition.scope))
    }
    pub async fn valid_in(
        &self,
        service: &ExecutionService,
        tx: &mut PgTransaction<'_>,
        plan: &db::ScheduledPolicy,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        let invocation = self.clone();
        let owner = plan.owner();
        let tenant = service.tenant;
        let instance = service.instance.clone();
        let sessions = service.sessions.clone();
        let current = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(invocation
                        .qualified_on(c, owner, tenant, &instance, &sessions)
                        .await)
                })
            })
            .await??;
        let Some(_) = current else {
            return Ok(false);
        };
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
        if execution_target_in(service, tx, plan, target).await? != self.execution_target {
            return Ok(false);
        }
        plan.authorized_in(service, tx, target, now).await
    }
}
fn effective_risk(policy: &rss_mdm_policy::Policy) -> u8 {
    if matches!(
        policy.definition.action,
        rss_mdm_policy::Action::Software { .. }
    ) {
        2
    } else {
        policy
            .definition
            .self_service
            .as_ref()
            .and_then(|s| s.risk_level)
            .map_or(2, |r| r.value())
    }
}
struct Prepared {
    task: wire::SelfServiceTask,
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
    if !plan.authorized_in(service, tx, target, now).await? {
        return Ok(None);
    }
    match plan {
        db::ScheduledPolicy::Script(script) => {
            let Some(entry) = script
                .entry_in(&service.source, tx, &target.device, now)
                .await?
            else {
                return Ok(None);
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
                task,
                parameters,
                slot,
                effect: None,
                execution_target: Some(
                    execution_target_in(service, tx, plan, target)
                        .await?
                        .ok_or(Error::Forbidden)?,
                ),
            }))
        }
        db::ScheduledPolicy::Software(software)
            if software.assignment.intent() == rss_mdm_policy::SoftwareIntent::AvailableInstall =>
        {
            if input.is_some_and(|input| !input.is_empty()) {
                return Err(Error::Malformed.into());
            }
            let Some(slot) = crate::actions::software::slot_in(
                service,
                tx,
                software,
                target,
                Some(request),
                now,
            )
            .await?
            else {
                return Ok(None);
            };
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
            let steps = software
                .assignment
                .prepared_in(
                    &service.admission(),
                    tx,
                    platform,
                    architecture,
                    &binding.execution_context,
                )
                .await?
                .ok_or(Error::Forbidden)?;
            let root = steps.last().ok_or(Error::Malformed)?;
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
                task,
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
                task: wire::SelfServiceTask::Enrollment {
                    organization: enrollment.frozen.organization,
                    entry: enrollment
                        .frozen
                        .entries
                        .for_platform(platform)
                        .ok_or(Error::Unsupported)?,
                },
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
    pub async fn self_service_directory(
        &self,
        p: &DevicePrincipal,
        proof: Option<&AuthorizedPrincipal>,
        input: &wire::SelfServiceDirectory,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        bind(p, proof, audit)?;
        if input.after.is_some_and(|id| id.is_nil()) {
            return Err(Error::Malformed);
        }
        run(&self.audit_store, &self.runtime, self.tenant, audit, (self, p, proof, input, audit), |ctx, tx| Box::pin(async move {
            let (service, p, proof, input, audit) = *ctx;
            storage::lock(tx, p.device()).await?;
            crate::actions::agent::principal(service, tx, p).await?;
            let tenant = tx.tenant_id().to_string(); let after = input.after;
            let mut ids = tx.with_connection(move |c| Box::pin(async move { sqlx::query_scalar::<_, Uuid>("SELECT id FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND (state='enabled') AND definition->'selfService'->>'published'='true' AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 65").bind(tenant).bind(after).fetch_all(c).await })).await?;
            let more = ids.len() > 64; ids.truncate(64); let next = if more { ids.last().copied() } else { None };
            let target = target(p); let now = storage::now(tx).await?; let mut items = Vec::new();
            for id in ids {
                let Some(policy) = crate::sources::storage::read_in(&service.policy_reader, tx, id).await? else { continue; };
                let Some(config) = policy.definition.self_service.as_ref() else { continue; };
                if !policy.state.is_enabled() || !config.published || (input.source == wire::SelfServiceCaller::Ai && config.allow_ai != Some(true)) { continue; }
                let Some(basis) = access::select(config, proof)? else { continue; };
                let Some(subject) = access::qualify_in(service, tx, config, &basis).await? else { continue; };
                let plan = db::load_source(&service.policy_reader, tx, db::Source::Policy { version: policy.version }).await?;
                let Some(prepared) = prepare_in(service, tx, &plan, &target, Uuid::new_v4(), None, now).await? else { continue; };
                let mut metadata = metadata(config)?; metadata.risk_level = effective_risk(&policy);
                items.push(wire::SelfServiceDirectoryItem { policy_id: id, policy_revision: policy.revision as u64, policy_version: policy.version, subject, self_service: metadata, task: prepared.task });
            }
            if let Some(proof) = proof { proof.check_live()?; }
            service.audit_store.append_request_in(tx, audit, 200, "success").await?;
            json(&wire::SelfServiceDirectoryResponse { items, next_cursor: next, as_of: now })
        })).await
    }
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
            || input.policy_version.is_nil()
            || input.policy_revision == 0
            || input.policy_revision > i64::MAX as u64
            || input.parameters.len() > 32
            || serde_json::to_vec(input)
                .map_err(|_| Error::Malformed)?
                .len()
                > 131072
        {
            return Err(Error::Malformed);
        }
        audit.operation(input.operation_id, "command_accept");
        run(&self.audit_store, &self.runtime, self.tenant, audit, (self, p, proof, input, audit), |ctx, tx| Box::pin(async move {
            let (service, p, proof, input, audit) = *ctx;
            storage::lock(tx, p.device()).await?; crate::actions::agent::principal(service, tx, p).await?;
            let policy = crate::sources::storage::read_in(&service.policy_reader, tx, input.policy_id).await?.ok_or(Error::NotFound)?;
            if policy.version != input.policy_version || policy.revision as u64 != input.policy_revision { return Err(Error::Conflict.into()); }
            let config = policy.definition.self_service.as_ref().ok_or(Error::Forbidden)?;
            let allow_ai = config.allow_ai.ok_or(Error::Forbidden)?; let risk = effective_risk(&policy);
            if !policy.state.is_enabled() || !config.published || (input.source == wire::SelfServiceCaller::Ai && (!allow_ai || (risk == 2 && !input.confirmed))) { return Err(Error::Forbidden.into()); }
            let basis = access::select(config, proof)?.ok_or(Error::Forbidden)?;
            let subject = access::qualify_in(service, tx, config, &basis).await?.ok_or(Error::Forbidden)?;
            let actor = actor(p, &subject); let hash = fingerprint(input)?; let event_key = format!("{actor}:{}", input.operation_id); let now = storage::now(tx).await?;
            let plan = db::load_source(&service.policy_reader, tx, db::Source::Policy { version: policy.version }).await?;
            if let Some(response) = db::replay(tx, &actor, input.operation_id, &hash).await? {
                let run = db::load_run(tx, checked_input(Uuid::parse_str(response["runId"].as_str().ok_or(Error::Malformed)?))?).await?;
                crate::actions::agent::belongs(&run, p)?;
                if !plan.authorized_run_in(service, tx, &run, now).await? { return Err(Error::Forbidden.into()); }
                let fact = Fact::business(audit, &event_key, &hash, 202, "success", None)?; service.audit_store.append_in(tx, &fact, true).await?;
                return Ok(response);
            }
            let target = target(p);
            if !plan.authorized_in(service, tx, &target, now).await? { return Err(Error::Forbidden.into()); }
            let Some(prepared) = prepare_in(service, tx, &plan, &target, input.operation_id, Some(&input.parameters), now).await? else { return Err(Error::Conflict.into()); };
            let decision = wire::TaskAuthorization::SelfService { request_id: input.operation_id, subject, source: input.source, policy_id: policy.id, policy_revision: input.policy_revision, policy_version: policy.version, allow_ai, risk_level: risk, confirmed: input.confirmed };
            checked_input(decision.validate(checked_input(Uuid::parse_str(&p.tenant().to_string()))?))?;
            let invocation = Invocation { authorization: decision, parameters: prepared.parameters, basis, execution_target: prepared.execution_target };
            let id = Uuid::new_v4();
            production::queue_run_in(service, tx, production::RunInput { triggered_at: None, source: db::Source::Policy { version: policy.version }, target: &target, id, occurrence: prepared.slot.occurrence, available: prepared.slot.available, deadline: prepared.slot.deadline, now }).await?;
            if let Some(effect) = prepared.effect { crate::actions::software::persist_effect_in(tx, id, &effect).await?; }
            let tenant = tx.tenant_id().to_string(); let document = json(&invocation)?;
            tx.with_connection(move |c| Box::pin(async move { sqlx::query("UPDATE mdm_commands.action_runs SET invocation=$3 WHERE tenant_id=$1::uuid AND id=$2 AND invocation IS NULL").bind(tenant).bind(id).bind(document).execute(c).await?; Ok(()) })).await?;
            let response = json(&wire::SelfServiceAccepted { request_id: input.operation_id, run_id: id, policy_id: policy.id, policy_revision: policy.revision as u64, policy_version: policy.version })?;
            db::receipt(tx, &actor, input.operation_id, hash.clone(), &response, None).await?;
            if let Some(proof) = proof { proof.check_live()?; }
            let fact = Fact::business(audit, &event_key, &hash, 202, "success", None)?; service.audit_store.append_in(tx, &fact, false).await?;
            crate::sources::storage::wake_execution_in(tx, policy.id).await?;
            Ok(response)
        })).await
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
        run(&self.audit_store, &self.runtime, self.tenant, audit, (self, p, proof, request, audit), |ctx, tx| Box::pin(async move {
            let (service, p, proof, request, audit) = *ctx;
            storage::lock(tx, p.device()).await?; crate::actions::agent::principal(service, tx, p).await?;
            let mut actors = vec![actor(p, &wire::SelfServiceSubject::Device {})];
            if let Some(proof) = proof { actors.insert(0, actor(p, &wire::SelfServiceSubject::User { user: wire::SelfServiceUser { tenant_id: checked_input(Uuid::parse_str(proof.tenant_id()))?, instance_id: checked_input(Uuid::parse_str(proof.instance_id()))?, principal_id: checked_input(Uuid::parse_str(proof.principal_id()))? } })); }
            let tenant = tx.tenant_id().to_string();
            let response: Value = tx.with_connection(move |c| Box::pin(async move { sqlx::query_scalar("SELECT response FROM mdm_commands.action_receipts WHERE tenant_id=$1::uuid AND actor=ANY($2) AND id=$3 ORDER BY array_position($2,actor) LIMIT 1").bind(tenant).bind(actors).bind(request).fetch_optional(c).await })).await?.ok_or(Error::NotFound)?;
            let id = checked_input(Uuid::parse_str(response["runId"].as_str().ok_or(Error::Malformed)?))?;
            let run = db::load_run(tx, id).await?; crate::actions::agent::belongs(&run, p)?;
            let invocation = run.invocation.as_ref().ok_or(Error::Forbidden)?;
            let wire::TaskAuthorization::SelfService { subject, .. } = &invocation.authorization else { return Err(Error::Forbidden.into()); };
            if !owns(subject, proof) { return Err(Error::Forbidden.into()); }
            let plan = db::load_source(&service.policy_reader, tx, run.source).await?;
            // Reading an accepted request uses the current reader's qualification, not Start authority.
            let policy = crate::sources::storage::read_in(&service.policy_reader, tx, plan.owner()).await?.ok_or(Error::NotFound)?;
            let config = policy.definition.self_service.as_ref().ok_or(Error::Forbidden)?;
            if !policy.state.is_enabled() || !config.published { return Err(Error::Forbidden.into()); }
            let basis = access::select(config, proof)?.ok_or(Error::Forbidden)?;
            if access::qualify_in(service, tx, config, &basis).await?.is_none()
                || !matches!(crate::sources::storage::admission_in(&service.source, tx,
                    policy.definition.scope, crate::source_authority::action_channel(policy.definition.action.kind())?, p.device()).await?,
                    crate::source_authority::ScopeAdmission::Eligible { .. }) {
                return Err(Error::Forbidden.into());
            }
            let result = match (&plan, run.result.as_ref()) {
                (db::ScheduledPolicy::Script(script), Some(result)) => {
                    let can_read = match proof {
                        Some(proof) => {
                            let auth = crate::action_admission::current(tx, proof).await?;
                            let basic = auth.require(proof, Permission::InventoryRead, Some(p.device())).is_ok();
                            let sensitive = script.frozen.collection.as_ref().is_some_and(|c| c.fields().any(|f| f.sensitivity == rss_mdm_inventory::Sensitivity::Sensitive));
                            basic && (!sensitive || auth.require(proof, Permission::InventorySensitiveRead, None).is_ok())
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
            service.audit_store.append_request_in(tx, audit, 200, "success").await?;
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
        display_name: config.display_name.clone(),
        description: config.description.clone(),
        prerequisites: config.prerequisites.clone(),
        side_effects: config.side_effects.clone(),
        category: config.category.clone(),
        keywords: config.keywords.clone(),
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
