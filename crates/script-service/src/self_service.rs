//! Script self-service binds the accepted Policy version and caller identity.
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

use crate::authorization::{Permission, context::AuthorizedPrincipal};
use crate::{
    Error, Result, ScriptService, Target, admission as production, runs::Invocation, storage,
    storage as db, transaction::*,
};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_registration_service::DevicePrincipal;
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
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
    execution_target: Option<wire::SoftwareExecutionTarget>,
}
async fn prepare_in(
    service: &ScriptService,
    tx: &mut PgTransaction<'_>,
    plan: &crate::policy::ScriptPolicy,
    target: &Target,
    request: Uuid,
    input: Option<&std::collections::BTreeMap<String, Value>>,
    now: i64,
) -> Result<Option<Prepared>> {
    let script = plan;
    if input.is_none()
        && !plan
            .authorized_in(&service.transactions, tx, target, now)
            .await?
    {
        return Ok(None);
    }

    let entry = match script
        .entry_in(&service.transactions, tx, &target.device, now)
        .await?
    {
        Some(entry) => entry,
        None if input.is_some() => 0,
        None => return Ok(None),
    };
    let Some(slot) = invocation_slot_in(
        &service.transactions,
        tx,
        script,
        target,
        entry,
        request,
        now,
    )
    .await?
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
        execution_target: plan
            .execution_target_in(&service.transactions, tx, target)
            .await?,
    }))
}
fn target(p: &DevicePrincipal) -> Target {
    Target {
        device: p.device().into(),
        registration: p.registration(),
        generation: p.generation(),
    }
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
impl ScriptService {
    pub async fn invoke_self_service_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        proof: Option<&AuthorizedPrincipal>,
        input: &wire::SelfServiceInvoke,
        audit: &RequestAudit,
    ) -> Result<Value> {
        let service = self;
        let id = Uuid::new_v4();
        storage::lock_device(tx, p.device()).await?;
        service.agent_prepare_in(tx, p).await?;
        let hash = fingerprint(input)?;
        let now = storage::now(tx).await?;
        crate::transaction::prepare_audit_in(&service.transactions.audit_store, tx, audit, &[])
            .await?;
        let policy =
            crate::policy::current_in(&service.transactions.policy_reader, tx, input.policy_id)
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
        let plan = crate::policy::read_in(&service.transactions, tx, policy.version).await?;
        let target = target(p);
        let admission = crate::policy::admission_in(
            &service.transactions.source,
            tx,
            policy.definition.scope,
            rss_mdm_scope_service::channels::Channel::Agent,
            p.device(),
        )
        .await?;
        if admission == rss_mdm_scope_service::channels::ScopeAdmission::Excluded {
            return Err(Error::Forbidden.into());
        }
        let pending_scope = (admission == rss_mdm_scope_service::channels::ScopeAdmission::Pending)
            .then_some(policy.definition.scope);
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
        checked_input(decision.validate(checked_input(Uuid::parse_str(&p.tenant().to_string()))?))?;
        let binding = crate::agent_facts::agent_binding_in(
            tx,
            service.transactions.agent_store.clone(),
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
        };
        production::queue_run_in(
            &service.transactions,
            tx,
            &plan,
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
                target: &target,
                id,
                occurrence: prepared.slot.occurrence,
                available: prepared.slot.available,
                deadline: prepared.slot.deadline,
                now,
            },
        )
        .await?;
        let response = json(&wire::SelfServiceAccepted {
            request_id: input.operation_id,
            run_id: id,
            policy_id: policy.id,
            policy_revision: policy.revision as u64,
            policy_version: policy.version,
        })?;
        db::receipt(tx, &actor, input.operation_id, hash.clone(), &response).await?;
        if let Some(proof) = proof {
            proof.check_live()?;
        }
        let fact = Fact::business(
            audit,
            rss_mdm_audit_integration::operation::OperationOwner::Script,
            &event_key,
            202,
            "success",
            None,
        )?;
        service
            .transactions
            .audit_store
            .append_in(tx, &fact)
            .await?;
        Ok(response)
    }
    pub async fn replay_self_service_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        actor: &str,
        input: &wire::SelfServiceInvoke,
    ) -> Result<Option<Value>> {
        let hash = fingerprint(input)?;
        let Some(response) = db::replay(tx, actor, input.operation_id, &hash).await? else {
            return Ok(None);
        };
        let id = stored(serde_json::from_value(response["runId"].clone()))?;
        let run = db::load_run(tx, id).await?;
        crate::agent::belongs(&run, p)?;
        Ok(Some(response))
    }
    pub async fn self_service_status_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        proof: Option<&AuthorizedPrincipal>,
        actor: &str,
        request: Uuid,
        audit: &RequestAudit,
    ) -> Result<Option<wire::SelfServiceStatus>> {
        let service = self;
        storage::lock_device(tx, p.device()).await?;
        service.agent_prepare_in(tx, p).await?;
        let actors = vec![actor.to_owned()];
        let tenant = tx.tenant_id().to_string();
        let response: Option<Value> = tx.with_connection(move |c| Box::pin(async move { sqlx::query_scalar("SELECT response FROM mdm_script.receipts WHERE tenant_id=$1::uuid AND actor=ANY($2) AND id=$3 ORDER BY array_position($2,actor) LIMIT 1").bind(tenant).bind(actors).bind(request).fetch_optional(c).await })).await?;
        let Some(response) = response else {
            return Ok(None);
        };
        let id = checked_input(Uuid::parse_str(
            response["runId"].as_str().ok_or(Error::Malformed)?,
        ))?;
        let run = db::load_run(tx, id).await?;
        crate::agent::belongs(&run, p)?;
        let invocation = run.invocation.as_ref().ok_or(Error::Forbidden)?;
        let wire::TaskAuthorization::SelfService { subject, .. } = &invocation.authorization else {
            return Err(Error::Forbidden.into());
        };
        if !owns(subject, proof) {
            return Err(Error::Forbidden.into());
        }
        let can_read = match proof {
            Some(proof) => storage::current(tx, proof)
                .await?
                .require(proof, Permission::InventoryRead, Some(p.device()))
                .is_ok(),
            None => false,
        };
        let result = if can_read {
            run.result
                .clone()
                .map(|evidence| wire::SelfServiceResult::Script { evidence })
        } else {
            None
        };
        if let Some(proof) = proof {
            proof.check_live()?;
        }
        audit.require_final_request();
        Ok(Some(wire::SelfServiceStatus {
            request_id: request,
            run_id: id,
            attempt_id: run.state.attempt(),
            state: public_state(&run.state),
            available_at: run.available_at,
            deadline: run.deadline,
            result,
        }))
    }
}

struct InvocationSlot {
    occurrence: String,
    available: i64,
    deadline: i64,
}
// A directory probe only reads the same facts rechecked atomically by invocation.
async fn invocation_slot_in(
    service: &crate::Transactions,
    tx: &mut PgTransaction<'_>,
    script: &crate::policy::ScriptPolicy,
    target: &Target,
    entry: i64,
    request: Uuid,
    now: i64,
) -> Result<Option<InvocationSlot>> {
    let (pending, last) = storage::pending_in(
        tx,
        script.owner,
        script.id,
        target,
        &script.frozen.resource.id,
        now,
    )
    .await?;
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
    if !production::occurrence_available_in(service, tx, script.id, target, &occurrence, now)
        .await?
    {
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
fn public_state(state: &rss_mdm_task_state::RunState) -> wire::TaskRunState {
    use rss_mdm_task_state::{Cancellation, Delivery, Execution};
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
    service: &ScriptService,
    tx: &mut PgTransaction<'_>,
    run: &mut crate::runs::Run,
    _plan: &crate::policy::ScriptPolicy,
    _now: i64,
) -> Result<bool> {
    let Some(invocation) = &run.invocation else {
        return Ok(true);
    };
    if let Some(scope) = invocation.pending_scope {
        if !matches!(
            crate::policy::admission_in(
                &service.transactions.source,
                tx,
                scope,
                rss_mdm_scope_service::channels::Channel::Agent,
                &run.target.device
            )
            .await?,
            rss_mdm_scope_service::channels::ScopeAdmission::Eligible { .. }
        ) {
            return Ok(false);
        }
        let source = service.transactions.source.clone();
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
                            rss_mdm_scope_service::channels::Channel::Agent,
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
    }
    let invocation = run.invocation.as_ref().ok_or(Error::Malformed)?;
    let document = json(invocation)?;
    let evidence = json(&run.source_objects)?;
    let id = run.id;
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_script.runs SET invocation=$3,source_objects=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(document).bind(evidence).execute(c).await?;Ok(())})).await?;
    Ok(true)
}
