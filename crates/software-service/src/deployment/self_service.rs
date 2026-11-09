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

use crate::deployment::{
    Error, Result, SoftwareService, Target,
    actions::{production, storage as db},
    authorization::context::AuthorizedPrincipal,
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
    pub(crate) async fn valid_in(
        &self,
        service: &crate::deployment::transactions::Transactions,
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
            db::ScheduledPolicy::Software(software)
                if software.id == *policy_version
                    && software.assignment.intent()
                        == rss_mdm_policy::SoftwareIntent::AvailableInstall
                    && self.parameters.is_empty() => {}
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
    service: &SoftwareService,
    tx: &mut PgTransaction<'_>,
    plan: &db::ScheduledPolicy,
    target: &Target,
    request: Uuid,
    input: Option<&std::collections::BTreeMap<String, Value>>,
    now: i64,
) -> Result<Option<Prepared>> {
    if input.is_none()
        && !plan
            .authorized_in(&service.transactions, tx, target, now)
            .await?
    {
        return Ok(None);
    }
    match plan {
        db::ScheduledPolicy::Software(software)
            if software.assignment.intent() == rss_mdm_policy::SoftwareIntent::AvailableInstall =>
        {
            if input.is_some_and(|input| !input.is_empty()) {
                return Err(Error::Malformed.into());
            }
            let binding = crate::deployment::agent_facts::agent_binding_in(
                tx,
                service.transactions.agent_store.clone(),
                target.device.clone(),
            )
            .await?
            .ok_or(Error::Forbidden)?;
            let (platform, architecture) =
                db::agent_profile_in(&service.transactions, tx, target.device.clone())
                    .await?
                    .ok_or(Error::Forbidden)?;
            if input.is_some()
                && !software
                    .assignment
                    .supported_in(&service.transactions.admission(), tx, &binding)
                    .await?
            {
                if software
                    .assignment
                    .admitted_in(
                        &service.transactions.admission(),
                        tx,
                        platform,
                        architecture,
                    )
                    .await?
                    .is_none()
                {
                    return Err(Error::Forbidden.into());
                }
                let occurrence = format!("self-service:{request}");
                if !production::occurrence_available_in(
                    &service.transactions,
                    tx,
                    software.id,
                    target,
                    &occurrence,
                    now,
                )
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
            let crate::deployment::actions::software::Preparation::Ready(slot) =
                crate::deployment::actions::software::slot_in(
                    &service.transactions,
                    tx,
                    software,
                    target,
                    Some(crate::deployment::actions::software::Invocation::SelfService(request)),
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
                run_as: crate::preparation::execution::execution_identity(&root.action),
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
        _ => Err(Error::Forbidden.into()),
    }
}
async fn execution_target_in(
    service: &crate::deployment::transactions::Transactions,
    tx: &mut PgTransaction<'_>,
    plan: &db::ScheduledPolicy,
    target: &Target,
) -> Result<Option<wire::SoftwareExecutionTarget>> {
    let Some(binding) = crate::deployment::agent_facts::agent_binding_in(
        tx,
        service.agent_store.clone(),
        target.device.clone(),
    )
    .await?
    else {
        return Ok(None);
    };
    let Some((platform, architecture)) =
        db::agent_profile_in(service, tx, target.device.clone()).await?
    else {
        return Ok(None);
    };
    match plan {
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
    }
}
fn target(p: &DevicePrincipal) -> Target {
    Target {
        device: p.device().into(),
    }
}
fn actor(p: &DevicePrincipal, subject: &wire::SelfServiceSubject) -> String {
    let subject = match subject {
        wire::SelfServiceSubject::Device {} => "device".into(),
        wire::SelfServiceSubject::User { user } => {
            format!("{}:{}", user.instance_id, user.principal_id)
        }
    };
    format!("self-service:{subject}:{}", p.device())
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
impl SoftwareService {
    #[expect(
        clippy::cognitive_complexity,
        reason = "self-service replay, current eligibility and effect admission share the original transaction"
    )]
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
        crate::deployment::actions::agent::principal(&service.transactions, tx, p).await?;
        let hash = fingerprint(input)?;
        let now = storage::now(tx).await?;
        crate::deployment::transaction::prepare_audit_in(
            &service.transactions.audit_store,
            tx,
            audit,
            &[],
        )
        .await?;
        let policy = crate::deployment::sources::storage::read_in(
            &service.transactions.policy_reader,
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
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::SoftwareInvocation,
            input.operation_id,
            "self_service_invoke",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.receipt_actor(&actor);
        audit.target_device(p.device());
        let event_key = format!("{actor}:{}", input.operation_id);
        let plan = db::load_source(
            &service.transactions,
            tx,
            db::Source::Policy {
                version: policy.version,
            },
        )
        .await?;
        let target = target(p);
        let admission = crate::deployment::sources::storage::admission_in(
            &service.transactions.source,
            tx,
            policy.definition.scope,
            crate::deployment::scope::Channel::Agent,
            p.device(),
        )
        .await?;
        if admission == crate::deployment::scope::ScopeAdmission::Excluded {
            return Err(Error::Forbidden.into());
        }
        let rollout_pending = {
            let db::ScheduledPolicy::Software(v) = &plan;
            v.assignment
                .entry_in(&service.transactions.source, tx, p.device(), now)
                .await?
                .is_none()
        };
        let pending_scope = (admission == crate::deployment::scope::ScopeAdmission::Pending
            || rollout_pending)
            .then_some(policy.definition.scope);
        let pending_rollout = if pending_scope.is_some() {
            match &policy.definition.action {
                rss_mdm_policy::Action::Software { rollout, .. } => Some(rollout.clone()),
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
        checked_input(decision.validate(checked_input(Uuid::parse_str(&p.tenant().to_string()))?))?;
        let binding = crate::deployment::agent_facts::agent_binding_in(
            tx,
            service.transactions.agent_store.clone(),
            p.device().to_string(),
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
            &service.transactions,
            tx,
            production::RunInput {
                request: Some(audit),
                origin: match input.source {
                    wire::SelfServiceCaller::Human => {
                        rss_mdm_audit_integration::activity::ActivityOrigin::Human
                    }
                    wire::SelfServiceCaller::Ai => {
                        rss_mdm_audit_integration::activity::ActivityOrigin::Ai
                    }
                },
                invocation: Some(invocation),
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
            crate::deployment::actions::software::persist_effect_in(tx, id, &effect).await?;
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
            &target,
            None,
        )
        .await?;
        if let Some(proof) = proof {
            proof.check_live()?;
        }
        let fact = Fact::business(
            audit,
            rss_mdm_audit_integration::operation::OperationOwner::SoftwareInvocation,
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
        crate::deployment::sources::storage::wake_execution_in(
            &service.transactions.reconcile_messaging,
            tx,
            policy.id,
        )
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
        crate::deployment::actions::agent::belongs(&run, p)?;
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
        crate::deployment::actions::agent::principal(&service.transactions, tx, p).await?;
        let actors = vec![actor.to_owned()];
        let tenant = tx.tenant_id().to_string();
        let response: Option<Value> = tx.with_connection(move |c| Box::pin(async move { sqlx::query_scalar("SELECT response FROM mdm_software_deployment.action_receipts WHERE tenant_id=$1::uuid AND actor=ANY($2) AND id=$3 ORDER BY array_position($2,actor) LIMIT 1").bind(tenant).bind(actors).bind(request).fetch_optional(c).await })).await?;
        let Some(response) = response else {
            return Ok(None);
        };
        let id = checked_input(Uuid::parse_str(
            response["runId"].as_str().ok_or(Error::Malformed)?,
        ))?;
        let run = db::load_run(tx, id).await?;
        crate::deployment::actions::agent::belongs(&run, p)?;
        let invocation = run.invocation.as_ref().ok_or(Error::Forbidden)?;
        let wire::TaskAuthorization::SelfService { subject, .. } = &invocation.authorization else {
            return Err(Error::Forbidden.into());
        };
        if !owns(subject, proof) {
            return Err(Error::Forbidden.into());
        }
        let plan = db::load_source(&service.transactions, tx, run.source).await?;
        // Current authenticated ownership and ordinary inventory permissions govern history.
        let result = match (&plan, run.result.as_ref()) {
            (
                db::ScheduledPolicy::Software(_),
                Some(crate::deployment::actions::result::RunResult::Software(result)),
            ) => Some(wire::SelfServiceResult::Software {
                effect: result.effect,
            }),
            (
                db::ScheduledPolicy::Software(_),
                Some(crate::deployment::actions::result::RunResult::NativeSoftware(result)),
            ) => {
                let effect = match result {
                    crate::deployment::actions::result::NativeSoftware::Verified { .. } => {
                        wire::SelfServiceSoftwareEffect::Verified
                    }
                    crate::deployment::actions::result::NativeSoftware::Unknown { .. } => {
                        wire::SelfServiceSoftwareEffect::Unknown
                    }
                    crate::deployment::actions::result::NativeSoftware::NotStarted { .. } => {
                        return Err(
                            Error::Unavailable(crate::deployment::Failure::CommandStorage).into(),
                        );
                    }
                };
                Some(wire::SelfServiceResult::Software { effect })
            }
            _ => None,
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

fn metadata(config: &rss_mdm_policy::SelfService) -> Result<wire::SelfServiceMetadata> {
    Ok(wire::SelfServiceMetadata {
        published: config.published,
        presentation: config.presentation.clone(),
        allow_ai: config.allow_ai.ok_or(Error::Malformed)?,
        risk_level: config.risk_level.ok_or(Error::Malformed)?.value(),
    })
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
    service: &SoftwareService,
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
            crate::deployment::sources::storage::admission_in(
                &service.transactions.source,
                tx,
                scope,
                crate::deployment::scope::Channel::Agent,
                &run.target.device
            )
            .await?,
            crate::deployment::scope::ScopeAdmission::Eligible { .. }
        ) {
            return Ok(false);
        }
        if let Some(rollout) = &invocation.pending_rollout {
            let db::ScheduledPolicy::Software(v) = plan;
            let assignment = v.assignment.pending_admission(scope, rollout.clone());
            if assignment
                .entry_in(&service.transactions.source, tx, &run.target.device, now)
                .await?
                .is_none()
            {
                return Ok(false);
            }
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
                            crate::deployment::scope::Channel::Agent,
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
    {
        let db::ScheduledPolicy::Software(software) = plan;
        let id = run.id;
        let tenant = tx.tenant_id().to_string();
        let (missing, created): (bool, i64) = tx.with_connection(move |c| Box::pin(async move { sqlx::query_as("SELECT software_effect IS NULL,created_at FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await })).await?;
        if missing {
            let Some(binding) = crate::deployment::agent_facts::agent_binding_in(
                tx,
                service.transactions.agent_store.clone(),
                run.target.device.clone(),
            )
            .await?
            else {
                return Ok(false);
            };
            if !software
                .assignment
                .supported_in(&service.transactions.admission(), tx, &binding)
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
            let crate::deployment::actions::software::Preparation::Ready(slot) =
                crate::deployment::actions::software::slot_in(
                    &service.transactions,
                    tx,
                    software,
                    &run.target,
                    Some(
                        crate::deployment::actions::software::Invocation::SelfService(*request_id),
                    ),
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
            crate::deployment::actions::software::persist_effect_in(tx, run.id, &slot.effect)
                .await?;
        }
    }
    let invocation = run.invocation.as_ref().ok_or(Error::Malformed)?;
    let document = json(invocation)?;
    let evidence = json(&run.source_objects)?;
    let id = run.id;
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_software_deployment.action_runs SET invocation=$3,source_objects=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(document).bind(evidence).execute(c).await?;Ok(())})).await?;
    Ok(true)
}

fn required_activity_user<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<rss_mdm_audit_integration::activity::ActivityUser>, D::Error> {
    Option::deserialize(d)
}

/// Read the immutable self-service response under current device authority without replaying it.
pub async fn diagnostic_on(
    c: &mut sqlx::PgConnection,
    p: &AuthorizedPrincipal,
    grant: &rss_mdm_authorization_service::Snapshot,
    locator: &rss_mdm_audit_integration::operation::OperationLocator,
) -> Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>> {
    if locator.owner != rss_mdm_audit_integration::operation::OperationOwner::SoftwareInvocation
        || locator.product != p.profile()
    {
        return Err(Error::Malformed.into());
    }
    let actor = locator.actor.as_deref().ok_or(Error::Malformed)?;
    let device = locator.device.as_deref().ok_or(Error::Malformed)?;
    grant.require(
        p,
        rss_mdm_authorization_service::Permission::OperationRead,
        Some(device),
    )?;
    let raw: Option<Value> = sqlx::query_scalar("SELECT response FROM mdm_software_deployment.action_receipts WHERE tenant_id = CAST($1 AS uuid) AND actor = $2 AND id = $3 AND device = $4")
        .bind(p.tenant_id()).bind(actor).bind(locator.operation_id)
        .bind(device).fetch_optional(c).await?;
    let Some(raw) = raw else { return Ok(None) };
    let response: wire::SelfServiceAccepted = stored(serde_json::from_value(raw))?;
    if response.request_id != locator.operation_id {
        return Err(Error::Malformed.into());
    }
    let mut value = rss_mdm_audit_integration::operation::ReceiptSummary::new(locator.operation_id);
    value.object = Some(device.into());
    value.accepted = Some(true);
    value.revision = Some(i64::try_from(response.policy_revision).map_err(|_| Error::Malformed)?);
    value.executions.push(response.run_id);
    p.check_live()?;
    Ok(Some(value))
}
