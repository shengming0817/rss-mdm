//! Targeted event admission borrows the original transaction and the existing execution owners.
//! ref: meilisearch crates/index-scheduler/src/queue/batches.rs — operation references in atomic batches.
use crate::{
    ExecutionService, Result, Target,
    actions::{production, storage as runs},
};
use rss_mdm_agent_wire::runtime::{
    PolicyEventDecision as Decision, PolicyEventOperation as Operation,
};
use rss_mdm_policy::{Action, Policy};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub fn rejected(reason: &str) -> Decision {
    Decision::Rejected {
        reason: reason.into(),
    }
}
fn accepted(ids: Vec<Uuid>, native: bool) -> Decision {
    Decision::Accepted {
        operations: ids
            .into_iter()
            .map(|id| {
                if native {
                    Operation::Native { id }
                } else {
                    Operation::Run { id }
                }
            })
            .collect(),
    }
}
/// Resolve the exact currently assigned channel; never silently choose an ambiguous registration.
pub async fn target_in(
    tx: &mut PgTransaction<'_>,
    device: &str,
    channel: &str,
) -> Result<Option<Target>> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let channel = match channel {
        "agent" => rss_mdm_inventory::Channel::Agent,
        "mdm" => rss_mdm_inventory::Channel::Mdm,
        _ => return Err(crate::Error::Malformed.into()),
    };
    let current = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(rss_mdm_registration_service::device::endpoints::current_in(
                    c, &tenant, &device, channel,
                )
                .await)
            })
        })
        .await??;
    Ok(current.map(|p| Target {
        device: p.device,
        registration: p.registration_id,
        generation: p.generation,
    }))
}
impl ExecutionService {
    /// Original execution transaction host for atomic event member acceptance.
    pub fn event_runtime(&self) -> &rss_transactional_messaging_postgres::PgRuntime {
        &self.runtime
    }

    /// A batch member has one immutable operation identity. Scope and execution rules remain owner-owned.
    pub async fn event_scope_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        target: &Target,
    ) -> Result<bool> {
        let channel = if matches!(policy.definition.action, Action::UnmanageDevice { .. }) {
            let tenant = tx.tenant_id().to_string();
            let registration = target.registration;
            let channel:String=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT channel FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(registration).fetch_one(c).await})).await?;
            if channel == "mdm" {
                crate::source_authority::Channel::Mdm
            } else {
                crate::source_authority::Channel::Agent
            }
        } else {
            crate::source_authority::action_channel(&policy.definition.action)?
        };
        Ok(matches!(
            crate::sources::storage::admission_in(
                &self.source,
                tx,
                policy.definition.scope,
                channel,
                &target.device
            )
            .await?,
            crate::source_authority::ScopeAdmission::Eligible { .. }
        ))
    }
    pub async fn accept_policy_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        target: &Target,
        request: Uuid,
        deadline: i64,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Decision> {
        let now = crate::storage::now(tx).await?;
        if now >= deadline {
            return Ok(Decision::Expired);
        }
        crate::actions::native_recovery::lock_device(tx, &target.device).await?;
        if !policy.state.is_enabled() {
            return Ok(rejected("policy_disabled"));
        }
        let channel = crate::source_authority::action_channel(&policy.definition.action)?;
        let eligible = crate::sources::storage::admission_in(
            &self.source,
            tx,
            policy.definition.scope,
            channel,
            &target.device,
        )
        .await?;
        if !matches!(
            eligible,
            crate::source_authority::ScopeAdmission::Eligible { .. }
        ) {
            return Ok(rejected("scope_not_eligible"));
        }
        match &policy.definition.action {
            Action::Execution { .. }
            | Action::Credential { .. }
            | Action::AgentCollection { .. }
            | Action::NativeCollection { .. }
            | Action::RequestMdmEnrollment { .. } => {
                let plan =
                    runs::load_policy_version(&self.policy_reader, tx, policy.version).await?;
                production::accept_for_device(
                    self,
                    tx,
                    &plan,
                    target,
                    production::AdmissionTrigger::Custom {
                        request,
                        at: now,
                        deadline,
                    },
                    now,
                    request,
                )
                .await?;
                let tenant = tx.tenant_id().to_string();
                let exists:bool=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2)").bind(tenant).bind(request).fetch_one(c).await})).await?;
                Ok(if exists {
                    accepted(vec![request], false)
                } else {
                    rejected("execution_not_eligible")
                })
            }
            Action::Software { .. } => {
                let plan =
                    runs::load_policy_version(&self.policy_reader, tx, policy.version).await?;
                let runs::ScheduledPolicy::Software(software) = plan else {
                    return Err(crate::Error::Malformed.into());
                };
                let preparation = crate::actions::software::slot_in(
                    self,
                    tx,
                    &software,
                    target,
                    Some(crate::actions::software::Invocation::Event(request)),
                    now,
                    None,
                )
                .await?;
                let slot = match preparation {
                    crate::actions::software::Preparation::Ready(slot) => slot,
                    crate::actions::software::Preparation::Satisfied => {
                        return Ok(Decision::NoChange {
                            reason: "software_verified".into(),
                        });
                    }
                    crate::actions::software::Preparation::NotEligible => {
                        return Ok(rejected("software_not_eligible"));
                    }
                };
                let end = slot.deadline.min(deadline);
                if end <= slot.available {
                    return Ok(Decision::Expired);
                }
                production::queue_run_in(
                    self,
                    tx,
                    production::RunInput {
                        source: runs::Source::Policy {
                            version: policy.version,
                        },
                        target,
                        id: request,
                        occurrence: slot.occurrence,
                        available: slot.available,
                        deadline: end,
                        now,
                        triggered_at: None,
                    },
                )
                .await?;
                crate::actions::software::persist_effect_in(tx, request, &slot.effect).await?;
                Ok(accepted(vec![request], false))
            }
            Action::Configuration { .. } => {
                let tenant = tx.tenant_id().to_string();
                let device = target.device.clone();
                tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_planning.configuration_devices(tenant_id,device) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(tenant).bind(device).execute(c).await?;Ok(())})).await?;
                self.reconcile_configuration_target_in(tx, &target.device, audit, Some(policy.id))
                    .await?;
                self.configuration_event_result_in(tx, policy, target).await
            }
            Action::EnsureAgentInstalled { .. } => {
                self.agent_install_event_in(tx, policy, target, deadline, audit)
                    .await
            }
            Action::DeviceAccess { .. } => {
                let prepared = crate::device_access::prepare_target_reconciliation_in(
                    self,
                    tx,
                    target,
                    Some(policy.id),
                )
                .await?;
                let outcome =
                    crate::device_access::reconcile_in(self, tx, prepared, now, audit).await?;
                Ok(if !outcome.operations.is_empty() {
                    accepted(outcome.operations, false)
                } else if outcome.blocked {
                    rejected("access_not_eligible")
                } else {
                    Decision::NoChange {
                        reason: "account_bindings_current".into(),
                    }
                })
            }
            // These are handled by Planning, whose lifecycle and telemetry owners hold their contracts.
            Action::UnmanageDevice { .. } | Action::TelemetryProfile { .. } => {
                Err(crate::Error::Unsupported.into())
            }
        }
    }
    async fn configuration_event_result_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        target: &Target,
    ) -> Result<Decision> {
        let tenant = tx.tenant_id().to_string();
        let device = target.device.clone();
        let id = policy.id;
        let version = policy.version;
        let rows:Vec<(Option<Uuid>,Option<String>)>=tx.with_connection(move|c|Box::pin(async move {sqlx::query_as("SELECT DISTINCT c.operation,o.diagnosis FROM mdm_planning.configuration_claims c JOIN mdm_planning.configuration_objects o USING(tenant_id,device,user_key,platform,object_kind,object_key) WHERE c.tenant_id=$1::uuid AND c.device=$2 AND c.policy=$3 AND c.version=$4 LIMIT 1000").bind(tenant).bind(device).bind(id).bind(version).fetch_all(c).await})).await?;
        if let Some(reason) = rows.iter().find_map(|(_, reason)| reason.as_deref()) {
            return Ok(rejected(reason));
        }
        let ids = rows
            .into_iter()
            .filter_map(|(id, _)| id)
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(rejected("configuration_not_eligible"));
        }
        let mut applied = true;
        for id in &ids {
            let op = crate::storage::load(tx, &self.protection, *id).await?;
            applied &= self.required_command(tx, &op).await?.status()
                == rss_device_command::Status::Applied;
        }
        Ok(if applied {
            Decision::NoChange {
                reason: "configuration_applied".into(),
            }
        } else {
            accepted(ids, true)
        })
    }
}
impl ExecutionService {
    /// Validate ingress using the same authenticated Agent and OS-context owner as task events.
    pub async fn verify_event_device(
        &self,
        p: &crate::device::DevicePrincipal,
        input: &rss_mdm_agent_wire::runtime::PolicyEventRequest,
        _audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> std::result::Result<(), crate::Error> {
        crate::transaction::inspect(&self.runtime, self.tenant, (self, p, input), |ctx, tx| {
            Box::pin(async move {
                let (s, p, input) = *ctx;
                crate::actions::agent::principal(s, tx, p).await?;
                let context = input
                    .execution_context
                    .as_ref()
                    .ok_or(crate::Error::Malformed)?;
                context.validate().map_err(|_| crate::Error::Malformed)?;
                if let rss_mdm_agent_wire::runtime::PolicyEventSource::Policy { run_id } =
                    input.source
                {
                    let run = runs::load_run(tx, run_id).await?;
                    crate::actions::agent::belongs(&run, p)?;
                }
                Ok(())
            })
        })
        .await
    }
    /// Apply the authoritative platform/revision check in the batch's original transaction.
    pub async fn apply_event_context_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        context: &rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    ) -> Result<()> {
        crate::channels::agent_context_in(
            tx,
            self.agent_store.clone(),
            target.registration,
            context,
        )
        .await
    }
    /// A completed parent may replay its receipt, but cannot initiate another child event.
    pub async fn event_parent_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        source: &rss_mdm_agent_wire::runtime::PolicyEventSource,
    ) -> Result<bool> {
        if let rss_mdm_agent_wire::runtime::PolicyEventSource::Policy { run_id } = source {
            let run = runs::load_run(tx, *run_id).await?;
            Ok(run.target.device == target.device
                && run.target.registration == target.registration
                && run.target.generation == target.generation
                && run.state.execution == crate::actions::state::Execution::Running
                && run.state.started_at.is_some())
        } else {
            Ok(true)
        }
    }
    pub async fn event_device_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &Target,
    ) -> Result<bool> {
        let tenant = tx.tenant_id().to_string();
        let target = target.clone();
        Ok(tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND device=$3 AND generation=$4 AND state='active')").bind(tenant).bind(target.registration).bind(target.device).bind(target.generation).fetch_one(c).await})).await?)
    }
}
impl ExecutionService {
    /// Return only operation progress, never script output or protected request inputs.
    pub async fn policy_event_operation_in(
        &self,
        tx: &mut PgTransaction<'_>,
        reference: &Operation,
    ) -> Result<serde_json::Value> {
        use serde_json::json;
        match reference {
            Operation::Run { id } => {
                let run = runs::load_run(tx, *id).await?;
                Ok(json!({"reference":reference,"state":run.state,"allowedActions":[]}))
            }
            Operation::Native { id } => {
                let operation = crate::storage::load(tx, &self.protection, *id).await?;
                let command = self.required_command(tx, &operation).await?;
                let installation = if matches!(
                    operation.authority,
                    crate::authority::ExecutionAuthority::AgentInstall { .. }
                ) {
                    Some(
                        crate::native_installation::installation_observation(
                            tx,
                            self.apple_results.clone(),
                            self.agent_store.clone(),
                            &operation,
                        )
                        .await?,
                    )
                } else {
                    None
                };
                Ok(
                    json!({"reference":reference,"state":command.status().as_str(),"agentInstallation":installation,"allowedActions":[]}),
                )
            }
            Operation::Retirement { id } => {
                let id = *id;
                let tenant = tx.tenant_id();
                let value = tx
                    .with_connection(move |c| {
                        Box::pin(async move { Ok(retirement_progress_on(c, tenant, id).await) })
                    })
                    .await??;
                Ok(json!({"reference":reference,"state":value,"allowedActions":[]}))
            }
        }
    }
}
async fn retirement_progress_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    id: Uuid,
) -> std::result::Result<serde_json::Value, crate::Error> {
    let retirement = rss_mdm_device_service::lifecycle::read_in(c, tenant, id)
        .await
        .map_err(crate::Error::from)?;
    serde_json::to_value(retirement).map_err(|_| crate::Error::Malformed)
}
