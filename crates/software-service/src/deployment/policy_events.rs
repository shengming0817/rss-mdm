//! Targeted event admission borrows the original transaction and the existing execution owners.
//! ref: meilisearch crates/index-scheduler/src/queue/batches.rs — operation references in atomic batches.
use crate::deployment::{
    Result, Target,
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
        _ => return Err(crate::deployment::Error::Malformed.into()),
    };
    let current = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(rss_mdm_registration_service::device::endpoints::current_in(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    &tenant,
                    &device,
                    channel,
                )
                .await)
            })
        })
        .await??;
    Ok(current.map(|p| Target { device: p.device }))
}

/// The actual operation owner's progress, retaining the established untagged HTTP shape.
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(untagged, rename_all_fields = "camelCase")]
pub enum EventOperationProgress {
    Run {
        reference: Operation,
        state: rss_mdm_task_state::RunState,
        allowed_actions: [String; 0],
    },
    Native {
        reference: Operation,
        #[serde(serialize_with = "serialize_native_status")]
        #[schemars(schema_with = "native_status_schema")]
        state: rss_device_command::Status,
        agent_installation: Option<crate::deployment::queries::records::InstallationObservation>,
        allowed_actions: [String; 0],
    },
}
fn serialize_native_status<S: serde::Serializer>(
    status: &rss_device_command::Status,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(status.as_str())
}
fn native_status_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type":"string","enum":rss_device_command::Status::ALL.map(|s|s.as_str())})
}

impl crate::deployment::transactions::Transactions {
    /// Bind Policy participation to this exact admitted runtime and tenant.
    pub fn validate_policy_transaction_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(crate::deployment::Error::Forbidden.into());
        }
        Ok(())
    }
    /// A batch member has one immutable operation identity. Scope and execution rules remain owner-owned.
    pub async fn event_scope_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        target: &Target,
    ) -> Result<bool> {
        self.validate_policy_transaction_in(tx)?;
        let channel = if matches!(policy.definition.action, Action::UnmanageDevice { .. }) {
            let tenant = tx.tenant_id().to_string();
            let registration = target.device.clone();
            let channel:String=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT channel FROM mdm_access.devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2").bind(tenant).bind(&registration).fetch_one(c).await})).await?;
            if channel == "mdm" {
                crate::deployment::scope::Channel::Mdm
            } else {
                crate::deployment::scope::Channel::Agent
            }
        } else {
            crate::deployment::sources::candidates::action_channel(&policy.definition.action)?
        };
        Ok(matches!(
            crate::deployment::sources::storage::admission_in(
                &self.source,
                tx,
                policy.definition.scope,
                channel,
                &target.device
            )
            .await?,
            crate::deployment::scope::ScopeAdmission::Eligible { .. }
        ))
    }
    pub async fn accept_policy_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        target: &Target,
        cause: (Uuid, rss_mdm_audit_integration::activity::ActivityOrigin),
        deadline: i64,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Decision> {
        self.validate_policy_transaction_in(tx)?;
        let (request, origin) = cause;
        let now = crate::deployment::storage::now(tx).await?;
        if now >= deadline {
            return Ok(Decision::Expired);
        }
        crate::deployment::actions::run_recovery::lock_device(tx, &target.device).await?;
        if !policy.state.is_enabled() {
            return Ok(rejected("policy_disabled"));
        }
        let channel =
            crate::deployment::sources::candidates::action_channel(&policy.definition.action)?;
        let eligible = crate::deployment::sources::storage::admission_in(
            &self.source,
            tx,
            policy.definition.scope,
            channel,
            &target.device,
        )
        .await?;
        if !matches!(
            eligible,
            crate::deployment::scope::ScopeAdmission::Eligible { .. }
        ) {
            return Ok(rejected("scope_not_eligible"));
        }
        match &policy.definition.action {
            Action::Software { .. } => {
                let plan =
                    runs::load_policy_version(&self.policy_reader, tx, policy.version).await?;
                let runs::ScheduledPolicy::Software(software) = plan;
                let preparation = crate::deployment::actions::software::slot_in(
                    self,
                    tx,
                    &software,
                    target,
                    Some(crate::deployment::actions::software::Invocation::Event(
                        request,
                    )),
                    now,
                    None,
                )
                .await?;
                let slot = match preparation {
                    crate::deployment::actions::software::Preparation::Ready(slot) => slot,
                    crate::deployment::actions::software::Preparation::Satisfied => {
                        return Ok(Decision::NoChange {
                            reason: "software_verified".into(),
                        });
                    }
                    crate::deployment::actions::software::Preparation::NotEligible
                    | crate::deployment::actions::software::Preparation::Waiting(_) => {
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
                        request: None,
                        origin,
                        invocation: None,
                        source: runs::Source::Policy {
                            version: policy.version,
                        },
                        target,
                        id: request,
                        occurrence: slot.occurrence,
                        available: slot.available,
                        deadline: end,
                        now,
                    },
                )
                .await?;
                crate::deployment::actions::software::persist_effect_in(tx, request, &slot.effect)
                    .await?;
                Ok(accepted(vec![request], false))
            }
            Action::Configuration { .. } => Err(crate::deployment::Error::Unsupported.into()),

            Action::EnsureAgentInstalled { .. } => {
                self.agent_install_event_in(tx, policy, target, deadline, origin, audit)
                    .await
            }

            // App dispatches these actions directly to their business owners.
            _ => Err(crate::deployment::Error::Unsupported.into()),
        }
    }

    /// Validate ingress using the same authenticated Agent and OS-context owner as task events.
    /// Keep the complete credential/source check and channel lock in the caller's transaction.
    pub async fn verify_event_device_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &crate::deployment::device::DevicePrincipal,
        input: Option<&rss_mdm_agent_wire::runtime::PolicyEventRequest>,
    ) -> Result<()> {
        self.validate_policy_transaction_in(tx)?;
        crate::deployment::actions::agent::principal(self, tx, p).await?;
        if let Some(input) = input {
            let context = input
                .execution_context
                .as_ref()
                .ok_or(crate::deployment::Error::Malformed)?;
            context
                .validate()
                .map_err(|_| crate::deployment::Error::Malformed)?;
            if let rss_mdm_agent_wire::runtime::PolicyEventSource::Policy { run_id } = input.source
            {
                let run = runs::load_run(tx, run_id).await?;
                crate::deployment::actions::agent::belongs(&run, p)?;
            }
        }
        Ok(())
    }
    /// Apply the authoritative platform/revision check in the batch's original transaction.
    pub async fn apply_event_context_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        context: &rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    ) -> Result<()> {
        self.validate_policy_transaction_in(tx)?;
        crate::deployment::agent_facts::agent_context_in(
            tx,
            self.agent_store.clone(),
            target.device.clone(),
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
        self.validate_policy_transaction_in(tx)?;
        if let rss_mdm_agent_wire::runtime::PolicyEventSource::Policy { run_id } = source {
            let run = runs::load_run(tx, *run_id).await?;
            Ok(run.target.device == target.device
                && run.state.execution == rss_mdm_task_state::Execution::Running
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
        self.validate_policy_transaction_in(tx)?;
        let tenant = tx.tenant_id().to_string();
        let target = target.clone();
        Ok(tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_access.devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND state = 'active')").bind(tenant).bind(&target.device).fetch_one(c).await})).await?)
    }
    /// Return only operation progress, never script output or protected request inputs.
    pub async fn policy_event_operation_in(
        &self,
        tx: &mut PgTransaction<'_>,
        reference: &Operation,
    ) -> Result<EventOperationProgress> {
        self.validate_policy_transaction_in(tx)?;
        match reference {
            Operation::Retirement { .. } => Err(crate::deployment::Error::Unsupported.into()),
            Operation::Run { id } => {
                let run = runs::load_run(tx, *id).await?;
                Ok(EventOperationProgress::Run {
                    reference: reference.clone(),
                    state: run.state,
                    allowed_actions: [],
                })
            }
            Operation::Native { id } => {
                let operation = crate::deployment::storage::load(tx, &self.protection, *id).await?;
                let command = self.required_command(tx, &operation).await?;
                let installation = if matches!(
                    operation.authority,
                    crate::deployment::authority::Authority::AgentInstall { .. }
                ) {
                    Some(
                        crate::deployment::native_installation::installation_observation(
                            self.inventory.clone(),
                            tx,
                            self.windows_results.clone(),
                            self.apple_results.clone(),
                            self.agent_store.clone(),
                            &operation,
                        )
                        .await?,
                    )
                } else {
                    None
                };
                Ok(EventOperationProgress::Native {
                    reference: reference.clone(),
                    state: command.status(),
                    agent_installation: installation
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|_| {
                            crate::deployment::Error::Unavailable(
                                crate::deployment::Failure::CommandStorage,
                            )
                        })?,
                    allowed_actions: [],
                })
            }
        }
    }
}

/// Policy-owned event transactions participate in Execution without adopting its worker or pool.
pub struct PolicyEvents {
    transactions: crate::deployment::transactions::Transactions,
}
impl PolicyEvents {
    /// Admit the Policy caller profile and create only bindings on its existing runtime.
    pub async fn bind(
        runtime: std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
        tenant: rss_request_context::TenantId,
        audit: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
        materials: std::sync::Arc<crate::deployment::Materials>,
    ) -> std::result::Result<Self, crate::deployment::Error> {
        Ok(Self {
            transactions: crate::deployment::transactions::Transactions::bind(
                runtime, tenant, audit, materials,
            )
            .await?,
        })
    }
    /// Borrow the original caller transaction; preserve its authority and operation identity.
    pub fn validate_policy_transaction_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.transactions.validate_policy_transaction_in(tx)
    }
    /// Borrow the original caller transaction; preserve its authority and operation identity.
    pub async fn event_scope_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        target: &Target,
    ) -> Result<bool> {
        self.transactions.event_scope_in(tx, policy, target).await
    }
    /// Borrow the original caller transaction; preserve its authority and operation identity.
    pub async fn accept_policy_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        target: &Target,
        cause: (Uuid, rss_mdm_audit_integration::activity::ActivityOrigin),
        deadline: i64,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Decision> {
        self.transactions
            .accept_policy_event_in(tx, policy, target, cause, deadline, audit)
            .await
    }
    /// Borrow the original caller transaction; preserve its authority and operation identity.
    pub async fn verify_event_device_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &crate::deployment::device::DevicePrincipal,
        input: Option<&rss_mdm_agent_wire::runtime::PolicyEventRequest>,
    ) -> Result<()> {
        self.transactions.verify_event_device_in(tx, p, input).await
    }
    /// Borrow the original caller transaction; preserve its authority and operation identity.
    pub async fn apply_event_context_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        context: &rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    ) -> Result<()> {
        self.transactions
            .apply_event_context_in(tx, target, context)
            .await
    }
    /// Borrow the original caller transaction; preserve its authority and operation identity.
    pub async fn event_parent_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        source: &rss_mdm_agent_wire::runtime::PolicyEventSource,
    ) -> Result<bool> {
        self.transactions
            .event_parent_current_in(tx, target, source)
            .await
    }
    /// Borrow the original caller transaction; preserve its authority and operation identity.
    pub async fn event_device_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &Target,
    ) -> Result<bool> {
        self.transactions.event_device_current_in(tx, target).await
    }
    /// Borrow the original caller transaction; preserve its authority and operation identity.
    pub async fn policy_event_operation_in(
        &self,
        tx: &mut PgTransaction<'_>,
        reference: &Operation,
    ) -> Result<EventOperationProgress> {
        self.transactions
            .policy_event_operation_in(tx, reference)
            .await
    }
}
