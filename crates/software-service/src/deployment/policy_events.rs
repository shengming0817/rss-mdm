//! Targeted event admission borrows the original transaction and the existing execution owners.
//! ref: meilisearch crates/index-scheduler/src/queue/batches.rs — operation references in atomic batches.
use crate::deployment::{
    Result, Target,
    actions::{production, storage as runs},
};
use rss_mdm_agent_wire::runtime::{
    PolicyEventDecision as Decision, PolicyEventOperation as Operation,
};
use rss_mdm_policy::Action;
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
    fn validate_policy_transaction_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;

        Ok(())
    }
    pub async fn accept_policy_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy_id: Uuid,
        version: Uuid,
        target: &Target,
        cause: (Uuid, rss_mdm_audit_integration::activity::ActivityOrigin),
        deadline: i64,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Decision> {
        self.validate_policy_transaction_in(tx)?;
        let binding = audit.binding()?;
        if tx.tenant_id() != binding.tenant() || tx.expected_epoch() != binding.epoch() {
            return Err(crate::deployment::Error::Forbidden.into());
        }
        let (request, origin) = cause;
        let now = crate::deployment::storage::now(tx).await?;
        if now >= deadline {
            return Ok(Decision::Expired);
        }
        let policy = crate::deployment::transaction::checked(
            self.policy_reader.locked_in(tx, policy_id).await?,
        )?
        .ok_or(crate::deployment::Error::NotFound)?;
        if policy.version != version {
            return Ok(rejected("policy_changed"));
        }
        if !matches!(
            policy.definition.action,
            Action::Software { .. } | Action::EnsureAgentInstalled { .. }
        ) {
            return Err(crate::deployment::Error::Unsupported.into());
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
                    binding,
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

            Action::EnsureAgentInstalled { .. } => {
                self.agent_install_event_in(tx, &policy, target, deadline, origin, audit)
                    .await
            }

            // App dispatches these actions directly to their business owners.
            _ => Err(crate::deployment::Error::Unsupported.into()),
        }
    }

    /// Apply the authoritative platform/revision check in the batch's original transaction.
    pub async fn apply_event_context_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: rss_mdm_agent_wire::DeviceId,
        context: &rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    ) -> Result<()> {
        self.validate_policy_transaction_in(tx)?;
        crate::deployment::agent_facts::agent_context_in(
            tx,
            self.agent_store.clone(),
            device,
            context,
        )
        .await
    }
    /// A completed parent may replay its receipt, but cannot initiate another child event.
    pub async fn event_parent_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: rss_mdm_agent_wire::DeviceId,
        run_id: Uuid,
    ) -> Result<bool> {
        self.validate_policy_transaction_in(tx)?;
        let run = runs::load_run(tx, run_id).await?;
        Ok(run.target.device == device
            && run.state.execution == rss_mdm_task_state::Execution::Running
            && run.state.started_at.is_some())
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
