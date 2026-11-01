//! Targeted event admission borrows the original transaction and the existing execution owners.
//! ref: meilisearch crates/index-scheduler/src/queue/batches.rs — operation references in atomic batches.
use crate::{Result, Target, actions::storage as runs};
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
async fn retirement_progress_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    id: Uuid,
) -> std::result::Result<rss_mdm_device_service::lifecycle::Retirement, crate::Error> {
    let retirement = rss_mdm_device_service::lifecycle::read_in(c, tenant, id)
        .await
        .map_err(crate::Error::from)?;
    Ok(retirement)
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
        allowed_actions: [String; 0],
    },
    Retirement {
        reference: Operation,
        state: rss_mdm_device_service::lifecycle::Retirement,
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

impl crate::transactions::ExecutionTransactions {
    /// Bind Policy participation to this exact admitted runtime and tenant.
    pub fn validate_policy_transaction_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(crate::Error::Forbidden.into());
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
            let registration = target.registration;
            let channel:String=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT channel FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(registration).fetch_one(c).await})).await?;
            if channel == "mdm" {
                rss_mdm_scope_service::channels::Channel::Mdm
            } else {
                rss_mdm_scope_service::channels::Channel::Agent
            }
        } else {
            crate::sources::candidates::action_channel(&policy.definition.action)?
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
            rss_mdm_scope_service::channels::ScopeAdmission::Eligible { .. }
        ))
    }
    pub async fn accept_policy_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        target: &Target,
        _cause: (Uuid, rss_mdm_audit_integration::activity::ActivityOrigin),
        deadline: i64,
        _audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Decision> {
        self.validate_policy_transaction_in(tx)?;
        let now = crate::storage::now(tx).await?;
        if now >= deadline {
            return Ok(Decision::Expired);
        }
        crate::actions::run_recovery::lock_device(tx, &target.device).await?;
        if !policy.state.is_enabled() {
            return Ok(rejected("policy_disabled"));
        }
        let channel = crate::sources::candidates::action_channel(&policy.definition.action)?;
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
            rss_mdm_scope_service::channels::ScopeAdmission::Eligible { .. }
        ) {
            return Ok(rejected("scope_not_eligible"));
        }
        Err(crate::Error::Unsupported.into())
    }

    /// Validate ingress using the same authenticated Agent and OS-context owner as task events.
    /// Keep the complete credential/source check and channel lock in the caller's transaction.
    pub async fn verify_event_device_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &crate::device::DevicePrincipal,
        input: Option<&rss_mdm_agent_wire::runtime::PolicyEventRequest>,
    ) -> Result<()> {
        self.validate_policy_transaction_in(tx)?;
        crate::actions::agent::principal(self, tx, p).await?;
        if let Some(input) = input {
            let context = input
                .execution_context
                .as_ref()
                .ok_or(crate::Error::Malformed)?;
            context.validate().map_err(|_| crate::Error::Malformed)?;
        }
        Ok(())
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
                && run.target.registration == target.registration
                && run.target.generation == target.generation
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
        Ok(tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND device=$3 AND generation=$4 AND state='active')").bind(tenant).bind(target.registration).bind(target.device).bind(target.generation).fetch_one(c).await})).await?)
    }
    /// Return only operation progress, never script output or protected request inputs.
    pub async fn policy_event_operation_in(
        &self,
        tx: &mut PgTransaction<'_>,
        reference: &Operation,
    ) -> Result<EventOperationProgress> {
        self.validate_policy_transaction_in(tx)?;
        match reference {
            Operation::Run { id } => {
                let run = runs::load_run(tx, *id).await?;
                Ok(EventOperationProgress::Run {
                    reference: reference.clone(),
                    state: run.state,
                    allowed_actions: [],
                })
            }
            Operation::Native { id } => {
                let operation = crate::storage::load(tx, &self.protection, *id).await?;
                let command = self.required_command(tx, &operation).await?;
                Ok(EventOperationProgress::Native {
                    reference: reference.clone(),
                    state: command.status(),
                    allowed_actions: [],
                })
            }
            Operation::Retirement { id } => {
                let id = *id;
                let tenant = tx.tenant_id();
                let value = tx
                    .with_connection(move |c| {
                        Box::pin(async move { Ok(retirement_progress_on(c, tenant, id).await) })
                    })
                    .await??;
                Ok(EventOperationProgress::Retirement {
                    reference: reference.clone(),
                    state: value,
                    allowed_actions: [],
                })
            }
        }
    }
}

/// Policy-owned event transactions participate in Execution without adopting its worker or pool.
pub struct PolicyEvents {
    transactions: crate::transactions::ExecutionTransactions,
}
impl PolicyEvents {
    /// Admit the Policy caller profile and create only bindings on its existing runtime.
    pub async fn bind(
        runtime: std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
        tenant: rss_request_context::TenantId,
        audit: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
        materials: std::sync::Arc<crate::ExecutionMaterials>,
    ) -> std::result::Result<Self, crate::Error> {
        Ok(Self {
            transactions: crate::transactions::ExecutionTransactions::bind(
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
        _cause: (Uuid, rss_mdm_audit_integration::activity::ActivityOrigin),
        deadline: i64,
        _audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Decision> {
        self.transactions
            .accept_policy_event_in(tx, policy, target, _cause, deadline, _audit)
            .await
    }
    /// Borrow the original caller transaction; preserve its authority and operation identity.
    pub async fn verify_event_device_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &crate::device::DevicePrincipal,
        input: Option<&rss_mdm_agent_wire::runtime::PolicyEventRequest>,
    ) -> Result<()> {
        self.transactions.verify_event_device_in(tx, p, input).await
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
