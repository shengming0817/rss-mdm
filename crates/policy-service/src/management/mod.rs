//! Authored Policy is the durable authority; execution progress never edits it.
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    transaction::*,
};
use rss_mdm_audit_integration::activity::ActivityOrigin;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_policy::Action;
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

pub mod lifecycle;
pub mod reconcile;
pub mod rerun;
pub mod storage;
pub mod telemetry;

pub mod authorization;
pub use rss_mdm_policy::Policy;
mod draft;
pub mod scopes;
pub use draft::{Change, View};
pub struct Policies {
    reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    scopes: std::sync::Arc<rss_mdm_scope_service::Scopes>,
    profile_validator: std::sync::Arc<dyn crate::inputs::ProfileValidator>,
    cursor_key: ring::hmac::Key,
    runtime: std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
    audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    tenant: rss_request_context::TenantId,
    policy_store: std::sync::Arc<rss_mdm_policy_postgres::PolicyStore>,
    inputs: std::sync::Arc<dyn crate::inputs::ExecutionPublication>,
    script: Option<std::sync::Arc<rss_mdm_script_service::inputs::Inputs>>,
    credentials: Option<std::sync::Arc<rss_mdm_recovery_credentials::tasks::publication::Inputs>>,
    collections:
        Option<std::sync::Arc<rss_mdm_inventory_service::collection::execution::inputs::Inputs>>,
    configuration: Option<std::sync::Arc<crate::configuration::publication::Publications>>,
    changes: std::sync::Arc<dyn crate::inputs::ExecutionChanges>,
    mdm_software_enabled: bool,
}
/// Dependencies for this Policy application, supplied by the host.
pub struct Dependencies {
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub scopes: std::sync::Arc<rss_mdm_scope_service::Scopes>,
    pub profile_validator: std::sync::Arc<dyn crate::inputs::ProfileValidator>,
    pub cursor_key: Vec<u8>,
    pub runtime: std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    pub tenant: rss_request_context::TenantId,
    pub policy_store: std::sync::Arc<rss_mdm_policy_postgres::PolicyStore>,
    pub inputs: std::sync::Arc<dyn crate::inputs::ExecutionPublication>,
    pub script: Option<std::sync::Arc<rss_mdm_script_service::inputs::Inputs>>,
    pub credentials:
        Option<std::sync::Arc<rss_mdm_recovery_credentials::tasks::publication::Inputs>>,
    pub collections:
        Option<std::sync::Arc<rss_mdm_inventory_service::collection::execution::inputs::Inputs>>,
    pub configuration: Option<std::sync::Arc<crate::configuration::publication::Publications>>,
    pub changes: std::sync::Arc<dyn crate::inputs::ExecutionChanges>,
    pub mdm_software_enabled: bool,
}
impl Policies {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.policy_store.profile()
    }
    pub fn new(deps: Dependencies) -> Self {
        let Dependencies {
            reconcile_messaging,
            scopes,
            profile_validator,
            cursor_key,
            runtime,
            audit_store,
            tenant,
            policy_store,
            inputs,
            script,
            collections,
            credentials,
            configuration,
            changes,
            mdm_software_enabled,
        } = deps;
        Self {
            reconcile_messaging,
            scopes,
            profile_validator,
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &cursor_key),
            runtime,
            audit_store,
            tenant,
            policy_store,
            inputs,
            script,
            collections,
            credentials,
            configuration,
            changes,
            mdm_software_enabled,
        }
    }

    pub async fn change(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        op: &crate::operation::Operation<Change>,
        audit: &RequestAudit,
    ) -> std::result::Result<View, Error> {
        let profile = self.profile();
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Policy,
            op.operation_id,
            "management_write",
            rss_mdm_audit_integration::AuditIntent::Management,
        );

        proof.require_initialization_target(&id.to_string())?;
        audit.resource_target(
            rss_mdm_audit_integration::TargetKind::Policy,
            &id.to_string(),
        );
        if id.is_nil() || op.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        proof.manage(Permission::PolicyWrite)?;
        // Verify content outside the database transaction, then bind that proof again at publication.
        let shape = op.input.checked_shape()?;
        let verified = if let rss_mdm_policy::Change::Put { definition, .. } = &shape {
            if definition.action.resource().is_some() {
                proof.manage(Permission::ResourceRead)?;
            }
            definition.validate()?;
            authorize_policy_snapshot(proof.authorization()?, proof, definition)?;
            match &definition.action {
                Action::TelemetryProfile { .. } | Action::UnmanageDevice { .. } => None,
                Action::Configuration { resource, .. } => Some(
                    self.configuration
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .prepare(resource)
                        .await?,
                ),
                Action::Execution {
                    resource,
                    parameters,
                    ..
                } => Some(
                    self.script
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .prepare_resource(
                            resource,
                            rss_mdm_script_service::Parameters::Sources(parameters),
                        )
                        .await?,
                ),
                Action::AgentCollection { resource, .. } => Some(
                    self.collections
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .prepare_resource(resource, rss_mdm_inventory::Channel::Agent)
                        .await?,
                ),
                Action::NativeCollection { resource, .. } => Some(
                    self.collections
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .prepare_resource(resource, rss_mdm_inventory::Channel::Mdm)
                        .await?,
                ),
                _ => None,
            }
        } else {
            None
        };

        run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, proof, id, op, audit, verified.as_ref(), &shape),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, id, op, audit, verified, shape) = *ctx;
                    if p.initialization_authority().is_some() {
                        crate::authorization::baseline::check_in(tx,p,Permission::PolicyWrite,&id.to_string()).await?;
                    }
                    crate::application::admit_in(profile, tx).await?;
                    let authorization = crate::action_admission::current(tx, p).await?;
                    authorization.require(p, Permission::PolicyWrite, None)?;
                    if matches!(shape, rss_mdm_policy::Change::Put { definition, .. } if definition.action.resource().is_some()) {
                        authorization.require(p, Permission::ResourceRead, None)?;
                    }

                    s.audit_store.prepare_in(tx,audit,&[]).await?;
                    let old = checked(s.policy_store.read_for_update_in(tx, id).await?)?;
                    if let Some(previous) = &old {
                        authorize_policy_snapshot(&authorization, p, &previous.definition)?;
                    }
                    if let rss_mdm_policy::Change::Put { definition, .. } = shape {
                        authorize_policy_snapshot(&authorization, p, definition)?;
                    }
                    if let Some(previous) = &old { s.view_in(tx, p, previous).await?; }
                    if let Change::Put { definition, .. } = &op.input {
                        let mut drafts = Vec::new();
                        definition.as_ref().clone().try_map_scopes(|_, scope| { drafts.push(scope); Ok::<_, Error>(Uuid::from_u128(1)) })?;
                        for draft in drafts { s.scopes.authorize_definition_in(tx, p, &draft).await?; }
                    }
                    let hash = fingerprint(&(id, &op.input, op.expected_revision, p.actor()))?;
                    if let Some(value) = checked(
                        s.policy_store
                            .replay_in(tx, op.operation_id, &hash)
                            .await?,
                    )? {
                        let value: View = stored(serde_json::from_value(value))?;
                        let mut definitions = value.scopes.iter().map(|s|s.definition.clone()).collect::<Vec<_>>();
                        let definition = value.definition.clone().try_map_scopes(|_, scope| {definitions.push(scope);Ok::<_,Error>(Uuid::from_u128(1))})?;
                        authorize_policy_snapshot(&authorization,p,&definition)?;
                        if definition.action.resource().is_some() {authorization.require(p,Permission::ResourceRead,None)?;}
                        for scope in definitions {s.scopes.authorize_definition_in(tx,p,&scope).await?;}
                        p.check_live()?;
                        return Ok(value);
                    }
                    if old.as_ref().map_or(0, |p| p.revision as u64) != op.expected_revision || old.as_ref().is_some_and(|p| p.state == rss_mdm_policy::State::Archived) { return Err(Error::Conflict.into()); }
                    let core_change = s.bind_change_in(tx, p, id, old.as_ref(), &op.input).await?;
                    let now = crate::action_admission::now(tx).await?;
                    let execution_binding=match &core_change { rss_mdm_policy::Change::Put {definition,..} if matches!(definition.action, Action::EnsureAgentInstalled { .. })=>s.inputs.software_binding_in(tx,&definition.action).await?,rss_mdm_policy::Change::Put {..}=>None,_=>old.as_ref().and_then(|p|p.execution_binding) };
                    let changed_policy = Policy::apply(
                        id,
                        old.as_ref(),
                        op.expected_revision,
                        &core_change,
                        Uuid::new_v4(),
                        execution_binding,
                    )?;
                    let changed = changed_policy.semantic_changed;
                    let policy = changed_policy.policy;
                    if policy.state.is_enabled() && !s.mdm_software_enabled && matches!(policy.definition.action,Action::Software{channel:rss_mdm_policy::SoftwareChannel::Mdm,..}) { return Err(Error::MdmSoftwareDisabled.into()); }
                    authorize_policy_snapshot(&authorization, p, &policy.definition)?;
                    if changed {
                        let frozen = if let Action::TelemetryProfile { resource } = &policy.definition.action {
                            telemetry::freeze(profile, tx, resource, p, &authorization, s.profile_validator.as_ref(), policy.id, policy.version).await?
                        } else {
                        if matches!(policy.definition.action,Action::Configuration{..}) {
                            s.configuration.as_ref().ok_or(Error::Unsupported)?.freeze_in(tx,&policy,verified,p,&authorization).await?
                        } else if let Action::UnmanageDevice{schedule,run_lifetime_seconds}=&policy.definition.action {
                            checked_input(serde_json::to_value(rss_mdm_device_service::control::frozen::Frozen::UnmanageDevice{schedule:schedule.clone(),run_lifetime_seconds:*run_lifetime_seconds,actor:p.actor()}))?
                        } else if let Action::DeviceAccess{mac,windows,self_enrollment,role}=&policy.definition.action {
                            let configuration=rss_mdm_agent_wire::runtime::AccessConfiguration{mac:mac.clone(),windows:windows.clone(),self_enrollment:*self_enrollment,enabled:true,role:role.map(|r|match r {rss_mdm_policy::AccessRole::Standard=>rss_mdm_agent_wire::runtime::AccessRole::Standard,rss_mdm_policy::AccessRole::Administrator=>rss_mdm_agent_wire::runtime::AccessRole::Administrator})};
                            configuration.validate().map_err(|_|Error::Malformed)?;
                            // MDM owns this publication; DA consumes only explicitly qualified sources.
                            serde_json::json!({"kind":"device_access","configuration":configuration})
                        } else if matches!(policy.definition.action,Action::Credential{..}) {
                            checked_input(serde_json::to_value(s.credentials.as_ref().ok_or(Error::Unsupported)?.publish_in(tx,&policy.definition.action,p,&authorization)?))?
                        } else if let Action::Execution {resource,parameters,schedule,frequency,run_lifetime_seconds}=&policy.definition.action {
                            checked_input(serde_json::to_value(s.script.as_ref().ok_or(Error::Unsupported)?.publish_in(tx,&rss_mdm_script_service::inputs::Publication {
                                binding:resource,parameters:rss_mdm_script_service::Parameters::Sources(parameters),schedule,frequency:*frequency,lifetime:*run_lifetime_seconds,
                            },verified.ok_or(Error::Conflict)?,p,&authorization).await?))?
                        } else if let Action::AgentCollection{resource,schedule,frequency,run_lifetime_seconds}|Action::NativeCollection{resource,schedule,frequency,run_lifetime_seconds}=&policy.definition.action {
                            checked_input(serde_json::to_value(s.collections.as_ref().ok_or(Error::Unsupported)?.publish_in(tx,&rss_mdm_inventory_service::collection::execution::inputs::Publication {
                                channel:if matches!(policy.definition.action,Action::AgentCollection{..}){rss_mdm_inventory::Channel::Agent}else{rss_mdm_inventory::Channel::Mdm},
                                binding:resource,schedule,frequency:*frequency,lifetime:*run_lifetime_seconds,
                            },verified.ok_or(Error::Conflict)?,p,&authorization).await?))?
                        } else {
                            s.inputs.publish_in(tx,&policy,p,&authorization).await?
                        }
                        };
                        storage::write_in(
                            s,
                            tx,
                            &policy,
                            &core_change,
                            Some(&frozen),
                            p,
                            now,
                        )
                        .await?;
                    } else {
                        storage::write_in(s, tx, &policy, &core_change, None, p, now)
                            .await?;
                    }
                    // Publication performs no Agent fanout. Native reconciliation is a bounded background job.
                    storage::enqueue_change_in(profile, &s.reconcile_messaging, s.changes.as_ref(), tx, &policy, old.as_ref()).await?;
                    s.retire_children_in(tx, old.as_ref(), &policy).await?;
                    let value = s.view_in(tx, p, &policy).await?;
                    checked(
                        s.policy_store
                            .receipt_in(tx, op.operation_id, &hash, &checked_input(serde_json::to_value(&value))?)
                            .await?,
                    )?;
                    let mut activity = rss_mdm_audit_integration::activity::Activity::new(
                        rss_mdm_audit_integration::activity::ActivityKind::Policy,
                        rss_mdm_audit_integration::activity::ActivityPhase::Changed);
                    activity.links.policy=Some(policy.id); activity.links.version=Some(policy.version);
                    activity.links.request=Some(op.operation_id); activity.origin=ActivityOrigin::Human;
                    let fact = Fact::business(audit, rss_mdm_audit_integration::operation::OperationOwner::Policy, &format!("policy:{id}:{}", op.operation_id), 200, "success", None)?.with_activity(&activity)?;
                    s.audit_store.append_in(tx, &fact).await?;
                    p.check_live()?;
                    Ok(value)
                })
            },
        )
        .await
    }
}

pub mod read;

impl Policies {
    pub async fn capabilities(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
    ) -> std::result::Result<Capabilities, Error> {
        proof.manage(Permission::PolicyRead)?;
        run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, proof, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, a) = *ctx;
                    crate::action_admission::current(tx, p).await?.require(
                        p,
                        Permission::PolicyRead,
                        None,
                    )?;
                    a.require_final_request();
                    Ok(Capabilities {
                        default_software_channel: DefaultSoftwareChannel::Agent,
                        mdm_software_distribution_enabled: s.mdm_software_enabled,
                    })
                })
            },
        )
        .await
    }
}

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    default_software_channel: DefaultSoftwareChannel,
    mdm_software_distribution_enabled: bool,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum DefaultSoftwareChannel {
    Agent,
}

pub mod scope_changes;

/// Policy publication authority, evaluated against the current locked snapshot.
pub fn authorize_policy_snapshot(
    snapshot: &rss_mdm_authorization_service::Snapshot,
    proof: &AuthorizedPrincipal,
    definition: &rss_mdm_policy::Definition,
) -> std::result::Result<(), Error> {
    snapshot.require_all_devices(proof, Permission::InventoryRead)?;
    authorization::authorize_action(snapshot, proof, &definition.action)?;
    Ok(())
}
