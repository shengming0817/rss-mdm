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

use rss_mdm_execution_service::{
    frozen::Frozen,
    input_preparation::{PublicationAuthority, PublicationInput},
};
pub use rss_mdm_policy::{Change, Policy};
pub struct Policies {
    #[cfg(feature = "integration")]
    publication_fault: std::sync::Mutex<
        Option<(
            Uuid,
            rss_transactional_messaging_postgres::PgTransactionFault,
        )>,
    >,
    scopes: rss_mdm_scope_postgres::ScopeBinding,
    profile_validator: std::sync::Arc<dyn crate::inputs::ProfileValidator>,
    cursor_key: ring::hmac::Key,
    runtime: std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
    reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    tenant: rss_request_context::TenantId,
    policy_store: std::sync::Arc<rss_mdm_policy_postgres::PolicyStore>,
    inputs: std::sync::Arc<rss_mdm_execution_service::Inputs>,
}
/// Dependencies for this Policy application, supplied by the host.
pub struct Dependencies {
    pub profile_validator: std::sync::Arc<dyn crate::inputs::ProfileValidator>,
    pub cursor_key: Vec<u8>,
    pub runtime: std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    pub tenant: rss_request_context::TenantId,
    pub policy_store: std::sync::Arc<rss_mdm_policy_postgres::PolicyStore>,
    pub inputs: std::sync::Arc<rss_mdm_execution_service::Inputs>,
}
impl Policies {
    pub fn new(deps: Dependencies) -> Self {
        let Dependencies {
            profile_validator,
            cursor_key,
            runtime,
            reconcile_messaging,
            audit_store,
            tenant,
            policy_store,
            inputs,
        } = deps;
        Self {
            #[cfg(feature = "integration")]
            publication_fault: std::sync::Mutex::new(None),
            scopes: rss_mdm_scope_postgres::ScopeBinding::new(runtime.clone(), tenant),
            profile_validator,
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &cursor_key),
            runtime,
            reconcile_messaging,
            audit_store,
            tenant,
            policy_store,
            inputs,
        }
    }

    /// Inject transport uncertainty into this fixture's publication, after resource preparation.
    #[cfg(feature = "integration")]
    pub fn inject_publication_fault(
        &self,
        operation: Uuid,
        fault: rss_transactional_messaging_postgres::PgTransactionFault,
    ) {
        *self.publication_fault.lock().expect("publication fault") = Some((operation, fault));
    }

    pub async fn change(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        op: &crate::operation::Operation<Change>,
        audit: &RequestAudit,
    ) -> std::result::Result<rss_mdm_policy::View, Error> {
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
        let verified = if let Change::Put { definition, .. } = &op.input {
            if definition.action.resource().is_some() {
                proof.manage(Permission::ResourceRead)?;
            }
            definition.validate()?;
            authorize_policy_snapshot(proof.authorization()?, proof, definition)?;
            if matches!(definition.action, Action::TelemetryProfile { .. }) {
                None
            } else {
                self.inputs
                    .prepare_resource(PublicationInput::try_from(&definition.action)?.resource())
                    .await?
            }
        } else {
            None
        };
        #[cfg(feature = "integration")]
        {
            let mut pending = self.publication_fault.lock().expect("publication fault");
            if pending
                .as_ref()
                .is_some_and(|(operation, _)| *operation == op.operation_id)
            {
                self.runtime.inject_next_transaction_fault(
                    pending.take().expect("matched publication fault").1,
                );
            }
        }
        run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, proof, id, op, audit, verified.as_ref()),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, id, op, audit, verified) = *ctx;
                    if p.initialization_authority().is_some() {
                        crate::authorization::baseline::check_in(tx,p,Permission::PolicyWrite,&id.to_string()).await?;
                    }
                    crate::application::admit_in(tx).await?;
                    let authorization = crate::action_admission::current(tx, p).await?;
                    authorization.require(p, Permission::PolicyWrite, None)?;
                    if matches!(&op.input, Change::Put { definition, .. } if definition.action.resource().is_some()) {
                        authorization.require(p, Permission::ResourceRead, None)?;
                    }

                    s.audit_store.prepare_in(tx,audit,&[]).await?;
                    let old = checked(s.policy_store.read_for_update_in(tx, id).await?)?;
                    if let Some(previous) = &old {
                        authorize_policy_snapshot(&authorization, p, &previous.definition)?;
                    }
                    if let Change::Put { definition, .. } = &op.input {
                        authorize_policy_snapshot(&authorization, p, definition)?;
                    }
                    let hash = fingerprint(&(id, &op.input, op.expected_revision, p.actor()))?;
                    if let Some(value) = checked(
                        s.policy_store
                            .replay_in(tx, op.operation_id, &hash)
                            .await?,
                    )? {
                        return stored(serde_json::from_value(value));
                    }
                    let now = crate::action_admission::now(tx).await?;
                    let execution_binding=match &op.input { Change::Put {definition,..}=>s.inputs.software_binding_in(tx,&definition.action).await?,_=>old.as_ref().and_then(|p|p.execution_binding) };
                    let changed_policy = Policy::apply(
                        id,
                        old.as_ref(),
                        op.expected_revision,
                        &op.input,
                        Uuid::new_v4(),
                        execution_binding,
                    )?;
                    let changed = changed_policy.semantic_changed;
                    let policy = changed_policy.policy;
                    if policy.state.is_enabled() { s.inputs.admit_software_channel(&policy.definition.action)?; }
                    authorize_policy_snapshot(&authorization, p, &policy.definition)?;
                    if changed {
                        let frozen = if let Action::TelemetryProfile { resource } = &policy.definition.action {
                            telemetry::freeze(tx, resource, p, &authorization, s.profile_validator.as_ref(), policy.id, policy.version).await?
                        } else {
                        let frozen = s.inputs.publish_in(tx, &PublicationInput::try_from(&policy.definition.action)?, verified, &PublicationAuthority {
                            proof: p, snapshot: &authorization,
                            owner: rss_mdm_execution_service::configuration::Owner::Policy { policy: policy.id, version: policy.version },
                            devices: None,
                        }).await?;
                        checked_input(serde_json::to_value(frozen))?
                        };
                        storage::write_in(
                            s,
                            tx,
                            &policy,
                            &op.input,
                            Some(&frozen),
                            p,
                            now,
                        )
                        .await?;
                    } else {
                        storage::write_in(s, tx, &policy, &op.input, None, p, now)
                            .await?;
                    }
                    // Publication performs no Agent fanout. Native reconciliation is a bounded background job.
                    storage::enqueue_change_in(&s.reconcile_messaging, tx, &policy, old.as_ref()).await?;
                    let value = storage::view(&policy);
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
                    let fact = Fact::business(audit, &format!("policy:{id}:{}", op.operation_id), 200, "success", None)?.with_activity(&activity)?;
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
                        mdm_software_distribution_enabled: s
                            .inputs
                            .software_distribution()
                            .mdm_enabled,
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

pub mod source;

/// Policy publication authority, evaluated against the current locked snapshot.
pub fn authorize_policy_snapshot(
    snapshot: &rss_mdm_authorization_service::Snapshot,
    proof: &AuthorizedPrincipal,
    definition: &rss_mdm_policy::Definition,
) -> std::result::Result<(), Error> {
    snapshot.require(proof, Permission::ScopeRead, None)?;
    snapshot.require_all_devices(proof, Permission::InventoryRead)?;
    rss_mdm_execution_service::authorize_action(snapshot, proof, &definition.action)?;
    Ok(())
}
