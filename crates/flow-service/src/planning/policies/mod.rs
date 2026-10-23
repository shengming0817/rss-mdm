//! Authored Policy is the durable authority; execution progress never edits it.
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    transaction::*,
};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_policy::Action;
use rss_mdm_resource as resource;
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
    authorize_policy_snapshot,
    frozen::Frozen,
    input_preparation::{PublicationAuthority, PublicationInput},
};
pub use rss_mdm_policy::{Change, Policy};
pub struct Policies {
    cursor_key: ring::hmac::Key,
    runtime: std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
    audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    tenant: rss_request_context::TenantId,
    policy_store: std::sync::Arc<rss_mdm_policy_postgres::PolicyStore>,
    inputs: std::sync::Arc<rss_mdm_execution_service::Inputs>,
}
impl Policies {
    pub fn new(
        cursor_key: &[u8],
        runtime: std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
        audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
        tenant: rss_request_context::TenantId,
        policy_store: std::sync::Arc<rss_mdm_policy_postgres::PolicyStore>,
        inputs: std::sync::Arc<rss_mdm_execution_service::Inputs>,
    ) -> Self {
        Self {
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, cursor_key),
            runtime,
            audit_store,
            tenant,
            policy_store,
            inputs,
        }
    }

    pub async fn change(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        op: &crate::operation::Operation<Change>,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
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
            authorize_policy_snapshot(proof.authorization()?, proof, definition)
                .map_err(Error::from)?;
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
                    super::admit_in(tx).await?;
                    let authorization = crate::action_admission::current(tx, p).await?;
                    authorization.require(p, Permission::PolicyWrite, None)?;
                    if matches!(&op.input, Change::Put { definition, .. } if definition.action.resource().is_some()) {
                        authorization.require(p, Permission::ResourceRead, None)?;
                    }
                    crate::transaction::lock(tx).await?;
                    storage::lock(tx, id).await?;
                    s.audit_store.prepare_in(tx,audit,&[]).await?;
                    let hash = fingerprint(&(id, &op.input, op.expected_revision, p.actor()))?;
                    if let Some(value) = checked(
                        s.policy_store
                            .replay_in(tx, op.operation_id, &hash)
                            .await?,
                    )? {
                        return Ok(value);
                    }
                    let old = storage::read_in(s.policy_store.reader(), tx, id).await?;
                    if let Some(previous) = &old {
                        authorize_policy_snapshot(&authorization, p, &previous.definition).map_err(Error::from)?;
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
                    authorize_policy_snapshot(&authorization, p, &policy.definition).map_err(Error::from)?;
                    if changed {
                        let frozen = if let Action::TelemetryProfile { resource } = &policy.definition.action {
                            telemetry::freeze(tx, resource, p, &authorization, policy.id, policy.version).await?
                        } else {
                        let frozen = s.inputs.publish_in(tx, &PublicationInput::try_from(&policy.definition.action)?, verified, &PublicationAuthority {
                            proof: p, snapshot: &authorization,
                            owner: rss_mdm_execution_service::configuration::Owner::Policy { policy: policy.id, version: policy.version },
                            devices: None,
                        }).await?;
                        checked_input(serde_json::to_value(frozen))?
                        };
                        storage::write_in(
                            &s.policy_store,
                            tx,
                            &policy,
                            &op.input,
                            Some(&frozen),
                            p,
                            now,
                        )
                        .await?;
                    } else {
                        storage::write_in(&s.policy_store, tx, &policy, &op.input, None, p, now)
                            .await?;
                    }
                    if changed {
                        let grant=rss_mdm_authorization_service::OperationAuthority::all_devices(&authorization,p,Permission::InventoryRead)?;
                        let grant=checked_input(serde_json::to_value(grant))?;let tenant=tx.tenant_id().to_string();let version=policy.version;
                        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_planning.policy_source_grants(tenant_id,version,read_grant) VALUES($1::uuid,$2,$3)").bind(tenant).bind(version).bind(grant).execute(c).await?;Ok(())})).await?;
                    }
                    // Publication performs no Agent fanout. Native reconciliation is a bounded background job.
                    storage::enqueue_change_in(tx, &policy, old.as_ref()).await?;
                    let value = storage::view(&policy)?;
                    checked(
                        s.policy_store
                            .receipt_in(tx, op.operation_id, &hash, &value)
                            .await?,
                    )?;
                    let fact = Fact::business(
                        audit,
                        &format!("policy:{id}:{}", op.operation_id),
                        &hash,
                        200,
                        "success",
                        None,
                    )?;
                    s.audit_store.append_in(tx, &fact, false).await?;
                    p.check_live()?;
                    Ok(value)
                })
            },
            TransactionOwner::Planning,
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
    ) -> std::result::Result<Value, Error> {
        proof.manage(Permission::PolicyRead)?;
        run(&self.audit_store, &self.runtime, self.tenant, audit, (self, proof, audit), |ctx, tx| Box::pin(async move {
            let (s, p, a) = *ctx;
            crate::action_admission::current(tx, p).await?.require(p, Permission::PolicyRead, None)?;
            a.require_request_settlement();
            Ok(json!({"defaultSoftwareChannel":"agent", "mdmSoftwareDistributionEnabled":s.inputs.software_distribution().mdm_enabled}))
        }), TransactionOwner::Planning).await
    }
}
