//! Authored Policy is the durable authority; execution progress never edits it.
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    transaction::*,
};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_execution_service::action_contract::{Architecture, Platform};
use rss_mdm_policy::{Action, Definition};
use rss_mdm_resource as resource;
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

pub mod reconcile;
pub mod rerun;
pub mod storage;

use rss_mdm_execution_service::{authorize_policy_snapshot, frozen::Frozen};
pub use rss_mdm_policy::{Change, Policy};
pub struct Policies {
    pub planning: std::sync::Arc<super::Planning>,
    pub inputs: std::sync::Arc<rss_mdm_execution_service::Inputs>,
}
impl Policies {
    pub async fn change(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        op: &crate::operation::Operation<Change>,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if id.is_nil() || op.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        proof.manage(Permission::PolicyWrite)?;
        // Verify content outside the database transaction, then bind that proof again at publication.
        let artifact = if let Change::Put { definition, .. } = &op.input {
            if definition.action.resource().is_some() {
                proof.manage(Permission::ResourceRead)?;
            }
            definition.validate()?;
            authorize_policy_snapshot(proof.authorization()?, proof, definition)
                .map_err(Error::from)?;
            if matches!(definition.action, Action::Execution { .. }) {
                None
            } else {
                inspect(
                    &self.planning.runtime,
                    self.planning.tenant,
                    (self, definition),
                    |ctx, tx| {
                        Box::pin(async move {
                            let (s, d) = *ctx;
                            let Some(binding) = d.action.resource() else {
                                return Ok(None);
                            };
                            let version = s
                                .planning
                                .catalog
                                .active_version_in(tx, binding.id(), binding.version())
                                .await?;
                            if matches!(
                                d.action,
                                Action::Software { .. } | Action::EnsureAgentInstalled { .. }
                            ) {
                                if binding.software().is_none()
                                    || version.kind() != resource::Kind::Software
                                {
                                    return Err(Error::Malformed.into());
                                }
                                Ok(None)
                            } else {
                                let variant = variant(&version, binding)?;
                                Ok(match variant.declaration() {
                                    resource::Declaration::Configuration { artifact } => Some((
                                        artifact.clone(),
                                        rss_mdm_content_service::StorageClass::NativeConfiguration,
                                    )),
                                    resource::Declaration::Script { artifact, .. }
                                    | resource::Declaration::NativeCollection {
                                        artifact, ..
                                    } => Some((
                                        artifact.clone(),
                                        rss_mdm_content_service::StorageClass::Artifact,
                                    )),
                                    _ => None,
                                })
                            }
                        })
                    },
                    TransactionOwner::Planning,
                )
                .await?
            }
        } else {
            None
        };
        let verified = if let Change::Put { definition, .. } = &op.input
            && let Action::Execution {
                resource,
                parameters,
                ..
            } = &definition.action
        {
            Some(
                self.inputs
                    .verify_script(resource, parameters, self.inputs.content.as_ref())
                    .await?,
            )
        } else if let Some((artifact, class)) = &artifact {
            Some(
                self.inputs
                    .content
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .verify_class(artifact, *class)
                    .await?,
            )
        } else {
            None
        };
        run(
            &self.planning.audit_store,
            &self.planning.runtime,
            self.planning.tenant,
            audit,
            (self, proof, id, op, audit, verified.as_ref()),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, id, op, audit, verified) = *ctx;
                    let authorization = crate::action_admission::current(tx, p).await?;
                    authorization.require(p, Permission::PolicyWrite, None)?;
                    if matches!(&op.input, Change::Put { definition, .. } if definition.action.resource().is_some()) {
                        authorization.require(p, Permission::ResourceRead, None)?;
                    }
                    crate::transaction::lock(tx).await?;
                    storage::lock(tx, id).await?;
                    let hash = fingerprint(&(id, &op.input, op.expected_revision, p.user()))?;
                    if let Some(value) = checked(
                        s.planning
                            .policy_store
                            .replay_in(tx, op.operation_id, &hash)
                            .await?,
                    )? {
                        return Ok(value);
                    }
                    let old = storage::read_in(s.planning.policy_store.reader(), tx, id).await?;
                    if let Some(previous) = &old {
                        authorize_policy_snapshot(&authorization, p, &previous.definition).map_err(Error::from)?;
                    }
                    let now = crate::action_admission::now(tx).await?;
                    let changed_policy = Policy::apply(
                        id,
                        old.as_ref(),
                        op.expected_revision,
                        &op.input,
                        Uuid::new_v4(),
                    )?;
                    let semantic = changed_policy.semantic.to_vec();
                    let changed = changed_policy.semantic_changed;
                    let policy = changed_policy.policy;
                    authorize_policy_snapshot(&authorization, p, &policy.definition).map_err(Error::from)?;
                    if changed {
                        let mut frozen = if matches!(policy.definition.action, Action::EnsureAgentInstalled { .. }) {
                            Frozen::AgentInstall { action: Box::new(s.inputs.freeze_agent_in(tx,p,&authorization,&policy.definition.action).await?) }
                        } else if matches!(policy.definition.action, Action::RequestMdmEnrollment { .. }) {
                            if !s.inputs.signing_enabled { return Err(Error::Unsupported.into()); }
                            Frozen::MdmEnrollment { action: Box::new(rss_mdm_execution_service::enrollment_preparation::freeze(p, &authorization, &policy.definition.action, &s.inputs.enrollment_entries)?) }
                        } else { s.inputs
                            .freeze_in(
                                tx,
                                &policy.definition.action,
                                verified,
                                Some(rss_mdm_execution_service::configuration::Owner::Policy { policy: policy.id, version: policy.version }),
                            )
                            .await? };
                        frozen.authorize_native(p,&authorization,None,&s.inputs.protection,tx.tenant_id(),Some(rss_mdm_execution_service::configuration::Owner::Policy { policy: policy.id, version: policy.version }))?;
                        storage::write_in(
                            &s.planning.policy_store,
                            tx,
                            &policy,
                            Some((&frozen, &semantic)),
                            p,
                            now,
                        )
                        .await?;
                    } else {
                        storage::write_in(&s.planning.policy_store, tx, &policy, None, p, now)
                            .await?;
                    }
                    // Publication performs no Agent fanout. Native reconciliation is a bounded background job.
                    storage::enqueue_change_in(tx, &policy, old.as_ref()).await?;
                    let value = storage::view(&policy)?;
                    checked(
                        s.planning
                            .policy_store
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
                    s.planning.audit_store.append_in(tx, &fact, false).await?;
                    p.check_live()?;
                    Ok(value)
                })
            },
            TransactionOwner::Planning,
        )
        .await
    }
}

pub fn variant<'a>(
    version: &'a resource::Version,
    binding: &rss_mdm_policy::ResourceBinding,
) -> Result<&'a resource::Variant> {
    let exact = binding.exact().ok_or(Error::Malformed)?;
    checked_input(version.resolve(
        match exact.platform {
            Platform::Windows => resource::Platform::Windows,
            Platform::Macos => resource::Platform::MacOS,
        },
        match exact.architecture {
            Architecture::X86_64 => resource::Architecture::X86_64,
            Architecture::Aarch64 => resource::Architecture::Aarch64,
        },
        &checked_input(resource::Id::new(&exact.variant))?,
    ))
}

pub mod read;
