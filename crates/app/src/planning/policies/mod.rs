//! Authored Policy is the durable authority; execution progress never edits it.
use super::action_contract::{Architecture, ExecutionInput, FrozenAction, Platform};
use super::assignment::{Behavior, Definition, Exit, Frequency, Targets};
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    transaction::*,
};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_resource as resource;
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

pub(crate) mod admission;
pub(crate) mod http;
mod preview;
pub(crate) mod reconcile;
mod rerun;
pub(crate) mod storage;

pub(crate) use rss_mdm_policy::{Change, Policy};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Frozen {
    Execution {
        action: Box<FrozenAction>,
        frequency: Frequency,
    },
    Configuration {
        enabled: bool,
        platform: Platform,
        exit: Exit,
        resource_digest: [u8; 32],
    },
}
pub(crate) struct Policies {
    pub planning: std::sync::Arc<super::Planning>,
    pub execution: std::sync::Arc<crate::execution::ExecutionService>,
}
impl Policies {
    pub(crate) async fn change(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        op: &crate::http_operation::Operation<Change>,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if id.is_nil() || op.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        proof.manage(Permission::PolicyWrite)?;
        // Verify content outside the database transaction, then bind that proof again at publication.
        let artifact = if let Change::Put { definition, .. } = &op.input {
            definition.validate()?;
            authorize(proof, definition)?;
            inspect(
                &self.planning.runtime,
                self.planning.tenant,
                (self, definition),
                |ctx, tx| {
                    Box::pin(async move {
                        let (s, d) = *ctx;
                        let version = s.resource_in(tx, &d.resource).await?;
                        let variant = variant(&version, &d.resource)?;
                        Ok(match variant.declaration() {
                            resource::Declaration::Script { artifact, .. } => {
                                Some(artifact.clone())
                            }
                            _ => None,
                        })
                    })
                },
                TransactionOwner::Planning,
            )
            .await?
        } else {
            None
        };
        let verified = if let Some(artifact) = &artifact {
            Some(
                self.execution
                    .content
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .verify(artifact)
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
                    let old = storage::read_in(tx, id).await?;
                    if let Some(previous) = &old {
                        authorize_snapshot(&authorization, p, &previous.definition)?;
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
                    authorize_snapshot(&authorization, p, &policy.definition)?;
                    if changed {
                        let frozen = s.freeze_in(tx, &policy.definition, verified).await?;
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
                    if let Targets::Scope { id: scope } = policy.definition.targets {
                        crate::automation::jobs::enqueue_job_in(
                            tx,
                            Uuid::new_v4(),
                            &crate::automation::JobInput::Scope { scope },
                        )
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
    pub(crate) async fn resource_in(
        &self,
        tx: &mut PgTransaction<'_>,
        binding: &super::assignment::ResourceBinding,
    ) -> Result<resource::Version> {
        let (version, state, _) = self
            .planning
            .catalog
            .lock_version_in(
                tx,
                &checked_input(resource::Id::new(&binding.id))?,
                &checked_input(resource::Id::new(&binding.version))?,
            )
            .await?;
        if state != resource::State::Active {
            return Err(Error::Conflict.into());
        }
        Ok(version)
    }
    pub(crate) async fn freeze_in(
        &self,
        tx: &mut PgTransaction<'_>,
        definition: &Definition,
        verified: Option<&crate::content::Verified>,
    ) -> Result<Frozen> {
        let version = self.resource_in(tx, &definition.resource).await?;
        let v = variant(&version, &definition.resource)?;
        match (&definition.behavior, v.declaration()) {
            (
                Behavior::Execution {
                    parameters,
                    schedule,
                    frequency,
                    run_lifetime_seconds,
                },
                resource::Declaration::Script {
                    artifact,
                    definition: script,
                },
            ) => {
                if self.execution.signer.is_none() || !verified.is_some_and(|v| v.matches(artifact))
                {
                    return Err(Error::Conflict.into());
                }
                checked_input(script.validate_parameters(parameters))?;
                if artifact.length() > 16_777_216 {
                    return Err(Error::Malformed.into());
                }
                if script.spec().profile == resource::ScriptProfile::OsqueryInfoV1
                    && artifact.digest()
                        != resource::Digest::of(b"SELECT version FROM osquery_info;\n")
                {
                    return Err(Error::Malformed.into());
                }
                Ok(Frozen::Execution {
                    action: Box::new(FrozenAction {
                        input: ExecutionInput {
                            platform: definition.resource.platform.clone(),
                            architecture: definition.resource.architecture.clone(),
                            parameters: parameters.clone(),
                            schedule: schedule.clone(),
                            run_lifetime_seconds: *run_lifetime_seconds,
                        },
                        definition: script.clone(),
                        resource_digest: version.digest().bytes(),
                        artifact_reference: artifact.reference().as_str().into(),
                        content: rss_mdm_agent_wire::TaskContent {
                            length: artifact.length(),
                            sha256: artifact.digest().bytes(),
                        },
                    }),
                    frequency: *frequency,
                })
            }
            (
                Behavior::Configuration { exit },
                resource::Declaration::Configuration { remove, .. },
            ) => {
                if matches!(exit, Exit::Remove) && remove.is_none() {
                    return Err(Error::Unsupported.into());
                }
                let tenant = tx.tenant_id().to_string();
                let resource = definition.resource.id.clone();
                let version_id = definition.resource.version.clone();
                let enabled=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query_scalar::<_,bool>("SELECT enabled FROM mdm_planning.firewall_resources WHERE tenant_id=$1::uuid AND resource=$2 AND version=$3")
                        .bind(tenant).bind(resource).bind(version_id).fetch_optional(c).await
                })).await?.ok_or(Error::Unsupported)?;
                Ok(Frozen::Configuration {
                    enabled,
                    platform: definition.resource.platform.clone(),
                    exit: *exit,
                    resource_digest: version.digest().bytes(),
                })
            }
            _ => Err(Error::Malformed.into()),
        }
    }
}
pub(crate) fn authorize_snapshot(
    snapshot: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    definition: &Definition,
) -> std::result::Result<(), Error> {
    let permission = match definition.behavior {
        Behavior::Execution { .. } => Permission::ScriptExecute,
        Behavior::Configuration { .. } => Permission::FirewallWrite,
    };
    match &definition.targets {
        Targets::Scope { .. } => {
            snapshot.require(proof, Permission::ScopeRead, None)?;
            snapshot.require_all_devices(proof, permission)?;
        }
        Targets::Devices { devices } => {
            for device in devices {
                snapshot.require(proof, permission, Some(device))?;
            }
        }
    }
    Ok(())
}
pub(crate) fn authorize(
    proof: &AuthorizedPrincipal,
    definition: &Definition,
) -> std::result::Result<(), Error> {
    let permission = match definition.behavior {
        Behavior::Execution { .. } => Permission::ScriptExecute,
        Behavior::Configuration { .. } => Permission::FirewallWrite,
    };
    match &definition.targets {
        Targets::Scope { .. } => {
            proof.manage(Permission::ScopeRead)?;
            proof.require_all_devices(permission)
        }
        Targets::Devices { devices } => {
            for device in devices {
                proof.require(permission, Some(device))?;
            }
            Ok(())
        }
    }
}
pub(crate) fn variant<'a>(
    version: &'a resource::Version,
    binding: &super::assignment::ResourceBinding,
) -> Result<&'a resource::Variant> {
    checked_input(version.resolve(
        match binding.platform {
            Platform::Windows => resource::Platform::Windows,
            Platform::Macos => resource::Platform::MacOS,
        },
        match binding.architecture {
            Architecture::X86_64 => resource::Architecture::X86_64,
            Architecture::Aarch64 => resource::Architecture::Aarch64,
        },
        &checked_input(resource::Id::new(&binding.variant))?,
    ))
}
