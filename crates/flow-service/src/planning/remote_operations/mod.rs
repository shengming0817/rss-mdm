//! One accepted operation owns one immutable target snapshot, without creating a Policy.
use super::policies::Policies;
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    transaction::*,
};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_execution_service::frozen::Frozen;
use rss_mdm_policy::{Action as PolicyAction, Exit, Frequency, ResourceBinding};
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

pub mod directory;
pub mod storage;
/// Explicit one-shot targets, distinct from a persistent Policy's Scope reference.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Targets {
    Scope {
        id: Uuid,
    },
    Devices {
        devices: std::collections::BTreeSet<String>,
    },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Execute { parameters: Value },
    ApplyConfiguration,
    CollectNative,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Input {
    pub operation_id: Uuid,
    pub resource: ResourceBinding,
    pub targets: Targets,
    pub action: Action,
    pub deadline: i64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Snapshot {
    Devices {
        devices: std::collections::BTreeSet<String>,
    },
    Scope {
        scope: Uuid,
        result: Uuid,
        definition_revision: i64,
        resolution_revision: i64,
    },
}
#[derive(Clone)]
pub struct Remote {
    pub id: Uuid,
    pub frozen: Frozen,
    pub deadline: i64,
    pub cancelled: bool,
    pub staged: bool,
    pub snapshot: Snapshot,
}
impl Input {
    fn validate(&self, now: i64) -> std::result::Result<(), Error> {
        if self.operation_id.is_nil()
            || self.deadline < now.saturating_add(60)
            || self.deadline > now.saturating_add(604800)
        {
            return Err(Error::Malformed);
        }
        self.resource.validate()?;
        if serde_json::to_vec(self)
            .map_err(|_| Error::Malformed)?
            .len()
            > 4_194_304
        {
            return Err(Error::Malformed);
        }
        match &self.targets {
            Targets::Scope { id } if id.is_nil() => return Err(Error::Malformed),
            Targets::Devices { devices }
                if devices
                    .iter()
                    .any(|d| d.is_empty() || d.len() > 256 || d.chars().any(char::is_control)) =>
            {
                return Err(Error::Malformed);
            }
            _ => (),
        }
        if self.resource.exact().is_none() {
            return Err(Error::Malformed);
        }
        self.schedule(now).validate()?;
        Ok(())
    }
    fn schedule(&self, now: i64) -> rss_mdm_policy::schedule::Schedule {
        rss_mdm_policy::schedule::Schedule {
            trigger: rss_mdm_policy::schedule::Trigger::Once { at: now },
            misfire: Default::default(),
            not_before: now,
            until: Some(self.deadline),
            jitter_seconds: 0,
            window: None,
        }
    }
    fn permission(&self) -> Permission {
        match self.action {
            Action::Execute { .. } => Permission::ScriptExecute,
            Action::ApplyConfiguration => Permission::ConfigurationWrite,
            Action::CollectNative => Permission::InventoryCollect,
        }
    }
    fn authorize(&self, proof: &AuthorizedPrincipal) -> std::result::Result<(), Error> {
        match &self.targets {
            Targets::Scope { .. } => {
                proof.manage(Permission::ScopeRead)?;
                proof
                    .require_all_devices(self.permission())
                    .map_err(Error::from)
            }
            Targets::Devices { devices } => {
                for d in devices {
                    proof.require(self.permission(), Some(d))?;
                }
                Ok(())
            }
        }
    }
    fn authorize_snapshot(
        &self,
        auth: &crate::authorization::Snapshot,
        proof: &AuthorizedPrincipal,
    ) -> std::result::Result<(), Error> {
        match &self.targets {
            Targets::Scope { .. } => {
                auth.require(proof, Permission::ScopeRead, None)?;
                auth.require_all_devices(proof, self.permission())
                    .map_err(Error::from)
            }
            Targets::Devices { devices } => {
                for d in devices {
                    auth.require(proof, self.permission(), Some(d))?;
                }
                Ok(())
            }
        }
    }
}

impl Policies {
    pub async fn create_remote(
        &self,
        proof: &AuthorizedPrincipal,
        input: &Input,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        proof.manage(Permission::ResourceRead)?;
        input.validate(input.deadline.saturating_sub(60))?;
        input.authorize(proof)?;
        let artifact = if matches!(input.action, Action::Execute { .. }) {
            None
        } else {
            inspect(
                &self.planning.runtime,
                self.planning.tenant,
                (self, input),
                |ctx, tx| {
                    Box::pin(async move {
                        let version = ctx
                            .0
                            .planning
                            .catalog
                            .active_version_in(tx, ctx.1.resource.id(), ctx.1.resource.version())
                            .await?;
                        Ok(
                            match super::policies::variant(&version, &ctx.1.resource)?.declaration()
                            {
                                rss_mdm_resource::Declaration::Configuration { artifact } => {
                                    Some((
                                        artifact.clone(),
                                        rss_mdm_content_service::StorageClass::NativeConfiguration,
                                    ))
                                }
                                rss_mdm_resource::Declaration::Script { artifact, .. }
                                | rss_mdm_resource::Declaration::NativeCollection {
                                    artifact,
                                    ..
                                } => Some((
                                    artifact.clone(),
                                    rss_mdm_content_service::StorageClass::Artifact,
                                )),
                                _ => None,
                            },
                        )
                    })
                },
                TransactionOwner::Planning,
            )
            .await?
        };
        let verified = if let Action::Execute { parameters } = &input.action {
            Some(
                self.planning
                    .catalog
                    .verify_script(&input.resource, parameters, self.execution.content.as_ref())
                    .await?,
            )
        } else if let Some((a, class)) = &artifact {
            Some(
                self.execution
                    .content
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .verify_class(a, *class)
                    .await?,
            )
        } else {
            None
        };
        run(&self.planning.audit_store,&self.planning.runtime,self.planning.tenant,audit,(self,proof,input,audit,verified.as_ref()),|ctx,tx|Box::pin(async move {
            let (s,proof,input,audit,verified)=*ctx;
            let auth=crate::action_admission::current(tx,proof).await?;
            auth.require(proof,Permission::ResourceRead,None)?;
            input.authorize_snapshot(&auth,proof)?;
            crate::transaction::lock(tx).await?;
            let hash=fingerprint(&(input,proof.user()))?;
            if let Some(receipt)=super::receipts::replay(tx,audit,input.operation_id,&hash).await? {return Ok(receipt);}
            let at=crate::action_admission::now(tx).await?;
            input.validate(at)?;
            let owner=Some(rss_mdm_execution_service::configuration::Owner::Remote { operation: input.operation_id });
            let mut frozen=match &input.action {
                Action::Execute { parameters } => {
                    if s.execution.signer.is_none() { return Err(Error::Conflict.into()); }
                    let version=s.planning.catalog.active_version_in(tx,input.resource.id(),input.resource.version()).await?;
                    let prepared=crate::resource_catalog::scripts::prepare(&version,&input.resource,parameters,verified.ok_or(Error::Conflict)?)?;
                    Frozen::Execution {
                        action:Box::new(super::freeze_inputs::freeze_script_in(tx,s.planning.tenant,&prepared,
                            input.schedule(at),(input.deadline-at) as u32,
                        ).await?),
                        frequency:Frequency::OncePerVersion,
                    }
                },
                Action::CollectNative => s.freeze_in(tx,&PolicyAction::NativeCollection {
                    resource:input.resource.clone(),schedule:input.schedule(at),
                    frequency:Frequency::OncePerVersion,run_lifetime_seconds:(input.deadline-at) as u32,
                },verified,owner).await?,
                Action::ApplyConfiguration => s.freeze_in(tx,&PolicyAction::Configuration {
                    resource:input.resource.clone(),exit:Exit::Retain,
                },verified,owner).await?,
            };
            frozen.authorize_native(proof,&auth,match &input.targets {Targets::Devices{devices}=>Some(devices),Targets::Scope{..}=>None},&s.execution.protection,tx.tenant_id(),owner)?;
            let snapshot=s.planning.capture_remote_targets_in(tx,&input.targets).await?;
            let tenant=tx.tenant_id().to_string();let id=input.operation_id;let resource=input.resource.id().to_owned();let version=input.resource.version().to_owned();let snapshot=checked_input(serde_json::to_value(snapshot))?;let content=checked_input(serde_json::to_value(frozen))?;let deadline=input.deadline;let author=checked_input(serde_json::to_value(proof.user()))?;
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("INSERT INTO mdm_planning.remote_operations(tenant_id,id,resource,resource_version,frozen,snapshot,created_at,deadline,author) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)").bind(tenant).bind(id).bind(resource).bind(version).bind(content).bind(snapshot).bind(at).bind(deadline).bind(author).execute(c).await?;Ok(())
            })).await?;
            storage::wake_in(tx,input.operation_id).await?;
            let value=json!({"operationId":input.operation_id,"deadline":input.deadline,"statusUrl":format!("/api/v3/remote-operations/{}",input.operation_id)});
            super::receipts::receipt(tx,audit,input.operation_id,&hash,&value).await?;
            s.planning.audit_store.append_in(tx,&Fact::business(audit,&format!("remote:{}:accept",input.operation_id),&hash,202,"success",None)?,false).await?;
            proof.check_live()?;Ok(value)
        }),TransactionOwner::Planning).await
    }
}

pub mod read;
