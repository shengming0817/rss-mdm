//! One accepted operation owns one immutable target snapshot, without creating a Policy.
//! Scope freeze: #2623 must resolve whether to retire this entrypoint or retain a defined scope.
//! Until it is complete, do not extend actions, target semantics, scheduling, authorization uses
//! or execution branches (including software). Existing fixes and required wire updates remain
//! permitted; completion permits only changes within the approved scope.
use crate::ExecutionService;
use crate::frozen::Frozen;
use crate::input_preparation::{
    PublicationAuthority, PublicationInput, ResourcePreparation, ScriptParameters,
};
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    transaction::*,
};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_policy::{ExactResourceBinding, Exit, Frequency};
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

pub mod directory;
use rss_mdm_audit_integration::operation_receipts as receipts;
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
// #2623: keep this closed action set unchanged until the Remote boundary is resolved.
pub enum Action {
    Execute { parameters: Value },
    ApplyConfiguration,
    CollectNative,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Input {
    pub operation_id: Uuid,
    pub resource: ExactResourceBinding,
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

impl ExecutionService {
    pub async fn create_remote(
        &self,
        proof: &AuthorizedPrincipal,
        input: &Input,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        proof.manage(Permission::ResourceRead)?;
        input.validate(input.deadline.saturating_sub(60))?;
        input.authorize(proof)?;
        let request = match &input.action {
            Action::Execute { parameters } => ResourcePreparation::Script {
                binding: &input.resource,
                parameters: ScriptParameters::Values(parameters),
            },
            Action::ApplyConfiguration => ResourcePreparation::Configuration {
                binding: &input.resource,
            },
            Action::CollectNative => ResourcePreparation::NativeCollection {
                binding: &input.resource,
            },
        };
        let verified = self.inputs.prepare_resource(Some(request)).await?;
        run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,input,audit,verified.as_ref()),|ctx,tx|Box::pin(async move {
            let (s,proof,input,audit,verified)=*ctx;
            let auth=crate::action_admission::current(tx,proof).await?;
            auth.require(proof,Permission::ResourceRead,None)?;
            input.authorize_snapshot(&auth,proof)?;
            crate::transaction::lock(tx).await?;
            let hash=fingerprint(&(input,proof.user()))?;
            if let Some(receipt)=receipts::replay(tx,audit,input.operation_id,&hash).await? {return Ok(receipt);}
            let at=crate::action_admission::now(tx).await?;
            input.validate(at)?;
            let schedule = input.schedule(at);
            let lifetime = (input.deadline-at) as u32;
            let request = match &input.action {
                Action::Execute { parameters } => PublicationInput::Script { binding: &input.resource, parameters: ScriptParameters::Values(parameters), schedule: &schedule, frequency: Frequency::OncePerVersion, lifetime },
                Action::CollectNative => PublicationInput::NativeCollection { binding: &input.resource, schedule: &schedule, frequency: Frequency::OncePerVersion, lifetime },
                Action::ApplyConfiguration => PublicationInput::Configuration { binding: &input.resource, exit: Exit::Retain },
            };
            let frozen = s.inputs.publish_in(tx, &request, verified, &PublicationAuthority {
                proof, snapshot: &auth, owner: crate::configuration::Owner::Remote { operation: input.operation_id },
                devices: match &input.targets { Targets::Devices { devices } => Some(devices), Targets::Scope { .. } => None },
            }).await?;
            let snapshot=s.capture_remote_targets_in(tx,&input.targets).await?;
            let tenant=tx.tenant_id().to_string();let id=input.operation_id;let resource=input.resource.id.as_str().to_owned();let version=input.resource.version.as_str().to_owned();let snapshot=checked_input(serde_json::to_value(snapshot))?;let content=checked_input(serde_json::to_value(frozen))?;let deadline=input.deadline;let author=checked_input(serde_json::to_value(proof.user()))?;
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("INSERT INTO mdm_planning.remote_operations(tenant_id,id,resource,resource_version,frozen,snapshot,created_at,deadline,author) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)").bind(tenant).bind(id).bind(resource).bind(version).bind(content).bind(snapshot).bind(at).bind(deadline).bind(author).execute(c).await?;Ok(())
            })).await?;
            storage::wake_in(tx,input.operation_id).await?;
            let value=json!({"operationId":input.operation_id,"deadline":input.deadline,"statusUrl":format!("/api/v1/remote-operations/{}",input.operation_id)});
            receipts::receipt(tx,audit,input.operation_id,&hash,&value).await?;
            s.audit_store.append_in(tx,&Fact::business(audit,&format!("remote:{}:accept",input.operation_id),&hash,202,"success",None)?,false).await?;
            proof.check_live()?;Ok(value)
        })).await
    }
}

pub mod read;
