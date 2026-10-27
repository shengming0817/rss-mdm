//! Durable lifecycle facts use the existing webhook SQL Outbox and delivery recovery.
use super::Binding;
use crate::Error;
use rss_mdm_webhook_service::{
    events,
    model::{Event, EventData, EventType},
};
use sqlx::PgConnection;
use uuid::Uuid;

pub(crate) async fn emit_on(
    c: &mut PgConnection,
    binding: &Binding,
    previous_principal: Option<Uuid>,
    event: Uuid,
    phase: &str,
) -> Result<(), Error> {
    let value = Event {
        event_id: events::identity(
            event,
            &format!("device-access:{}:{}:{phase}", binding.id, binding.revision),
        ),
        event_type: EventType::DeviceAccessChanged,
        version: 1,
        occurred_at: events::now_on(c).await.map_err(|_| Error::Storage)?,
        tenant_id: binding.tenant,
        device_id: binding.device.clone(),
        data: EventData::DeviceAccess {
            operation_id: binding.operation_id,
            binding_id: binding.id,
            registration_id: binding.registration,
            registration_generation: binding.registration_generation,
            instance_id: binding.person.instance,
            principal_id: binding.person.principal,
            previous_principal,
            binding_generation: binding.generation,
            factor_generation: binding.factor_generation,
            revision: binding.revision,
            revoked: binding.state == super::State::Revoked,
            phase: phase.into(),
        },
    };
    events::emit_on(c, &value)
        .await
        .map_err(|error| match error {
            rss_mdm_webhook_service::Error::Conflict => Error::Conflict,
            _ => Error::Storage,
        })
}

use super::{Person, State};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};

#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalPhase {
    Pending,
    Executing,
    Confirmed,
    RequiresAuthentication,
    Failed,
    Unknown,
}

/// One frozen offboarding intent. Device work stays in the existing execution owner.
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Offboarding {
    pub operation_id: Uuid,
    pub person: Person,
    pub targets: Vec<Binding>,
    pub identity: ExternalPhase,
    pub idp: Vec<IdpDisposition>,
    pub attempts: std::collections::BTreeMap<String, ExternalAttempt>,
}

/// A retained denial never disappears merely because Identity membership is re-enabled.
pub async fn require_subject_on(
    c: &mut PgConnection,
    tenant: Uuid,
    person: &Person,
) -> Result<(), Error> {
    let denied: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_access.device_access_subject_denials WHERE tenant_id=$1 AND instance=$2 AND principal=$3 AND denied)")
        .bind(tenant).bind(person.instance).bind(person.principal).fetch_one(c).await.map_err(crate::database::db)?;
    if denied {
        Err(Error::Forbidden)
    } else {
        Ok(())
    }
}

pub(super) async fn accept_offboarding_on(
    c: &mut PgConnection,
    actor: &AuthorizedPrincipal,
    current: &Binding,
    idp_fingerprints: &std::collections::BTreeMap<Uuid, String>,
) -> Result<(), Error> {
    if current.person.principal.to_string() == actor.principal_id() {
        return Err(Error::Forbidden);
    }
    require_settled_on(c, current.tenant, &current.person).await?;
    let snapshot =
        rss_mdm_authorization_service::snapshot_on(c, actor.tenant_id(), actor.instance_id())
            .await?;
    snapshot
        .require(actor, Permission::IdentityAccountsManage, None)
        .map_err(|_| Error::Forbidden)?;
    let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT document FROM mdm_access.device_access_bindings WHERE tenant_id=$1 AND instance=$2 AND principal=$3 AND id<>$4 AND state<>'revoked' ORDER BY device,id LIMIT 1024 FOR UPDATE")
        .bind(current.tenant).bind(current.person.instance).bind(current.person.principal).bind(current.id)
        .fetch_all(&mut *c).await.map_err(crate::database::db)?;
    if rows.len() > 1023 {
        return Err(Error::Capacity);
    }
    let mut targets = vec![current.clone()];
    for row in rows {
        let mut binding: Binding = serde_json::from_value(row).map_err(|_| Error::Corrupt)?;
        binding.validate()?;
        snapshot
            .require(actor, Permission::AccountWrite, Some(&binding.device))
            .map_err(|_| Error::Forbidden)?;
        crate::device::endpoints::lock_in(
            c,
            actor.tenant_id(),
            &binding.device,
            rss_mdm_inventory::Channel::Agent,
        )
        .await?;
        let revision = binding.revision;
        binding.operation_id = current.operation_id;
        binding.origin = super::Origin::Administrator {
            actor: actor.actor(),
        };
        binding.generation = binding.generation.checked_add(1).ok_or(Error::Capacity)?;
        binding.factor_generation = binding
            .factor_generation
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        binding.revision = revision.checked_add(1).ok_or(Error::Capacity)?;
        binding.state = State::Revoked;
        binding.configuration.enabled = false;
        binding.account_disposition = current.account_disposition;
        super::storage::save_in(c, &binding, revision).await?;
        emit_on(
            c,
            &binding,
            Some(binding.person.principal),
            current.operation_id,
            "accepted",
        )
        .await?;
        targets.push(binding);
    }
    sqlx::query("INSERT INTO mdm_access.device_access_subject_denials(tenant_id,instance,principal,operation,denied) VALUES($1,$2,$3,$4,true) ON CONFLICT(tenant_id,instance,principal) DO UPDATE SET operation=excluded.operation,denied=true")
        .bind(current.tenant).bind(current.person.instance).bind(current.person.principal).bind(current.operation_id)
        .execute(&mut *c).await.map_err(crate::database::db)?;
    let invalid_owner:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_enterprise.subject_versions h LEFT JOIN mdm_enterprise.subject_owners o ON(o.tenant_id,o.provider,o.subject)=(h.tenant_id,h.provider,h.document->>'subject') WHERE h.tenant_id=$1 AND h.principal=$2 AND (o.principal IS NULL OR o.principal<>h.principal))")
        .bind(current.tenant).bind(current.person.principal).fetch_one(&mut *c).await.map_err(crate::database::db)?;
    if invalid_owner {
        return Err(Error::Corrupt);
    }
    let histories:Vec<serde_json::Value>=sqlx::query_scalar("SELECT DISTINCT ON(provider,document->>'subject') document FROM mdm_enterprise.subject_versions WHERE tenant_id=$1 AND principal=$2 ORDER BY provider,document->>'subject',revision DESC LIMIT 65")
        .bind(current.tenant).bind(current.person.principal).fetch_all(&mut *c).await.map_err(crate::database::db)?;
    if histories.len() > 64 {
        return Err(Error::Capacity);
    }
    let idp = histories
        .into_iter()
        .map(|doc| {
            let identity: crate::enterprise::Subject =
                serde_json::from_value(doc).map_err(|_| Error::Corrupt)?;
            if identity.person != current.person {
                return Err(Error::Corrupt);
            }
            Ok(IdpDisposition {
                id: events::identity(identity.provider, &identity.subject),
                fingerprint: idp_fingerprints
                    .get(&identity.provider)
                    .cloned()
                    .ok_or(Error::Configuration)?,
                identity,
                account: ExternalPhase::Pending,
                sessions: ExternalPhase::Pending,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let operation = Offboarding {
        operation_id: current.operation_id,
        person: current.person.clone(),
        targets,
        identity: ExternalPhase::Pending,
        idp,
        attempts: Default::default(),
    };
    sqlx::query("INSERT INTO mdm_access.device_access_lifecycles(tenant_id,operation,actor,instance,device,document) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(current.tenant).bind(current.operation_id).bind(actor.principal_id()).bind(actor.instance_id()).bind(&current.device)
        .bind(serde_json::to_value(operation).map_err(|_|Error::Corrupt)?)
        .execute(c).await.map_err(crate::database::db)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalComponent {
    Identity,
    Idp { target: Uuid, action: IdpAction },
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdpAction {
    DisableAccount,
    RevokeSessions,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdpDisposition {
    pub id: Uuid,
    pub identity: crate::enterprise::Subject,
    pub fingerprint: String,
    pub account: ExternalPhase,
    pub sessions: ExternalPhase,
}

impl crate::agent::Service {
    pub async fn offboarding(
        &self,
        actor: &AuthorizedPrincipal,
        device: &str,
        operation: Uuid,
    ) -> Result<Offboarding, Error> {
        if actor.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.begin(actor.tenant_id()).await?;
        super::service::authorize(&mut tx, actor, device, Permission::AccountWrite).await?;
        let value = load_on(&mut tx, actor, device, operation, false).await?;
        tx.rollback().await.map_err(crate::database::db)?;
        Ok(value)
    }

    pub async fn claim_offboarding(
        &self,
        actor: &AuthorizedPrincipal,
        device: &str,
        operation: Uuid,
        component: ExternalComponent,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Option<Uuid>, Error> {
        self.transition_offboarding(
            actor,
            device,
            operation,
            component,
            Transition::Claim {
                attempt: Uuid::new_v4(),
            },
            audit,
        )
        .await
        .map(|v| v.1)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Frozen target, external component, attempt and observed outcome are independently fenced"
    )]
    pub async fn settle_offboarding(
        &self,
        actor: &AuthorizedPrincipal,
        device: &str,
        operation: Uuid,
        component: ExternalComponent,
        attempt: Uuid,
        phase: ExternalPhase,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Offboarding, Error> {
        self.transition_offboarding(
            actor,
            device,
            operation,
            component,
            Transition::Settle { attempt, phase },
            audit,
        )
        .await
        .map(|v| v.0)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Frozen target, external component, attempt and observed outcome are independently fenced"
    )]
    pub async fn observe_offboarding(
        &self,
        actor: &AuthorizedPrincipal,
        device: &str,
        operation: Uuid,
        component: ExternalComponent,
        attempt: Option<Uuid>,
        confirmed: bool,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<Offboarding, Error> {
        self.transition_offboarding(
            actor,
            device,
            operation,
            component,
            Transition::Observe { attempt, confirmed },
            audit,
        )
        .await
        .map(|v| v.0)
    }
    async fn transition_offboarding(
        &self,
        actor: &AuthorizedPrincipal,
        device: &str,
        operation: Uuid,
        component: ExternalComponent,
        transition: Transition,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<(Offboarding, Option<Uuid>), Error> {
        self.proof(actor, audit)?;
        let coordinate = serde_json::to_string(&(operation, component, transition))
            .map_err(|_| Error::Malformed)?;
        audit.operation(
            events::identity(audit.request_id(), &coordinate),
            "device_access_external_phase",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device);
        self.write_admitted(&self.access_audit,audit,(actor,device,operation,component,transition),
            |ctx,c|Box::pin(async move {super::service::admit_session(c,ctx.0).await}),
            |ctx,c|Box::pin(async move {
                let (actor,device,operation,component,transition)=ctx;
                super::service::authorize(c,actor,device,Permission::AccountWrite).await?;
                let mut value=load_on(c,actor,device,*operation,true).await?;
                let current:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_access.device_access_subject_denials WHERE tenant_id=$1::uuid AND instance=$2 AND principal=$3 AND operation=$4 AND denied)")
                    .bind(actor.tenant_id()).bind(value.person.instance).bind(value.person.principal).bind(*operation).fetch_one(&mut *c).await.map_err(crate::database::db)?;
                if !current{return Err(Error::Conflict);}
                let key=component.key();
                let phase=*value.phase_mut(*component)?;
                let previous=value.attempts.get(&key).map(|v|v.id);
                let mut next=phase;
                let mut claimed=None;
                match *transition {
                    Transition::Claim{attempt}=>{
                        if phase!=ExternalPhase::Confirmed {
                            if matches!(phase,ExternalPhase::Executing|ExternalPhase::Unknown){return Err(Error::Conflict);}
                            let now=events::now_on(c).await.map_err(|_|Error::Storage)?;
                            value.attempts.insert(key,ExternalAttempt{id:attempt,expires_at:now+45});
                            next=ExternalPhase::Executing;claimed=Some(attempt);
                        }
                    }
                    Transition::Settle{attempt,phase:result}=>{
                        if previous!=Some(attempt)||matches!(result,ExternalPhase::Pending|ExternalPhase::Executing){return Err(Error::Conflict);}
                        if phase!=ExternalPhase::Confirmed {
                            if !matches!(phase,ExternalPhase::Executing|ExternalPhase::Unknown){return Err(Error::Conflict);}
                            next=result;
                        }
                    }
                    Transition::Observe{attempt,confirmed}=>{
                        if previous!=attempt||phase==ExternalPhase::Executing{return Err(Error::Conflict);}
                        // A negative read cannot prove that a timed-out remote mutation will never commit.
                        if confirmed {next=ExternalPhase::Confirmed;}
                    }
                }
                *value.phase_mut(*component)?=next;
                sqlx::query("UPDATE mdm_access.device_access_lifecycles SET document=$3 WHERE tenant_id=$1::uuid AND operation=$2")
                    .bind(actor.tenant_id()).bind(*operation).bind(serde_json::to_value(&value).map_err(|_|Error::Corrupt)?)
                    .execute(c).await.map_err(crate::database::db)?;


                Ok(crate::agent::Change{value:(value,claimed), replay:false})
            })).await
    }
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalAttempt {
    pub id: Uuid,
    pub expires_at: i64,
}
#[derive(Clone, Copy, Serialize)]
enum Transition {
    Claim {
        attempt: Uuid,
    },
    Settle {
        attempt: Uuid,
        phase: ExternalPhase,
    },
    Observe {
        attempt: Option<Uuid>,
        confirmed: bool,
    },
}
impl ExternalComponent {
    fn key(self) -> String {
        match self {
            Self::Identity => "identity".into(),
            Self::Idp { target, action } => format!(
                "idp:{target}:{}",
                match action {
                    IdpAction::DisableAccount => "account",
                    IdpAction::RevokeSessions => "sessions",
                }
            ),
        }
    }
}
impl Offboarding {
    fn phase_mut(&mut self, component: ExternalComponent) -> Result<&mut ExternalPhase, Error> {
        match component {
            ExternalComponent::Identity => Ok(&mut self.identity),
            ExternalComponent::Idp { target, action } => {
                let idp = self
                    .idp
                    .iter_mut()
                    .find(|v| v.id == target)
                    .ok_or(Error::NotFound)?;
                Ok(match action {
                    IdpAction::DisableAccount => &mut idp.account,
                    IdpAction::RevokeSessions => &mut idp.sessions,
                })
            }
        }
    }
    pub fn attempt(&self, component: ExternalComponent) -> Option<Uuid> {
        self.attempts.get(&component.key()).map(|a| a.id)
    }
    fn in_flight(&self) -> bool {
        matches!(
            self.identity,
            ExternalPhase::Executing | ExternalPhase::Unknown
        ) || self.idp.iter().any(|v| {
            matches!(v.account, ExternalPhase::Executing | ExternalPhase::Unknown)
                || matches!(
                    v.sessions,
                    ExternalPhase::Executing | ExternalPhase::Unknown
                )
        })
    }
}
/// Rehire or replacement of an intent cannot race an unconfirmed external action.
pub(super) async fn require_settled_on(
    c: &mut PgConnection,
    tenant: Uuid,
    person: &Person,
) -> Result<(), Error> {
    let doc:Option<serde_json::Value>=sqlx::query_scalar("SELECT l.document FROM mdm_access.device_access_subject_denials d JOIN mdm_access.device_access_lifecycles l ON(l.tenant_id,l.operation)=(d.tenant_id,d.operation) WHERE d.tenant_id=$1 AND d.instance=$2 AND d.principal=$3 AND d.denied FOR UPDATE OF d,l")
        .bind(tenant).bind(person.instance).bind(person.principal).fetch_optional(c).await.map_err(crate::database::db)?;
    if let Some(doc) = doc {
        let value: Offboarding = serde_json::from_value(doc).map_err(|_| Error::Corrupt)?;
        if value.in_flight() {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

async fn load_on(
    c: &mut PgConnection,
    actor: &AuthorizedPrincipal,
    device: &str,
    operation: Uuid,
    locked: bool,
) -> Result<Offboarding, Error> {
    let sql = if locked {
        "SELECT document FROM mdm_access.device_access_lifecycles WHERE tenant_id=$1::uuid AND operation=$2 AND instance=$3 AND device=$4 FOR UPDATE"
    } else {
        "SELECT document FROM mdm_access.device_access_lifecycles WHERE tenant_id=$1::uuid AND operation=$2 AND instance=$3 AND device=$4"
    };
    let document: serde_json::Value = sqlx::query_scalar(sql)
        .bind(actor.tenant_id())
        .bind(operation)
        .bind(actor.instance_id())
        .bind(device)
        .fetch_optional(&mut *c)
        .await
        .map_err(crate::database::db)?
        .ok_or(Error::NotFound)?;
    let mut value: Offboarding = serde_json::from_value(document).map_err(|_| Error::Corrupt)?;
    if value.operation_id != operation
        || value.person.instance.to_string() != actor.instance_id()
        || value.targets.is_empty()
        || value.targets.len() > 1024
    {
        return Err(Error::Corrupt);
    }
    let snapshot =
        rss_mdm_authorization_service::snapshot_on(c, actor.tenant_id(), actor.instance_id())
            .await?;
    snapshot
        .require(actor, Permission::IdentityAccountsManage, None)
        .map_err(|_| Error::Forbidden)?;
    for binding in &value.targets {
        snapshot
            .require(actor, Permission::AccountWrite, Some(&binding.device))
            .map_err(|_| Error::Forbidden)?;
        binding.validate()?;
        if binding.tenant.to_string() != actor.tenant_id()
            || binding.person != value.person
            || binding.operation_id != operation
        {
            return Err(Error::Corrupt);
        }
    }
    let now = events::now_on(c).await.map_err(|_| Error::Storage)?;
    let mut components = vec![ExternalComponent::Identity];
    for target in &value.idp {
        components.extend([
            ExternalComponent::Idp {
                target: target.id,
                action: IdpAction::DisableAccount,
            },
            ExternalComponent::Idp {
                target: target.id,
                action: IdpAction::RevokeSessions,
            },
        ]);
    }
    for component in components {
        if value
            .attempts
            .get(&component.key())
            .is_some_and(|a| a.expires_at <= now)
            && *value.phase_mut(component)? == ExternalPhase::Executing
        {
            *value.phase_mut(component)? = ExternalPhase::Unknown;
        }
    }
    Ok(value)
}

#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetProgress {
    pub binding_id: Uuid,
    pub device: String,
    pub registration: Uuid,
    pub registration_generation: i64,
    pub revision: i64,
    pub phase: ExternalPhase,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub operation: Offboarding,
    pub devices: Vec<TargetProgress>,
    pub complete: bool,
}
impl crate::agent::Service {
    pub async fn offboarding_progress(
        &self,
        actor: &AuthorizedPrincipal,
        device: &str,
        operation: Uuid,
    ) -> Result<Progress, Error> {
        use sqlx::Row;
        let operation = self.offboarding(actor, device, operation).await?;
        let targets = operation
            .targets
            .iter()
            .map(|b| {
                Ok(serde_json::json!({
                    "id":b.id,"generation":b.generation,"revision":b.revision,
                    "digest":b.definition_digest()?,"disposition":b.account_disposition,
                    "factorGeneration":b.factor_generation,
                    "hello":b.intent.platform()==rss_mdm_agent_wire::runtime::TaskPlatform::Windows && matches!(b.configuration.windows,rss_mdm_agent_wire::runtime::AccessWindowsConfiguration::Whfb)
                }))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mut tx = self.store.begin(actor.tenant_id()).await?;
        super::service::authorize(&mut tx, actor, device, Permission::AccountWrite).await?;
        let rows=sqlx::query("SELECT (t->>'id')::uuid AS id,coalesce(bool_or(r.document#>'{effect,disposition}'=t->'disposition' AND CASE WHEN t->>'hello'='true' THEN r.document#>>'{effect,state}'='whfb_retired' AND r.document#>>'{effect,facts,policy}'='absent' AND r.document#>>'{effect,facts,registration}'='absent' AND r.document#>'{effect,facts,factorGeneration}'=t->'factorGeneration' ELSE r.document#>>'{effect,state}'='unbound' END),false) AS confirmed,coalesce(bool_or(r.document#>>'{effect,state}'='unknown'),false) AS unknown,coalesce(bool_or(r.document#>>'{effect,state}'='failed'),false) AS failed FROM jsonb_array_elements($2) t LEFT JOIN mdm_access.device_access_results r ON r.tenant_id=$1::uuid AND r.binding=(t->>'id')::uuid AND r.document->'bindingGeneration'=t->'generation' AND r.document->'revision'=t->'revision' AND r.document->'definitionDigest'=t->'digest' GROUP BY t")
            .bind(actor.tenant_id()).bind(serde_json::Value::Array(targets)).fetch_all(&mut *tx).await.map_err(crate::database::db)?;
        let mut phases = std::collections::BTreeMap::new();
        for row in rows {
            let phase = if row
                .try_get::<bool, _>("confirmed")
                .map_err(crate::database::db)?
            {
                ExternalPhase::Confirmed
            } else if row
                .try_get::<bool, _>("unknown")
                .map_err(crate::database::db)?
            {
                ExternalPhase::Unknown
            } else if row
                .try_get::<bool, _>("failed")
                .map_err(crate::database::db)?
            {
                ExternalPhase::Failed
            } else {
                ExternalPhase::Pending
            };
            phases.insert(
                row.try_get::<Uuid, _>("id").map_err(crate::database::db)?,
                phase,
            );
        }
        tx.rollback().await.map_err(crate::database::db)?;
        let devices = operation
            .targets
            .iter()
            .map(|b| TargetProgress {
                binding_id: b.id,
                device: b.device.clone(),
                registration: b.registration,
                registration_generation: b.registration_generation,
                revision: b.revision,
                phase: phases.get(&b.id).copied().unwrap_or(ExternalPhase::Unknown),
            })
            .collect::<Vec<_>>();
        let complete = operation.identity == ExternalPhase::Confirmed
            && operation.idp.iter().all(|t| {
                t.account == ExternalPhase::Confirmed && t.sessions == ExternalPhase::Confirmed
            })
            && devices.iter().all(|d| d.phase == ExternalPhase::Confirmed);
        Ok(Progress {
            operation,
            devices,
            complete,
        })
    }
}

/// Live Identity account order; reconciliation observes facts, not a frozen account snapshot.
pub static IDENTITY_RECONCILIATION: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "device_access",
    default_limit: 64,
    max_limit: 100,
    order: "Identity principal UUID ascending (live observation)",
    context: &[],
};
