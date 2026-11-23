//! Targeted RSS Login work uses the credential run and custody owners on the DA mTLS channel.
use super::credential_tasks;
use crate::{Binding, Coordinates, Credentials, Error, Validity, storage};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::{DeviceId, runtime as wire};
use rss_mdm_authorization_service::{OperationAuthority, Permission};
use rss_mdm_install_support::StorageProfile;
use rss_mdm_policy::CredentialOperation;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

const DA: StorageProfile = StorageProfile::Da;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Verify,
    Rotate,
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub operation_id: Uuid,
    pub binding_id: Uuid,
    pub policy_version: Uuid,
    pub binding_generation: i64,
    pub action: Action,
    /// Exact active operation to supersede or verify after its original execution stops.
    pub replaces: Option<Uuid>,
}

use rss_mdm_agent_wire::da::CredentialEvent as Event;
pub use rss_mdm_agent_wire::da::CredentialState as State;
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub received_at: Option<i64>,
    pub device: DeviceId,
    pub request: Request,
    pub state: State,
    pub receipt: Option<wire::CredentialReceipt>,
}

#[derive(Serialize, Deserialize)]
struct Frozen {
    registration_epoch: Uuid,
    installation: Uuid,
    factor_generation: i64,
    request: Request,
    authority: OperationAuthority,
    instance: String,
    actor: String,
    operation: CredentialOperation,
    predecessor: wire::CredentialReceipt,
    spec: wire::CredentialTaskSpec,
}
#[derive(Serialize, Deserialize)]
struct RecordedReceipt {
    receipt: wire::CredentialReceipt,
    applied_event: Option<[u8; 32]>,
}

fn event_digest(event: &Event) -> Result<[u8; 32], Error> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(serde_json::to_vec(event).map_err(|_| Error::Malformed)?).into())
}

pub struct Run {
    frozen: Frozen,
    anchor: Binding,
    state: State,
    receipt: Option<wire::CredentialReceipt>,
    applied_event: Option<[u8; 32]>,
    escrow_digest: Option<[u8; 32]>,
    received_at: Option<i64>,
    permit_until: i64,
}
impl Run {
    pub fn status(&self) -> Status {
        Status {
            received_at: self.received_at,
            device: self.anchor.device,
            request: self.frozen.request.clone(),
            state: self.state,
            receipt: self.receipt.clone(),
        }
    }
    /// Match the typed event against the digest committed with its original receipt.
    pub fn recorded(&self, event: &Event) -> Result<bool, Error> {
        let existing = match event {
            Event::Received {
                attempt_id,
                definition_digest,
            } => {
                if *attempt_id != self.spec().attempt_id
                    || *definition_digest != self.spec().definition_digest
                {
                    return Err(Error::Conflict);
                }
                return Ok(self.received_at.is_some());
            }
            Event::Escrow { .. } => self.escrow_digest,
            Event::Applied { .. } => self.applied_event,
        };
        match existing {
            None => Ok(false),
            Some(digest) if digest == event_digest(event)? => Ok(true),
            Some(_) => Err(Error::Conflict),
        }
    }
    pub fn matches_registration(&self, installation: Uuid, epoch: Uuid) -> bool {
        self.frozen.installation == installation && self.frozen.registration_epoch == epoch
    }
    pub fn factor_generation(&self) -> i64 {
        self.frozen.factor_generation
    }
    pub fn owned(&self, p: &rss_mdm_authorization_service::context::AuthorizedPrincipal) -> bool {
        self.frozen.actor == p.principal_id() && self.frozen.instance == p.instance_id()
    }
    pub fn operation(&self) -> &CredentialOperation {
        &self.frozen.operation
    }
    pub fn spec(&self) -> &wire::CredentialTaskSpec {
        &self.frozen.spec
    }
    pub async fn lock_authority(&self, c: &mut PgConnection) -> Result<(), Error> {
        self.frozen
            .authority
            .lock_source(c)
            .await
            .map_err(Into::into)
    }
    pub async fn authority_current(&self, c: &mut PgConnection, now: i64) -> Result<bool, Error> {
        self.frozen
            .authority
            .valid(DA, c, Permission::AccountWrite, now)
            .await
            .map_err(Into::into)
    }
    pub fn admit(&self, anchor: &Binding, policy: Uuid, version: Uuid) -> Result<(), Error> {
        if anchor != &self.anchor
            || self.spec().authorization
                != (wire::TaskAuthorization::Policy {
                    policy_id: policy,
                    policy_version: version,
                })
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
}
fn decode<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, Error> {
    serde_json::from_value(v).map_err(|_| Error::Integrity)
}
fn encode<T: Serialize>(v: &T) -> Result<serde_json::Value, Error> {
    serde_json::to_value(v).map_err(|_| Error::Malformed)
}
pub async fn load(
    c: &mut PgConnection,
    tenant: Uuid,
    device: DeviceId,
    id: Option<Uuid>,
    lock: bool,
) -> Result<Option<Run>, Error> {
    macro_rules! select_run { () => {"SELECT da_execution,material_binding,state,result,da_permit_until,da_escrow_digest,da_received_at FROM rss_da.credential_runs WHERE tenant_id=$1 AND device=$2 AND da_execution IS NOT NULL AND (id=$3 OR ($3 IS NULL AND state IN ('\"accepted\"'::jsonb,'\"pending_application\"'::jsonb)))"}; }
    let query = if lock {
        concat!(select_run!(), " FOR UPDATE")
    } else {
        select_run!()
    };
    sqlx::query(query)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(id)
        .fetch_optional(c)
        .await?
        .map(|row| {
            let recorded: Option<RecordedReceipt> = row
                .try_get::<Option<serde_json::Value>, _>("result")?
                .map(decode)
                .transpose()?;
            Ok(Run {
                applied_event: recorded.as_ref().and_then(|result| result.applied_event),
                received_at: row.try_get("da_received_at")?,
                permit_until: row.try_get("da_permit_until")?,
                escrow_digest: row
                    .try_get::<Option<Vec<u8>>, _>("da_escrow_digest")?
                    .map(|v| v.try_into().map_err(|_| Error::Integrity))
                    .transpose()?,
                frozen: decode(row.try_get("da_execution")?)?,
                anchor: decode(row.try_get("material_binding")?)?,
                state: decode(row.try_get("state")?)?,
                receipt: recorded.map(|result| result.receipt),
            })
        })
        .transpose()
}

impl Run {
    async fn transition(&self, c: &mut PgConnection, to: State) -> Result<(), Error> {
        let changed=sqlx::query("UPDATE rss_da.credential_runs SET state=$4 WHERE tenant_id=$1 AND id=$2 AND state=$3 AND da_execution IS NOT NULL")
            .bind(self.spec().tenant_id).bind(self.spec().task_id).bind(encode(&self.state)?).bind(encode(&to)?).execute(c).await?;
        if changed.rows_affected() != 1 {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub fn unresolved(&self) -> Option<wire::CredentialRecovery> {
        if let Some(original) = &self.spec().recovery {
            Some(original.clone())
        } else if self.state == State::PendingApplication
            && self.frozen.request.action == Action::Rotate
        {
            Some(wire::CredentialRecovery {
                task_id: self.spec().task_id,
                attempt_id: self.spec().attempt_id,
            })
        } else {
            None
        }
    }
    /// The replacing verifier must fence the journal of the exact original mutation.
    async fn replace(
        &self,
        c: &mut PgConnection,
        request: &Request,
    ) -> Result<Option<wire::CredentialRecovery>, Error> {
        if !matches!(self.state, State::Accepted | State::PendingApplication) {
            return Err(Error::Conflict);
        }
        let recovery = self.unresolved();
        if recovery.is_some() && request.action != Action::Verify {
            return Err(Error::Conflict);
        }
        self.transition(
            c,
            if recovery
                .as_ref()
                .is_some_and(|r| r.task_id == self.spec().task_id)
            {
                State::Reconciling
            } else {
                State::Superseded
            },
        )
        .await?;
        Ok(recovery)
    }
}
async fn release_guard(c: &mut PgConnection, id: Uuid, attempt: Uuid) -> Result<(), Error> {
    if !sqlx::query_scalar::<_, bool>("SELECT rss_da.release_targeted_credential($1,$2)")
        .bind(id)
        .bind(attempt)
        .fetch_one(c)
        .await?
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "The caller fences the authenticated actor, policy version, registration and material in one transaction"
)]
pub async fn accept(
    c: &mut PgConnection,
    credentials: &Credentials,
    p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    request: &Request,
    anchor: Binding,
    operation: CredentialOperation,
    policy: &rss_mdm_policy_postgres::device_access::CredentialPublication,
    authority: OperationAuthority,
    installation: Uuid,
    registration_epoch: Uuid,
    factor_generation: i64,
    now: i64,
) -> Result<Status, Error> {
    if credentials.profile() != DA || request.operation_id.is_nil() {
        return Err(Error::Malformed);
    }
    let tenant = Uuid::parse_str(p.tenant_id()).map_err(|_| Error::Malformed)?;
    let current = storage::current_in(credentials.custody(), c, tenant, &anchor)
        .await?
        .ok_or(Error::NotFound)?;
    if !current.current || !current.escrowed || current.validity != Validity::Verified {
        return Err(Error::Conflict);
    }
    let recipient = credentials.protection().selected_on(DA, c, tenant).await?;
    recipient.require_current(now)?;
    let recipient = wire::CredentialRecipient {
        key_id: recipient.id().into(),
        public_key: STANDARD.encode(recipient.public_key_der()?),
    };
    let subject: wire::CredentialSubject = decode(encode(&anchor.subject)?)?;
    let predecessor = wire::CredentialReceipt {
        subject: subject.clone(),
        material: current.id,
        version: current.version,
    };
    let revision = storage::revisions_in(credentials.custody(), c, tenant, &anchor.device)
        .await?
        .into_iter()
        .find(|(subject, _)| subject == &anchor.subject)
        .ok_or(Error::Conflict)?
        .1;
    let expected = vec![wire::CredentialVersion { subject, revision }];
    let active = load(c, tenant, anchor.device, None, true).await?;
    let recovery = match (request.replaces, active) {
        (None, None) => None,
        (Some(id), Some(prior)) if id == prior.spec().task_id => prior.replace(c, request).await?,
        _ => return Err(Error::Conflict),
    };
    let action = credential_tasks::operation(&operation);
    let definition_digest =
        wire::CredentialTaskSpec::digest(&action, &recipient, &expected, &recovery)
            .map_err(|_| Error::Malformed)?;
    let deadline = policy.deadline(now).ok_or(Error::Forbidden)?;
    let version = policy.version;
    let policy = policy.id;
    // The operation can wait offline. An mTLS claim issues a short-lived start permit.
    let spec = wire::CredentialTaskSpec {
        wire_version: wire::WIRE_VERSION,
        tenant_id: tenant,
        device_id: anchor.device,
        platform: wire::TaskPlatform::Windows,
        architecture: wire::TaskArchitecture::X86_64,
        task_id: request.operation_id,
        attempt_id: Uuid::new_v4(),
        permit: wire::TaskPermit::Start,
        expires_at: now,
        deadline,
        authorization: wire::TaskAuthorization::Policy {
            policy_id: policy,
            policy_version: version,
        },
        definition_digest,
        operation: action,
        recipient,
        expected,
        recovery,
    };
    spec.validate().map_err(|_| Error::Malformed)?;
    let frozen = Frozen {
        installation,
        registration_epoch,
        factor_generation,
        request: request.clone(),
        authority,
        instance: p.instance_id().into(),
        actor: p.principal_id().into(),
        operation,
        predecessor,
        spec,
    };
    let run = Run {
        frozen,
        anchor,
        state: State::Accepted,
        receipt: None,
        applied_event: None,
        escrow_digest: None,
        received_at: None,
        permit_until: 0,
    };
    let written=sqlx::query("INSERT INTO rss_da.credential_runs(expected_epoch,tenant_id,id,policy_version,origin,source_objects,material_binding,device,occurrence,created_at,available_at,deadline,state,dispatch_fingerprint,da_execution) VALUES($1,$2,$3,$4,'\"human\"','[]',$5,$6,$7,$8,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING")
        .bind(p.binding().epoch().get()).bind(tenant).bind(request.operation_id).bind(version).bind(encode(&run.anchor)?).bind(run.anchor.device.into_uuid())
        .bind(request.operation_id.to_string()).bind(now).bind(run.spec().deadline).bind(encode(&run.state)?).bind(definition_digest.as_slice()).bind(encode(&run.frozen)?)
        .execute(c).await?;
    if written.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(run.status())
}
impl Run {
    pub async fn permit(
        &self,
        c: &mut PgConnection,
        credentials: &Credentials,
        now: i64,
    ) -> Result<wire::CredentialTaskSpec, Error> {
        let mut spec = self.spec().clone();
        if self.receipt.is_none() {
            credentials
                .protection()
                .recipient(&spec.recipient.key_id)?
                .require_current(now)?;
        }
        spec.expires_at = now.saturating_add(300).min(spec.deadline);
        sqlx::query("UPDATE rss_da.credential_runs SET da_permit_until=$3 WHERE tenant_id=$1 AND id=$2 AND da_execution IS NOT NULL")
            .bind(spec.tenant_id).bind(spec.task_id).bind(spec.expires_at).execute(c).await?;
        Ok(spec)
    }
    async fn mark_received(&mut self, c: &mut PgConnection, now: i64) -> Result<(), Error> {
        if self.received_at.is_none() {
            sqlx::query("UPDATE rss_da.credential_runs SET da_received_at=$3 WHERE tenant_id=$1 AND id=$2 AND da_execution IS NOT NULL")
                .bind(self.spec().tenant_id).bind(self.spec().task_id).bind(now).execute(c).await?;
            self.received_at = Some(now);
        }
        Ok(())
    }
    pub async fn settle(
        &mut self,
        c: &mut PgConnection,
        credentials: &Credentials,
        event: &Event,
        now: i64,
    ) -> Result<(), Error> {
        if credentials.profile() != DA {
            return Err(Error::Forbidden);
        }
        if matches!(event, Event::Escrow { .. }) {
            self.mark_received(c, now).await?;
        }
        let spec = self.spec();
        if let Event::Received {
            attempt_id,
            definition_digest,
        } = event
        {
            if *attempt_id != spec.attempt_id
                || *definition_digest != spec.definition_digest
                || now >= self.permit_until
            {
                return Err(Error::Forbidden);
            }
            self.mark_received(c, now).await?;
            return Ok(());
        }
        let receipt = match event {
            Event::Received { .. } => unreachable!("received handled above"),
            Event::Escrow { attempt_id, value } => {
                if spec.attempt_id != *attempt_id
                    || value.materials.len() != 1
                    || value.definition_digest != spec.definition_digest
                    || value.materials[0].subject != spec.expected[0].subject
                    || value.materials[0].expected_revision != spec.expected[0].revision
                {
                    return Err(Error::Conflict);
                }
                if now >= self.permit_until {
                    return Err(Error::Forbidden);
                }
                if self.state != State::Accepted {
                    return Err(Error::Conflict);
                }
                credentials
                    .protection()
                    .recipient(&spec.recipient.key_id)?
                    .require_current(now)?;
                if self.frozen.request.action == Action::Rotate {
                    storage::start_agent_in(
                        credentials.custody(),
                        c,
                        spec.tenant_id,
                        self.anchor.device,
                        spec.task_id,
                        spec.attempt_id,
                    )
                    .await?;
                }
                let receipts = credential_tasks::escrow_on(
                    c,
                    credentials.custody(),
                    credentials.protection(),
                    Some(&self.anchor),
                    spec,
                    value,
                )
                .await?;
                let [candidate] = receipts.as_slice() else {
                    return Err(Error::Conflict);
                };
                if let Some(original) = &spec.recovery {
                    let prior = load(
                        c,
                        spec.tenant_id,
                        self.anchor.device,
                        Some(original.task_id),
                        true,
                    )
                    .await?
                    .ok_or(Error::Conflict)?;
                    if prior.state != State::Reconciling
                        || prior.spec().attempt_id != original.attempt_id
                        || !(candidate == &self.frozen.predecessor
                            || (prior.anchor == self.anchor
                                && prior.receipt.as_ref() == Some(candidate)))
                    {
                        return Err(Error::Conflict);
                    }
                }
                self.escrow_digest = Some(event_digest(event)?);
                self.state = State::PendingApplication;
                candidate.clone()
            }
            Event::Applied {
                attempt_id,
                definition_digest,
                receipt,
            } => {
                if spec.attempt_id != *attempt_id
                    || spec.definition_digest != *definition_digest
                    || self.receipt.as_ref() != Some(receipt)
                {
                    return Err(Error::Conflict);
                }
                if self.state != State::PendingApplication {
                    return Err(Error::Conflict);
                }
                let coordinates = Coordinates {
                    profile: DA,
                    tenant: spec.tenant_id,
                    material: receipt.material,
                    binding: self.anchor.clone(),
                    version: receipt.version,
                };
                if self.frozen.request.action == Action::Rotate {
                    storage::verify_in(credentials.custody(), c, &coordinates, spec.task_id)
                        .await?;
                } else if let Some(original) = &spec.recovery {
                    let previous = load(
                        c,
                        spec.tenant_id,
                        self.anchor.device,
                        Some(original.task_id),
                        true,
                    )
                    .await?
                    .ok_or(Error::Conflict)?;
                    if previous.state != State::Reconciling
                        || previous.spec().attempt_id != original.attempt_id
                    {
                        return Err(Error::Conflict);
                    }
                    let outcome = if previous.anchor == self.anchor {
                        let state = if previous.receipt.as_ref() == Some(receipt) {
                            State::Applied
                        } else if &previous.frozen.predecessor == receipt {
                            State::Unchanged
                        } else {
                            return Err(Error::Conflict);
                        };
                        storage::reconcile_in(
                            credentials.custody(),
                            c,
                            &coordinates,
                            original.task_id,
                        )
                        .await?;
                        state
                    } else {
                        // Current generation was independently verified after the old journal stopped.
                        if receipt != &self.frozen.predecessor {
                            return Err(Error::Conflict);
                        }
                        let old = previous.receipt.as_ref().ok_or(Error::Integrity)?;
                        let updated=sqlx::query("UPDATE rss_da.recovery_versions SET validity='revoked',pending=false,invalidated_at=$5 WHERE tenant_id=$1 AND entry=$2 AND version=$3 AND operation=$4 AND pending")
                            .bind(spec.tenant_id).bind(old.material).bind(old.version).bind(original.task_id).bind(now).execute(&mut *c).await?;
                        if updated.rows_affected() != 1 {
                            return Err(Error::Conflict);
                        }
                        State::Retired
                    };
                    previous.transition(c, outcome).await?;
                    release_guard(c, original.task_id, original.attempt_id).await?;
                } else {
                    let current =
                        storage::current_in(credentials.custody(), c, spec.tenant_id, &self.anchor)
                            .await?
                            .ok_or(Error::Conflict)?;
                    if current.id != receipt.material
                        || current.version != receipt.version
                        || current.validity != Validity::Verified
                    {
                        return Err(Error::Conflict);
                    }
                }
                self.applied_event = Some(event_digest(event)?);
                self.state = State::Applied;
                receipt.clone()
            }
        };
        self.receipt = Some(receipt.clone());
        let result = RecordedReceipt {
            receipt,
            applied_event: self.applied_event,
        };
        sqlx::query("UPDATE rss_da.credential_runs SET state=$3,result=$4,da_escrow_digest=$5 WHERE tenant_id=$1 AND id=$2 AND da_execution IS NOT NULL")
            .bind(self.spec().tenant_id).bind(self.spec().task_id).bind(encode(&self.state)?).bind(encode(&result)?).bind(self.escrow_digest.as_ref().map(|v|v.as_slice())).execute(&mut *c).await?;
        if self.state == State::Applied && self.frozen.request.action == Action::Rotate {
            release_guard(c, self.spec().task_id, self.spec().attempt_id).await?;
        }
        Ok(())
    }
}

/// The authenticated device confirmed removal of this binding and stopped its older factor journals.
pub async fn retire_unbound(
    c: &mut PgConnection,
    tenant: Uuid,
    device: DeviceId,
    binding: Uuid,
    generation: i64,
    registration: (Uuid, Uuid),
    stopped: &[Uuid],
) -> Result<(), Error> {
    let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM rss_da.credential_runs WHERE tenant_id=$1 AND device=$2 AND da_execution->'request'->>'bindingId'=$3 AND (da_execution->'request'->>'bindingGeneration')::bigint<$4 AND da_execution->>'installation'=$5 AND da_execution->>'registration_epoch'=$6 AND state IN ('\"accepted\"','\"pending_application\"','\"reconciling\"') ORDER BY id FOR UPDATE")
        .bind(tenant).bind(device.into_uuid()).bind(binding.to_string()).bind(generation).bind(registration.0.to_string()).bind(registration.1.to_string()).fetch_all(&mut *c).await?;
    for id in ids {
        let run = load(c, tenant, device, Some(id), true)
            .await?
            .ok_or(Error::Integrity)?;
        run.transition(c, State::Retired).await?;
        if run.frozen.request.action == Action::Rotate
            && let Some(receipt) = run.receipt
        {
            sqlx::query("UPDATE rss_da.recovery_versions SET pending=false,validity='revoked',invalidated_at=COALESCE(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1 AND entry=$2 AND version=$3 AND operation=$4 AND pending")
                .bind(tenant).bind(receipt.material).bind(receipt.version).bind(id).execute(&mut *c).await?;
            release_guard(c, id, run.frozen.spec.attempt_id).await?;
        }
    }
    // Original account journals were stopped by the same authenticated cleanup.
    sqlx::query(
        "UPDATE rss_da.recovery_versions v SET pending=false
        FROM rss_da.recovery_entries e,rss_da.recovery_agent_materials m
        WHERE (v.tenant_id,v.entry)=(e.tenant_id,e.id)
          AND (m.tenant_id,m.entry,m.version)=(v.tenant_id,v.entry,v.version)
          AND e.tenant_id=$1 AND e.device=$2 AND e.subject->>'kind'='rss_login'
          AND e.subject->>'binding'=$3 AND (e.subject->>'bindingGeneration')::bigint<$4
          AND m.task=ANY($5) AND v.operation=m.task AND v.pending",
    )
    .bind(tenant)
    .bind(device.into_uuid())
    .bind(binding.to_string())
    .bind(generation)
    .bind(stopped)
    .execute(c)
    .await?;
    Ok(())
}
