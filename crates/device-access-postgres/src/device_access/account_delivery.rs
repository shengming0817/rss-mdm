//! Windows RSS-factor execution over the current DA device certificate.
use super::{Binding, Origin, participants::AccessRecovery, storage};
use crate::{Error, Service, database::db, delivery, recovery::AccessMaterials, service::Change};
use rss_mdm_agent_wire::{DeviceId, da, runtime as w};
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_authorization_service::{OperationAuthority, Permission, context::AuthorizedPrincipal};
use rss_mdm_device_access::State;
use rss_mdm_install_support::StorageProfile;
use rss_mdm_registration_service::{DevicePrincipal, device::endpoints};
use rss_mdm_task_state::{Execution, RunState};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Da {
        installation: Uuid,
        epoch: Uuid,
    },
    Agent {
        agent: delivery::Agent,
        revision: i64,
        epoch: Uuid,
    },
}

async fn mapping(
    c: &mut PgConnection,
    b: &Binding,
) -> Result<Option<(i64, delivery::Agent)>, Error> {
    let row=sqlx::query("SELECT revision,agent_installation,agent_device FROM rss_da.agent_delivery WHERE tenant_id=$1 AND da_device=$2 AND enabled")
        .bind(b.tenant).bind(b.device.into_uuid()).fetch_optional(c).await.map_err(db)?;
    row.map(|r| {
        Ok((
            r.try_get("revision").map_err(db)?,
            delivery::Agent {
                installation: r.try_get("agent_installation").map_err(db)?,
                device: crate::database::device_id(r.try_get("agent_device").map_err(db)?)
                    .map_err(db)?,
            },
        ))
    })
    .transpose()
}
async fn agent_epoch(
    c: &mut PgConnection,
    b: &Binding,
    agent: &delivery::Agent,
) -> Result<Uuid, Error> {
    sqlx::query_scalar("SELECT epoch FROM mdm_access.devices WHERE tenant_id=$1 AND id=$2 AND state='active' AND retirement IS NULL")
        .bind(b.tenant).bind(agent.device.into_uuid()).fetch_optional(c).await.map_err(db)?.ok_or(Error::Forbidden)
}
pub(super) async fn select(
    c: &mut PgConnection,
    b: &Binding,
    installation: Uuid,
    has_custody: bool,
) -> Result<Option<Target>, Error> {
    // A change can only clean or update the endpoint which owned the preceding execution.
    if b.state == State::Revoked || b.account_delivery.is_some() {
        if b.state != State::Revoked
            && matches!(b.account_delivery, Some(Target::Da { .. }))
            && !has_custody
        {
            return Err(Error::Unsupported);
        }
        return Ok(b.account_delivery.clone());
    }
    if b.intent.platform() != w::TaskPlatform::Windows
        || !b
            .configuration
            .windows
            .accounts()
            .contains(&w::AccessWindowsKind::Local)
        || b.account.as_ref().is_some_and(|a| !local(a))
    {
        return Ok(None);
    }
    if let Some((revision, agent)) = mapping(c, b).await? {
        if delivery::for_binding_on(c, b).await?.as_ref() != Some(&agent) {
            return Err(Error::Forbidden);
        }
        let epoch = agent_epoch(c, b, &agent).await?;
        return Ok(Some(Target::Agent {
            agent,
            revision,
            epoch,
        }));
    }
    if !has_custody {
        return Err(Error::Unsupported);
    }
    let epoch = endpoints::current_da_epoch_in(c, &b.tenant.to_string(), &b.device).await?;
    Ok(Some(Target::Da {
        installation,
        epoch,
    }))
}
fn local(a: &w::AccessAccount) -> bool {
    matches!(
        a,
        w::AccessAccount::Windows {
            authority: w::AccessWindowsAuthority::Local,
            ..
        }
    )
}
pub(crate) async fn agent(
    c: &mut PgConnection,
    b: &Binding,
) -> Result<Option<delivery::Agent>, Error> {
    match &b.account_delivery {
        Some(Target::Da { .. }) => Ok(None),
        Some(Target::Agent {
            agent,
            revision,
            epoch,
        }) => {
            if mapping(c, b).await? != Some((*revision, agent.clone())) {
                return Ok(None);
            }
            let current = delivery::for_binding_on(c, b).await?;
            if current.as_ref() != Some(agent) || agent_epoch(c, b, agent).await? != *epoch {
                return Ok(None);
            }
            Ok(current)
        }
        None => delivery::for_binding_on(c, b).await,
    }
}
#[derive(Serialize, Deserialize)]
struct Frozen {
    installation: Uuid,
    epoch: Uuid,
    authority: Option<OperationAuthority>,
}
pub(super) async fn accept(
    c: &mut PgConnection,
    b: &Binding,
    actor: Option<&AuthorizedPrincipal>,
    expected_epoch: i64,
) -> Result<(), Error> {
    let Some(Target::Da {
        installation,
        epoch,
    }) = b.account_delivery
    else {
        return Ok(());
    };
    let authority = match actor {
        Some(p) => Some(OperationAuthority::from_proof(
            &super::service::grants(c, p).await?,
            p,
            &b.device,
            Permission::AccountWrite,
        )?),
        None if matches!(b.origin, Origin::SelfEnrollment) => None,
        None => return Err(Error::Forbidden),
    };
    let target = Frozen {
        installation,
        epoch,
        authority,
    };
    let now = crate::platform_sso::store::now(c).await?;
    // An offline cleanup remains queued; a finite execution permit starts only after receipt.
    let deadline = i64::MAX;
    let mut state = RunState::new(deadline, now).map_err(|_| Error::Corrupt)?;
    if b.state == State::Revoked && b.account.is_none() {
        let started: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM rss_da.access_runs WHERE tenant_id=$1 AND binding_id=$2
               AND da_target->>'epoch'=$3 AND state->>'startedAt' IS NOT NULL
               AND access_binding->>'state'<>'revoked')",
        )
        .bind(b.tenant)
        .bind(b.id)
        .bind(epoch.to_string())
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
        if !started {
            state.cancel();
        }
    }
    sqlx::query("INSERT INTO rss_da.access_runs(expected_epoch,tenant_id,id,policy_version,origin,access_binding,device,occurrence,created_at,available_at,deadline,state,da_target) VALUES($1,$2,$3,$4,'\"human\"',$5,$6,$7,$8,$8,$9,$10,$11)")
        .bind(expected_epoch).bind(b.tenant).bind(Uuid::new_v4()).bind(b.policy_version).bind(sqlx::types::Json(b))
        .bind(b.device.into_uuid()).bind(format!("device-access:{}:{}",b.id,b.revision)).bind(now).bind(deadline)
        .bind(sqlx::types::Json(state)).bind(sqlx::types::Json(target)).execute(c).await.map_err(db)?;
    Ok(())
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Journal {
    start: Option<w::AccessTaskSpec>,
    native_observed: bool,
    prepared: Option<w::AccessAccount>,
    custody: Option<w::CredentialReceipt>,
}
struct Run {
    id: Uuid,
    binding: Binding,
    state: RunState,
    journal: Journal,
    target: Frozen,
}
impl Run {
    fn offer(&self) -> Result<da::AccountOffer, Error> {
        Ok(da::AccountOffer {
            operation_id: self.binding.operation_id,
            task_id: self.id,
            attempt_id: self.state.attempt().ok_or(Error::Corrupt)?,
            binding_id: self.binding.id,
            definition_digest: self.binding.definition_digest()?,
        })
    }
    async fn authorize(&self, c: &mut PgConnection, now: i64) -> Result<Binding, Error> {
        if let Some(authority) = &self.target.authority
            && !authority
                .valid(StorageProfile::Da, c, Permission::AccountWrite, now)
                .await?
        {
            return Err(Error::Forbidden);
        }
        let b = storage::locked_in(c, self.binding.tenant, self.binding.id).await?;
        if b.definition_digest()? != self.binding.definition_digest()? {
            return Err(Error::Conflict);
        }
        // Only the explicit unbind disposition remains actionable after the binding is revoked.
        if b.state != State::Revoked {
            super::lifecycle::require_subject_on(c, b.tenant, &b.person).await?;
            let tenant = rss_request_context::TenantId::parse(&b.tenant.to_string())
                .map_err(|_| Error::Corrupt)?;
            let policy =
                super::execution::admission::policy_on(tenant, c, b.tenant, &b.device, b.policy)
                    .await?;
            if !policy.configuration.enabled
                || policy.version != b.policy_version
                || policy.configuration != b.configuration
            {
                return Err(Error::Forbidden);
            }
            if matches!(b.origin, Origin::SelfEnrollment) && !b.configuration.self_enrollment {
                return Err(Error::Forbidden);
            }
        }
        Ok(b)
    }
    async fn save(&self, c: &mut PgConnection) -> Result<(), Error> {
        let n=sqlx::query("UPDATE rss_da.access_runs SET state=$3,da_journal=$4 WHERE tenant_id=$1 AND id=$2 AND da_target IS NOT NULL")
            .bind(self.binding.tenant).bind(self.id).bind(sqlx::types::Json(&self.state)).bind(sqlx::types::Json(&self.journal)).execute(c).await.map_err(db)?.rows_affected();
        if n != 1 {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
// Acquire authorizing sources in deterministic order before the common device fence.
async fn candidates(
    c: &mut PgConnection,
    s: &Service,
    p: &DevicePrincipal,
    id: Option<Uuid>,
) -> Result<Vec<(Uuid, sqlx::types::Json<Frozen>)>, Error> {
    let tenant = p.tenant().to_string();
    let hints: Vec<(Uuid, sqlx::types::Json<Frozen>)> = sqlx::query_as(
        "SELECT r.id,r.da_target FROM rss_da.access_runs r
         JOIN rss_da.bindings b ON (b.tenant_id,b.id)=(r.tenant_id,r.binding_id)
         WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.da_target IS NOT NULL
           AND (r.id=$3 OR ($3 IS NULL AND b.revision=(r.access_binding->>'revision')::bigint
               AND (b.state<>'revoked' OR b.account IS NOT NULL)
               AND r.state->>'execution' IN ('not_started','running','unknown')))
         ORDER BY r.da_target#>>'{authority,source}', (r.state->>'execution'='not_started') DESC,
                  r.created_at,r.id LIMIT 129",
    )
    .bind(&tenant)
    .bind(p.device().into_uuid())
    .bind(id)
    .fetch_all(&mut *c)
    .await
    .map_err(db)?;
    if hints.len() > 128 {
        return Err(Error::Capacity);
    }
    for (_, target) in &hints {
        if let Some(authority) = &target.authority {
            authority.lock_source(c).await?;
        }
    }
    delivery::lock_da_target(c, &tenant, p.device(), None).await?;
    crate::reports::admit(c, s, p, None).await?;
    Ok(hints)
}
async fn load_run(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    id: Uuid,
    target: Frozen,
) -> Result<Run, Error> {
    let tenant = p.tenant().to_string();
    if target.epoch != p.epoch() || target.installation != p.installation() {
        return Err(Error::Forbidden);
    }
    let row=sqlx::query("SELECT access_binding,state,da_journal FROM rss_da.access_runs WHERE tenant_id=$1::uuid AND id=$2 AND device=$3 AND da_target IS NOT NULL FOR UPDATE")
        .bind(&tenant).bind(id).bind(p.device().into_uuid()).fetch_one(c).await.map_err(db)?;
    Ok(Run {
        id,
        target,
        binding: row
            .try_get::<sqlx::types::Json<Binding>, _>("access_binding")
            .map_err(db)?
            .0,
        state: row
            .try_get::<sqlx::types::Json<RunState>, _>("state")
            .map_err(db)?
            .0,
        journal: row
            .try_get::<sqlx::types::Json<Journal>, _>("da_journal")
            .map_err(db)?
            .0,
    })
}
impl Service {
    pub async fn claim_account(
        &self,
        p: &DevicePrincipal,
        a: &RequestAudit,
    ) -> Result<Option<da::AccountOffer>, Error> {
        a.identify_device(p.device());
        self.write(a, (self, p), |ctx, c| {
            Box::pin(async move {
                let (s, p) = *ctx;
                let hints = candidates(c, s, p, None).await?;
                let now = crate::platform_sso::store::now(c).await?;
                for (id, sqlx::types::Json(target)) in hints {
                    if target.epoch != p.epoch() || target.installation != p.installation() {
                        continue;
                    }
                    let mut run = load_run(c, p, id, target).await?;
                    match run.authorize(c, now).await {
                        Ok(_) => (),
                        Err(Error::Conflict | Error::Forbidden)
                            if run.journal.start.is_some()
                                && matches!(
                                    run.state.execution,
                                    Execution::Running | Execution::Unknown
                                ) =>
                        {
                            ()
                        }
                        Err(Error::Conflict | Error::Forbidden) => continue,
                        Err(error) => return Err(error),
                    }
                    if run.state.attempt().is_none() {
                        run.state
                            .claim(Uuid::new_v4(), now)
                            .map_err(|_| Error::Conflict)?;
                        run.save(c).await?;
                    }
                    return Ok(Change {
                        value: Some(run.offer()?),
                        replay: true,
                    });
                }
                Ok(Change {
                    value: None,
                    replay: true,
                })
            })
        })
        .await
    }
    pub async fn account_event(
        &self,
        p: &DevicePrincipal,
        id: Uuid,
        input: &da::AccountEvent,
        a: &RequestAudit,
    ) -> Result<da::AccountSettlement, Error> {
        if input.event_id.is_nil() {
            return Err(Error::Malformed);
        }
        a.identify_device(p.device());
        a.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::DeviceAccessTask,
            id,
            "da_account_event",
            AuditIntent::Management,
        );
        let key = format!("da-account:{id}:{}:{}", input.attempt_id, input.event_id);
        self.write_keyed(&self.audit,a,Some(key),(self, p, id, input), |_,_|Box::pin(async{Ok(())}), |ctx, c| {
            Box::pin(async move {
                let (s, p, id, input) = *ctx;
                let (_, sqlx::types::Json(target)) = candidates(c, s, p, Some(id))
                    .await?
                    .pop()
                    .ok_or(Error::NotFound)?;
                let mut run = load_run(c, p, id, target).await?;
                if run.state.attempt() != Some(input.attempt_id)
                    || run.binding.definition_digest()? != input.definition_digest
                {
                    return Err(Error::Conflict);
                }
                let now = crate::platform_sso::store::now(c).await?;
                use sha2::{Digest, Sha256};
                let digest: [u8; 32] =
                    Sha256::digest(serde_json::to_vec(input).map_err(|_| Error::Malformed)?).into();
                let grant = matches!(
                    input.event,
                    da::AccountObservation::Received | da::AccountObservation::NotStarted{..}
                );
                let old=sqlx::query("SELECT digest,permit_until,receipt FROM rss_da.account_events WHERE tenant_id=$1 AND run=$2 AND event=$3")
                    .bind(run.binding.tenant).bind(id).bind(input.event_id).fetch_optional(&mut *c).await.map_err(db)?;
                if let Some(old)=old {
                    if old.try_get::<Vec<u8>,_>("digest").map_err(db)? != digest {
                        return Err(Error::Conflict);
                    }
                    let receipt = old.try_get::<Option<sqlx::types::Json<w::CredentialReceipt>>,_>("receipt").map_err(db)?.map(|v|v.0);
                    let issued=old.try_get::<Option<i64>,_>("permit_until").map_err(db)?;
                    let permit = if grant
                        && run.state.execution == Execution::Running
                        && run
                            .journal
                            .start
                            .as_ref()
                            .is_some_and(|t| Some(t.expires_at)==issued && t.expires_at > now)
                    {
                        run.authorize(c, now).await?;
                        run.journal.start.clone()
                    } else {
                        None
                    };
                    return Ok(Change {
                        value: da::AccountSettlement {
                            event_id: input.event_id,
                            permit,
                            receipt,
                        },
                        replay: true,
                    });
                }
                let (binding,current)=match run.authorize(c,now).await {
                    Ok(b)=>(b,true),
                    Err(Error::Forbidden|Error::Conflict) if run.journal.start.is_some()
                        && matches!(run.state.execution,Execution::Running|Execution::Unknown)
                        && matches!(input.event,da::AccountObservation::Prepared(_)|da::AccountObservation::Result(_)) => {
                        let latest=storage::locked_in(c,run.binding.tenant,run.binding.id).await?;
                        if matches!(input.event,da::AccountObservation::Prepared(_))
                            && latest.definition_digest()?!=input.definition_digest
                            && !(latest.state==State::Revoked && latest.generation==run.binding.generation+1
                                 && latest.intent==run.binding.intent && latest.created_by_rss && latest.account.is_none()){
                            return Err(Error::Conflict);
                        }
                        let mut frozen=run.binding.clone();
                        if frozen.account.is_none(){frozen.account=run.journal.prepared.clone();}
                        (frozen,false)
                    }
                    Err(e)=>return Err(e),
                };
                let materials=AccessMaterials::for_device(s.recovery.clone(),p);
                let receipt=run.observe(c,&materials,input,&binding,now,current).await?;
                run.journal.native_observed |= !grant;
                let permit_until=run.journal.start.as_ref().filter(|_|grant).map(|t|t.expires_at);
                sqlx::query("INSERT INTO rss_da.account_events(tenant_id,run,event,digest,permit_until,receipt) VALUES($1,$2,$3,$4,$5,$6)")
                    .bind(binding.tenant).bind(id).bind(input.event_id).bind(digest.as_slice()).bind(permit_until)
                    .bind(receipt.as_ref().map(sqlx::types::Json)).execute(&mut *c).await.map_err(db)?;
                run.save(c).await?;
                Ok(Change {
                    value: da::AccountSettlement {
                        event_id: input.event_id,
                        permit: if grant { run.journal.start } else { None },
                        receipt,
                    },
                    replay: false,
                })
            })
        })
        .await
    }
}

impl Run {
    async fn observe(
        &mut self,
        c: &mut PgConnection,
        materials: &AccessMaterials,
        input: &da::AccountEvent,
        b: &Binding,
        now: i64,
        current: bool,
    ) -> Result<Option<w::CredentialReceipt>, Error> {
        use da::AccountObservation as E;
        if matches!(input.event, E::Received) {
            if self.journal.start.is_some() || self.state.execution != Execution::NotStarted {
                return Err(Error::Conflict);
            }
            // A single authenticated DA recipient can acknowledge its durable offer after reconnecting.
            self.state = RunState::new(now + 300, now).map_err(|_| Error::Corrupt)?;
            self.state
                .claim(input.attempt_id, now)
                .and_then(|()| self.state.received(input.attempt_id, now))
                .and_then(|()| self.state.start(input.attempt_id, now))
                .map_err(|_| Error::Conflict)?;
            storage::received_in(
                c,
                b.tenant,
                b.id,
                b.generation,
                b.revision,
                input.definition_digest,
            )
            .await?;
            let windows = if b.state == State::Revoked {
                None
            } else {
                Some(materials.plan(c, b, now).await?)
            };
            let spec = super::execution::admission::task_spec(
                b,
                b.device,
                w::TaskArchitecture::X86_64,
                super::execution::storage::TaskIssue {
                    run: self.id,
                    attempt: input.attempt_id,
                    permit: w::TaskPermit::Start,
                    expiry: self.state.deadline,
                },
                self.state.deadline,
                windows,
            )?;
            spec.validate().map_err(|_| Error::Corrupt)?;
            self.journal.start = Some(spec);
            return Ok(None);
        }
        if !matches!(
            self.state.execution,
            Execution::Running | Execution::Unknown
        ) {
            return Err(Error::Conflict);
        }
        if let E::NotStarted { expires_at } = input.event {
            let start = self.journal.start.as_mut().ok_or(Error::Conflict)?;
            if self.state.execution != Execution::Running
                || start.expires_at > now
                || start.expires_at != expires_at
                || self.journal.native_observed
            {
                return Err(Error::Conflict);
            }
            // The earlier permit has expired, and the device proved the local attempt never started.
            if b.state != State::Revoked {
                start.windows = Some(materials.plan(c, b, now).await?);
            }
            start.expires_at = now + 300;
            start.deadline = start.expires_at;
            self.state.deadline = start.deadline;
            self.state.delivery = rss_mdm_task_state::Delivery::Received {
                attempt: input.attempt_id,
                lease_until: start.deadline,
            };
            return Ok(None);
        }
        let task = self.journal.start.as_ref().ok_or(Error::Conflict)?;
        match &input.event {
            E::Received | E::NotStarted { .. } => unreachable!(),
            E::Prepared(v) => {
                if !local(&v.account)
                    || matches!(task.action, w::AccessAction::Unbind { .. })
                    || v.binding_id != b.id
                    || v.binding_generation != b.generation
                    || v.revision != b.revision
                    || v.definition_digest != task.definition_digest
                {
                    return Err(Error::Conflict);
                }
                storage::prepared_in(c, b.tenant, v).await?;
                self.journal.prepared = Some(v.account.clone());
            }
            E::Escrow(v) => {
                let mut receipts = materials.escrow(c, task, v).await?;
                let receipt = receipts.pop().ok_or(Error::Corrupt)?;
                self.journal.custody = Some(receipt.clone());
                return Ok(Some(receipt));
            }
            E::Result(v) => {
                if v.binding_id != b.id
                    || v.binding_generation != b.generation
                    || v.revision != b.revision
                    || v.definition_digest != task.definition_digest
                {
                    return Err(Error::Conflict);
                }
                v.validate_for(w::TaskPlatform::Windows)
                    .map_err(|_| Error::Malformed)?;
                match (&task.action, &v.effect) {
                    (_, w::AccessEffect::Failed { .. } | w::AccessEffect::Unknown) => (),
                    (
                        w::AccessAction::Unbind { disposition, .. },
                        w::AccessEffect::Unbound {
                            disposition: actual,
                        },
                    ) if disposition == actual => (),
                    (
                        w::AccessAction::Create { .. } | w::AccessAction::Apply { .. },
                        w::AccessEffect::Applied {
                            account,
                            windows: Some(w::AccessWindowsFacts::RssFactor(facts)),
                            ..
                        },
                    ) if local(account)
                        && facts.factor_generation == task.factor_generation
                        && b.account.as_ref() == Some(account) =>
                    {
                        if let (
                            w::AccessAction::Create { configuration, .. },
                            w::AccessEffect::Applied { role, .. },
                        ) = (&task.action, &v.effect)
                            && *role != configuration.role.unwrap_or(w::AccessRole::Standard)
                        {
                            return Err(Error::Conflict);
                        }
                        let expected = match &task.windows {
                            Some(w::AccessWindowsPlan::Initialize { .. }) => {
                                self.journal.custody.as_ref()
                            }
                            Some(w::AccessWindowsPlan::Preserve { facts }) => Some(&facts.recovery),
                            _ => None,
                        };
                        if expected != Some(&facts.recovery) {
                            return Err(Error::Conflict);
                        }
                        if current {
                            materials.settle(c, task, facts).await?;
                        }
                    }
                    _ => return Err(Error::Conflict),
                }
                if current
                    && !storage::result_in(
                        c,
                        b.tenant,
                        self.id,
                        input.attempt_id,
                        input.event_id,
                        v,
                        true,
                    )
                    .await?
                {
                    return Err(Error::Conflict);
                }
                if current && matches!(v.effect, w::AccessEffect::Unbound { .. }) {
                    let stopped:Vec<Uuid>=sqlx::query_scalar(
                        "SELECT id FROM rss_da.access_runs WHERE tenant_id=$1 AND binding_id=$2 AND device=$3
                         AND da_target->>'epoch'=$4 AND da_target->>'installation'=$5
                         AND (access_binding->>'generation')::bigint<$6 AND state->>'execution' IN ('running','unknown')"
                    ).bind(b.tenant).bind(b.id).bind(b.device.into_uuid()).bind(self.target.epoch.to_string())
                     .bind(self.target.installation.to_string()).bind(b.generation).fetch_all(&mut *c).await.map_err(db)?;
                    rss_mdm_recovery_credentials::tasks::device::retire_unbound(
                        c,
                        b.tenant,
                        b.device,
                        b.id,
                        b.generation,
                        (self.target.installation, self.target.epoch),
                        &stopped,
                    )
                    .await
                    .map_err(crate::recovery::error)?;
                    materials
                        .unbound(c, b.tenant, b.id, b.generation, b.revision)
                        .await?;
                }
                let success = v
                    .effect
                    .complete(&b.configuration, w::TaskPlatform::Windows);
                let unresolved = materials
                    .unresolved(
                        c,
                        task,
                        if current {
                            super::participants::BindingDisposition::Current
                        } else {
                            super::participants::BindingDisposition::Withdrawn
                        },
                        if current {
                            !success
                        } else {
                            !matches!(v.effect, w::AccessEffect::Unknown)
                        },
                    )
                    .await?;
                if unresolved || matches!(v.effect, w::AccessEffect::Unknown) {
                    self.state.uncertain_result(input.attempt_id)
                } else {
                    self.state.result(input.attempt_id, success)
                }
                .map_err(|_| Error::Conflict)?;
                sqlx::query("UPDATE rss_da.access_runs SET result=$3 WHERE tenant_id=$1 AND id=$2 AND da_target IS NOT NULL")
                    .bind(b.tenant).bind(self.id).bind(sqlx::types::Json(v)).execute(c).await.map_err(db)?;
            }
        }
        Ok(None)
    }
}

/// Progress for one management receipt, including earlier revisions after a later change.
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub operation_id: Uuid,
    pub binding_id: Uuid,
    pub revision: i64,
    pub task_id: Option<Uuid>,
    pub received: bool,
    pub execution: Execution,
    pub effect: Option<w::AccessEffect>,
    pub cleanup_pending: bool,
}
impl Service {
    pub async fn account_progress(
        &self,
        actor: &AuthorizedPrincipal,
        device: &DeviceId,
        id: Uuid,
    ) -> Result<Progress, Error> {
        self.read_with_session(actor, (actor,device,id), |ctx,c| {
            Box::pin(async move {
                let (actor,device,id)=*ctx;
                let b=super::service::operation_on(c,actor,device,id).await?;
                let row=sqlx::query(
                    "SELECT id,state,result FROM rss_da.access_runs WHERE tenant_id=$1 AND binding_id=$2
                     AND access_binding->>'operationId'=$3 AND access_binding->>'revision'=$4
                     ORDER BY created_at DESC,id DESC LIMIT 1"
                )
                .bind(b.tenant).bind(b.id).bind(id.to_string()).bind(b.revision.to_string())
                .fetch_optional(&mut *c).await.map_err(db)?;
                let mut progress=Progress{
                    operation_id:id,binding_id:b.id,revision:b.revision,task_id:None,
                    received:false,execution:Execution::NotStarted,effect:None,
                    cleanup_pending:b.state==State::Revoked,
                };
                if let Some(row)=row{
                    let mut state=row.try_get::<sqlx::types::Json<RunState>,_>("state").map_err(db)?.0;
                    state.expire(crate::platform_sso::store::now(c).await?);
                    progress.task_id=Some(row.try_get("id").map_err(db)?);
                    progress.execution=state.execution;
                    progress.cleanup_pending &= state.cancellation!=rss_mdm_task_state::Cancellation::Confirmed;
                    progress.received=matches!(state.delivery,rss_mdm_task_state::Delivery::Received{..});
                    progress.effect=row.try_get::<Option<sqlx::types::Json<w::AccessResult>>,_>("result")
                        .map_err(db)?.map(|r|r.0.effect);
                    if matches!(progress.effect,Some(w::AccessEffect::Unbound{..}|w::AccessEffect::WhfbRetired{..})){
                        progress.cleanup_pending=false;
                    }
                }
                Ok(progress)
            })
        }).await
    }
}
