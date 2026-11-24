//! Local account execution over the current DA device certificate.
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
            && b.intent.platform() == w::TaskPlatform::Windows
            && !has_custody
        {
            return Err(Error::Unsupported);
        }
        return refresh_target(c, b).await;
    }
    let mac_create = matches!(
        b.intent,
        super::AccountIntent::Create {
            platform: w::TaskPlatform::Macos,
            ..
        }
    ) && matches!(b.origin, Origin::Administrator { .. });
    if !mac_create
        && (b.intent.platform() != w::TaskPlatform::Windows
            || !b
                .configuration
                .windows
                .accounts()
                .contains(&w::AccessWindowsKind::Local)
            || b.account.as_ref().is_some_and(|a| !local(a)))
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
    if !mac_create && !has_custody {
        return Err(Error::Unsupported);
    }
    let epoch = endpoints::current_da_epoch_in(c, &b.tenant.to_string(), &b.device).await?;
    Ok(Some(Target::Da {
        installation,
        epoch,
    }))
}
/// A new management revision may use fresh authorization for the same physical recipient.
pub(super) async fn refresh_target(
    c: &mut PgConnection,
    b: &Binding,
) -> Result<Option<Target>, Error> {
    if let Some(Target::Agent { agent, epoch, .. }) = &b.account_delivery
        && let Some((revision, current)) = mapping(c, b).await?
        && &current == agent
        && delivery::for_binding_on(c, b).await?.as_ref() == Some(agent)
        && agent_epoch(c, b, agent).await? == *epoch
    {
        return Ok(Some(Target::Agent {
            agent: current,
            revision,
            epoch: *epoch,
        }));
    }
    Ok(b.account_delivery.clone())
}
/// Under the DA device fence, a late UID may already belong to a different live binding.
async fn has_other_owner(
    c: &mut PgConnection,
    b: &Binding,
    account: &w::AccessAccount,
) -> Result<bool, Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_da.bindings WHERE tenant_id=$1 AND device=$2 AND id<>$3 AND state<>'revoked' AND account=$4)")
        .bind(b.tenant).bind(b.device.into_uuid()).bind(b.id).bind(sqlx::types::Json(account))
        .fetch_one(c).await.map_err(db)
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
    if b.intent.platform() == w::TaskPlatform::Macos
        && b.state != State::Revoked
        && (!matches!(b.intent, super::AccountIntent::Create { .. }) || b.account.is_some())
    {
        return Ok(());
    }
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
    let mut journal = Journal::default();
    if b.state == State::Revoked
        && let Some(account @ w::AccessAccount::Macos { .. }) = &b.account
        && storage::cleanup_owns_account(c, b, account, Some(b.id)).await?
    {
        // An earlier unlink already owns this UID. Keep this disposition visibly unfulfilled.
        journal.cleanup_conflict = true;
        state.execution = Execution::Failed;
    } else if b.state == State::Revoked && b.account.is_none() {
        let previous: Option<(Uuid, Option<sqlx::types::Json<da::AccountResult>>, bool)> =
            sqlx::query_as(
                "SELECT id,result,COALESCE((da_journal->>'uid_conflict')::boolean,false) FROM rss_da.access_runs WHERE tenant_id=$1 AND binding_id=$2
               AND da_target->>'epoch'=$3 AND da_target->>'installation'=$4
               AND (access_binding->>'generation')::bigint=$5 AND state->>'startedAt' IS NOT NULL
               AND access_binding->>'state'<>'revoked' AND state->>'cancellation'<>'confirmed'
               ORDER BY (access_binding->>'revision')::bigint DESC LIMIT 1",
            )
            .bind(b.tenant)
            .bind(b.id)
            .bind(epoch.to_string())
            .bind(installation.to_string())
            .bind(b.generation - 1)
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?;
        match previous.and_then(|(id, result, conflict)| {
            (!conflict).then(|| (id, result.map(|value| value.0.effect)))
        }) {
            Some((_, Some(da::AccountEffect::MacAccountCreated { generated_uid, .. }))) => {
                // A completed Create can predate this unlink while its policy was withdrawn.
                let mut cleanup = b.clone();
                let account = w::AccessAccount::Macos { generated_uid };
                if storage::cleanup_owns_account(c, b, &account, Some(b.id)).await? {
                    journal.cleanup_conflict = true;
                    state.execution = Execution::Failed;
                } else {
                    cleanup.account = Some(account);
                    storage::save_in(c, &cleanup, b.revision).await?;
                }
            }
            Some((_, Some(da::AccountEffect::Access(w::AccessEffect::Failed { .. }))))
                if b.intent.platform() == w::TaskPlatform::Macos =>
            {
                state.cancel()
            }
            Some((id, _)) => journal.awaiting_create = Some(id),
            None => state.cancel(),
        }
    }
    sqlx::query("INSERT INTO rss_da.access_runs(expected_epoch,tenant_id,id,policy_version,origin,access_binding,device,occurrence,created_at,available_at,deadline,state,da_target,da_journal) VALUES($1,$2,$3,$4,'\"human\"',$5,$6,$7,$8,$8,$9,$10,$11,$12)")
        .bind(expected_epoch).bind(b.tenant).bind(Uuid::new_v4()).bind(b.policy_version).bind(sqlx::types::Json(b))
        .bind(b.device.into_uuid()).bind(format!("device-access:{}:{}",b.id,b.revision)).bind(now).bind(deadline)
        .bind(sqlx::types::Json(state)).bind(sqlx::types::Json(target)).bind(sqlx::types::Json(journal)).execute(c).await.map_err(db)?;
    Ok(())
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Journal {
    awaiting_create: Option<Uuid>,
    uid_conflict: bool,
    cleanup_conflict: bool,
    renewals: u16,
    received: bool,
    unknown_observed: bool,
    failure_observed: bool,
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
        if b.state == State::Revoked
            && let Some(account @ w::AccessAccount::Macos { .. }) = &b.account
            && (self.journal.cleanup_conflict
                || has_other_owner(c, &b, account).await?
                || storage::cleanup_owns_account(c, &b, account, Some(b.id)).await?)
        {
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
    platform: Option<w::TaskPlatform>,
) -> Result<Vec<(Uuid, sqlx::types::Json<Frozen>)>, Error> {
    let tenant = p.tenant().to_string();
    let hints: Vec<(Uuid, sqlx::types::Json<Frozen>)> = sqlx::query_as(
        "SELECT r.id,r.da_target FROM rss_da.access_runs r
         JOIN rss_da.bindings b ON (b.tenant_id,b.id)=(r.tenant_id,r.binding_id)
         WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.da_target IS NOT NULL
           AND ($4::text IS NULL OR COALESCE(r.access_binding#>>'{intent,platform}',r.access_binding#>>'{intent,account,platform}')=$4)
           AND (r.id=$3 OR ($3 IS NULL AND r.state->>'cancellation'<>'confirmed' AND (
              (b.revision=(r.access_binding->>'revision')::bigint
               AND (b.state<>'revoked' OR b.account IS NOT NULL)
               AND r.state->>'execution' IN ('not_started','running','unknown'))
              OR (b.state='revoked' AND b.account IS NULL AND EXISTS (
                  SELECT FROM rss_da.access_runs u WHERE u.tenant_id=b.tenant_id AND u.binding_id=b.id
                  AND (u.access_binding->>'revision')::bigint=b.revision
                  AND u.da_journal->>'awaiting_create'=r.id::text AND u.state->>'cancellation'<>'confirmed')))))
         ORDER BY r.da_target#>>'{authority,source}', (r.state->>'execution'='not_started') DESC,
                  r.created_at,r.id LIMIT 129",
    )
    .bind(&tenant)
    .bind(p.device().into_uuid())
    .bind(id)
    .bind(platform.map(|v|match v {w::TaskPlatform::Windows=>"windows",w::TaskPlatform::Macos=>"macos"}))
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
        platform: w::TaskPlatform,
        a: &RequestAudit,
    ) -> Result<Option<da::AccountOffer>, Error> {
        a.identify_device(p.device());
        self.write(a, (self, p), move |ctx, c| {
            Box::pin(async move {
                let (s, p) = *ctx;
                let hints = candidates(c, s, p, None, Some(platform)).await?;
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
                                    Execution::Running | Execution::Unknown | Execution::Failed
                                ) => {}
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
                let (_, sqlx::types::Json(target)) = candidates(c, s, p, Some(id), None)
                    .await?
                    .pop()
                    .ok_or(Error::NotFound)?;
                let mut run = load_run(c, p, id, target).await?;
                if run.binding.definition_digest()? != input.definition_digest
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
                    let permit = if grant && run.state.attempt()==Some(input.attempt_id)
                        && run.state.execution == Execution::Running
                        && run
                            .journal
                            .start
                            .as_ref()
                            .is_some_and(|t| Some(t.expires_at)==issued && t.expires_at > now)
                    {
                        match run.authorize(c, now).await {
                            Ok(_) => run.journal.start.clone(),
                            Err(Error::Conflict | Error::Forbidden) => None,
                            Err(e) => return Err(e),
                        }
                    } else {
                        None
                    };
                    return Ok(Change {
                        value: da::AccountSettlement {
                            event_id: input.event_id,
                            issued_expires_at: issued,
                            permit,
                            receipt,
                        },
                        replay: true,
                    });
                }
                if run.state.attempt()!=Some(input.attempt_id) || run.state.cancellation == rss_mdm_task_state::Cancellation::Confirmed {
                    return Err(Error::Conflict);
                }
                let settled_absence = run.settle_absence(c,input,now).await?;
                let receipt = if settled_absence {
                    None
                } else {
                    let (binding,current)=run.event_binding(c,input,now).await?;
                    let materials=AccessMaterials::for_device(s.recovery.clone(),p);
                    let receipt=run.observe(c,&materials,input,&binding,now,current).await?;
                    run.journal.native_observed |= !grant;
                    receipt
                };
                let permit = run.journal.start.as_ref().filter(|_| grant && !settled_absence);
                let permit_until=permit.map(|t|t.expires_at);
                sqlx::query("INSERT INTO rss_da.account_events(tenant_id,run,event,digest,permit_until,receipt) VALUES($1,$2,$3,$4,$5,$6)")
                    .bind(run.binding.tenant).bind(id).bind(input.event_id).bind(digest.as_slice()).bind(permit_until)
                    .bind(receipt.as_ref().map(sqlx::types::Json)).execute(&mut *c).await.map_err(db)?;
                run.save(c).await?;
                Ok(Change {
                    value: da::AccountSettlement {
                        event_id: input.event_id,
                        issued_expires_at: permit_until,
                        permit: permit.cloned(),
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
    /// A withdrawn definition may still have changed the machine. Only matching cleanup
    /// evidence can retire the current revoked binding without granting new execution.
    async fn event_binding(
        &self,
        c: &mut PgConnection,
        input: &da::AccountEvent,
        now: i64,
    ) -> Result<(Binding, bool), Error> {
        use da::AccountObservation as E;
        match self.authorize(c, now).await {
            Ok(binding) => Ok((binding, true)),
            Err(Error::Forbidden | Error::Conflict)
                if self.journal.start.is_some()
                    && matches!(
                        self.state.execution,
                        Execution::Running | Execution::Unknown
                    )
                    && matches!(input.event, E::Prepared(_) | E::Result(_)) =>
            {
                let latest = storage::locked_in(c, self.binding.tenant, self.binding.id).await?;
                let same = latest.definition_digest()? == input.definition_digest;
                if same
                    && latest.state == State::Revoked
                    && matches!(&input.event,E::Result(r) if matches!(r.effect,da::AccountEffect::Access(w::AccessEffect::Unbound{..})))
                {
                    return Ok((latest, true));
                }
                if matches!(input.event, E::Prepared(_))
                    && !same
                    && !(latest.state == State::Revoked
                        && latest.generation == self.binding.generation + 1
                        && latest.intent == self.binding.intent
                        && latest.created_by_rss
                        && latest.account.is_none())
                {
                    return Err(Error::Conflict);
                }
                let mut frozen = self.binding.clone();
                if frozen.account.is_none() {
                    frozen.account = self.journal.prepared.clone();
                }
                Ok((frozen, false))
            }
            Err(e) => Err(e),
        }
    }

    /// An unlink may consume evidence only from the exact Create run it froze.
    async fn waiting_cleanup(
        &self,
        c: &mut PgConnection,
    ) -> Result<Option<(Uuid, RunState)>, Error> {
        let row: Option<(Uuid, sqlx::types::Json<RunState>)> = sqlx::query_as(
            "SELECT u.id,u.state FROM rss_da.access_runs u JOIN rss_da.bindings b
             ON (b.tenant_id,b.id)=(u.tenant_id,u.binding_id)
             WHERE u.tenant_id=$1 AND u.binding_id=$2 AND b.state='revoked' AND b.account IS NULL
             AND (u.access_binding->>'revision')::bigint=b.revision AND u.da_journal->>'awaiting_create'=$3
             AND u.state->>'cancellation'<>'confirmed' FOR UPDATE OF u"
        ).bind(self.binding.tenant).bind(self.binding.id).bind(self.id.to_string())
         .fetch_optional(&mut *c).await.map_err(db)?;
        Ok(row.map(|(id, state)| (id, state.0)))
    }
    async fn confirm_no_cleanup(
        c: &mut PgConnection,
        tenant: Uuid,
        id: Uuid,
        mut state: RunState,
    ) -> Result<(), Error> {
        state.cancel();
        sqlx::query("UPDATE rss_da.access_runs SET state=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(tenant)
            .bind(id)
            .bind(sqlx::types::Json(state))
            .execute(c)
            .await
            .map_err(db)?;
        Ok(())
    }
    async fn settle_absence(
        &mut self,
        c: &mut PgConnection,
        input: &da::AccountEvent,
        now: i64,
    ) -> Result<bool, Error> {
        use da::AccountObservation as E;
        let expires_at = match input.event {
            E::NotStarted { expires_at } | E::CreateAbsent { expires_at } => expires_at,
            _ => return Ok(false),
        };
        let Some(start) = self.journal.start.as_ref() else {
            return Err(Error::Conflict);
        };
        if !matches!(
            self.state.execution,
            Execution::Running | Execution::Unknown
        ) || expires_at != start.expires_at
            || expires_at > now
            || self.journal.prepared.is_some()
            || self.journal.custody.is_some()
            || (matches!(input.event, E::NotStarted { .. }) && self.journal.native_observed)
        {
            return Err(Error::Conflict);
        }
        if !matches!(start.action, w::AccessAction::Create { .. }) {
            return Ok(false);
        }
        if let Some((cleanup, state)) = self.waiting_cleanup(c).await? {
            Self::confirm_no_cleanup(c, self.binding.tenant, cleanup, state).await?;
        } else if start.platform == w::TaskPlatform::Macos {
            match self.authorize(c, now).await {
                Ok(_) if matches!(input.event, E::NotStarted { .. }) => return Ok(false),
                Ok(_) | Err(Error::Forbidden | Error::Conflict) => (),
                Err(error) => return Err(error),
            }
        } else {
            return Ok(false);
        }

        if matches!(input.event, E::NotStarted { .. }) {
            self.state.execution = Execution::NotStarted;
        } else if start.platform == w::TaskPlatform::Macos {
            self.state
                .result(input.attempt_id, false)
                .map_err(|_| Error::Conflict)?;
            // The device established absence. Keep earlier Unknown in immutable history only.
            sqlx::query("UPDATE rss_da.access_runs SET result=NULL WHERE tenant_id=$1 AND id=$2")
                .bind(self.binding.tenant)
                .bind(self.id)
                .execute(&mut *c)
                .await
                .map_err(db)?;
        }
        self.state.cancel();
        self.state
            .cancelled(input.attempt_id)
            .map_err(|_| Error::Conflict)?;
        Ok(true)
    }
    /// Creation evidence settles the original attempt even when configuration or authority changed.
    async fn mac_create_result(
        &mut self,
        c: &mut PgConnection,
        event: &da::AccountEvent,
        b: &Binding,
        result: &da::AccountResult,
        expected_role: w::AccessRole,
        current: bool,
    ) -> Result<(), Error> {
        let account = match &result.effect {
            da::AccountEffect::MacAccountCreated {
                generated_uid,
                role,
                ..
            } => {
                if generated_uid.is_nil() {
                    return Err(Error::Malformed);
                }
                let account = w::AccessAccount::Macos {
                    generated_uid: *generated_uid,
                };
                let claimed_elsewhere = storage::cleanup_owns_account(c, b, &account, Some(b.id))
                    .await?
                    || (current && has_other_owner(c, b, &account).await?);
                self.journal.uid_conflict = claimed_elsewhere;
                self.state
                    .result(
                        event.attempt_id,
                        *role == expected_role && !claimed_elsewhere,
                    )
                    .map_err(|_| Error::Conflict)?;
                (!claimed_elsewhere).then_some(account)
            }
            da::AccountEffect::Access(w::AccessEffect::Failed { .. }) => {
                self.state
                    .result(event.attempt_id, false)
                    .map_err(|_| Error::Conflict)?;
                None
            }
            da::AccountEffect::Access(w::AccessEffect::Unknown) => {
                self.state
                    .uncertain_result(event.attempt_id)
                    .map_err(|_| Error::Conflict)?;
                None
            }
            _ => return Err(Error::Conflict),
        };
        if !storage::record_result_in(
            c,
            b.tenant,
            self.id,
            event.attempt_id,
            event.event_id,
            result,
        )
        .await?
        {
            return Err(Error::Conflict);
        }
        let mut binding = storage::locked_observation_in(c, b.tenant, b.id).await?;
        let cleanup = if !current {
            self.waiting_cleanup(c).await?
        } else {
            None
        };
        if let Some(account) = account {
            if current || cleanup.is_some() {
                if binding.account.as_ref().is_some_and(|old| old != &account) {
                    return Err(Error::Conflict);
                }
                binding.account = Some(account);
                storage::save_in(c, &binding, binding.revision).await?;
            }
        } else if let Some((id, mut state)) = cleanup {
            if self.journal.uid_conflict {
                state.execution = Execution::Failed;
                sqlx::query("UPDATE rss_da.access_runs SET state=$3,da_journal=jsonb_set(da_journal-'awaiting_create','{cleanup_conflict}','true') WHERE tenant_id=$1 AND id=$2")
                    .bind(b.tenant).bind(id).bind(sqlx::types::Json(state)).execute(&mut *c).await.map_err(db)?;
            } else if matches!(
                result.effect,
                da::AccountEffect::Access(w::AccessEffect::Failed { .. })
            ) {
                Self::confirm_no_cleanup(c, b.tenant, id, state).await?;
            }
        }
        sqlx::query("UPDATE rss_da.access_runs SET result=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(b.tenant)
            .bind(self.id)
            .bind(sqlx::types::Json(result))
            .execute(&mut *c)
            .await
            .map_err(db)?;
        let phase = match self.state.execution {
            Execution::Unknown => "unknown",
            Execution::Failed => "failed",
            _ => "pending",
        };
        super::lifecycle::emit_on(c, &self.binding, None, event.event_id, phase).await?;
        Ok(())
    }
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
            let platform = b.intent.platform();
            let architecture = match platform {
                w::TaskPlatform::Macos => w::TaskArchitecture::Aarch64,
                w::TaskPlatform::Windows => w::TaskArchitecture::X86_64,
            };
            let windows = if platform == w::TaskPlatform::Macos || b.state == State::Revoked {
                None
            } else {
                Some(materials.plan(c, b, now).await?)
            };
            let spec = super::execution::admission::task_spec(
                b,
                b.device,
                architecture,
                super::execution::storage::TaskIssue {
                    run: self.id,
                    attempt: input.attempt_id,
                    permit: w::TaskPermit::Start,
                    expiry: self.state.deadline,
                },
                self.state.deadline,
                windows,
            )?;
            if platform == w::TaskPlatform::Macos
                && matches!(spec.action, w::AccessAction::Apply { .. })
            {
                return Err(Error::Conflict);
            }
            spec.validate().map_err(|_| Error::Corrupt)?;
            self.journal.received = true;
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
            // Bound receipts per attempt while keeping an offline device able to make progress.
            // Only an authenticated unused-expired proof may release this attempt for a fresh offer.
            if self.journal.renewals >= 64 {
                self.state = RunState::new(i64::MAX, now).map_err(|_| Error::Corrupt)?;
                self.journal = Journal {
                    received: true,
                    ..Journal::default()
                };
                return Ok(None);
            }
            self.journal.renewals += 1;
            // The earlier permit has expired, and the device proved the local attempt never started.
            if start.windows.is_some() {
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
            E::CreateAbsent { .. } => return Err(Error::Conflict),
            E::Prepared(v) => {
                if self.journal.prepared.is_some()
                    || !local(&v.account)
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
                if task.platform != w::TaskPlatform::Windows || self.journal.custody.is_some() {
                    return Err(Error::Conflict);
                }
                let mut receipts = materials.escrow(c, task, v).await?;
                let receipt = receipts.pop().ok_or(Error::Corrupt)?;
                self.journal.custody = Some(receipt.clone());
                return Ok(Some(receipt));
            }
            E::Result(v) => {
                let seen = match v.effect {
                    da::AccountEffect::Access(w::AccessEffect::Unknown) => {
                        Some(&mut self.journal.unknown_observed)
                    }
                    da::AccountEffect::Access(w::AccessEffect::Failed { .. }) => {
                        Some(&mut self.journal.failure_observed)
                    }
                    _ => None,
                };
                if seen.is_some_and(|flag| std::mem::replace(flag, true)) {
                    return Err(Error::Conflict);
                }
                if v.binding_id != b.id
                    || v.binding_generation != b.generation
                    || v.revision != b.revision
                    || v.definition_digest != task.definition_digest
                {
                    return Err(Error::Conflict);
                }

                if task.platform == w::TaskPlatform::Macos
                    && let w::AccessAction::Create { configuration, .. } = &task.action
                {
                    let role = configuration.role.unwrap_or(w::AccessRole::Standard);
                    self.mac_create_result(c, input, b, v, role, current)
                        .await?;
                    return Ok(None);
                }
                let da::AccountEffect::Access(effect) = &v.effect else {
                    return Err(Error::Conflict);
                };
                let v = &v.with_effect(effect.clone());
                v.validate_for(task.platform)
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
                if current
                    && task.platform == w::TaskPlatform::Windows
                    && matches!(v.effect, w::AccessEffect::Unbound { .. })
                {
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
                let success = v.effect.complete(&b.configuration, task.platform);
                let unresolved = task.platform == w::TaskPlatform::Windows
                    && materials
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
    pub effect: Option<da::AccountEffect>,
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
                    "SELECT id,state,result,COALESCE((da_journal->>'received')::boolean,false) AS issued
                     FROM rss_da.access_runs WHERE tenant_id=$1 AND binding_id=$2
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
                    progress.received=matches!(state.delivery,rss_mdm_task_state::Delivery::Received{..}) || row.try_get::<bool,_>("issued").map_err(db)?;
                    progress.effect=row.try_get::<Option<sqlx::types::Json<da::AccountResult>>,_>("result")
                        .map_err(db)?.map(|r|r.0.effect);
                }
                if progress.cleanup_pending {
                    let phases=super::lifecycle::cleanup_phases(c,actor.tenant_id(),std::slice::from_ref(&b)).await?;
                    progress.cleanup_pending=phases.get(&b.id)!=Some(&super::lifecycle::ExternalPhase::Confirmed);
                }
                Ok(progress)
            })
        }).await
    }
}
