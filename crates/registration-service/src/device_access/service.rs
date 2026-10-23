use super::*;
use crate::{
    agent::{Change as AuditedChange, Service},
    database::db,
    operations::{Actor, Operation},
};
use rss_mdm_agent_wire::runtime::{AccessBegin, AccessChallenge, AccessConfirm};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{
    Permission, context::AuthorizedPrincipal, session::SessionAuthority,
};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

fn tenant_uuid(tenant: rss_request_context::TenantId) -> Result<Uuid, Error> {
    Uuid::parse_str(&tenant.to_string()).map_err(|_| Error::Corrupt)
}
fn person(p: &AuthorizedPrincipal) -> Result<Person, Error> {
    p.session()?;
    Ok(Person {
        instance: Uuid::parse_str(p.instance_id()).map_err(|_| Error::Corrupt)?,
        principal: Uuid::parse_str(p.principal_id()).map_err(|_| Error::Corrupt)?,
    })
}
fn digest(value: &impl Serialize) -> Result<String, Error> {
    Ok(
        Sha256::digest(serde_json::to_vec(value).map_err(|_| Error::Malformed)?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}
fn nonce_digest(value: &rss_mdm_agent_wire::runtime::Secret) -> [u8; 32] {
    Sha256::digest(value.expose().as_bytes()).into()
}
async fn now(c: &mut PgConnection) -> Result<i64, Error> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(c)
        .await
        .map_err(db)
}
async fn authorize(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &str,
    permission: Permission,
) -> Result<(), Error> {
    p.check_live()?;
    rss_mdm_authorization_service::lock_on(c, p.tenant_id(), p.instance_id()).await?;
    rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id())
        .await?
        .require(p, permission, Some(device))
        .map_err(|_| Error::Forbidden)?;
    Ok(())
}

impl Service {
    pub async fn device_access_operation(
        &self,
        actor: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
    ) -> Result<Binding, Error> {
        if actor.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.begin(actor.tenant_id()).await?;
        authorize(&mut tx, actor, device, Permission::AccountWrite).await?;
        let result:Option<String>=sqlx::query_scalar("SELECT result FROM mdm_access.registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND instance=$3 AND operation_id=$4")
            .bind(actor.tenant_id()).bind(actor.principal_id()).bind(actor.instance_id()).bind(id).fetch_optional(&mut *tx).await.map_err(db)?;
        let binding: Uuid =
            serde_json::from_str(&result.ok_or(Error::NotFound)?).map_err(|_| Error::NotFound)?;
        let value = storage::get_in(&mut tx, tenant_uuid(self.tenant)?, binding).await?;
        if value.device != device {
            return Err(Error::NotFound);
        }
        tx.rollback().await.map_err(db)?;
        Ok(value)
    }
    /// First association only. Both authenticated device and human proofs are mandatory.
    pub async fn begin_device_access(
        &self,
        device: &crate::DevicePrincipal,
        employee: &AuthorizedPrincipal,
        input: &AccessBegin,
        admission: &dyn Admission,
        sessions: &SessionAuthority,
        audit: &RequestAudit,
    ) -> Result<AccessChallenge, Error> {
        self.proof(employee, audit)?;
        if device.tenant() != self.tenant
            || device.channel() != rss_mdm_inventory::Channel::Agent
            || input.operation_id.is_nil()
            || input.policy.is_nil()
        {
            return Err(Error::Forbidden);
        }
        let who = person(employee)?;
        let reference = employee
            .session()?
            .reference()
            .map_err(|_| Error::Unauthorized)?;
        sessions.recheck(&reference).await?;
        audit.operation(input.operation_id, "device_access_begin");
        audit.target_device(device.device());
        self.write(audit, (device, employee, input, admission, sessions, reference, who), |ctx,c| Box::pin(async move {
            let (device,employee,input,admission,sessions,reference,who) = ctx;
            crate::device::store::revalidate_management(c, device).await?;
            crate::lifecycle::require_work_in(c, employee.tenant_id(), device.device()).await?;
            let time = now(c).await?;
            if !employee.recently_authenticated(time, 300)? { return Err(Error::Unauthorized); }
            sessions.recheck(reference).await?;
            let selection = admission.policy(c, tenant_uuid(device.tenant())?, device.device(), input.policy).await?;
            if !selection.configuration.enabled || !selection.configuration.self_enrollment { return Err(Error::Forbidden); }
            let local = admission.local_session(c, device).await?;
            local.validate().map_err(|_| Error::Malformed)?;
            if !storage::first_in(c, tenant_uuid(device.tenant())?, device.device(), device.registration(), who, &local.account).await? { return Err(Error::Conflict); }
            sqlx::query("DELETE FROM mdm_access.device_access_ceremonies WHERE tenant_id=$1 AND expires_at<to_timestamp($2::bigint::double precision) AND consumed IS NULL")
                .bind(tenant_uuid(device.tenant())?).bind(time).execute(&mut *c).await.map_err(db)?;
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.device_access_ceremonies WHERE tenant_id=$1 AND device=$2")
                .bind(tenant_uuid(device.tenant())?).bind(device.device()).fetch_one(&mut *c).await.map_err(db)?;
            if count >= 128 { return Err(Error::Capacity); }
            use base64::Engine;
            let mut bytes = [0u8;32];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).map_err(|_| Error::Runtime)?;
            let nonce = rss_mdm_agent_wire::runtime::Secret::parse(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)).map_err(|_| Error::Corrupt)?;
            let expires_at = time.checked_add(120).ok_or(Error::Capacity)?;
            sqlx::query("INSERT INTO mdm_access.device_access_ceremonies(tenant_id,id,device,registration,generation,instance,principal,nonce_digest,session,policy,policy_version,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,to_timestamp($12::bigint::double precision))")
                .bind(tenant_uuid(device.tenant())?).bind(input.operation_id).bind(device.device()).bind(device.registration()).bind(device.generation())
                .bind(who.instance).bind(who.principal).bind(nonce_digest(&nonce).as_slice()).bind(serde_json::to_value(&local).map_err(|_| Error::Malformed)?)
                .bind(selection.policy).bind(selection.version).bind(expires_at).execute(c).await.map_err(|e| if e.as_database_error().is_some_and(|e| e.is_unique_violation()) { Error::Conflict } else { db(e) })?;
            Ok(AuditedChange { digest: digest(&(*input,&*who,device.registration(),&local))?, replay: false, value: AccessChallenge { id: input.operation_id, nonce, expires_at, local_session: local } })
        })).await
    }

    pub async fn confirm_device_access(
        &self,
        device: &crate::DevicePrincipal,
        employee: &AuthorizedPrincipal,
        input: &AccessConfirm,
        admission: &dyn Admission,
        sessions: &SessionAuthority,
        audit: &RequestAudit,
    ) -> Result<Binding, Error> {
        self.proof(employee, audit)?;
        if device.tenant() != self.tenant || input.operation_id.is_nil() || input.challenge.is_nil()
        {
            return Err(Error::Forbidden);
        }
        input
            .local_session
            .validate()
            .map_err(|_| Error::Malformed)?;
        let who = person(employee)?;
        let reference = employee
            .session()?
            .reference()
            .map_err(|_| Error::Unauthorized)?;
        sessions.recheck(&reference).await?;
        audit.operation(input.operation_id, "device_access_confirm");
        audit.target_device(device.device());
        self.write(audit,(device,employee,input,admission,sessions,reference,who,audit),|ctx,c|Box::pin(async move {
            let (device,employee,input,admission,sessions,reference,who,audit)=ctx;
            crate::device::store::revalidate_management(c,device).await?;
            crate::lifecycle::require_work_in(c,employee.tenant_id(),device.device()).await?;
            sessions.recheck(reference).await?;
            let hash=digest(&("device_access_confirm", input.operation_id,input.challenge,nonce_digest(&input.nonce),&input.local_session,&*who))?;
            let op=Operation { actor:Actor::from_authorized(employee),key:input.operation_id,digest:&hash };
            if let Some(old)=crate::operations::replay(c,&op).await? {
                let id:Uuid=serde_json::from_str(&old).map_err(|_|Error::Corrupt)?;
                let saved=storage::get_in(c,tenant_uuid(device.tenant())?,id).await?;
                if saved.device!=device.device() || saved.registration!=device.registration() || saved.registration_generation!=device.generation() || saved.person!=*who {return Err(Error::Forbidden);}
                return Ok(AuditedChange{value:saved,digest:hash,replay:true});
            }
            let time=now(c).await?;
            if !employee.recently_authenticated(time,300)? { return Err(Error::Unauthorized); }
            let local=admission.local_session(c,device).await?;
            if local!=input.local_session { return Err(Error::Conflict); }
            let row=sqlx::query("SELECT *,floor(extract(epoch FROM expires_at))::bigint AS expires_unix FROM mdm_access.device_access_ceremonies WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind(tenant_uuid(device.tenant())?).bind(input.challenge).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::NotFound)?;
            use subtle::ConstantTimeEq;
            let expected:Vec<u8>=row.try_get("nonce_digest").map_err(db)?;
            if !bool::from(expected.as_slice().ct_eq(&nonce_digest(&input.nonce)))
                || row.try_get::<Uuid,_>("instance").map_err(db)?!=who.instance || row.try_get::<Uuid,_>("principal").map_err(db)?!=who.principal
                || row.try_get::<Uuid,_>("registration").map_err(db)?!=device.registration() || row.try_get::<i64,_>("generation").map_err(db)?!=device.generation()
                || row.try_get::<String,_>("device").map_err(db)?!=device.device()
                || row.try_get::<serde_json::Value,_>("session").map_err(db)?!=serde_json::to_value(&local).map_err(|_|Error::Malformed)? { return Err(Error::Forbidden); }
            if row.try_get::<i64,_>("expires_unix").map_err(db)?<=time || row.try_get::<Option<Uuid>,_>("consumed").map_err(db)?.is_some() { return Err(Error::Conflict); }
            let policy:Uuid=row.try_get("policy").map_err(db)?;
            let selected=admission.policy(c,tenant_uuid(device.tenant())?,device.device(),policy).await?;
            if selected.version!=row.try_get::<Uuid,_>("policy_version").map_err(db)? || !selected.configuration.self_enrollment || !selected.configuration.enabled { return Err(Error::Forbidden); }
            if !storage::first_in(c,tenant_uuid(device.tenant())?,device.device(),device.registration(),who,&local.account).await? {return Err(Error::Conflict);}
            let binding=Binding{id:Uuid::new_v4(),tenant:tenant_uuid(device.tenant())?,device:device.device().into(),registration:device.registration(),registration_generation:device.generation(),person:who.clone(),origin:Origin::SelfEnrollment,generation:1,revision:1,state:State::Pending,intent:AccountIntent::Existing{account:local.account.clone()},account:Some(local.account),policy:selected.policy,policy_version:selected.version,configuration:selected.configuration,received_revision:None,applied_revision:None,effect:None,created_by_rss:false};
            storage::insert_in(c,&binding).await?;
            sqlx::query("UPDATE mdm_access.device_access_ceremonies SET consumed=$3 WHERE tenant_id=$1 AND id=$2").bind(binding.tenant).bind(input.challenge).bind(binding.id).execute(&mut *c).await.map_err(db)?;
            crate::operations::save(c,&op,&serde_json::to_string(&binding.id).map_err(|_|Error::Corrupt)?,audit).await?;
            Ok(AuditedChange{value:binding,digest:hash,replay:false})
        })).await
    }

    pub async fn device_access_bindings(
        &self,
        actor: &AuthorizedPrincipal,
        device: &str,
        after: Option<Uuid>,
    ) -> Result<Vec<Binding>, Error> {
        if actor.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.begin(actor.tenant_id()).await?;
        authorize(&mut tx, actor, device, Permission::AccountWrite).await?;
        let out = storage::page_in(&mut tx, tenant_uuid(self.tenant)?, device, after).await?;
        tx.rollback().await.map_err(db)?;
        Ok(out)
    }

    pub async fn change_device_access(
        &self,
        actor: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        input: &Change,
        admission: &dyn Admission,
        audit: &RequestAudit,
    ) -> Result<Binding, Error> {
        self.proof(actor, audit)?;
        person(actor)?;
        if input.operation_id.is_nil() || id.is_nil() || input.expected_revision < 0 {
            return Err(Error::Malformed);
        }
        actor.require(Permission::AccountWrite, Some(device))?;
        audit.operation(input.operation_id, "device_access_change");
        audit.target_device(device);
        self.write(
            audit,
            (actor, device, id, input, admission, audit),
            |ctx, c| {
                Box::pin(async move {
                    let (actor, device, id, input, admission, audit) = ctx;
                    authorize(c, actor, device, Permission::AccountWrite).await?;
                    let tenant = Uuid::parse_str(actor.tenant_id()).map_err(|_| Error::Corrupt)?;
                    crate::lifecycle::require_work_in(c, actor.tenant_id(), device).await?;
                    crate::device::endpoints::lock_in(
                        c,
                        actor.tenant_id(),
                        device,
                        rss_mdm_inventory::Channel::Agent,
                    )
                    .await?;
                    let registration = crate::device::endpoints::current_in(
                        c,
                        actor.tenant_id(),
                        device,
                        rss_mdm_inventory::Channel::Agent,
                    )
                    .await?
                    .ok_or(Error::Conflict)?;
                    let hash = digest(&("device_access_change", *device, *id, *input))?;
                    let op = Operation {
                        actor: Actor::from_authorized(actor),
                        key: input.operation_id,
                        digest: &hash,
                    };
                    if let Some(old) = crate::operations::replay(c, &op).await? {
                        let binding: Uuid =
                            serde_json::from_str(&old).map_err(|_| Error::Corrupt)?;
                        return Ok(AuditedChange {
                            value: storage::get_in(c, tenant, binding).await?,
                            digest: hash,
                            replay: true,
                        });
                    }
                    let old = match storage::get_in(c, tenant, *id).await {
                        Ok(b) => Some(b),
                        Err(Error::NotFound) => None,
                        Err(e) => return Err(e),
                    };
                    if old.as_ref().map_or(0, |b| b.revision) != input.expected_revision
                        || old.as_ref().is_some_and(|b| {
                            b.device != *device
                                || b.registration != registration.registration_id
                                || b.registration_generation != registration.generation
                        })
                    {
                        return Err(Error::Conflict);
                    }
                    let value = match &input.action {
                        Action::Put {
                            person,
                            intent,
                            policy,
                        } => {
                            person.validate()?;
                            intent.validate()?;
                            if person.instance.to_string() != actor.instance_id() {
                                return Err(Error::Forbidden);
                            }
                            let selected = admission.policy(c, tenant, device, *policy).await?;
                            if !selected.configuration.enabled {
                                return Err(Error::Forbidden);
                            }
                            // Existing accounts may only be changed with an explicit stable target.
                            // A create retry must reconcile the original binding, never create a second OS user.
                            if old.as_ref().is_some_and(|b| {
                                b.account
                                    .as_ref()
                                    .zip(intent.account())
                                    .is_some_and(|(old, new)| old != new)
                            }) {
                                return Err(Error::Conflict);
                            }
                            if old.as_ref().is_some_and(|b| {
                                (b.account.is_none() && b.intent != *intent)
                                    || (matches!(intent, AccountIntent::Create { .. }) && b.account.is_some())
                            }) {
                                return Err(Error::Conflict);
                            }
                            let generation = old
                                .as_ref()
                                .map_or(Some(1), |b| b.generation.checked_add(1))
                                .ok_or(Error::Capacity)?;
                            let revision = input
                                .expected_revision
                                .checked_add(1)
                                .ok_or(Error::Capacity)?;
                            Binding {
                                id: *id,
                                tenant,
                                device: (*device).into(),
                                registration: registration.registration_id,
                                registration_generation: registration.generation,
                                person: person.clone(),
                                origin: Origin::Administrator { authority: rss_mdm_authorization_service::OperationAuthority::from_proof(
                                    &rss_mdm_authorization_service::snapshot_on(c,actor.tenant_id(),actor.instance_id()).await?,
                                    actor,device,Permission::AccountWrite)? },
                                generation,
                                revision,
                                state: State::Pending,
                                intent: intent.clone(),
                                account: intent.account().cloned(),
                                policy: selected.policy,
                                policy_version: selected.version,
                                configuration: selected.configuration,
                                received_revision: old.as_ref().and_then(|b| b.received_revision),
                                applied_revision: old.as_ref().and_then(|b| b.applied_revision),
                                effect: old.as_ref().and_then(|b| b.effect.clone()),
                                created_by_rss: old.as_ref().is_some_and(|b| b.created_by_rss)
                                    || matches!(intent, AccountIntent::Create { .. }),
                            }
                        }
                        Action::Unbind => {
                            let mut b = old.clone().ok_or(Error::NotFound)?;
                            b.generation = b.generation.checked_add(1).ok_or(Error::Capacity)?;
                            b.revision = b.revision.checked_add(1).ok_or(Error::Capacity)?;
                            b.state = State::Revoked;
                            b.configuration.enabled = false;
                            b
                        }
                    };
                    if old.is_some() {
                        storage::save_in(c, &value, input.expected_revision).await?;
                    } else {
                        storage::insert_in(c, &value).await?;
                    }
                    crate::operations::save(
                        c,
                        &op,
                        &serde_json::to_string(&value.id).map_err(|_| Error::Corrupt)?,
                        audit,
                    )
                    .await?;
                    Ok(AuditedChange {
                        value,
                        digest: hash,
                        replay: false,
                    })
                })
            },
        )
        .await
    }
}
