use super::*;
use crate::operations::Operation;
use crate::{
    database::db,
    service::{Change as AuditedChange, Service},
};
use rss_mdm_agent_wire::runtime::{AccessBegin, AccessChallenge, AccessConfirm};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

fn tenant_uuid(tenant: rss_request_context::TenantId) -> Result<Uuid, Error> {
    Uuid::parse_str(&tenant.to_string()).map_err(|_| Error::Corrupt)
}
pub(crate) fn person(p: &AuthorizedPrincipal) -> Result<Person, Error> {
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
pub(crate) async fn grants(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
) -> Result<rss_mdm_authorization_service::Snapshot, Error> {
    p.check_live()?;
    rss_mdm_authorization_service::lock_on(
        p.authority_profile(),
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
    Ok(rss_mdm_authorization_service::snapshot_on(
        p.authority_profile(),
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?)
}

pub(crate) async fn authorize(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &rss_mdm_agent_wire::DeviceId,
    permission: Permission,
) -> Result<(), Error> {
    grants(c, p).await?.require(p, permission, Some(device))?;
    Ok(())
}

impl Service {
    pub async fn device_access_directory(
        &self,
        device: &rss_mdm_registration_service::DevicePrincipal,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        query: &rss_mdm_query::window::Query,
        admission: &dyn Admission,
    ) -> Result<rss_mdm_agent_wire::runtime::AccessDirectory, Error> {
        let employee = request.proof.as_ref();
        if employee.tenant_id() != device.tenant().to_string() {
            return Err(Error::Forbidden);
        }
        query
            .require_schema(&super::DISCOVERY)
            .map_err(|_| Error::Malformed)?;
        let fresh = request.revalidate().await?.ok_or(Error::Unauthorized)?;
        self.read_with_session(
            employee,
            (self, employee, device, admission, query, &fresh),
            |ctx, c| {
                Box::pin(async move {
                    let (service, employee, device, admission, query, fresh) = *ctx;
                    let who = person(employee)?;
                    let reference = employee
                        .session()?
                        .reference()
                        .map_err(|_| Error::Unauthorized)?;
                    let tenant = tenant_uuid(device.tenant())?;
                    rss_mdm_authorization_service::lock_shared_on(
                        employee.authority_profile(),
                        c,
                        employee.tenant_id(),
                        employee.instance_id(),
                    )
                    .await?;
                    let endpoint = crate::delivery::resolve_on(c, device).await?;
                    rss_mdm_registration_service::lifecycle::require_work_in(
                        rss_mdm_install_support::StorageProfile::Da,
                        c,
                        employee.tenant_id(),
                        endpoint.device(),
                    )
                    .await?;
                    let authority = rss_mdm_authorization_service::snapshot_on(
                        employee.authority_profile(),
                        c,
                        employee.tenant_id(),
                        employee.instance_id(),
                    )
                    .await?
                    .query_binding_revalidated(employee, fresh)?;
                    let local = admission.local_session(c, device).await?;
                    let binding = rss_mdm_query::cursor::fingerprint(&(
                        "device_access.discovery",
                        &who,
                        &reference,
                        endpoint.device(),
                        device.epoch(),
                        &local,
                        &authority,
                    ))
                    .map_err(|_| Error::Malformed)?;
                    let after = query
                        .cursor()
                        .as_ref()
                        .map(|value| {
                            let token = rss_contract::PageCursor::parse(value)
                                .map_err(|_| Error::Malformed)?;
                            service
                                .cursor
                                .decode::<Uuid>(&token, &binding)
                                .map_err(|_| Error::CursorInvalidated)
                        })
                        .transpose()?;

                    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
                        "SELECT document FROM rss_da.bindings WHERE tenant_id=$1 AND device=$2
                         AND instance=$3 AND principal=$4 AND account=$5 ORDER BY id LIMIT 129",
                    )
                    .bind(tenant)
                    .bind(endpoint.device().into_uuid())
                    .bind(who.instance)
                    .bind(who.principal)
                    .bind(sqlx::types::Json(&local.account))
                    .fetch_all(&mut *c)
                    .await
                    .map_err(db)?;
                    if rows.len() > 128 {
                        return Err(Error::Capacity);
                    }
                    let mut bindings = Vec::with_capacity(rows.len());
                    for row in rows {
                        let value: Binding =
                            serde_json::from_value(row).map_err(|_| Error::Corrupt)?;
                        value.validate()?;
                        bindings.push(value.status()?);
                    }

                    let (policies, after) =
                        if storage::first_in(c, tenant, endpoint.device()).await? {
                            admission
                                .policies(
                                    c,
                                    tenant,
                                    endpoint.device(),
                                    after,
                                    u16::try_from(query.limit()).map_err(|_| Error::Malformed)?,
                                )
                                .await?
                        } else {
                            (Vec::new(), None)
                        };
                    let next_cursor = after
                        .map(|id| {
                            service
                                .cursor
                                .encode(&binding, &id)
                                .map(|value| value.as_str().to_owned())
                        })
                        .transpose()
                        .map_err(|_| Error::Malformed)?;
                    employee.check_live()?;
                    Ok(rss_mdm_agent_wire::runtime::AccessDirectory {
                        device_id: *endpoint.device(),
                        policies,
                        next_cursor,
                        bindings,
                    })
                })
            },
        )
        .await
    }

    pub async fn change_step_up_context(
        &self,
        actor: &AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
        id: Uuid,
        input: &Change,
        fingerprints: &std::collections::BTreeMap<Uuid, String>,
        admission: &dyn Admission,
    ) -> Result<(rss_identity_core::step_up::StepUpContext, Option<Uuid>), Error> {
        let epoch = self
            .read_with_session(actor, (actor, device, id, input, admission), |ctx, c| {
                Box::pin(async move {
                    let (p, device, id, input, admission) = *ctx;
                    Ok(owner::change(c, p, device, id, input, admission)
                        .await?
                        .map(|(_, epoch)| epoch))
                })
            })
            .await?;
        let context = input.step_up_context(actor, device, id, fingerprints)?;
        let context = if let Some(epoch) = epoch {
            let mut digest = Sha256::new();
            digest.update(context.digest());
            digest.update(epoch.as_bytes());
            rss_identity_core::step_up::StepUpContext::new(
                "mdm.device_access.employee".into(),
                digest.finalize().into(),
            )
            .map_err(|_| Error::Corrupt)?
        } else {
            context
        };
        Ok((context, epoch))
    }

    pub async fn device_access_operation(
        &self,
        actor: &AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
        id: Uuid,
    ) -> Result<Binding, Error> {
        self.read_with_session(actor, (actor, device, id), |ctx, c| {
            Box::pin(async move {
                let (actor, device, id) = *ctx;
                operation_on(c, actor, device, id).await
            })
        })
        .await
    }

    /// First association only. Both authenticated device and human proofs are mandatory.
    pub async fn begin_device_access(
        &self,
        device: &rss_mdm_registration_service::DevicePrincipal,
        employee: &AuthorizedPrincipal,
        input: &AccessBegin,
        admission: &dyn Admission,
        audit: &RequestAudit,
    ) -> Result<AccessChallenge, Error> {
        let execution = device.binding();

        self.proof(employee, audit)?;
        if device.tenant() != execution.tenant()
            || input.operation_id.is_nil()
            || input.policy.is_nil()
        {
            return Err(Error::Forbidden);
        }
        let who = person(employee)?;
        audit.operation(
            input.operation_id,
            "device_access_begin",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device.device());
        self.write_admitted(&self.access_audit, audit, (device, employee, input, admission, who),
            |ctx,c| Box::pin(async move { admit_session(c, ctx.1).await }), |ctx,c| Box::pin(async move {
            let (device,employee,input,admission,who) = ctx;
            let authenticated=*device;
            let endpoint=crate::delivery::resolve_on(c,authenticated).await?;
            let device=&endpoint;
            rss_mdm_registration_service::lifecycle::require_work_in(rss_mdm_install_support::StorageProfile::Da, c, employee.tenant_id(), device.device()).await?;
            super::lifecycle::require_subject_on(c,tenant_uuid(device.tenant())?,who).await?;
            let time = now(c).await?;
            if !employee.recently_authenticated(time, 300)? { return Err(Error::Unauthorized); }
            let selection = admission.policy(c, tenant_uuid(device.tenant())?, device.device(), input.policy).await?;
            if !selection.configuration.enabled || !selection.configuration.self_enrollment { return Err(Error::Forbidden); }
            let local = admission.local_session(c, authenticated).await?;
            local.validate().map_err(|_| Error::Malformed)?;
            if !selection.configuration.admits(&local.account) {return Err(Error::Forbidden);}
            if !storage::first_in(c, tenant_uuid(device.tenant())?, device.device()).await? { return Err(Error::Conflict); }
            sqlx::query("DELETE FROM rss_da.ceremonies WHERE tenant_id=$1 AND expires_at<to_timestamp($2::bigint::double precision)")
                .bind(tenant_uuid(device.tenant())?).bind(time).execute(&mut *c).await.map_err(db)?;
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_da.ceremonies WHERE tenant_id=$1 AND device=$2")
                .bind(tenant_uuid(device.tenant())?).bind(device.device().into_uuid()).fetch_one(&mut *c).await.map_err(db)?;
            if count >= 128 { return Err(Error::Capacity); }
            use base64::Engine;
            let mut bytes = [0u8;32];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).map_err(|_| Error::Runtime)?;
            let nonce = rss_mdm_agent_wire::runtime::Secret::parse(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)).map_err(|_| Error::Corrupt)?;
            let expires_at = time.checked_add(120).ok_or(Error::Capacity)?;
            sqlx::query("INSERT INTO rss_da.ceremonies (tenant_id, id, device, instance, principal, nonce_digest, session, policy, policy_version, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, to_timestamp(CAST(CAST($10 AS bigint) AS double precision)))")
                .bind(tenant_uuid(device.tenant())?).bind(input.operation_id).bind(device.device().into_uuid())
                .bind(who.instance).bind(who.principal).bind(nonce_digest(&nonce).as_slice()).bind(serde_json::to_value(&local).map_err(|_| Error::Malformed)?)
                .bind(selection.policy).bind(selection.version).bind(expires_at).execute(c).await.map_err(|e| if e.as_database_error().is_some_and(|e| e.is_unique_violation()) { Error::Conflict } else { db(e) })?;
            Ok(AuditedChange {replay: false, value: AccessChallenge { id: input.operation_id, nonce, expires_at, local_session: local }})
        })).await
    }

    pub async fn confirm_device_access(
        &self,
        device: &rss_mdm_registration_service::DevicePrincipal,
        employee: &AuthorizedPrincipal,
        input: &AccessConfirm,
        admission: &dyn Admission,
        audit: &RequestAudit,
    ) -> Result<Binding, Error> {
        let execution = device.binding();

        self.proof(employee, audit)?;
        if device.tenant() != execution.tenant()
            || input.operation_id.is_nil()
            || input.challenge.is_nil()
        {
            return Err(Error::Forbidden);
        }
        input
            .local_session
            .validate()
            .map_err(|_| Error::Malformed)?;
        let who = person(employee)?;
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::DeviceAccess,
            input.operation_id,
            "device_access_confirm",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device.device());
        let has_custody = self.recovery.is_some();
        self.write_admitted(&self.access_audit,audit,(device,employee,input,admission,who,audit),
            |ctx,c| Box::pin(async move { admit_session(c, ctx.1).await }),|ctx,c|Box::pin(async move {
            let (device,employee,input,admission,who,audit)=ctx;
            let authenticated=*device;
            let endpoint=crate::delivery::resolve_on(c,authenticated).await?;
            let device=&endpoint;
            rss_mdm_registration_service::lifecycle::require_work_in(rss_mdm_install_support::StorageProfile::Da, c,employee.tenant_id(),device.device()).await?;
            let hash=digest(&("device_access_confirm", input.operation_id,input.challenge,nonce_digest(&input.nonce),&input.local_session,&*who))?;
            let op=Operation::new(employee, input.operation_id, &hash )?;
            if let Some(old)=crate::operations::replay( c,&op).await? {
                let saved:Binding=serde_json::from_str(&old).map_err(|_|Error::Corrupt)?;
                saved.validate()?;
                if saved.device != *device.device() || saved.person!=*who {return Err(Error::Forbidden);}
                return Ok(AuditedChange{value:saved, replay:true});
            }
            super::lifecycle::require_subject_on(c,tenant_uuid(device.tenant())?,who).await?;
            let time=now(c).await?;
            if !employee.recently_authenticated(time,300)? { return Err(Error::Unauthorized); }
            let local=admission.local_session(c,authenticated).await?;
            if local!=input.local_session { return Err(Error::Conflict); }
            let row=sqlx::query("SELECT *,floor(extract(epoch FROM expires_at))::bigint AS expires_unix FROM rss_da.ceremonies WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind(tenant_uuid(device.tenant())?).bind(input.challenge).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::NotFound)?;
            use subtle::ConstantTimeEq;
            let expected:Vec<u8>=row.try_get("nonce_digest").map_err(db)?;
            if !bool::from(expected.as_slice().ct_eq(&nonce_digest(&input.nonce)))
                || row.try_get::<Uuid,_>("instance").map_err(db)?!=who.instance || row.try_get::<Uuid,_>("principal").map_err(db)?!=who.principal
                || row.try_get::<uuid::Uuid, _>("device").and_then(|id| rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))).map_err(db)?!=*device.device()
                || row.try_get::<uuid::Uuid, _>("device").and_then(|id| rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))).map_err(db)?!=*device.device()
                || row.try_get::<serde_json::Value,_>("session").map_err(db)?!=serde_json::to_value(&local).map_err(|_|Error::Malformed)? { return Err(Error::Forbidden); }
            if row.try_get::<i64,_>("expires_unix").map_err(db)?<=time || row.try_get::<Option<Uuid>,_>("consumed").map_err(db)?.is_some() { return Err(Error::Conflict); }
            let policy:Uuid=row.try_get("policy").map_err(db)?;
            let selected=admission.policy(c,tenant_uuid(device.tenant())?,device.device(),policy).await?;
            if selected.version!=row.try_get::<Uuid,_>("policy_version").map_err(db)? || !selected.configuration.self_enrollment || !selected.configuration.enabled || !selected.configuration.admits(&local.account) { return Err(Error::Forbidden); }
            if !storage::first_in(c,tenant_uuid(device.tenant())?,device.device()).await? {return Err(Error::Conflict);}
            let mut binding=Binding{account_delivery:None,deployment_application:None,operation_id:input.operation_id,account_disposition:rss_mdm_agent_wire::runtime::AccessAccountDisposition::Keep,id:Uuid::new_v4(),tenant:tenant_uuid(device.tenant())?,device:*device.device(),person:who.clone(),origin:Origin::SelfEnrollment,generation:1,factor_generation:1,revision:1,state:State::Pending,intent:AccountIntent::Existing{account:local.account.clone()},account:Some(local.account),policy:selected.policy,policy_version:selected.version,configuration:selected.configuration,received_revision:None,applied_revision:None,effect:None,applied_windows:None,created_by_rss:false};
            binding.account_delivery=super::account_delivery::select(c,&binding,authenticated.installation(),has_custody).await?;
            storage::insert_in(c,&binding).await?;
            super::account_delivery::accept(c,&binding,None,employee.binding().epoch().get()).await?;
            super::lifecycle::emit_on(c,&binding,None,input.operation_id,"accepted").await?;
            sqlx::query("UPDATE rss_da.ceremonies SET consumed=$3 WHERE tenant_id=$1 AND id=$2").bind(binding.tenant).bind(input.challenge).bind(binding.id).execute(&mut *c).await.map_err(db)?;
            crate::operations::save( c,&op,&serde_json::to_string(&binding).map_err(|_|Error::Corrupt)?,audit).await?;
            Ok(AuditedChange{value:binding, replay:false})
        })).await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Actor, current authorization, one-use proof and audited operation remain distinct capabilities"
    )]
    pub async fn change_device_access(
        &self,
        actor: &AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
        id: Uuid,
        input: &Change,
        proof: Option<&rss_mdm_agent_wire::runtime::Secret>,
        idp_fingerprints: &std::collections::BTreeMap<Uuid, String>,
        admission: &dyn Admission,
        audit: &RequestAudit,
    ) -> Result<Binding, Error> {
        self.proof(actor, audit)?;
        person(actor)?;
        if input.operation_id.is_nil() || id.is_nil() || input.expected_revision < 0 {
            return Err(Error::Malformed);
        }
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::DeviceAccess,
            input.operation_id,
            "device_access_change",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device);
        let hash = digest(&("device_access_change", device, id, input, idp_fingerprints))?;
        if let Some(value) = self
            .access_replay(actor, device, input.operation_id, &hash)
            .await?
        {
            return Ok(value);
        }
        let has_custody = self.recovery.is_some();
        let result = async {
            let (context, expected_epoch) = self.change_step_up_context(actor, device, id, input, idp_fingerprints, admission).await?;
            self.write_admitted(
            &self.access_audit,
            audit,
            (actor, device, id, input, admission, audit, proof, &context, idp_fingerprints, expected_epoch, &hash),
            |ctx, c| Box::pin(async move {
                let proof = ctx.6.ok_or(Error::Unauthorized)?;
                ctx.0.session_authority()?.consume_step_up_on(c, ctx.0.session()?, ctx.7, proof.expose())
                    .await.map_err(|error| match error.kind() {
                        rss_transactional_messaging::error::MessagingErrorKind::Conflict => Error::Unauthorized,
                        rss_transactional_messaging::error::MessagingErrorKind::DeadlineElapsed => Error::Deadline,
                        _ => Error::Storage,
                    })?;
                Ok(())
            }),
            |ctx, c| {
                Box::pin(async move {
                    let (actor, device, id, input, admission, audit, _, _, idp_fingerprints, expected_epoch, hash) = ctx;
                    let employee=owner::change(c,actor,device,*id,input,*admission).await?;
                    if employee.as_ref().map(|(_, epoch)| *epoch) != *expected_epoch { return Err(Error::Conflict); }
                    let tenant = Uuid::parse_str(actor.tenant_id()).map_err(|_| Error::Corrupt)?;
                    if matches!(input.action,Action::Offboard{..}) {super::lifecycle::lock_offboarding_on(c,tenant,*id).await?;}
                    if employee.is_none() {
                        storage::lock_registration(c, tenant, device).await?;
                    } else {
                        rss_mdm_registration_service::lifecycle::require_work_in(rss_mdm_install_support::StorageProfile::Da, c, actor.tenant_id(), device).await?;
                    }
                    let op = Operation::new(actor, input.operation_id, hash)?;
                    if crate::operations::replay( c, &op).await?.is_some() {
                        // Roll back this proof consumption, then return the committed receipt.
                        return Err(Error::Conflict);
                    }
                    let (old,origin) = if let Some((binding,registration_epoch))=employee {
                        let windows_key=crate::enterprise::eligible_key(c,&binding,registration_epoch).await?;
                        (Some(binding),Origin::Employee {registration_epoch,windows_key})
                    } else {
                        let old=match storage::get_in(c,tenant,*id).await {
                            Ok(binding)=>Some(binding),
                            Err(Error::NotFound)=>None,
                            Err(error)=>return Err(error),
                        };
                        (old,Origin::Administrator{actor:actor.actor()})
                    };
                    if old.as_ref().map_or(0, |b| b.revision) != input.expected_revision
                        || old.as_ref().is_some_and(|b| {
                            b.device != **device
                        })
                    {
                        return Err(Error::Conflict);
                    }
                    if let Some(prior)=old.as_ref(){
                        if prior.state==State::Revoked && prior.account.is_none(){
                            storage::require_retired_in(c,prior).await?;
                        }
                        let withdrawing = matches!(input.action, Action::Unbind { .. } | Action::Offboard { .. });
                        let direct_mac_cleanup = prior.state == State::Revoked && prior.intent.platform() == TaskPlatform::Macos
                            && matches!(prior.account_delivery, Some(super::account_delivery::Target::Da { .. }));
                        // A withdrawal fences a Create, but cannot supersede a cleanup Start already on the Mac.
                        if !withdrawing || direct_mac_cleanup {
                            let unresolved:bool=sqlx::query_scalar(
                                "SELECT EXISTS(SELECT FROM rss_da.access_runs WHERE tenant_id=$1 AND binding_id=$2
                                 AND da_target IS NOT NULL AND state->>'execution' IN ('running','unknown') AND state->>'cancellation'<>'confirmed'
                                 AND (access_binding->>'revision')::bigint=$3)"
                            ).bind(tenant).bind(*id).bind(input.expected_revision).fetch_one(&mut *c).await.map_err(db)?;
                            if unresolved {return Err(Error::Conflict);}
                        }
                        if !withdrawing {
                            rss_mdm_recovery_credentials::tasks::device::require_rotation_settled(
                                c,tenant,**device,prior.id,prior.generation
                            ).await.map_err(crate::recovery::error)?;
                        }
                    }
                    let mut value = match &input.action {
                        Action::Put { person, intent, policy } | Action::Reinstate { person, intent, policy } => {
                            person.validate()?;
                            if matches!(input.action,Action::Reinstate{..}) {
                                super::lifecycle::require_settled_on(c,tenant,person).await?;
                                let snapshot=rss_mdm_authorization_service::snapshot_on(actor.authority_profile(), c,actor.tenant_id(),actor.instance_id()).await?;
                                snapshot.require(actor,Permission::IdentityAccountsManage,None).map_err(|_|Error::Forbidden)?;
                                let changed=sqlx::query("UPDATE rss_da.subject_denials SET denied=false,operation=$4 WHERE tenant_id=$1 AND instance=$2 AND principal=$3 AND denied")
                                    .bind(tenant).bind(person.instance).bind(person.principal).bind(input.operation_id).execute(&mut *c).await.map_err(db)?.rows_affected();
                                if changed!=1 {return Err(Error::Conflict);}
                            } else {super::lifecycle::require_subject_on(c,tenant,person).await?;}
                            intent.validate()?;
                            if person.instance.to_string() != actor.instance_id() {
                                return Err(Error::Forbidden);
                            }
                            let selected = admission.policy(c, tenant, device, *policy).await?;
                            if !selected.configuration.enabled {
                                return Err(Error::Forbidden);
                            }
                            selected.configuration.validate().map_err(|_| Error::Malformed)?;
                            if intent.account().is_some_and(|account| !selected.configuration.admits(account))
                                || (intent.platform() == TaskPlatform::Macos && selected.configuration.mac.is_none())
                                || (matches!(intent, AccountIntent::Create { platform: TaskPlatform::Windows, .. })
                                    && !selected.configuration.windows.accounts().contains(&rss_mdm_agent_wire::runtime::AccessWindowsKind::Local))
                            { return Err(Error::Forbidden); }
                            if intent.platform() == TaskPlatform::Macos {
                                // A System PSSO profile has one Policy owner for every user on the device.
                                let conflict: bool = sqlx::query_scalar("SELECT EXISTS (SELECT FROM rss_da.bindings WHERE tenant_id = $1 AND device = $2 AND id <> $3 AND state <> 'revoked' AND COALESCE(account ->> 'platform', document #>> '{intent,platform}') = 'macos' AND document ->> 'policy' <> $4)")
                                    .bind(tenant).bind(device.into_uuid()).bind(*id).bind(policy.to_string())
                                    .fetch_one(&mut *c).await.map_err(db)?;
                                if conflict { return Err(Error::Conflict); }
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
                            if intent.platform() == TaskPlatform::Windows && old.as_ref().is_some_and(|b| std::mem::discriminant(&b.configuration.windows) != std::mem::discriminant(&selected.configuration.windows)) { return Err(Error::Conflict); }
                            let rebound = old.as_ref().is_some_and(|b| b.person != *person || b.state == State::Revoked);
                            let generation = old.as_ref().map_or(Some(1), |b|
                                if rebound { b.generation.checked_add(1) } else { Some(b.generation) }).ok_or(Error::Capacity)?;
                            let factor_generation = old.as_ref().map_or(Some(1), |b|
                                if rebound { b.factor_generation.checked_add(1) } else { Some(b.factor_generation) }).ok_or(Error::Capacity)?;
                            let revision = input
                                .expected_revision
                                .checked_add(1)
                                .ok_or(Error::Capacity)?;
                            Binding {
                                account_delivery:old.as_ref().filter(|b|b.state!=State::Revoked).and_then(|b|b.account_delivery.clone()),
                                deployment_application: None,
                                operation_id: input.operation_id,
                                account_disposition: rss_mdm_agent_wire::runtime::AccessAccountDisposition::Keep,
                                id: *id,
                                tenant,
                                device: **device,


                                person: person.clone(),
                                origin: origin.clone(),
                                generation,
                                factor_generation,
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
                                applied_windows: old.as_ref().and_then(|b| b.applied_windows.clone()),
                                created_by_rss: old.as_ref().is_some_and(|b| b.created_by_rss)
                                    || matches!(intent, AccountIntent::Create { .. }),
                            }
                        }
                        Action::RepairBinding => {
                            let mut b=old.clone().ok_or(Error::NotFound)?;
                            b.revision=b.revision.checked_add(1).ok_or(Error::Capacity)?;
                            b.state=State::Pending;
                            b.deployment_application=None;
                            b.origin=origin.clone();
                            b
                        }
                        Action::ResetFactors => {
                            let mut b = old.clone().ok_or(Error::NotFound)?;
                            if b.state == State::Revoked || b.intent.platform() != TaskPlatform::Windows { return Err(Error::Conflict); }
                            let selected = admission.policy(c,tenant,device,b.policy).await?;
                            if !selected.configuration.enabled { return Err(Error::Forbidden); }
                            if std::mem::discriminant(&b.configuration.windows) != std::mem::discriminant(&selected.configuration.windows) { return Err(Error::Conflict); }
                            b.factor_generation = b.factor_generation.checked_add(1).ok_or(Error::Capacity)?;
                            b.revision = b.revision.checked_add(1).ok_or(Error::Capacity)?;
                            b.policy_version = selected.version;
                            b.configuration = selected.configuration;
                            b.origin = origin;
                            b.state = State::Pending;
                            b
                        }
                        Action::Unbind { disposition } | Action::Offboard { disposition } => {
                            let mut b = old.clone().ok_or(Error::NotFound)?;
                            b.generation = b.generation.checked_add(1).ok_or(Error::Capacity)?;
                            b.revision = b.revision.checked_add(1).ok_or(Error::Capacity)?;
                            b.state = State::Revoked;
                            b.configuration.enabled = false;
                            b.account_disposition = *disposition;
                            b.origin=origin;
                            b
                        }
                    };
                    if old.is_some() && matches!(input.action, Action::Put { .. } | Action::Reinstate { .. }) { storage::require_retired_in(c, &value).await?; }
                    value.operation_id = input.operation_id;
                    let subject = rss_identity_postgres::platform::PlatformBinding {
                        instance: rss_identity_core::InstanceId::parse(&value.person.instance.to_string()).map_err(|_| Error::Malformed)?,
                        account: rss_identity_core::account::AccountKey {
                            tenant: self::tenant_id(tenant)?,
                            principal: rss_identity_core::PrincipalId::parse(&value.person.principal.to_string()).map_err(|_| Error::Malformed)?,
                        },
                        binding_id: value.id,
                        binding_epoch: value.generation,
                        source_id: value.id,
                        source_version: value.generation,
                        external_identity: None,
                    };
                    // The guard was already acquired by consume_step_up_on before product locks.
                    if !matches!(input.action, Action::Unbind { .. } | Action::Offboard { .. }) {
                        super::lifecycle::require_subject_on(c,tenant,&value.person).await?;
                        rss_identity_postgres::platform::admit_platform_subject_on(c, subject.instance, &subject, None)
                            .await.map_err(|error| match error {
                                rss_identity_postgres::platform::PlatformSubjectAdmissionError::Rejected => Error::Forbidden,
                                rss_identity_postgres::platform::PlatformSubjectAdmissionError::Storage(_) => Error::Storage,
                            })?;
                    }
                    if matches!(input.action, Action::Offboard { .. }) {
                        value.factor_generation = value.factor_generation.checked_add(1).ok_or(Error::Capacity)?;
                        super::lifecycle::accept_offboarding_on(c,actor,&value,idp_fingerprints).await?;
                    }
                    let installation=rss_mdm_registration_service::device::installation_in(rss_mdm_install_support::StorageProfile::Da,c).await?;
                    value.account_delivery=super::account_delivery::select(c,&value,installation,has_custody).await?;
                    if old.is_some() {
                        storage::save_in(c, &value, input.expected_revision).await?;
                    } else {
                        storage::insert_in(c, &value).await?;
                    }
                    super::account_delivery::accept(c,&value,Some(actor),actor.binding().epoch().get()).await?;
                    super::lifecycle::emit_on(c, &value, old.as_ref().map(|b| b.person.principal), input.operation_id, "accepted").await?;
                    crate::operations::save(
                        c,
                        &op,
                        &serde_json::to_string(&value).map_err(|_| Error::Corrupt)?,
                        audit,
                    )
                    .await?;
                    Ok(AuditedChange {value, replay: false})
                })
            },
        )
        .await
        }.await;
        match result {
            Ok(value) => Ok(value),
            Err(error) => match self
                .access_replay(actor, device, input.operation_id, &hash)
                .await
            {
                Ok(Some(value)) => Ok(value),
                _ => Err(error),
            },
        }
    }
    async fn access_replay(
        &self,
        actor: &AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
        operation: Uuid,
        hash: &str,
    ) -> Result<Option<Binding>, Error> {
        self.read_with_session(actor, (actor, device, operation, hash), |ctx, c| {
            Box::pin(async move {
                let (actor, device, operation, hash) = *ctx;
                let op = Operation::new(actor, operation, hash)?;
                let Some(document) = crate::operations::read(c, &op).await? else {
                    return Ok(None);
                };
                let saved: Binding = serde_json::from_str(&document).map_err(|_| Error::Corrupt)?;
                saved.validate()?;
                owner::receipt(c, actor, device, &saved).await?;
                Ok(Some(saved))
            })
        })
        .await
    }
}
fn tenant_id(value: Uuid) -> Result<rss_request_context::TenantId, Error> {
    rss_request_context::TenantId::parse(&value.to_string()).map_err(|_| Error::Malformed)
}

/// Identity owns credential/session checks and holds its guard until the host settles.
pub(crate) async fn admit_session(
    c: &mut PgConnection,
    actor: &AuthorizedPrincipal,
) -> Result<(), Error> {
    actor
        .session_authority()?
        .recheck_authenticated_session_on(c, actor.session()?)
        .await
        .map_err(|error| match error.kind() {
            rss_transactional_messaging::error::MessagingErrorKind::Conflict => Error::Unauthorized,
            rss_transactional_messaging::error::MessagingErrorKind::DeadlineElapsed => {
                Error::Deadline
            }
            _ => Error::Storage,
        })
}

pub(super) async fn operation_on(
    c: &mut PgConnection,
    actor: &AuthorizedPrincipal,
    device: &rss_mdm_agent_wire::DeviceId,
    id: Uuid,
) -> Result<Binding, Error> {
    let result:Option<String>=sqlx::query_scalar("SELECT result FROM rss_da.operations WHERE tenant_id=$1::uuid AND actor=$2::uuid AND instance=$3::uuid AND operation_id=$4")
            .bind(actor.tenant_id()).bind(actor.principal_id()).bind(actor.instance_id()).bind(id).fetch_optional(&mut *c).await.map_err(db)?;
    let value: Binding =
        serde_json::from_str(&result.ok_or(Error::NotFound)?).map_err(|_| Error::NotFound)?;
    value.validate()?;
    if value.operation_id != id {
        return Err(Error::NotFound);
    }
    owner::receipt(c, actor, device, &value).await?;
    // A subject offboarding receipt represents all frozen targets, not only its initiating device.
    let offboarding: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM rss_da.lifecycles WHERE tenant_id=$1::uuid AND operation=$2)",
    )
    .bind(actor.tenant_id())
    .bind(id)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if offboarding {
        super::lifecycle::load_on(c, actor, device, id, false).await?;
    }
    Ok(value)
}
