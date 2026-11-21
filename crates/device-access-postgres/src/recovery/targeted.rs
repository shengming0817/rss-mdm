//! Shared management admission and DA mTLS delivery for targeted credential operations.
use crate::{Error, Service, service::Change};
use rss_mdm_agent_wire::da::{CredentialEvent as Event, CredentialSettlement};
use rss_mdm_agent_wire::{
    DeviceId,
    runtime::{AccessAccount, CredentialTaskSpec},
};
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_authorization_service::{OperationAuthority, Permission, context::AuthorizedPrincipal};
use rss_mdm_policy_postgres::device_access::CredentialPublication;
use rss_mdm_recovery_credentials::{
    Credentials,
    tasks::device::{self, Action, Request, Status},
};
use rss_mdm_registration_service::{DevicePrincipal, device::endpoints};
use sqlx::PgConnection;
use uuid::Uuid;
async fn target(
    c: &mut PgConnection,
    actor: &AuthorizedPrincipal,
    device: &DeviceId,
) -> Result<Uuid, Error> {
    crate::device_access::service::authorize(c, actor, device, Permission::AccountWrite).await?;
    crate::delivery::lock_da_target(c, actor.tenant_id(), device, None).await?;
    endpoints::current_da_in(c, actor.tenant_id(), device)
        .await?
        .ok_or(Error::NotFound)?;
    Uuid::parse_str(actor.tenant_id()).map_err(|_| Error::Malformed)
}
async fn policy_authority(
    c: &mut PgConnection,
    actor: &AuthorizedPrincipal,
    device: &DeviceId,
) -> Result<(), Error> {
    let grants = crate::device_access::service::grants(c, actor).await?;
    grants
        .require(actor, Permission::PolicyWrite, None)
        .map_err(|_| Error::Forbidden)?;
    grants
        .require(actor, Permission::AccountWrite, Some(device))
        .map_err(|_| Error::Forbidden)?;
    Ok(())
}
async fn current_policy(
    c: &mut PgConnection,
    tenant: Uuid,
    device: DeviceId,
    version: Uuid,
    operation: &rss_mdm_policy::CredentialOperation,
    now: i64,
) -> Result<CredentialPublication, Error> {
    CredentialPublication::read(c, tenant, version, true)
        .await
        .map_err(crate::configuration::policy_fault)?
        .filter(|p| p.device == device && &p.operation == operation && p.deadline(now).is_some())
        .ok_or(Error::Forbidden)
}
impl Service {
    pub async fn publish_credential_policy(
        &self,
        actor: &AuthorizedPrincipal,
        device: &DeviceId,
        policy: &CredentialPublication,
        audit: &RequestAudit,
    ) -> Result<CredentialPublication, Error> {
        self.proof(actor, audit)?;
        actor.session()?;
        if *device != policy.device {
            return Err(Error::Malformed);
        }
        audit.operation(
            policy.version,
            "da_credential_policy_publish",
            AuditIntent::Management,
        );
        audit.target_device(device);
        self.write_admitted(&self.access_audit, audit, (actor,device,policy),
            |ctx,c| Box::pin(async move { crate::device_access::service::admit_session(c,ctx.0).await }),
            |ctx,c| Box::pin(async move {
                let (actor,device,policy)=*ctx;
                policy_authority(c,actor,device).await?;
                let tenant=Uuid::parse_str(actor.tenant_id()).map_err(|_|Error::Malformed)?;
                crate::delivery::lock_da_target(c,actor.tenant_id(),device,None).await?;
                let now=crate::platform_sso::store::now(c).await?;
                let replay=policy.publish(c,tenant,serde_json::json!({"actor":actor.principal_id(),"instance":actor.instance_id()}),now)
                    .await.map_err(crate::configuration::policy_fault)?;
                Ok(Change { value:policy.clone(), replay })
            })).await
    }
    pub async fn credential_policy(
        &self,
        actor: &AuthorizedPrincipal,
        device: &DeviceId,
        version: Uuid,
    ) -> Result<CredentialPublication, Error> {
        self.read_with_session(actor, (actor, device, version), |ctx, c| {
            Box::pin(async move {
                let (actor, device, version) = *ctx;
                policy_authority(c, actor, device).await?;
                let tenant = Uuid::parse_str(actor.tenant_id()).map_err(|_| Error::Malformed)?;
                CredentialPublication::read(c, tenant, version, false)
                    .await
                    .map_err(crate::configuration::policy_fault)?
                    .filter(|p| &p.device == device)
                    .ok_or(Error::NotFound)
            })
        })
        .await
    }
    pub async fn credential_status(
        &self,
        actor: &AuthorizedPrincipal,
        device: &DeviceId,
        id: Uuid,
    ) -> Result<Status, Error> {
        self.read_with_session(actor, (actor, device, id), |ctx, c| {
            Box::pin(async move {
                let (actor, device, id) = *ctx;
                crate::device_access::service::authorize(
                    c,
                    actor,
                    device,
                    Permission::AccountWrite,
                )
                .await?;
                let tenant = Uuid::parse_str(actor.tenant_id()).map_err(|_| Error::Malformed)?;
                let run = device::load(c, tenant, *device, Some(id), false)
                    .await
                    .map_err(super::error)?
                    .ok_or(Error::NotFound)?;
                Ok(run.status())
            })
        })
        .await
    }
    pub async fn request_credential(
        &self,
        credentials: &Credentials,
        actor: &AuthorizedPrincipal,
        device: &DeviceId,
        input: &Request,
        a: &RequestAudit,
    ) -> Result<Status, Error> {
        self.proof(actor, a)?;
        a.operation(
            input.operation_id,
            "da_credential_request",
            AuditIntent::Management,
        );
        a.target_device(device);
        self.write_admitted(
            &self.access_audit,
            a,
            (credentials, actor, device, input),
            |ctx, c| {
                Box::pin(
                    async move { crate::device_access::service::admit_session(c, ctx.1).await },
                )
            },
            |ctx, c| {
                Box::pin(async move {
                    let (credentials, actor, device, input) = *ctx;
                    let tenant = target(c, actor, device).await?;
                    if let Some(run) =
                        device::load(c, tenant, *device, Some(input.operation_id), false)
                            .await
                            .map_err(super::error)?
                    {
                        if !run.owned(actor) || run.status().request != *input {
                            return Err(Error::Conflict);
                        }
                        return Ok(Change {
                            value: run.status(),
                            replay: true,
                        });
                    }
                    let binding =
                        crate::device_access::storage::get_in(c, tenant, input.binding_id).await?;
                    if binding.device != *device || binding.generation != input.binding_generation {
                        return Err(Error::Conflict);
                    }
                    let Some(AccessAccount::Windows { sid, .. }) = &binding.account else {
                        return Err(Error::Forbidden);
                    };
                    let operation = match input.action {
                        Action::Rotate => rss_mdm_policy::CredentialOperation::RotateRssLogin {
                            binding: binding.id,
                            binding_generation: binding.generation,
                            sid: sid.clone(),
                        },
                        Action::Verify => rss_mdm_policy::CredentialOperation::VerifyRssLogin {
                            binding: binding.id,
                            binding_generation: binding.generation,
                            sid: sid.clone(),
                        },
                    };
                    let (_, anchor) = super::credential_tasks::qualified(c, tenant, &operation)
                        .await
                        .map_err(super::error)?;
                    if let Some(id) = input.replaces {
                        let previous = device::load(c, tenant, *device, Some(id), false)
                            .await
                            .map_err(super::error)?
                            .ok_or(Error::Conflict)?;
                        if let Some(recovery) = previous.unresolved() {
                            let original = if recovery.task_id == id {
                                previous
                            } else {
                                device::load(c, tenant, *device, Some(recovery.task_id), false)
                                    .await
                                    .map_err(super::error)?
                                    .ok_or(Error::Conflict)?
                            };
                            let old = &original.status().request;
                            if old.binding_id != input.binding_id
                                || old.binding_generation != input.binding_generation
                            {
                                let retired = crate::device_access::storage::get_in(
                                    c,
                                    tenant,
                                    old.binding_id,
                                )
                                .await?;
                                if retired.device != *device
                                    || (retired.generation == old.binding_generation
                                        && retired.state != rss_mdm_device_access::State::Revoked)
                                {
                                    return Err(Error::Conflict);
                                }
                            }
                        }
                    }
                    let snapshot = rss_mdm_authorization_service::snapshot_on(
                        actor.authority_profile(),
                        c,
                        actor.tenant_id(),
                        actor.instance_id(),
                    )
                    .await?;
                    let authority = OperationAuthority::from_proof(
                        &snapshot,
                        actor,
                        device,
                        Permission::AccountWrite,
                    )?;
                    let now = crate::platform_sso::store::now(c).await?;
                    let policy =
                        current_policy(c, tenant, *device, input.policy_version, &operation, now)
                            .await?;
                    let value = device::accept(
                        c,
                        credentials,
                        actor,
                        input,
                        anchor,
                        operation,
                        &policy,
                        authority,
                        now,
                    )
                    .await
                    .map_err(super::error)?;
                    Ok(Change {
                        value,
                        replay: false,
                    })
                })
            },
        )
        .await
    }
    pub async fn claim_credential(
        &self,
        credentials: &Credentials,
        p: &DevicePrincipal,
        a: &RequestAudit,
    ) -> Result<Option<CredentialTaskSpec>, Error> {
        a.identify_device(p.device());
        self.write(a, (self, credentials, p), |ctx, c| {
            Box::pin(async move {
                let (service, credentials, p) = *ctx;
                let run = admitted_run(c, service, p, None).await?;
                let value = match run {
                    Some(run) => {
                        let now = crate::platform_sso::store::now(c).await?;
                        Some(
                            run.permit(c, credentials, now)
                                .await
                                .map_err(super::error)?,
                        )
                    }
                    None => None,
                };
                Ok(Change {
                    value,
                    replay: true,
                })
            })
        })
        .await
    }
    pub async fn credential_event(
        &self,
        credentials: &Credentials,
        p: &DevicePrincipal,
        id: Uuid,
        input: &Event,
        a: &RequestAudit,
    ) -> Result<CredentialSettlement, Error> {
        a.identify_device(p.device());
        let action = match input {
            Event::Escrow { .. } => "da_credential_escrow",
            Event::Applied { .. } => "da_credential_applied",
        };
        a.operation(id, action, AuditIntent::Management);
        self.write(a, (self, credentials, p, id, input), |ctx, c| {
            Box::pin(async move {
                let (service, credentials, p, id, input) = *ctx;
                let mut run = admitted_run(c, service, p, Some(id))
                    .await?
                    .ok_or(Error::NotFound)?;
                let now = crate::platform_sso::store::now(c).await?;
                let replay = run
                    .settle(c, credentials, input, now)
                    .await
                    .map_err(super::error)?;
                let status = run.status();
                Ok(Change {
                    value: CredentialSettlement {
                        operation_id: id,
                        state: status.state,
                        receipt: status.receipt,
                    },
                    replay,
                })
            })
        })
        .await
    }
}
/// Acquire the frozen authorization fence before the device fence, then re-read the locked run.
async fn admitted_run(
    c: &mut PgConnection,
    service: &Service,
    p: &DevicePrincipal,
    id: Option<Uuid>,
) -> Result<Option<device::Run>, Error> {
    let tenant = Uuid::parse_str(&p.tenant().to_string()).map_err(|_| Error::Malformed)?;
    let hint = device::load(c, tenant, *p.device(), id, false)
        .await
        .map_err(super::error)?;
    if let Some(run) = &hint {
        run.lock_authority(c).await.map_err(super::error)?;
    }
    crate::delivery::lock_da_target(c, &tenant.to_string(), p.device(), None).await?;
    crate::reports::admit(c, service, p, None).await?;
    let run = device::load(c, tenant, *p.device(), id, true)
        .await
        .map_err(super::error)?;
    if hint.as_ref().map(|r| r.spec().task_id) != run.as_ref().map(|r| r.spec().task_id) {
        return Err(Error::ReadConflict);
    }
    if let Some(run) = &run {
        let current_time = crate::platform_sso::store::now(c).await?;
        if !run
            .authority_current(c, current_time)
            .await
            .map_err(super::error)?
        {
            return Err(Error::Forbidden);
        }
        let (_, anchor) = super::credential_tasks::qualified(c, tenant, run.operation())
            .await
            .map_err(super::error)?;
        let policy = current_policy(
            c,
            tenant,
            *p.device(),
            run.status().request.policy_version,
            run.operation(),
            current_time,
        )
        .await?;
        if current_time >= run.spec().deadline {
            return Err(Error::Forbidden);
        }
        run.admit(&anchor, policy.id, policy.version)
            .map_err(super::error)?;
    }
    Ok(run)
}
