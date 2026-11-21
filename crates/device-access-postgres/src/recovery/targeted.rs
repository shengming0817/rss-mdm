//! Shared management admission and DA mTLS delivery for targeted credential operations.
use crate::{Error, Service, service::Change};
use rss_mdm_agent_wire::{
    DeviceId,
    runtime::{AccessAccount, CredentialTaskSpec},
};
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_authorization_service::{OperationAuthority, Permission, context::AuthorizedPrincipal};
use rss_mdm_recovery_credentials::{
    Credentials,
    tasks::device::{self, Action, Event, Request, Status},
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
    endpoints::lock_da_in(c, actor.tenant_id(), device).await?;
    endpoints::current_da_in(c, actor.tenant_id(), device)
        .await?
        .ok_or(Error::NotFound)?;
    Uuid::parse_str(actor.tenant_id()).map_err(|_| Error::Malformed)
}
impl Service {
    pub async fn credential_status(
        &self,
        actor: &AuthorizedPrincipal,
        device: &DeviceId,
        id: Uuid,
    ) -> Result<Status, Error> {
        self.read_with_session(actor, (actor, device, id), |ctx, c| {
            Box::pin(async move {
                let (actor, device, id) = *ctx;
                let tenant = target(c, actor, device).await?;
                let run = device::load(c, tenant, *device, Some(id), false)
                    .await
                    .map_err(super::error)?
                    .ok_or(Error::NotFound)?;
                if !run.owned(actor) {
                    return Err(Error::NotFound);
                }
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
                        crate::device_access::storage::locked_in(c, tenant, input.binding_id)
                            .await?;
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
                    let (binding, anchor) =
                        super::credential_tasks::qualified(c, tenant, &operation)
                            .await
                            .map_err(super::error)?;
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
                    let value = device::accept(
                        c,
                        credentials,
                        actor,
                        input,
                        anchor,
                        operation,
                        binding.policy,
                        binding.policy_version,
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
        p: &DevicePrincipal,
        a: &RequestAudit,
    ) -> Result<Option<CredentialTaskSpec>, Error> {
        a.identify_device(p.device());
        self.write(a, (self, p), |ctx, c| {
            Box::pin(async move {
                let (service, p) = *ctx;
                crate::reports::admit(c, service, p, None).await?;
                let tenant =
                    Uuid::parse_str(&p.tenant().to_string()).map_err(|_| Error::Malformed)?;
                let run = device::load(c, tenant, *p.device(), None, true)
                    .await
                    .map_err(super::error)?;
                let value = match run {
                    Some(run) => {
                        let now = admit_run(c, tenant, &run).await?;
                        Some(run.permit(c, now).await.map_err(super::error)?)
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
    ) -> Result<Status, Error> {
        a.identify_device(p.device());
        let action = match input {
            Event::Escrow { .. } => "da_credential_escrow",
            Event::Applied { .. } => "da_credential_applied",
        };
        a.operation(id, action, AuditIntent::Management);
        self.write(a, (self, credentials, p, id, input), |ctx, c| {
            Box::pin(async move {
                let (service, credentials, p, id, input) = *ctx;
                crate::reports::admit(c, service, p, None).await?;
                let tenant =
                    Uuid::parse_str(&p.tenant().to_string()).map_err(|_| Error::Malformed)?;
                let mut run = device::load(c, tenant, *p.device(), Some(id), true)
                    .await
                    .map_err(super::error)?
                    .ok_or(Error::NotFound)?;
                let now = admit_run(c, tenant, &run).await?;
                let replay = run
                    .settle(c, credentials, input, now)
                    .await
                    .map_err(super::error)?;
                Ok(Change {
                    value: run.status(),
                    replay,
                })
            })
        })
        .await
    }
}
async fn admit_run(c: &mut PgConnection, tenant: Uuid, run: &device::Run) -> Result<i64, Error> {
    let (binding, anchor) = super::credential_tasks::qualified(c, tenant, run.operation())
        .await
        .map_err(super::error)?;
    let now = crate::platform_sso::store::now(c).await?;
    run.admit(c, &anchor, binding.policy, binding.policy_version, now)
        .await
        .map_err(super::error)?;
    Ok(now)
}
