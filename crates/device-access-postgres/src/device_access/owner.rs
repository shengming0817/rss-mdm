//! Resource authorization for changes and their durable receipts.
use super::{
    Action, Admission, Binding, Change, Origin, State, account_delivery::Target, lifecycle,
    service, storage,
};
use crate::Error;
use rss_mdm_agent_wire::{
    DeviceId,
    runtime::{AccessWindowsConfiguration, TaskPlatform},
};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_registration_service::device::endpoints;
use sqlx::PgConnection;
use uuid::Uuid;

async fn registration(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &DeviceId,
) -> Result<Uuid, Error> {
    crate::delivery::lock_da_target(c, p.tenant_id(), device, None).await?;
    endpoints::current_da_epoch_in(c, p.tenant_id(), device)
        .await
        .map_err(Into::into)
}

async fn owned(c: &mut PgConnection, b: &Binding, epoch: Uuid) -> Result<(), Error> {
    if b.state == State::Revoked
        || b.account.is_none()
        || matches!(b.origin, Origin::Employee { registration_epoch, .. } if registration_epoch != epoch)
        || matches!(b.account_delivery, Some(Target::Da { epoch: original, .. }) if original != epoch)
    {
        return Err(Error::Forbidden);
    }
    lifecycle::require_subject_on(c, b.tenant, &b.person).await
}

/// Employee operations retain the existing account, enterprise identity and policy.
pub(super) async fn change(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &DeviceId,
    id: Uuid,
    input: &Change,
    admission: &dyn Admission,
) -> Result<Option<(Binding, Uuid)>, Error> {
    let manager = match service::authorize(c, p, device, Permission::AccountWrite).await {
        Ok(()) => true,
        Err(Error::Forbidden) => false,
        Err(error) => return Err(error),
    };
    if !matches!(input.action, Action::RepairBinding | Action::ResetFactors) {
        return if manager {
            Ok(None)
        } else {
            Err(Error::Forbidden)
        };
    }
    let epoch = registration(c, p, device).await?;
    let tenant = Uuid::parse_str(p.tenant_id()).map_err(|_| Error::Corrupt)?;
    let b = storage::get_in(c, tenant, id).await?;
    if b.device != *device {
        return Err(Error::NotFound);
    }
    let employee = b.person == service::person(p)?;
    if !employee {
        if !manager {
            return Err(Error::Forbidden);
        }
        if matches!(input.action, Action::ResetFactors) {
            return Ok(None);
        }
    }
    owned(c, &b, epoch).await?;
    if b.revision != input.expected_revision {
        return Err(Error::Conflict);
    }
    if matches!(input.action, Action::ResetFactors)
        && (b.intent.platform() != TaskPlatform::Windows
            || matches!(
                b.configuration.windows,
                AccessWindowsConfiguration::Disabled
            ))
    {
        return Err(Error::Unsupported);
    }
    let policy = admission.policy(c, tenant, device, b.policy).await?;
    if policy.version != b.policy_version
        || policy.configuration != b.configuration
        || !policy.configuration.enabled
        || !b
            .account
            .as_ref()
            .is_some_and(|account| policy.configuration.admits(account))
    {
        return Err(Error::Forbidden);
    }
    Ok(employee.then_some((b, epoch)))
}

/// Results keep their original revision. Access follows the current binding owner.
pub(super) async fn receipt(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &DeviceId,
    saved: &Binding,
) -> Result<(), Error> {
    if saved.device != *device || saved.tenant.to_string() != p.tenant_id() {
        return Err(Error::NotFound);
    }
    match service::authorize(c, p, device, Permission::AccountWrite).await {
        Ok(()) => return Ok(()),
        Err(Error::Forbidden) => (),
        Err(e) => return Err(e),
    }
    let Origin::Employee {
        registration_epoch, ..
    } = saved.origin
    else {
        return Err(Error::Forbidden);
    };
    if saved.person != service::person(p)?
        || registration(c, p, device).await? != registration_epoch
    {
        return Err(Error::Forbidden);
    }
    let current = storage::get_in(c, saved.tenant, saved.id).await?;
    if current.device != *device
        || current.person != saved.person
        || current.account != saved.account
        || current.generation != saved.generation
    {
        return Err(Error::Forbidden);
    }
    owned(c, &current, registration_epoch).await
}
