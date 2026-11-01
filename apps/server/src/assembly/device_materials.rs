//! Static mapping from Device material needs to credential custody.
use rss_mdm_device_service::control::{Error, Failure, Target};
use std::{future::Future, pin::Pin};
pub(super) struct Pins(pub rss_mdm_recovery_credentials::lock_pin::LockPins);
impl rss_mdm_device_service::control::lock_pin::LockPins for Pins {
    fn hold_in<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: uuid::Uuid,
        target: &'a Target,
        operation: uuid::Uuid,
        pin: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .hold_in(
                    c,
                    tenant,
                    &target.device,
                    target.registration,
                    target.generation,
                    operation,
                    pin,
                )
                .await
                .map_err(|e| match e {
                    rss_mdm_recovery_credentials::Error::CommitUnknown => Error::CommitUnknown,
                    rss_mdm_recovery_credentials::Error::RollbackFailed => Error::RollbackFailed,
                    rss_mdm_recovery_credentials::Error::Conflict => Error::Conflict,
                    rss_mdm_recovery_credentials::Error::Forbidden => Error::Forbidden,
                    rss_mdm_recovery_credentials::Error::Malformed => Error::Malformed,
                    _ => Error::Unavailable(Failure::NativeProtection),
                })
        })
    }
}

pub(super) struct Channel(pub std::sync::Arc<rss_mdm_apple_channel::flow_store::Store>);
impl rss_mdm_device_service::control::credential_inputs::ChannelCopies for Channel {
    fn purge_in<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: &'a str,
        operation: uuid::Uuid,
        command: &'a rss_device_command::Command,
    ) -> Pin<Box<dyn Future<Output = Result<bool, Error>> + Send + 'a>> {
        Box::pin(async move {
            use rss_mdm_recovery_credentials::cleanup::{ChannelCopies, CopyState};
            self.0
                .purge_in(c, tenant, operation, command)
                .await
                .map(|state| state == CopyState::Purged)
                .map_err(|e| match e {
                    rss_mdm_recovery_credentials::Error::CommitUnknown => Error::CommitUnknown,
                    rss_mdm_recovery_credentials::Error::RollbackFailed => Error::RollbackFailed,
                    rss_mdm_recovery_credentials::Error::Conflict => Error::Conflict,
                    _ => Error::Unavailable(Failure::NativeProtection),
                })
        })
    }
}
