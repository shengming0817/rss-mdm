//! Scrub this owner's sealed inputs only after the channel proves it will not dispatch them again.
use crate::control::*;
use std::{future::Future, pin::Pin};
pub trait ChannelCopies: Send + Sync {
    fn purge_in<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: &'a str,
        operation: Uuid,
        command: &'a rss_device_command::Command,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<bool, Error>> + Send + 'a>>;
}
pub struct Copies {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    protection: Arc<rss_mdm_native_protection::Protector>,
    store: rss_device_command_postgres::PgStore<()>,
    channel: Arc<dyn ChannelCopies>,
}
impl Copies {
    pub async fn bind(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        protection: Arc<rss_mdm_native_protection::Protector>,
        channel: Arc<dyn ChannelCopies>,
    ) -> std::result::Result<Self, Error> {
        let caller = runtime.clone();
        let (_, store) = runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    storage::bind_command_in(
                        caller,
                        tx,
                        rss_device_command_postgres::CommandClock::Postgres,
                    )
                    .await
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::CommandStorage)),
                |_| Err(Error::Unavailable(Failure::CommandStorage)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::CommandStorage)),
            )?;
        Ok(Self {
            runtime,
            tenant,
            protection,
            store,
            channel,
        })
    }
    pub async fn purge_in(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool> {
        self.runtime.validate_transaction(tx)?;
        if self.tenant != tx.tenant_id() {
            return Err(Error::Forbidden.into());
        }
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT id FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(tenant).bind(id).fetch_one(c).await.map(|_|())})).await?;
        let mut op = storage::load(tx, &self.protection, id).await?;
        let command = self
            .store
            .load(tx, op.scope, &op.command_id()?)
            .await?
            .ok_or(Error::Conflict)?;
        let tenant = tx.tenant_id().to_string();
        let state = tx
            .with_connection_context(
                &mut (&self.channel, &tenant, &command),
                |(channel, tenant, command), c| {
                    Box::pin(async move { Ok(channel.purge_in(c, tenant, id, command).await) })
                },
            )
            .await??;
        if !state {
            return Ok(state);
        }
        if let Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::Command { command },
        } = &mut op.request.task
        {
            for key in [
                "PIN",
                "Password",
                "CurrentPassword",
                "NewPassword",
                "FileVaultUnlock",
            ] {
                command.fields.0.remove(key);
            }
        }
        let (_, sealed) = input_storage::seal(
            &self.protection,
            self.tenant,
            &input_storage::Identity {
                operation: id,
                device: &op.device,
                registration: op.registration,
                generation: op.registration_generation,
            },
            &op.request,
        )?;
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_devices.control_operations SET request=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(sealed).execute(c).await.map(|_|())})).await?;
        Ok(true)
    }
}
