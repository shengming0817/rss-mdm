//! Bind one device to its RSS command fencing coordinate in the original transaction.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs.
use rss_device_command::{self as dc, Store};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sqlx::Row;
use uuid::Uuid;
#[derive(Debug, thiserror::Error)]
pub enum CommandAuthorityError {
    #[error("device is not active")]
    Conflict,
    #[error(transparent)]
    Registration(#[from] crate::Error),
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}
pub struct CommandAuthority {
    pub scope: dc::Scope,
    pub coordinate: dc::Coordinate,
}
fn valid<T, E>(value: Result<T, E>) -> Result<T, CommandAuthorityError> {
    value.map_err(|_| CommandAuthorityError::Conflict)
}
pub async fn resolve_in(
    store: &rss_device_command_postgres::PgStore<()>,
    tx: &mut PgTransaction<'_>,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<CommandAuthority, CommandAuthorityError> {
    let tenant = tx.tenant_id();
    let name = device.to_owned();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::lifecycle::require_work_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                &tenant.to_string(),
                &name,
            )
            .await)
        })
    })
    .await??;
    let name = device.to_owned();
    let active: bool = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2 AND channel='mdm' AND state='active')")
            .bind(tenant.to_string()).bind(name.into_uuid()).fetch_one(c).await
    })).await?;
    if !active {
        return Err(CommandAuthorityError::Conflict);
    }
    let name = device.to_owned();
    let row = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT command_device::text,generation,epoch FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE")
            .bind(tenant.to_string()).bind(name.into_uuid()).fetch_optional(c).await
    })).await?;
    if let Some(row) = row {
        return Ok(CommandAuthority {
            scope: dc::Scope::new(
                tenant,
                valid(dc::DeviceId::parse(
                    &row.try_get::<String, _>("command_device")?,
                ))?,
            ),
            coordinate: valid(dc::Coordinate::new(
                row.try_get("generation")?,
                row.try_get("epoch")?,
            ))?,
        });
    }
    let command_device = Uuid::new_v4();
    let scope = dc::Scope::new(
        tenant,
        valid(dc::DeviceId::parse(&command_device.to_string()))?,
    );
    let coordinate = valid(dc::Coordinate::new(1, 1))?;
    let name = device.to_owned();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_access.command_authorities(tenant_id,device,command_device,generation,epoch) VALUES($1::uuid,$2,$3,1,1)")
            .bind(tenant.to_string()).bind(name.into_uuid()).bind(command_device).execute(c).await?;
        Ok(())
    })).await?;
    store.initialize(tx, scope, coordinate).await?;
    Ok(CommandAuthority { scope, coordinate })
}
/// Bind an existing RSS operation to its original device.
#[derive(Clone)]
pub struct CommandBinding {
    pub operation: Uuid,
    pub device: rss_mdm_agent_wire::DeviceId,
}
