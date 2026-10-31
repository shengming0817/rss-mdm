//! The registration owner binds the single RSS command fencing coordinate to the management root.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs (borrow the original connection).
use rss_device_command::{self as dc, Store};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sqlx::Row;
use uuid::Uuid;
#[derive(Debug, thiserror::Error)]
pub enum CommandAuthorityError {
    #[error("command registration changed")]
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
    pub root_registration: Uuid,
    pub root_generation: i64,
}
fn valid<T, E>(value: Result<T, E>) -> Result<T, CommandAuthorityError> {
    value.map_err(|_| CommandAuthorityError::Conflict)
}
pub async fn resolve_in(
    store: &rss_device_command_postgres::PgStore<()>,
    tx: &mut PgTransaction<'_>,
    device: &str,
    registration: Uuid,
    registration_generation: i64,
) -> Result<CommandAuthority, CommandAuthorityError> {
    let tenant = tx.tenant_id();
    let name = device.to_owned();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::device::store::lock_channel(
                c,
                &tenant.to_string(),
                &name,
                rss_mdm_inventory::Channel::Mdm,
            )
            .await)
        })
    })
    .await??;
    let name = device.to_owned();
    let registration_active: bool = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 AND device=$4 AND channel='mdm' AND state='active')")
            .bind(tenant.to_string()).bind(registration).bind(registration_generation).bind(name).fetch_one(c).await
    })).await?;
    if !registration_active {
        return Err(CommandAuthorityError::Conflict);
    }

    let (registration, registration_generation) = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(crate::device::read::management_root_in(
                    c,
                    tenant.to_string(),
                    registration,
                    registration_generation,
                )
                .await)
            })
        })
        .await??;
    let name = device.to_owned();
    let row=tx.with_connection(|c|Box::pin(async move {sqlx::query("SELECT command_device::text,generation,epoch,registration::text,registration_generation FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE").bind(tenant.to_string()).bind(&name).fetch_optional(c).await})).await?;
    if let Some(row) = row {
        let scope = dc::Scope::new(
            tenant,
            valid(dc::DeviceId::parse(
                &row.try_get::<String, _>("command_device")?,
            ))?,
        );
        let old = valid(dc::Coordinate::new(
            row.try_get("generation")?,
            row.try_get("epoch")?,
        ))?;
        if row.try_get::<String, _>("registration")? == registration.to_string()
            && row.try_get::<i64, _>("registration_generation")? == registration_generation
        {
            return Ok(CommandAuthority {
                scope,
                coordinate: old,
                root_registration: registration,
                root_generation: registration_generation,
            });
        }
        let next = valid(dc::Coordinate::new(
            old.generation(),
            old.epoch()
                .checked_add(1)
                .ok_or(CommandAuthorityError::Conflict)?,
        ))?;
        store.advance(tx, scope, old, next).await?;
        let name = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_access.command_authorities SET epoch=$3,registration=$4::uuid,registration_generation=$5 WHERE tenant_id=$1::uuid AND device=$2").bind(tenant.to_string()).bind(name).bind(next.epoch()).bind(registration.to_string()).bind(registration_generation).execute(c).await?;Ok(())})).await?;
        Ok(CommandAuthority {
            scope,
            coordinate: next,
            root_registration: registration,
            root_generation: registration_generation,
        })
    } else {
        let uuid = Uuid::new_v4();
        let scope = dc::Scope::new(tenant, valid(dc::DeviceId::parse(&uuid.to_string()))?);
        let coordinate = valid(dc::Coordinate::new(1, 1))?;
        let name = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_access.command_authorities(tenant_id,device,command_device,generation,epoch,registration,registration_generation) VALUES($1::uuid,$2,$3::uuid,1,1,$4::uuid,$5)").bind(tenant.to_string()).bind(name).bind(uuid.to_string()).bind(registration.to_string()).bind(registration_generation).execute(c).await?;Ok(())})).await?;
        store.initialize(tx, scope, coordinate).await?;
        Ok(CommandAuthority {
            scope,
            coordinate,
            root_registration: registration,
            root_generation: registration_generation,
        })
    }
}
/// Protocol binding of an existing RSS command to its actual wire registration.
#[derive(Clone, Copy)]
pub struct CommandBinding {
    pub operation: Uuid,
    pub registration: Uuid,
    pub generation: i64,
}
