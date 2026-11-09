//! Immutable protocol correlation to the existing RSS command and wire device.
use rss_mdm_registration_service::command_authority::CommandBinding;
use rss_request_context::TenantId;
use sqlx::PgConnection;
pub async fn bind_on(
    c: &mut PgConnection,
    tenant: TenantId,
    binding: CommandBinding,
) -> Result<(), crate::Error> {
    let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_device_command.commands c JOIN mdm_access.command_authorities a ON(a.tenant_id,a.command_device,a.generation,a.epoch)=(c.tenant_id,c.device_id,c.generation,c.authority_epoch) JOIN mdm_access.devices d ON(d.tenant_id,d.id)=(a.tenant_id,a.device) WHERE c.tenant_id=$1::uuid AND c.command_id=$2 AND d.id=$3 AND d.state='active')")
        .bind(tenant.to_string()).bind(binding.operation.to_string()).bind(&binding.device)
        .fetch_one(&mut *c).await.map_err(|_|crate::Error::Unavailable(crate::Failure::Database))?;
    if !valid {
        return Err(crate::Error::Conflict);
    }
    sqlx::query("INSERT INTO mdm_apple.native_commands (tenant_id, id, device) VALUES (CAST($1 AS uuid), $2, $3) ON CONFLICT DO NOTHING")
        .bind(tenant.to_string()).bind(binding.operation).bind(&binding.device)
        .execute(&mut *c).await.map_err(|_|crate::Error::Unavailable(crate::Failure::Database))?;
    let same: bool = sqlx::query_scalar("SELECT device = $3 FROM mdm_apple.native_commands WHERE tenant_id = CAST($1 AS uuid) AND id = $2")
        .bind(tenant.to_string()).bind(binding.operation).bind(&binding.device)
        .fetch_one(c).await.map_err(|_|crate::Error::Unavailable(crate::Failure::Database))?;
    if !same {
        return Err(crate::Error::Conflict);
    }
    Ok(())
}

/// Immutable channel evidence; existence does not grant business ownership or authorization.
pub async fn execute_was_sent_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    id: uuid::Uuid,
) -> Result<bool, crate::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute' AND state<>'pending')").bind(tenant.to_string()).bind(id).fetch_one(c).await.map_err(crate::database::db)
}
