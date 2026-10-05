//! Product-owned registration; installation identity and the RSS epoch have separate owners.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
use crate::{
    ConfigIssue, Error, Failure, config,
    migration::{self, Installation},
};
use sqlx::{Connection, PgConnection, Row};
use std::time::Duration;
use uuid::Uuid;

/// Registration policy, independent of any host's single-tenant binding.
pub const TENANT_LIMIT: i64 = 1024;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub database: config::Database,
    pub installation: Installation,
    pub tenant_id: String,
    pub initial_epoch: i64,
    pub operation_id: Uuid,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub database: config::Database,
    pub installation: Installation,
    pub operation_id: Uuid,
}
/// Durable evidence of the registration transaction, not account or business authorization.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub tenant_id: String,
    pub initial_epoch: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Reason {
    #[error("invalid input")]
    Invalid,
    #[error("operator rejected")]
    Forbidden,
    #[error("installation identity rejected")]
    Binding,
    #[error("registration conflict")]
    Conflict,
    #[error("tenant limit reached")]
    Capacity,
    #[error("storage unavailable")]
    Storage,
    #[error("commit result unknown; query or replay the operation")]
    CommitUnknown,
    #[error("deadline; result unknown; query or replay the operation")]
    Deadline,
    #[error("connection cleanup failed")]
    Cleanup,
}
#[derive(Clone, Debug, thiserror::Error)]
#[error("tenant registration operation={operation_id}: {reason} (cleanup_failed={cleanup_failed})")]
pub struct RegistryError {
    pub operation_id: Uuid,
    pub reason: Reason,
    pub cleanup_failed: bool,
}
fn error(operation_id: Uuid, reason: Reason) -> RegistryError {
    RegistryError {
        operation_id,
        reason,
        cleanup_failed: false,
    }
}
type Result<T> = std::result::Result<T, Reason>;

pub async fn register(input: Register) -> std::result::Result<Receipt, RegistryError> {
    validate(&input).map_err(|r| error(input.operation_id, r))?;
    let mut conn = connect(&input.database, input.operation_id).await?;
    let result = tokio::time::timeout(Duration::from_secs(30), register_on(&mut conn, &input))
        .await
        .unwrap_or(Err(Reason::Deadline));
    settle(conn, input.operation_id, result).await
}
/// Waits behind in-flight installation/registration before observing an absent receipt.
pub async fn query_operation(input: Query) -> std::result::Result<Option<Receipt>, RegistryError> {
    if input.operation_id.is_nil() || input.installation.validate().is_err() {
        return Err(error(input.operation_id, Reason::Invalid));
    }
    let mut conn = connect(&input.database, input.operation_id).await?;
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let mut tx = operator_transaction(&mut conn, &input.installation).await?;
        let row = receipt_on(&mut tx, input.operation_id).await?;
        tx.rollback().await.map_err(|_| Reason::Storage)?;
        Ok(row.map(|(receipt, _)| receipt))
    })
    .await
    .unwrap_or(Err(Reason::Deadline));
    settle(conn, input.operation_id, result).await
}
async fn connect(
    database: &config::Database,
    operation: Uuid,
) -> std::result::Result<PgConnection, RegistryError> {
    if database.user != "mdm_owner" {
        return Err(error(operation, Reason::Forbidden));
    }
    let options = database
        .options()
        .map_err(|_| error(operation, Reason::Invalid))?;
    tokio::time::timeout(Duration::from_secs(5), PgConnection::connect_with(&options))
        .await
        .map_err(|_| error(operation, Reason::Storage))?
        .map_err(|_| error(operation, Reason::Storage))
}
async fn settle<T>(
    conn: PgConnection,
    operation: Uuid,
    result: Result<T>,
) -> std::result::Result<T, RegistryError> {
    let closed = matches!(
        tokio::time::timeout(Duration::from_secs(5), conn.close()).await,
        Ok(Ok(()))
    );
    match result {
        Err(reason) => Err(RegistryError {
            cleanup_failed: !closed,
            ..error(operation, reason)
        }),
        Ok(value) if closed => Ok(value),
        Ok(_) => Err(RegistryError {
            cleanup_failed: true,
            ..error(operation, Reason::Cleanup)
        }),
    }
}
fn validate(input: &Register) -> Result<()> {
    use rss_transactional_messaging::fence::Epoch;
    let tenant =
        rss_request_context::TenantId::parse(&input.tenant_id).map_err(|_| Reason::Invalid)?;
    if input.operation_id.is_nil()
        || tenant.to_string() != input.tenant_id
        || input.installation.validate().is_err()
    {
        return Err(Reason::Invalid);
    }
    Epoch::new(input.initial_epoch).map_err(|_| Reason::Invalid)?;
    Ok(())
}
async fn operator_transaction<'a>(
    conn: &'a mut PgConnection,
    installation: &Installation,
) -> Result<sqlx::Transaction<'a, sqlx::Postgres>> {
    if !migration::owner_admitted(conn)
        .await
        .map_err(|_| Reason::Storage)?
    {
        return Err(Reason::Forbidden);
    }
    let mut tx = conn.begin().await.map_err(|_| Reason::Storage)?;
    sqlx::raw_sql("SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='10s'")
        .execute(&mut *tx)
        .await
        .map_err(|_| Reason::Storage)?;
    sqlx::query("SELECT pg_advisory_xact_lock(2346)")
        .execute(&mut *tx)
        .await
        .map_err(|_| Reason::Storage)?;
    migration::verify_current_manifest(&mut tx)
        .await
        .map_err(|_| Reason::Storage)?;
    migration::verify_identity(&mut tx, installation)
        .await
        .map_err(|_| Reason::Binding)?;
    Ok(tx)
}
pub(crate) async fn register_on(conn: &mut PgConnection, input: &Register) -> Result<Receipt> {
    validate(input)?;
    let mut tx = operator_transaction(conn, &input.installation).await?;
    let request = serde_json::json!({"installation":input.installation,"tenant_id":input.tenant_id,"initial_epoch":input.initial_epoch});
    if let Some((receipt, original)) = receipt_on(&mut tx, input.operation_id).await? {
        if original != request {
            return Err(Reason::Conflict);
        }
        tx.rollback().await.map_err(|_| Reason::Storage)?;
        return Ok(receipt);
    }
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(&input.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| Reason::Storage)?;
    let duplicate: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.mdm_tenants WHERE tenant_id=$1::uuid) OR EXISTS(SELECT 1 FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id=$1::uuid)")
        .bind(&input.tenant_id).fetch_one(&mut *tx).await.map_err(|_| Reason::Storage)?;
    if duplicate {
        return Err(Reason::Conflict);
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM public.mdm_tenants")
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| Reason::Storage)?;
    if count >= TENANT_LIMIT {
        return Err(Reason::Capacity);
    }
    sqlx::query("INSERT INTO public.mdm_tenants(tenant_id,initial_epoch) VALUES($1::uuid,$2)")
        .bind(&input.tenant_id)
        .bind(input.initial_epoch)
        .execute(&mut *tx)
        .await
        .map_err(|_| Reason::Storage)?;
    sqlx::query(
        "INSERT INTO rss_transactional_messaging.tenant_epoch(tenant_id,epoch) VALUES($1::uuid,$2)",
    )
    .bind(&input.tenant_id)
    .bind(input.initial_epoch)
    .execute(&mut *tx)
    .await
    .map_err(|_| Reason::Storage)?;
    rss_mdm_registration_service::agent::settings::initialize_on(&mut tx, &input.tenant_id)
        .await
        .map_err(|_| Reason::Storage)?;
    sqlx::query("INSERT INTO public.mdm_tenant_registrations(operation_id,tenant_id,initial_epoch,request) VALUES($1,$2::uuid,$3,$4)")
        .bind(input.operation_id).bind(&input.tenant_id).bind(input.initial_epoch).bind(request).execute(&mut *tx).await.map_err(|_| Reason::Storage)?;
    tx.commit().await.map_err(|_| Reason::CommitUnknown)?;
    Ok(Receipt {
        operation_id: input.operation_id,
        tenant_id: input.tenant_id.clone(),
        initial_epoch: input.initial_epoch,
    })
}
async fn receipt_on(
    conn: &mut PgConnection,
    operation: Uuid,
) -> Result<Option<(Receipt, serde_json::Value)>> {
    let row = sqlx::query("SELECT tenant_id::text,initial_epoch,request FROM public.mdm_tenant_registrations WHERE operation_id=$1").bind(operation).fetch_optional(conn).await.map_err(|_| Reason::Storage)?;
    row.map(|row| {
        Ok((
            Receipt {
                operation_id: operation,
                tenant_id: row.try_get("tenant_id").map_err(|_| Reason::Storage)?,
                initial_epoch: row.try_get("initial_epoch").map_err(|_| Reason::Storage)?,
            },
            row.try_get("request").map_err(|_| Reason::Storage)?,
        ))
    })
    .transpose()
}

/// Read-only binding validation. Never substitutes a current epoch for the caller's expected epoch.
pub(crate) async fn verify_binding(
    conn: &mut PgConnection,
    installation: &Installation,
    tenant: &str,
    expected_epoch: i64,
) -> std::result::Result<(), Error> {
    if installation.validate().is_err()
        || rss_request_context::TenantId::parse(tenant).is_err()
        || rss_transactional_messaging::fence::Epoch::new(expected_epoch).is_err()
    {
        return Err(Error::Configuration(ConfigIssue::IdentityConfiguration));
    }
    let mut tx = conn
        .begin()
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    sqlx::query(
        "SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','2000',true)",
    )
    .bind(tenant)
    .execute(&mut *tx)
    .await
    .map_err(|_| Error::Unavailable(Failure::Database))?;
    verify_read_profile(&mut tx).await?;
    migration::verify_identity(&mut tx, installation)
        .await
        .map_err(|_| Error::Configuration(ConfigIssue::IdentityConfiguration))?;
    let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.mdm_tenants t JOIN rss_transactional_messaging.tenant_epoch e USING(tenant_id) WHERE tenant_id=$1::uuid AND e.epoch=$2)")
        .bind(tenant).bind(expected_epoch).fetch_one(&mut *tx).await.map_err(|_| Error::Unavailable(Failure::Database))?;
    tx.rollback()
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    if !valid {
        return Err(Error::Configuration(ConfigIssue::IdentityConfiguration));
    }
    Ok(())
}

/// These installation-owned read relations augment the closed access-role union.
pub(crate) const ACCESS_CONTRACT: &str = r#"{"tables":[],"functions":[],"external_relations":["public.mdm_installation","public.mdm_tenants","rss_transactional_messaging.tenant_epoch"],"verified_schemas":[]}"#;
pub(crate) async fn verify_read_profile(conn: &mut PgConnection) -> std::result::Result<(), Error> {
    let valid: bool = sqlx::query_scalar("SELECT bool_and(has_table_privilege(current_user,r,'SELECT') AND NOT has_table_privilege(current_user,r,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND NOT has_any_column_privilege(current_user,r,'INSERT,UPDATE,REFERENCES')) FROM unnest(ARRAY['public.mdm_installation','public.mdm_tenants','rss_transactional_messaging.tenant_epoch']) r")
        .fetch_one(conn).await.map_err(|_| Error::Unavailable(Failure::AccessAdmission))?;
    if !valid {
        return Err(Error::Unavailable(Failure::AccessAdmission));
    }
    Ok(())
}
pub(crate) async fn verify_database_binding(
    database: &config::Database,
    installation: &Installation,
    tenant: &str,
    epoch: i64,
) -> std::result::Result<(), Error> {
    let mut conn = tokio::time::timeout(
        Duration::from_secs(5),
        PgConnection::connect_with(&database.options()?),
    )
    .await
    .map_err(|_| Error::Unavailable(Failure::Database))?
    .map_err(|_| Error::Unavailable(Failure::Database))?;
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        verify_binding(&mut conn, installation, tenant, epoch),
    )
    .await
    .unwrap_or(Err(Error::Unavailable(Failure::Database)));
    let closed = matches!(
        tokio::time::timeout(Duration::from_secs(5), conn.close()).await,
        Ok(Ok(()))
    );
    match result {
        Err(error) => Err(error),
        Ok(()) if closed => Ok(()),
        Ok(()) => Err(Error::Unavailable(Failure::Database)),
    }
}

#[cfg(test)]
#[path = "../tests/tenant_registry/mod.rs"]
mod tests;
