//! Product-owned tenant CRUD; installation identity and RSS epochs have separate owners.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
use crate::{
    ConfigIssue, Error, Failure, config,
    migration::{self, Installation},
};
use sqlx::{Connection, PgConnection, Row};
use std::time::Duration;
use uuid::Uuid;

pub const TENANT_LIMIT: i64 = 1024;
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub database: config::Database,
    pub installation: Installation,
    pub tenant_id: String,
    pub initial_epoch: i64,
    pub operation_id: Uuid,
    pub name: Option<String>,
    pub notes: Option<String>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    pub database: config::Database,
    pub installation: Installation,
    pub tenant_id: String,
    pub expected_revision: i64,
    pub operation_id: Uuid,
    pub name: Option<String>,
    pub notes: Option<String>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delete {
    pub database: config::Database,
    pub installation: Installation,
    pub tenant_id: String,
    pub expected_revision: i64,
    pub operation_id: Uuid,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Get {
    pub database: config::Database,
    pub installation: Installation,
    pub tenant_id: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct List {
    pub database: config::Database,
    pub installation: Installation,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub database: config::Database,
    pub installation: Installation,
    pub operation_id: Uuid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Create,
    Update,
    Delete,
}
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Tenant {
    pub tenant_id: String,
    /// Reserved installation tenant; it cannot be updated, deleted or used for business.
    pub management: bool,
    pub initial_epoch: i64,
    pub current_epoch: i64,
    pub name: Option<String>,
    pub notes: Option<String>,
    pub revision: i64,
    pub deletable: bool,
}
/// A durable snapshot; replay never substitutes current tenant state.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub action: Action,
    pub tenant: Tenant,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Reason {
    #[error("invalid input")]
    Invalid,
    #[error("operator rejected")]
    Forbidden,
    #[error("installation identity rejected")]
    Binding,
    #[error("tenant not found")]
    NotFound,
    #[error("operation or revision conflict")]
    Conflict,
    #[error("tenant already used")]
    InUse,
    #[error("reserved management tenant")]
    Reserved,
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
#[error("tenant registry operation={operation_id:?}: {reason} (cleanup_failed={cleanup_failed})")]
pub struct RegistryError {
    pub operation_id: Option<Uuid>,
    pub reason: Reason,
    pub cleanup_failed: bool,
}
fn error(operation_id: Option<Uuid>, reason: Reason) -> RegistryError {
    RegistryError {
        operation_id,
        reason,
        cleanup_failed: false,
    }
}
impl From<Reason> for RegistryError {
    fn from(reason: Reason) -> Self {
        error(None, reason)
    }
}
type Result<T> = std::result::Result<T, Reason>;
type RegistryResult<T> = std::result::Result<T, RegistryError>;
enum Outcome {
    Replay(Receipt),
    Changed(Receipt),
}

struct Mutation<'a> {
    installation: &'a Installation,
    tenant_id: &'a str,
    operation_id: Uuid,
    action: Action,
    initial_epoch: Option<i64>,
    expected_revision: Option<i64>,
    name: Option<&'a str>,
    notes: Option<&'a str>,
}
impl Create {
    fn mutation(&self) -> Mutation<'_> {
        Mutation {
            installation: &self.installation,
            tenant_id: &self.tenant_id,
            operation_id: self.operation_id,
            action: Action::Create,
            initial_epoch: Some(self.initial_epoch),
            expected_revision: None,
            name: self.name.as_deref(),
            notes: self.notes.as_deref(),
        }
    }
}
impl Update {
    fn mutation(&self) -> Mutation<'_> {
        Mutation {
            installation: &self.installation,
            tenant_id: &self.tenant_id,
            operation_id: self.operation_id,
            action: Action::Update,
            initial_epoch: None,
            expected_revision: Some(self.expected_revision),
            name: self.name.as_deref(),
            notes: self.notes.as_deref(),
        }
    }
}
impl Delete {
    fn mutation(&self) -> Mutation<'_> {
        Mutation {
            installation: &self.installation,
            tenant_id: &self.tenant_id,
            operation_id: self.operation_id,
            action: Action::Delete,
            initial_epoch: None,
            expected_revision: Some(self.expected_revision),
            name: None,
            notes: None,
        }
    }
}
fn validate_tenant(installation: &Installation, tenant: &str) -> Result<()> {
    let parsed = rss_request_context::TenantId::parse(tenant).map_err(|_| Reason::Invalid)?;
    if parsed.to_string() != tenant || installation.validate().is_err() {
        return Err(Reason::Invalid);
    }
    Ok(())
}
fn validate(input: &Mutation<'_>) -> Result<()> {
    validate_tenant(input.installation, input.tenant_id)?;
    if input.operation_id.is_nil()
        || input
            .initial_epoch
            .is_some_and(|epoch| rss_transactional_messaging::fence::Epoch::new(epoch).is_err())
        || input
            .expected_revision
            .is_some_and(|revision| revision <= 0)
        || input.name.is_some_and(|name| {
            name.contains('\0') || name.trim().is_empty() || name.chars().count() > 128
        })
        || input
            .notes
            .is_some_and(|notes| notes.contains('\0') || notes.chars().count() > 2048)
    {
        return Err(Reason::Invalid);
    }
    Ok(())
}
pub async fn create(input: Create) -> std::result::Result<Receipt, RegistryError> {
    mutate(&input.database, input.mutation()).await
}
pub async fn update(input: Update) -> std::result::Result<Receipt, RegistryError> {
    mutate(&input.database, input.mutation()).await
}
pub async fn delete(input: Delete) -> std::result::Result<Receipt, RegistryError> {
    mutate(&input.database, input.mutation()).await
}
async fn mutate(
    database: &config::Database,
    input: Mutation<'_>,
) -> std::result::Result<Receipt, RegistryError> {
    let operation = Some(input.operation_id);
    validate(&input).map_err(|r| error(operation, r))?;
    let mut conn = connect(database, operation).await?;
    let result = tokio::time::timeout(Duration::from_secs(30), mutate_on(&mut conn, &input))
        .await
        .unwrap_or(Err(Reason::Deadline.into()));
    settle(conn, operation, result).await
}
pub async fn get(input: Get) -> std::result::Result<Tenant, RegistryError> {
    validate_tenant(&input.installation, &input.tenant_id).map_err(|r| error(None, r))?;
    let mut conn = connect(&input.database, None).await?;
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let mut tx = operator_transaction(&mut conn, &input.installation).await?;
        let result = tenant_on(&mut tx, &input.tenant_id, false).await;
        rollback(tx, result, None).await
    })
    .await
    .unwrap_or(Err(Reason::Deadline.into()));
    settle(conn, None, result).await
}
pub async fn list(input: List) -> std::result::Result<Vec<Tenant>, RegistryError> {
    if input.installation.validate().is_err() {
        return Err(error(None, Reason::Invalid));
    }
    let mut conn = connect(&input.database, None).await?;
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let mut tx = operator_transaction(&mut conn, &input.installation).await?;
        let result: Result<Vec<Tenant>> = async {
            let ids: Vec<String> = sqlx::query_scalar(
            "SELECT tenant_id::text FROM public.mdm_tenants WHERE NOT deleted ORDER BY tenant_id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| Reason::Storage)?;
            let mut tenants = Vec::with_capacity(ids.len());
            for id in ids {
                tenants.push(tenant_on(&mut tx, &id, false).await?);
            }
            Ok(tenants)
        }
        .await;
        rollback(tx, result, None).await
    })
    .await
    .unwrap_or(Err(Reason::Deadline.into()));
    settle(conn, None, result).await
}
/// Wait behind in-flight mutations before observing an absent receipt.
pub async fn query_operation(input: Query) -> std::result::Result<Option<Receipt>, RegistryError> {
    let operation = Some(input.operation_id);
    if input.operation_id.is_nil() || input.installation.validate().is_err() {
        return Err(error(operation, Reason::Invalid));
    }
    let mut conn = connect(&input.database, operation).await?;
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        query_on(&mut conn, &input.installation, input.operation_id),
    )
    .await
    .unwrap_or(Err(Reason::Deadline.into()));
    settle(conn, operation, result).await
}
async fn query_on(
    conn: &mut PgConnection,
    installation: &Installation,
    operation: Uuid,
) -> RegistryResult<Option<Receipt>> {
    let mut tx = operator_transaction(conn, installation).await?;
    let result = receipt_on(&mut tx, operation)
        .await
        .map(|row| row.map(|(receipt, _)| receipt));
    rollback(tx, result, Some(operation)).await
}
async fn connect(
    database: &config::Database,
    operation: Option<Uuid>,
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
    operation: Option<Uuid>,
    result: RegistryResult<T>,
) -> RegistryResult<T> {
    let closed = matches!(
        tokio::time::timeout(Duration::from_secs(5), conn.close()).await,
        Ok(Ok(()))
    );
    match result {
        Err(mut error) => {
            error.operation_id = operation;
            error.cleanup_failed |= !closed;
            Err(error)
        }
        Ok(value) if closed => Ok(value),
        Ok(_) => Err(RegistryError {
            cleanup_failed: true,
            ..error(operation, Reason::Cleanup)
        }),
    }
}
// Transaction::drop queues rollback; callers must not retain a locked connection on rejection.
// ref: sqlx v0.9.0 sqlx-core/src/transaction.rs:269; sqlx-postgres/src/transaction.rs:64
async fn rollback<T>(
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    result: Result<T>,
    operation: Option<Uuid>,
) -> RegistryResult<T> {
    let failed = tx.rollback().await.is_err();
    match result {
        Err(reason) => Err(RegistryError {
            cleanup_failed: failed,
            ..error(operation, reason)
        }),
        Ok(value) if !failed => Ok(value),
        Ok(_) => Err(RegistryError {
            cleanup_failed: true,
            ..error(operation, Reason::Cleanup)
        }),
    }
}
async fn operator_transaction<'a>(
    conn: &'a mut PgConnection,
    installation: &Installation,
) -> RegistryResult<sqlx::Transaction<'a, sqlx::Postgres>> {
    if !migration::owner_admitted(conn)
        .await
        .map_err(|_| Reason::Storage)?
    {
        return Err(Reason::Forbidden.into());
    }
    let mut tx = conn.begin().await.map_err(|_| Reason::Storage)?;
    // Lock waiters must observe the preceding commit even with a session default of RR.
    // ref: https://www.postgresql.org/docs/17/transaction-iso.html#XACT-READ-COMMITTED
    let check: Result<()> = async {
        sqlx::raw_sql("SET TRANSACTION ISOLATION LEVEL READ COMMITTED; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='10s'").execute(&mut *tx).await.map_err(|_| Reason::Storage)?;
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
        Ok(())
    }
    .await;
    if let Err(reason) = check {
        return rollback(tx, Err(reason), None).await;
    }
    Ok(tx)
}
#[cfg(test)]
pub(crate) async fn create_on(conn: &mut PgConnection, input: &Create) -> Result<Receipt> {
    mutate_on(conn, &input.mutation())
        .await
        .map_err(|error| error.reason)
}
async fn mutate_on(conn: &mut PgConnection, input: &Mutation<'_>) -> RegistryResult<Receipt> {
    validate(input)?;
    let mut tx = operator_transaction(conn, input.installation).await?;
    let operation = Some(input.operation_id);
    match apply_on(&mut tx, input).await {
        Ok(Outcome::Changed(receipt)) => {
            tx.commit().await.map_err(|_| Reason::CommitUnknown)?;
            Ok(receipt)
        }
        Ok(Outcome::Replay(receipt)) => rollback(tx, Ok(receipt), operation).await,
        Err(reason) => rollback(tx, Err(reason), operation).await,
    }
}
async fn apply_on(tx: &mut PgConnection, input: &Mutation<'_>) -> Result<Outcome> {
    let request = serde_json::json!({"installation":input.installation,"action":input.action,"tenant_id":input.tenant_id,"initial_epoch":input.initial_epoch,"expected_revision":input.expected_revision,"name":input.name,"notes":input.notes});
    if let Some((receipt, original)) = receipt_on(&mut *tx, input.operation_id).await? {
        if original != request {
            return Err(Reason::Conflict);
        }
        return Ok(Outcome::Replay(receipt));
    }
    scope(&mut *tx, input.tenant_id).await?;
    match input.action {
        Action::Create => {
            let duplicate:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.mdm_tenants WHERE tenant_id=$1::uuid) OR EXISTS(SELECT 1 FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id=$1::uuid)").bind(input.tenant_id).fetch_one(&mut *tx).await.map_err(|_| Reason::Storage)?;
            if duplicate {
                return Err(Reason::Conflict);
            }
            let count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM public.mdm_tenants WHERE NOT deleted AND tenant_id<>(SELECT management_tenant_id FROM public.mdm_installation)")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| Reason::Storage)?;
            if count >= TENANT_LIMIT {
                return Err(Reason::Capacity);
            }
            sqlx::query("INSERT INTO public.mdm_tenants(tenant_id,initial_epoch,name,notes) VALUES($1::uuid,$2,$3,$4)").bind(input.tenant_id).bind(input.initial_epoch).bind(input.name).bind(input.notes).execute(&mut *tx).await.map_err(|_| Reason::Storage)?;
            sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch(tenant_id,epoch) VALUES($1::uuid,$2)").bind(input.tenant_id).bind(input.initial_epoch).execute(&mut *tx).await.map_err(|_| Reason::Storage)?;
            rss_mdm_inventory_postgres::initialize_fields_in(
                &mut *tx,
                rss_request_context::TenantId::parse(input.tenant_id)
                    .map_err(|_| Reason::Invalid)?,
            )
            .await
            .map_err(|_| Reason::Storage)?;
            rss_mdm_registration_service::agent::settings::initialize_on(&mut *tx, input.tenant_id)
                .await
                .map_err(|_| Reason::Storage)?;
        }
        Action::Update | Action::Delete => {
            let tenant = tenant_on(&mut *tx, input.tenant_id, false).await?;
            if tenant.management {
                return Err(Reason::Reserved);
            }
            if Some(tenant.revision) != input.expected_revision || tenant.revision == i64::MAX {
                return Err(Reason::Conflict);
            }
            if input.action == Action::Delete {
                if !tenant.deletable {
                    return Err(Reason::InUse);
                }
                sqlx::query("UPDATE public.mdm_tenants SET deleted=true,revision=revision+1 WHERE tenant_id=$1::uuid").bind(input.tenant_id).execute(&mut *tx).await.map_err(|_| Reason::Storage)?;
            } else {
                sqlx::query("UPDATE public.mdm_tenants SET name=$2,notes=$3,revision=revision+1 WHERE tenant_id=$1::uuid").bind(input.tenant_id).bind(input.name).bind(input.notes).execute(&mut *tx).await.map_err(|_| Reason::Storage)?;
            }
        }
    }
    let receipt = Receipt {
        operation_id: input.operation_id,
        action: input.action,
        tenant: tenant_on(&mut *tx, input.tenant_id, true).await?,
    };
    sqlx::query("INSERT INTO public.mdm_tenant_operations(operation_id,tenant_id,action,request,receipt) VALUES($1,$2::uuid,$3,$4,$5)").bind(input.operation_id).bind(input.tenant_id).bind(serde_json::to_value(input.action).map_err(|_| Reason::Storage)?.as_str().ok_or(Reason::Storage)?).bind(request).bind(serde_json::to_value(&receipt).map_err(|_| Reason::Storage)?).execute(&mut *tx).await.map_err(|_| Reason::Storage)?;
    Ok(Outcome::Changed(receipt))
}
async fn scope(conn: &mut PgConnection, tenant: &str) -> Result<()> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(conn)
        .await
        .map_err(|_| Reason::Storage)?;
    Ok(())
}
async fn tenant_on(conn: &mut PgConnection, tenant: &str, include_deleted: bool) -> Result<Tenant> {
    scope(conn, tenant).await?;
    let row=sqlx::query("SELECT t.tenant_id::text,t.tenant_id=i.management_tenant_id AS management,t.initial_epoch,e.epoch AS current_epoch,t.name,t.notes,t.revision,NOT(t.used OR t.deleted OR t.tenant_id=i.management_tenant_id) AS deletable FROM public.mdm_tenants t JOIN rss_transactional_messaging.tenant_epoch e USING(tenant_id) CROSS JOIN public.mdm_installation i WHERE t.tenant_id=$1::uuid AND ($2 OR NOT t.deleted)").bind(tenant).bind(include_deleted).fetch_optional(conn).await.map_err(|_| Reason::Storage)?.ok_or(Reason::NotFound)?;
    Ok(Tenant {
        tenant_id: row.try_get("tenant_id").map_err(|_| Reason::Storage)?,
        management: row.try_get("management").map_err(|_| Reason::Storage)?,
        initial_epoch: row.try_get("initial_epoch").map_err(|_| Reason::Storage)?,
        current_epoch: row.try_get("current_epoch").map_err(|_| Reason::Storage)?,
        name: row.try_get("name").map_err(|_| Reason::Storage)?,
        notes: row.try_get("notes").map_err(|_| Reason::Storage)?,
        revision: row.try_get("revision").map_err(|_| Reason::Storage)?,
        deletable: row.try_get("deletable").map_err(|_| Reason::Storage)?,
    })
}
async fn receipt_on(
    conn: &mut PgConnection,
    operation: Uuid,
) -> Result<Option<(Receipt, serde_json::Value)>> {
    let row = sqlx::query(
        "SELECT receipt,request FROM public.mdm_tenant_operations WHERE operation_id=$1",
    )
    .bind(operation)
    .fetch_optional(conn)
    .await
    .map_err(|_| Reason::Storage)?;
    row.map(|row| {
        Ok((
            serde_json::from_value(row.try_get("receipt").map_err(|_| Reason::Storage)?)
                .map_err(|_| Reason::Storage)?,
            row.try_get("request").map_err(|_| Reason::Storage)?,
        ))
    })
    .transpose()
}

#[path = "tenant_use.rs"]
mod tenant_use;
pub(crate) use tenant_use::{ACCESS_CONTRACT, claim_database_use, claim_use, verify_read_profile};
#[cfg(test)]
#[path = "../tests/tenant_registry/mod.rs"]
mod tests;
