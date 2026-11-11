//! Read-only PKI projections borrowed by an already authorized enrollment owner.
use crate::Error;
use rss_mdm_query::{
    Page,
    cursor::CursorCodec,
    directory::{Projection, Query, Schema},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

#[derive(Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Prepared,
    Signing,
    Unknown,
    Issued,
    Superseded,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Signing {
    pub attempt: Uuid,
    pub state: State,
    pub issuer: String,
    pub created_at: i64,
    pub deadline: i64,
    pub not_before: i64,
    pub not_after: i64,
    pub successor: Option<Uuid>,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIdentity {
    pub actor: String,
    pub instance: String,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    #[schemars(extend("x-rss-maxUtf8Bytes" = 1024))]
    pub actor: String,
    pub instance: String,
    pub operation_id: Uuid,
}
pub static OPERATIONS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema::derived::<Operation>("windows_signing_recovery_operations", &["actor", "operationId"], rss_mdm_query::DEFAULT_PAGE_LIMIT, rss_mdm_query::MAX_PAGE_LIMIT, &[]).expect("Public directory model"));
fn db(_: sqlx::Error) -> Error {
    Error::Storage
}
fn query_error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::CursorInvalidated,
        _ => Error::Request,
    }
}
/// Caller proves the attempt belongs to its authorized device and owns the read snapshot.
pub async fn read_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    attempt: Uuid,
) -> Result<Signing, Error> {
    read_many_in(profile, c, tenant, &[attempt])
        .await?
        .remove(&attempt)
        .ok_or(Error::Storage)
}
pub async fn read_many_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    attempts: &[Uuid],
) -> Result<std::collections::BTreeMap<Uuid, Signing>, Error> {
    let rows = sqlx::query(crate::storage_profile::sql(profile).signing_queries_read_many_in_1)
        .bind(tenant)
        .bind(attempts)
        .fetch_all(c)
        .await
        .map_err(db)?;
    let mut result = std::collections::BTreeMap::new();
    for row in rows {
        let attempt: Uuid = row.try_get("attempt").map_err(db)?;
        let bytes: Vec<u8> = row.try_get("binding").map_err(db)?;
        use sha2::Digest;
        let frozen: crate::signing::Frozen =
            serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
        if sha2::Sha256::digest(&bytes).as_slice()
            != row.try_get::<Vec<u8>, _>("digest").map_err(db)?
            || frozen.purpose != row.try_get::<String, _>("purpose").map_err(db)?
            || frozen.issuer != row.try_get::<String, _>("issuer").map_err(db)?
        {
            return Err(Error::Storage);
        }
        result.insert(
            attempt,
            Signing {
                attempt,
                state: serde_json::from_value(serde_json::Value::String(
                    row.try_get("state").map_err(db)?,
                ))
                .map_err(|_| Error::Storage)?,
                issuer: frozen.issuer,
                created_at: row.try_get("created_at").map_err(db)?,
                deadline: row.try_get("deadline").map_err(db)?,
                not_before: frozen.start,
                not_after: frozen.end,
                successor: row.try_get("successor").map_err(db)?,
            },
        );
    }
    Ok(result)
}

/// Caller supplies an authorization-bound query binding, never a client identity assertion.
pub async fn operations_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    attempt: Uuid,
    q: &Query,
    codec: &CursorCodec,
    binding: &str,
) -> Result<Page<Projection<Operation>>, Error> {
    q.require_schema(&OPERATIONS).map_err(query_error)?;
    let after = q.after(codec, binding).map_err(query_error)?;
    let mut sql = sqlx::QueryBuilder::new(
        crate::storage_profile::sql(profile).signing_queries_operations_in_1,
    );
    sql.push_bind(tenant.to_owned())
        .push("::uuid AND signing_recovery_attempt=")
        .push_bind(attempt)
        .push(" AND phase='signing_recover'");
    rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*OPERATION_BINDINGS).map_err(query_error)?;
    let rows: Vec<serde_json::Value> = sql.build_query_scalar().fetch_all(c).await.map_err(db)?;
    let rows = rows
        .into_iter()
        .map(serde_json::from_value::<Operation>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Storage)?;
    q.page_typed(rows, codec, binding).map_err(query_error)
}
/// Exact original receipt; absence never proves that an in-flight operation rolled back.
pub async fn operation_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    attempt: Uuid,
    operation: Uuid,
    identity: &ReceiptIdentity,
) -> Result<Option<crate::recovery::Receipt>, Error> {
    if identity.actor.is_empty()
        || identity.instance.is_empty()
        || identity.actor.len() > 1024
        || identity.instance.len() > 1024
        || operation.is_nil()
    {
        return Err(Error::Request);
    }
    let row = sqlx::query(crate::storage_profile::sql(profile).signing_queries_operation_in_1)
        .bind(tenant)
        .bind(&identity.actor)
        .bind(operation)
        .bind(attempt)
        .fetch_optional(c)
        .await
        .map_err(db)?;
    row.map(|row| {
        if row.try_get::<String, _>("instance").map_err(db)? != identity.instance {
            return Err(Error::Conflict);
        }
        let receipt: crate::recovery::Receipt =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("receipt").map_err(db)?)
                .map_err(|_| Error::Storage)?;
        let chain: Vec<Vec<u8>> =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("chain").map_err(db)?)
                .map_err(|_| Error::Storage)?;
        if receipt.attempt != attempt
            || receipt.fingerprint
                != rss_mdm_device_trust::digest(chain.first().ok_or(Error::Storage)?)
        {
            return Err(Error::Storage);
        }
        Ok(receipt)
    })
    .transpose()
}

pub static OPERATION_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> = std::sync::LazyLock::new(|| rss_mdm_query_postgres::Bindings::new(&OPERATIONS, &[rss_mdm_query_postgres::Source::required_column("actor", "actor COLLATE \"C\""),
rss_mdm_query_postgres::Source::required_column("operationId", "operation::text COLLATE \"C\""),
rss_mdm_query_postgres::Source::column("instance", "instance COLLATE \"C\"")]).expect("Complete public model storage binding"));
