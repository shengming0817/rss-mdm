//! Minimal DA configuration publications in the existing Policy provider.
//! These publications have no Scope identity or Group backend dependency.
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
/// The only supported DA assignment selectors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    /// Default for DA registrations without an explicit override.
    TenantDefault,
    /// An override applies to exactly one DA device.
    Device {
        /// DA device identity, never an Inventory object or Group ID.
        device: String,
    },
}
/// One current publication; previous immutable versions remain queryable.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Publication {
    /// Policy identity.
    pub id: Uuid,
    /// Configuration CAS.
    pub revision: i64,
    /// Immutable definition version.
    pub version: Uuid,
    /// Closed assignment selector.
    pub target: Target,
    /// Disabled overrides deliberately block fallback to the tenant default.
    pub enabled: bool,
    /// Client groups authorized for managed-mandatory transport.
    pub managed_fields: Vec<rss_mdm_agent_wire::da::ConfigurationField>,
    /// Validated device access configuration.
    pub configuration: rss_mdm_agent_wire::runtime::AccessConfiguration,
}
/// Errors before persistence; the host owns audit and settlement.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid publication.
    #[error("invalid DA configuration")]
    Malformed,
    /// Concurrent publication changed the expected revision or assignment.
    #[error("DA configuration changed")]
    Conflict,
    /// PostgreSQL operation failed; its transaction must roll back.
    #[error(transparent)]
    Storage(#[from] sqlx::Error),
}
/// Borrow the Policy aggregate lock without reading an MDM Scope definition.
pub async fn lock_on(c: &mut PgConnection, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT rss_da.lock_policy($1)")
        .bind(id)
        .execute(c)
        .await?;
    Ok(())
}
/// Persist current DA configuration and its immutable version in the caller's transaction.
pub async fn publish_on(
    c: &mut PgConnection,
    tenant: Uuid,
    value: &Publication,
    expected: i64,
    author: serde_json::Value,
    now: i64,
) -> Result<(), Error> {
    use sha2::{Digest, Sha256};
    if value.id.is_nil()
        || value.version.is_nil()
        || expected < 0
        || expected.checked_add(1) != Some(value.revision)
        || now < 0
    {
        return Err(Error::Malformed);
    }
    if value.managed_fields.len() > 2 || value.managed_fields.windows(2).any(|v| v[0] >= v[1]) {
        return Err(Error::Malformed);
    }
    value
        .configuration
        .validate()
        .map_err(|_| Error::Malformed)?;
    if matches!(&value.target,Target::Device{device} if device.is_empty() || device.len()>256) {
        return Err(Error::Malformed);
    }
    lock_on(c, value.id).await?;
    let row=sqlx::query("SELECT revision,version_number FROM rss_da.policies WHERE tenant_id=$1 AND id=$2 FOR UPDATE").bind(tenant).bind(value.id).fetch_optional(&mut *c).await?;
    let (revision, number) = match row {
        Some(r) => (
            r.try_get::<i64, _>("revision")?,
            r.try_get::<i64, _>("version_number")?,
        ),
        None => (0, 0),
    };
    if revision != expected {
        return Err(Error::Conflict);
    }
    let number = number.checked_add(1).ok_or(Error::Malformed)?;
    let definition = serde_json::to_value(value).map_err(|_| Error::Malformed)?;
    let frozen = serde_json::json!({"kind":"device_access","configuration":value.configuration,"publication":value});
    let fingerprint = Sha256::digest(serde_json::to_vec(&frozen).map_err(|_| Error::Malformed)?);
    let result=sqlx::query("INSERT INTO rss_da.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision,current_version=excluded.current_version,version_number=excluded.version_number,state=excluded.state,definition=excluded.definition,author=excluded.author,updated_at=excluded.updated_at")
        .bind(tenant).bind(value.id).bind(value.revision).bind(value.version).bind(number).bind(if value.enabled{"enabled"}else{"disabled"}).bind(definition).bind(author).bind(now).execute(&mut *c).await;
    match result {
        Err(e)
            if e.as_database_error()
                .is_some_and(|e| e.is_unique_violation()) =>
        {
            return Err(Error::Conflict);
        }
        Err(e) => return Err(e.into()),
        Ok(_) => (),
    }
    sqlx::query("INSERT INTO rss_da.policy_versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint) VALUES($1,$2,$3,$4,'device_access',$5,$6)").bind(tenant).bind(value.version).bind(value.id).bind(number).bind(frozen).bind(fingerprint.as_slice()).execute(c).await?;
    Ok(())
}
/// Assignment uniqueness is independent of enablement, so a disabled override cannot widen scope.
pub const INSTALL_SQL:&str="GRANT SELECT,INSERT ON rss_da.policies,rss_da.policy_versions TO da_access,da_identity_runtime;
GRANT UPDATE(revision,current_version,version_number,state,definition,author,updated_at) ON rss_da.policies TO da_access,da_identity_runtime;
GRANT EXECUTE ON FUNCTION rss_da.lock_policy(uuid) TO da_access,da_policy_runtime,da_identity_runtime;
CREATE UNIQUE INDEX da_configuration_target ON rss_da.policies(tenant_id,(definition#>>'{target,kind}'),(coalesce(definition#>>'{target,device}',''))) WHERE definition->'target' IS NOT NULL;";

/// Access profile for the minimal DA publication consumer.
pub const ACCESS_CONTRACT: &str = include_str!("../schema/da-device-access.json");

/// Serialize selector changes, exports and selection on the same borrowed transaction.
pub async fn lock_publications_on(c: &mut PgConnection, tenant: Uuid) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,31291))")
        .bind(tenant.to_string())
        .execute(c)
        .await?;
    Ok(())
}
/// Read one current publication; disabled is an explicit tombstone, never absence.
pub async fn get_on(
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
) -> Result<Option<Publication>, Error> {
    let value: Option<serde_json::Value> = sqlx::query_scalar("SELECT definition FROM rss_da.policies WHERE tenant_id=$1 AND id=$2 AND definition->'target' IS NOT NULL")
        .bind(tenant).bind(id).fetch_optional(c).await?;
    value
        .map(|v| serde_json::from_value(v).map_err(|_| Error::Malformed))
        .transpose()
}
/// Device override or tenant default, including explicit disabled overrides.
pub async fn selected_on(
    c: &mut PgConnection,
    tenant: Uuid,
    device: &str,
) -> Result<Option<Publication>, Error> {
    let value: Option<serde_json::Value> = sqlx::query_scalar("SELECT definition FROM rss_da.policies WHERE tenant_id=$1 AND (definition#>>'{target,kind}'='tenant_default' OR (definition#>>'{target,kind}'='device' AND definition#>>'{target,device}'=$2)) ORDER BY (definition#>>'{target,kind}'='device') DESC LIMIT 1")
        .bind(tenant).bind(device).fetch_optional(c).await?;
    value
        .map(|v| serde_json::from_value(v).map_err(|_| Error::Malformed))
        .transpose()
}

/// Ordered current publications for a tenant directory or an explicitly selected device.
pub async fn directory_on(
    c: &mut PgConnection,
    tenant: Uuid,
    device: Option<&str>,
    query: &rss_mdm_query::directory::Query,
    after: Option<&rss_mdm_query::directory::Position>,
) -> Result<Vec<Publication>, Error> {
    query
        .require_schema(&DIRECTORY_SCHEMA)
        .map_err(|_| Error::Malformed)?;
    let mut sql =
        sqlx::QueryBuilder::new("SELECT definition FROM rss_da.policies WHERE tenant_id=");
    sql.push_bind(tenant)
        .push(" AND definition->'target' IS NOT NULL");
    if let Some(device) = device {
        sql.push(" AND (definition#>>'{target,device}'=")
            .push_bind(device.to_owned())
            .push(")");
    }
    rss_mdm_query_postgres::append(&mut sql, query, after, &*DIRECTORY_BINDINGS)
        .map_err(|_| Error::Malformed)?;
    let rows: Vec<serde_json::Value> = sql.build_query_scalar().fetch_all(c).await?;
    rows.into_iter()
        .map(|row| serde_json::from_value(row).map_err(|_| Error::Malformed))
        .collect()
}
/// Public DA configuration model, including active and explicitly disabled publications.
pub static DIRECTORY_SCHEMA: std::sync::LazyLock<rss_mdm_query::directory::Schema> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query::directory::Schema::derived::<Publication>(
            "da_configurations",
            &["id"],
            64,
            100,
            &[],
        )
        .expect("DA configuration directory model")
    });
/// The same checked mapping is consumed by the HTTP declaration and the actual SQL read.
pub static DIRECTORY_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &DIRECTORY_SCHEMA,
            &[rss_mdm_query_postgres::Source::json("", "definition")],
        )
        .expect("DA configuration binding")
    });

/// Immutable history, including withdrawn publications, in descending revision order.
pub async fn history_on(
    c: &mut PgConnection,
    tenant: Uuid,
    policy: Uuid,
    after: Option<i64>,
    limit: i64,
) -> Result<Vec<Publication>, Error> {
    let values:Vec<serde_json::Value>=sqlx::query_scalar("SELECT frozen->'publication' FROM rss_da.policy_versions WHERE tenant_id=$1 AND policy=$2 AND action_kind='device_access' AND ($3::bigint IS NULL OR number<$3) ORDER BY number DESC LIMIT $4")
        .bind(tenant).bind(policy).bind(after).bind(limit).fetch_all(c).await?;
    values
        .into_iter()
        .map(|v| serde_json::from_value(v).map_err(|_| Error::Malformed))
        .collect()
}
