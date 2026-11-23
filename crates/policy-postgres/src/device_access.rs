//! Minimal DA configuration publications in the existing Policy provider.
//! These publications have no Scope identity or Group backend dependency.
use rss_mdm_agent_wire::da::Publication;
use rss_mdm_agent_wire::da::{ConfigurationField, FieldAuthority, PolicyAuthority};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use std::collections::BTreeMap;
use uuid::Uuid;
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
    let previous: Option<sqlx::types::Json<BTreeMap<ConfigurationField, FieldAuthority>>> =
        sqlx::query_scalar(
            "SELECT v.frozen->'fieldAuthority' FROM rss_da.policies p
             JOIN rss_da.policy_versions v ON (v.tenant_id,v.id)=(p.tenant_id,p.current_version)
             WHERE p.tenant_id=$1 AND p.id=$2 AND p.revision=$3 AND v.action_kind='device_access'",
        )
        .bind(tenant)
        .bind(value.id)
        .bind(expected)
        .fetch_optional(&mut *c)
        .await?;
    if expected > 0 && previous.is_none() {
        return Err(Error::Conflict);
    }
    let mut fields = previous.map(|v| v.0).unwrap_or_default();
    for field in [ConfigurationField::Mac, ConfigurationField::Windows] {
        let authorized = value.managed_fields.contains(&field);
        if fields.get(&field).is_some_and(|v| v.authorized) != authorized {
            fields.insert(
                field,
                FieldAuthority {
                    authorized,
                    revision: value.revision as u64,
                },
            );
        }
    }
    let definition = serde_json::to_value(value).map_err(|_| Error::Malformed)?;
    let frozen = serde_json::json!({"kind":"device_access","configuration":value.configuration,
        "publication":value, "fieldAuthority":fields});
    persist(
        c,
        tenant,
        value.id,
        value.version,
        value.revision,
        expected,
        value.enabled,
        "device_access",
        definition,
        frozen,
        author,
        now,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "shared Policy CAS and immutable version rows are written together on the caller's connection"
)]
async fn persist(
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
    version: Uuid,
    revision: i64,
    expected: i64,
    enabled: bool,
    kind: &str,
    definition: serde_json::Value,
    frozen: serde_json::Value,
    author: serde_json::Value,
    now: i64,
) -> Result<(), Error> {
    use sha2::{Digest, Sha256};
    lock_on(c, id).await?;
    let row=sqlx::query("SELECT revision,version_number,definition FROM rss_da.policies WHERE tenant_id=$1 AND id=$2 FOR UPDATE").bind(tenant).bind(id).fetch_optional(&mut *c).await?;
    let (current_revision, number) = match row {
        Some(r) => {
            let previous: serde_json::Value = r.try_get("definition")?;
            if previous.get("device") != definition.get("device")
                || previous.get("target").is_some() != definition.get("target").is_some()
            {
                return Err(Error::Conflict);
            }
            (
                r.try_get::<i64, _>("revision")?,
                r.try_get::<i64, _>("version_number")?,
            )
        }
        None => (0, 0),
    };
    if current_revision != expected {
        return Err(Error::Conflict);
    }
    let number = number.checked_add(1).ok_or(Error::Malformed)?;
    let fingerprint = Sha256::digest(serde_json::to_vec(&frozen).map_err(|_| Error::Malformed)?);
    let result=sqlx::query("INSERT INTO rss_da.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision,current_version=excluded.current_version,version_number=excluded.version_number,state=excluded.state,definition=excluded.definition,author=excluded.author,updated_at=excluded.updated_at")
        .bind(tenant).bind(id).bind(revision).bind(version).bind(number).bind(if enabled{"enabled"}else{"disabled"}).bind(definition).bind(author).bind(now).execute(&mut *c).await;
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
    sqlx::query("INSERT INTO rss_da.policy_versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(tenant).bind(version).bind(id).bind(number).bind(kind).bind(frozen).bind(fingerprint.as_slice()).execute(c).await?;
    Ok(())
}
/// Assignment uniqueness is independent of enablement, so a disabled override cannot widen scope.
pub const INSTALL_SQL:&str="GRANT SELECT,INSERT ON rss_da.policies,rss_da.policy_versions TO da_access,da_identity_runtime;
GRANT UPDATE(revision,current_version,version_number,state,definition,author,updated_at) ON rss_da.policies TO da_access,da_identity_runtime;
GRANT EXECUTE ON FUNCTION rss_da.lock_policy(uuid) TO da_access,da_policy_runtime,da_identity_runtime;
CREATE UNIQUE INDEX da_configuration_target ON rss_da.policies(tenant_id,(definition#>>'{target,kind}'),((definition#>>'{target,device}')::uuid)) NULLS NOT DISTINCT WHERE definition->'target' IS NOT NULL;";

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
/// All applicable issuers under the publication fence, with the selected backend first.
pub async fn applicable_on(
    c: &mut PgConnection,
    tenant: Uuid,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Vec<(Publication, PolicyAuthority)>, Error> {
    let rows = sqlx::query(
        "SELECT p.definition, v.frozen->'fieldAuthority' AS fields
         FROM rss_da.policies p LEFT JOIN rss_da.policy_versions v
           ON (v.tenant_id,v.id)=(p.tenant_id,p.current_version)
         WHERE p.tenant_id=$1 AND (p.definition#>>'{target,kind}'='tenant_default'
             OR (p.definition#>>'{target,kind}'='device' AND (p.definition#>>'{target,device}')::uuid=$2))
         ORDER BY (p.definition#>>'{target,kind}'='device') DESC",
    )
    .bind(tenant).bind(device.into_uuid()).fetch_all(c).await?;
    rows.into_iter()
        .map(|row| {
            let publication = row
                .try_get::<sqlx::types::Json<Publication>, _>("definition")?
                .0;
            let fields = row.try_get::<sqlx::types::Json<_>, _>("fields")?.0;
            let authority = PolicyAuthority {
                policy: publication.id,
                version: publication.version,
                revision: publication.revision as u64,
                enabled: publication.enabled,
                fields,
            };
            Ok((publication, authority))
        })
        .collect()
}

/// Ordered current publications for a tenant directory or an explicitly selected device.
pub async fn directory_on(
    c: &mut PgConnection,
    tenant: Uuid,
    device: Option<&rss_mdm_agent_wire::DeviceId>,
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
        sql.push(" AND ((definition#>>'{target,device}')::uuid=")
            .push_bind(device.into_uuid())
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

/// A Credential Policy assigned to one DA device, independent of login configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialPublication {
    /// Stable Policy aggregate.
    pub id: Uuid,
    /// Caller-selected immutable version and retry identity.
    pub version: Uuid,
    /// Next aggregate revision, starting at one.
    pub revision: i64,
    /// Exact device owned by the current DA tenant.
    pub device: rss_mdm_agent_wire::DeviceId,
    /// Exact RSS Login binding, generation, account and authorized action.
    pub operation: rss_mdm_policy::CredentialOperation,
    /// Whether new and in-flight executions can use this version.
    pub enabled: bool,
    /// First authorized UNIX second.
    pub not_before: i64,
    /// Exclusive end of the authorization window.
    pub expires_at: i64,
    /// Maximum lifetime of a single accepted execution in seconds.
    pub run_lifetime_seconds: u32,
}
impl CredentialPublication {
    /// Determine the original execution deadline under the current Policy window.
    pub fn deadline(&self, now: i64) -> Option<i64> {
        (self.enabled && self.not_before <= now && now < self.expires_at).then(|| {
            self.expires_at
                .min(now.saturating_add(i64::from(self.run_lifetime_seconds)))
        })
    }
    /// Insert an immutable credential authorization, or replay its exact already-committed publication.
    pub async fn publish(
        &self,
        c: &mut PgConnection,
        tenant: Uuid,
        author: serde_json::Value,
        now: i64,
    ) -> Result<bool, Error> {
        use rss_mdm_policy::CredentialOperation::{RotateRssLogin, VerifyRssLogin};
        if self.id.is_nil()
            || self.version.is_nil()
            || self.revision < 1
            || self.not_before < 0
            || self.expires_at <= self.not_before
            || !(60..=604800).contains(&self.run_lifetime_seconds)
            || !matches!(
                self.operation,
                VerifyRssLogin { .. } | RotateRssLogin { .. }
            )
            || self.operation.validate().is_err()
        {
            return Err(Error::Malformed);
        }
        lock_on(c, self.id).await?;
        if let Some(prior) = Self::read(c, tenant, self.version, false).await? {
            return if prior == *self {
                Ok(true)
            } else {
                Err(Error::Conflict)
            };
        }
        let definition = serde_json::to_value(self).map_err(|_| Error::Malformed)?;
        let frozen = serde_json::json!({"kind":"credential","publication":self});
        persist(
            c,
            tenant,
            self.id,
            self.version,
            self.revision,
            self.revision - 1,
            self.enabled,
            "credential",
            definition,
            frozen,
            author,
            now,
        )
        .await?;
        Ok(false)
    }
    /// Read an exact immutable version and optionally fence the owning current policy for execution.
    pub async fn read(
        c: &mut PgConnection,
        tenant: Uuid,
        version: Uuid,
        current: bool,
    ) -> Result<Option<Self>, Error> {
        let row: Option<(Uuid,serde_json::Value)> = sqlx::query_as(
            "SELECT policy,frozen->'publication' FROM rss_da.policy_versions WHERE tenant_id=$1 AND id=$2 AND action_kind='credential'")
            .bind(tenant).bind(version).fetch_optional(&mut *c).await?;
        let Some((owner, frozen)) = row else {
            return Ok(None);
        };
        if current {
            lock_on(c, owner).await?;
            let selected: Option<Uuid> = sqlx::query_scalar("SELECT current_version FROM rss_da.policies WHERE tenant_id=$1 AND id=$2 AND state='enabled'")
                .bind(tenant).bind(owner).fetch_optional(c).await?;
            if selected != Some(version) {
                return Ok(None);
            }
        }
        let result: Self = serde_json::from_value(frozen).map_err(|_| Error::Malformed)?;
        if result.id != owner || result.version != version {
            return Err(Error::Malformed);
        }
        Ok(Some(result))
    }
}
