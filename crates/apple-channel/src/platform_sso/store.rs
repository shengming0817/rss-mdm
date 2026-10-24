//! Borrowed, tenant-fenced transactions. Audit owns all mutation settlement.
use super::*;
use crate::database::db;
use rss_mdm_agent_wire::platform_sso::PublicKey;
use rss_mdm_inventory_service::objects::{DeviceObject, ObjectReader};
use rss_mdm_registration_service::device_access::Binding;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Source {
    pub id: Uuid,
    pub kind: rss_mdm_agent_wire::platform_sso::Kind,
    pub registration: Uuid,
    pub object: DeviceObject,
    pub binding: Option<Uuid>,
    pub binding_generation: i64,
    pub parent: Option<Uuid>,
    pub parent_version: i64,
    pub version: i64,
    pub revoked: bool,
    pub configuration: String,
    pub signing: PublicKey,
    pub encryption: PublicKey,
    pub subject: Option<rss_identity_postgres::platform::PlatformBinding>,
    pub subject_version: Option<rss_identity_postgres::platform::PlatformSubjectVersion>,
}
pub(super) async fn now(c: &mut PgConnection) -> Result<i64, Error> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(c)
        .await
        .map_err(db)
}
pub(super) async fn fence(c: &mut PgConnection, tenant: &str) -> Result<(), Error> {
    sqlx::query("SELECT mdm.lock_asset_watermark($1::uuid)")
        .bind(tenant)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
pub(super) async fn source(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<Source, Error> {
    let row=sqlx::query("SELECT version,revoked,document FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(tenant).bind(id).fetch_optional(c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    let mut source: Source = serde_json::from_value(row.try_get("document").map_err(db)?)
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    source.version = row.try_get("version").map_err(db)?;
    source.revoked = row.try_get("revoked").map_err(db)?;
    if source.id != id {
        return Err(Error::Unauthorized);
    }
    Ok(source)
}
pub(super) async fn put(c: &mut PgConnection, tenant: &str, s: &Source) -> Result<(), Error> {
    sqlx::query("INSERT INTO mdm_apple.psso_sources(tenant_id,id,kind,registration,binding,parent,version,revoked,signing_kid,document) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(tenant_id,id) DO UPDATE SET registration=excluded.registration,parent=excluded.parent,version=excluded.version,revoked=excluded.revoked,signing_kid=excluded.signing_kid,document=excluded.document")
        .bind(tenant).bind(s.id).bind(s.kind.as_str()).bind(s.registration).bind(s.binding).bind(s.parent).bind(s.version).bind(s.revoked).bind(crypto::kid(&s.signing)?).bind(serde_json::to_value(s).map_err(|_|Error::Malformed)?).execute(c).await.map_err(db)?;
    Ok(())
}
pub(super) async fn current_object(
    app: &Context,
    c: &mut PgConnection,
    object: &DeviceObject,
    registration: Uuid,
) -> Result<(), Error> {
    let tenant = app.tenant;
    fence(c, &tenant.to_string()).await?;
    let selected = app
        .platform_objects
        .validate(c, tenant, object, rss_mdm_inventory::Channel::Mdm)
        .await
        .map_err(db)?
        .ok_or(Error::Unauthorized)?;
    if selected.registration_id != registration {
        return Err(Error::Unauthorized);
    }
    let apple:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state='active')").bind(tenant.to_string()).bind(registration).fetch_one(c).await.map_err(db)?;
    if !apple {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub(super) async fn current_user(
    app: &Context,
    c: &mut PgConnection,
    id: Uuid,
    login: bool,
) -> Result<(Source, Source, Binding), Error> {
    let tenant = app.tenant.to_string();
    fence(c, &tenant).await?;
    // Watermark serializes relation and device lifecycle changes before source/parent locks.
    let user = source(c, &tenant, id).await?;
    if user.kind != rss_mdm_agent_wire::platform_sso::Kind::User
        || user.revoked
        || user.configuration != app.runtime()?.fingerprint()?
    {
        return Err(Error::Unauthorized);
    }
    current_object(app, c, &user.object, user.registration).await?;
    if login {
        let now = now(c).await?;
        super::deployment::ready(app, c, &user.object, now).await?;
    }
    let device = source(c, &tenant, user.parent.ok_or(Error::Unauthorized)?).await?;
    if device.kind != rss_mdm_agent_wire::platform_sso::Kind::Device
        || device.revoked
        || device.version != user.parent_version
        || device.registration != user.registration
        || device.object != user.object
        || device.configuration != user.configuration
    {
        return Err(Error::Unauthorized);
    }
    let binding = if login {
        app.execution
            .active_access_binding_on(
                c,
                user.binding.ok_or(Error::Unauthorized)?,
                user.binding_generation,
            )
            .await?
    } else {
        rss_mdm_registration_service::device_access::storage::locked_in(
            c,
            Uuid::parse_str(&tenant).map_err(|_| Error::Malformed)?,
            user.binding.ok_or(Error::Unauthorized)?,
        )
        .await?
    };
    if binding.generation != user.binding_generation
        || binding.state == rss_mdm_registration_service::device_access::State::Revoked
        || !user.object.members.iter().any(|m| {
            m.registration_id == binding.registration
                && m.generation == binding.registration_generation
                && m.device == binding.device
        })
    {
        return Err(Error::Unauthorized);
    }
    if login {
        let config = serde_json::to_value(app.runtime()?.qualification_configuration()?)
            .map_err(|_| Error::Malformed)?;
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_apple.platform_session_qualifications($1,$2,$3) WHERE source_version=$4)")
            .bind(id).bind(config).bind(now(c).await?).bind(user.version).fetch_one(&mut *c).await.map_err(db)?;
        if !valid {
            return Err(Error::Unauthorized);
        }
    }
    Ok((user, device, binding))
}
pub(super) async fn cleanup(c: &mut PgConnection, tenant: &str, time: i64) -> Result<(), Error> {
    for table in ["psso_challenges", "psso_tokens"] {
        // Closed owner table set; no request-controlled SQL identifiers.
        let sql = format!(
            "DELETE FROM mdm_apple.{table} WHERE ctid IN (SELECT ctid FROM mdm_apple.{table} WHERE tenant_id=$1::uuid AND expires_at<$2 ORDER BY expires_at LIMIT 128)"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(tenant)
            .bind(time)
            .execute(&mut *c)
            .await
            .map_err(db)?;
    }
    Ok(())
}
pub(super) async fn read(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<Source, Error> {
    let value: serde_json::Value = sqlx::query_scalar(
        "SELECT document FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(c)
    .await
    .map_err(db)?
    .ok_or(Error::Unauthorized)?;
    let source: Source =
        serde_json::from_value(value).map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    if source.id != id {
        return Err(Error::Unauthorized);
    }
    Ok(source)
}
