//! Confidential protocol material belongs to one authenticated device scope.
use crate::{Error, Failure};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
fn failed() -> Error {
    Error::Unavailable(Failure::AppleStorage)
}
pub(crate) fn aad(
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,

    user: &str,
    revision: i64,
    purpose: &str,
) -> Result<DerivedAad, Error> {
    aad_coordinate(tenant, device.into_uuid(), user, revision, purpose)
}
pub(crate) fn aad_coordinate(
    tenant: &str,
    coordinate: uuid::Uuid,
    user: &str,
    revision: i64,
    purpose: &str,
) -> Result<DerivedAad, Error> {
    let tenant = TenantId::parse(tenant).map_err(|_| failed())?;
    let owner = serde_json::to_string(&(coordinate, user, revision)).map_err(|_| failed())?;
    ProtectionContext::new(tenant, &owner, purpose, 1)
        .map(|context| context.derive())
        .map_err(|_| failed())
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Push {
    pub token: Vec<u8>,
    pub magic: String,
}
pub(crate) async fn token(
    c: &mut PgConnection,
    protection: &Protector,
    p: &crate::device::DevicePrincipal,
    user: &str,
    token: &[u8],
    magic: &str,
) -> Result<Option<i64>, Error> {
    if magic.len() > 1024 {
        return Err(Error::Malformed);
    }
    let tenant = p.tenant().to_string();
    let plain = zeroize::Zeroizing::new(
        serde_json::to_vec(&Push {
            token: token.to_vec(),
            magic: magic.into(),
        })
        .map_err(|_| failed())?,
    );
    let digest = protection
        .mac(
            &plain,
            &aad(&tenant, p.device(), user, 0, "apple.push.compare")?,
        )
        .map_err(|_| failed())?;
    let old=sqlx::query("SELECT state, token_revision, material_digest, push_outcome FROM mdm_apple.channels WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND user_key = $3 FOR UPDATE").bind(&tenant).bind(p.device().into_uuid()).bind(user).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
    let revision = if let Some(old) = old {
        if old
            .try_get::<String, _>("state")
            .map_err(crate::database::db)?
            == "active"
            && old
                .try_get::<Option<Vec<u8>>, _>("material_digest")
                .map_err(crate::database::db)?
                .as_deref()
                == Some(digest.as_slice())
            && old
                .try_get::<Option<String>, _>("push_outcome")
                .map_err(crate::database::db)?
                .as_deref()
                != Some("rejected")
        {
            return Ok(None);
        }
        old.try_get::<i64, _>("token_revision")
            .map_err(crate::database::db)?
            .checked_add(1)
            .ok_or_else(failed)?
    } else {
        1
    };
    let sealed = protection
        .seal_bytes(
            &plain,
            &aad(&tenant, p.device(), user, revision, "apple.push.material")?,
        )
        .map_err(|_| failed())?;
    sqlx::query("INSERT INTO mdm_apple.channels (tenant_id, device, user_key, state, material, material_digest, token_revision) VALUES (CAST($1 AS uuid), $2, $3, 'active', $4, $5, $6) ON CONFLICT (tenant_id, device, user_key) DO UPDATE SET state = 'active', material = excluded.material, material_digest = excluded.material_digest, token_revision = excluded.token_revision, next_push = clock_timestamp(), push_id = NULL, push_lease_until = NULL, push_status = NULL, push_outcome = NULL, push_failures = 0")
        .bind(&tenant).bind(p.device().into_uuid()).bind(user).bind(sealed).bind(digest.as_slice()).bind(revision).execute(&mut *c).await.map_err(crate::database::db)?;
    if user.is_empty() {
        sqlx::query("UPDATE mdm_apple.devices SET state = 'active' WHERE tenant_id = CAST($1 AS uuid) AND device = $2").bind(&tenant).bind(p.device().into_uuid()).execute(&mut *c).await.map_err(crate::database::db)?;
    }
    crate::notify(c, "apple")
        .await
        .map_err(crate::database::db)?;
    Ok(Some(revision))
}

pub(crate) async fn bootstrap_allowed(
    c: &mut PgConnection,
    p: &crate::device::DevicePrincipal,
) -> Result<(), Error> {
    let value:Option<serde_json::Value>=sqlx::query_scalar("SELECT context FROM mdm_apple.attempts WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND accepted AND context IS NOT NULL AND user_key = '' ORDER BY received_at DESC, id DESC LIMIT 1").bind(p.tenant().to_string()).bind(p.device().into_uuid()).fetch_optional(c).await.map_err(crate::database::db)?;
    let context = value
        .map(serde_json::from_value::<rss_mdm_apple_mdm::applicability::Context>)
        .transpose()
        .map_err(|_| failed())?
        .ok_or(Error::Unsupported)?;
    rss_mdm_apple_mdm::protocol::bootstrap_allowed(&context).map_err(Into::into)
}
