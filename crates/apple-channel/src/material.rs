//! Confidential protocol material belongs to one authenticated registration scope.
use crate::{Error, Failure};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
fn failed() -> Error {
    Error::Unavailable(Failure::AppleStorage)
}
pub(crate) fn aad(
    tenant: &str,
    registration: Uuid,
    generation: i64,
    user: &str,
    revision: i64,
    purpose: &str,
) -> Result<DerivedAad, Error> {
    let tenant = TenantId::parse(tenant).map_err(|_| failed())?;
    let owner =
        serde_json::to_string(&(registration, generation, user, revision)).map_err(|_| failed())?;
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
            &aad(
                &tenant,
                p.registration(),
                p.generation(),
                user,
                0,
                "apple.push.compare",
            )?,
        )
        .map_err(|_| failed())?;
    let old=sqlx::query("SELECT generation,state,token_revision,material_digest,push_outcome FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND registration=$2 AND user_key=$3 FOR UPDATE").bind(&tenant).bind(p.registration()).bind(user).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
    let revision = if let Some(old) = old {
        if old
            .try_get::<i64, _>("generation")
            .map_err(crate::database::db)?
            != p.generation()
        {
            return Err(Error::Unauthorized);
        }
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
            &aad(
                &tenant,
                p.registration(),
                p.generation(),
                user,
                revision,
                "apple.push.material",
            )?,
        )
        .map_err(|_| failed())?;
    sqlx::query("INSERT INTO mdm_apple.channels(tenant_id,registration,generation,user_key,state,material,material_digest,token_revision) VALUES($1::uuid,$2,$3,$4,'active',$5,$6,$7) ON CONFLICT(tenant_id,registration,user_key) DO UPDATE SET state='active',material=EXCLUDED.material,material_digest=EXCLUDED.material_digest,token_revision=EXCLUDED.token_revision,next_push=clock_timestamp(),push_id=NULL,push_lease_until=NULL,push_status=NULL,push_outcome=NULL,push_failures=0")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(user).bind(sealed).bind(digest.as_slice()).bind(revision).execute(&mut *c).await.map_err(crate::database::db)?;
    if user.is_empty() {
        sqlx::query("UPDATE mdm_apple.devices SET state='active' WHERE tenant_id=$1::uuid AND registration=$2").bind(&tenant).bind(p.registration()).execute(&mut *c).await.map_err(crate::database::db)?;
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
    let value:Option<serde_json::Value>=sqlx::query_scalar("SELECT context FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND accepted AND context IS NOT NULL AND user_key='' ORDER BY received_at DESC,id DESC LIMIT 1").bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).fetch_optional(c).await.map_err(crate::database::db)?;
    let context = value
        .map(serde_json::from_value::<rss_mdm_apple_mdm::applicability::Context>)
        .transpose()
        .map_err(|_| failed())?
        .ok_or(Error::Unsupported)?;
    rss_mdm_apple_mdm::protocol::bootstrap_allowed(&context).map_err(Into::into)
}
