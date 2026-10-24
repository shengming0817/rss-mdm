//! Password login reserves one nonce, calls the IdP without SQL locks, then rechecks all authority.
//! ref: Apple AuthenticationServices/creating-and-validating-a-login-request.
use super::{Context, crypto, service, store};
use crate::{Error, Failure, database::db};
use rss_mdm_agent_wire::platform_sso::{
    AuthenticationMode, GRANT, LOGIN_TYPE, SCOPE, TOKEN_SECONDS,
};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Encryption {
    alg: String,
    enc: String,
    apv: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    client_id: String,
    aud: String,
    sub: String,
    username: String,
    iat: i64,
    exp: i64,
    nonce: String,
    request_nonce: String,
    scope: String,
    grant_type: String,
    jwe_crypto: Encryption,
    #[serde(deserialize_with = "password")]
    password: Zeroizing<String>,
}
fn password<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Clone, Serialize, Deserialize)]
struct Reservation {
    user: store::Source,
    device: Uuid,
    device_version: i64,
    principal: Uuid,
    client_nonce: String,
    apv: String,
}
struct Prepared {
    id: Uuid,
    expires: i64,
    started_at: i64,
    reservation: Reservation,
    provider: Arc<super::password_provider::Provider>,
}
/// Discriminate the signed device request without materializing confidential JSON into a Value.
pub(super) async fn is_password(app: &Context, token: &str) -> Result<bool, Error> {
    let kid = crypto::signing_key_id(token)?;
    let mut tx = app.access.begin(&app.tenant.to_string()).await?;
    let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND kind='device' AND signing_kid=$2 AND NOT revoked")
        .bind(app.tenant.to_string()).bind(kid).fetch_optional(&mut *tx).await.map_err(db)?;
    let device = store::read(
        &mut tx,
        &app.tenant.to_string(),
        id.ok_or(Error::Unauthorized)?,
    )
    .await?;
    tx.rollback().await.map_err(db)?;
    let bytes = crypto::verified_payload(
        token,
        device.signing.as_ref().ok_or(Error::Unauthorized)?,
        LOGIN_TYPE,
    )?;
    #[derive(Deserialize)]
    struct Method {
        grant_type: String,
    }
    let method: Method = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
    match method.grant_type.as_str() {
        "password" => Ok(true),
        GRANT => Ok(false),
        _ => Err(Error::Malformed),
    }
}
pub(super) async fn login(
    app: &Context,
    audit: &RequestAudit,
    token: &str,
) -> Result<Value, Error> {
    let kid = crypto::signing_key_id(token)?;
    let mut read = app.access.begin(&app.tenant.to_string()).await?;
    let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM mdm_apple.psso_sources WHERE tenant_id=$1::uuid AND kind='device' AND signing_kid=$2 AND NOT revoked")
        .bind(app.tenant.to_string()).bind(&kid).fetch_optional(&mut *read).await.map_err(db)?;
    let device = store::read(
        &mut read,
        &app.tenant.to_string(),
        id.ok_or(Error::Unauthorized)?,
    )
    .await?;
    read.rollback().await.map_err(db)?;
    let bytes = crypto::verified_payload(
        token,
        device.signing.as_ref().ok_or(Error::Unauthorized)?,
        LOGIN_TYPE,
    )?;
    let claims: Claims = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
    drop(bytes);
    let user = Uuid::parse_str(&claims.sub).map_err(|_| Error::Unauthorized)?;
    let budget = AuditBudget::new(Duration::from_secs(10));
    let operation = Uuid::new_v4();
    audit.operation(operation, "apple_platform_password");
    let prepared = app
        .audit_store
        .write(
            app.tenant,
            &budget.source_control(),
            (app, &claims, &device, user, audit, operation),
            |(app, claims, device, user, audit, operation), tx| {
                Box::pin(async move {
                    let prepared = tx
                        .with_connection_context(
                            &mut (*app, *claims, *device, *user),
                            |(app, claims, device, user), c| {
                                Box::pin(prepare(app, c, claims, device, *user))
                            },
                        )
                        .await?;
                    let fact = Fact::business(
                        audit,
                        &format!("psso-password-prepare:{operation}"),
                        prepared.id.as_bytes(),
                        200,
                        "success",
                        None,
                    )?;
                    app.audit_store.append(tx, &fact, false).await?;
                    audit.mark_commit_started();
                    Ok(prepared)
                })
            },
        )
        .await;
    let prepared: Prepared = crate::operations::settle(prepared, audit)?;
    let verified = tokio::time::timeout(
        Duration::from_secs(8),
        prepared.provider.verify(
            prepared
                .reservation
                .user
                .password_identity
                .as_ref()
                .ok_or(Error::Unauthorized)?,
            &claims.password,
            prepared.started_at,
        ),
    )
    .await
    .unwrap_or(Err(Error::Unavailable(Failure::RequestDeadline)));
    drop(claims);
    let state = match &verified {
        Ok(()) => "succeeded",
        Err(Error::Unauthorized | Error::Forbidden) => "rejected",
        Err(_) => "unavailable",
    };
    let final_budget = AuditBudget::new(Duration::from_secs(5));
    let result = app
        .audit_store
        .write(
            app.tenant,
            &final_budget.source_control(),
            (app, &prepared, state, audit, operation),
            |(app, prepared, state, audit, operation), tx| {
                Box::pin(async move {
                    let value = tx
                        .with_connection_context(
                            &mut (*app, *prepared, *state),
                            |(app, prepared, state), c| Box::pin(finish(app, c, prepared, state)),
                        )
                        .await?;
                    let fact = Fact::business(
                        audit,
                        &format!("psso-password-finish:{operation}"),
                        prepared.id.as_bytes(),
                        if *state == "succeeded" {
                            200
                        } else if *state == "rejected" {
                            401
                        } else {
                            503
                        },
                        match *state {
                            "succeeded" => "success",
                            "rejected" => "denied",
                            _ => "unknown",
                        },
                        None,
                    )?;
                    app.audit_store.append(tx, &fact, false).await?;
                    audit.mark_commit_started();
                    Ok(value)
                })
            },
        )
        .await;
    let result = crate::operations::settle(result, audit)?;
    verified?;
    Ok(result)
}
async fn prepare(
    app: &Context,
    c: &mut PgConnection,
    claims: &Claims,
    device: &store::Source,
    id: Uuid,
) -> Result<Prepared, Error> {
    let tenant = app.tenant.to_string();
    let candidate = store::read(c, &tenant, id).await?;
    service::admit(app, c, &candidate).await?;
    let (user, parent, binding) = store::current_user(app, c, id, false).await?;
    let now = store::now(c).await?;
    super::deployment::ready(app, c, &user.object, now).await?;
    let rt = app.runtime()?;
    if user.login_configuration.authentication != AuthenticationMode::Password
        || user.signing.is_some()
        || parent.id != device.id
        || parent.version != device.version
        || parent.signing != device.signing
        || user.subject != candidate.subject
        || user.subject_version != candidate.subject_version
        || claims.iss != rt.configuration.client_id.to_string()
        || claims.client_id != claims.iss
        || claims.aud != rt.endpoints.token
        || claims.username != claims.sub
        || claims.sub != user.id.to_string()
        || claims.scope != SCOPE
        || claims.grant_type != "password"
        || claims.iat > now
        || claims.iat < now.saturating_sub(300)
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.exp.saturating_sub(claims.iat) > 300
        || claims.request_nonce.len() != 43
        || !(16..=256).contains(&claims.nonce.len())
        || claims.jwe_crypto.alg != "ECDH-ES"
        || claims.jwe_crypto.enc != "A256GCM"
        || claims.jwe_crypto.apv.len() > 4096
        || claims.password.is_empty()
        || claims.password.len() > 4096
    {
        return Err(Error::Unauthorized);
    }
    let provider = rt.password_provider(&user.login_configuration)?;
    provider.check_on(c, app.tenant).await?;
    if user.password_identity.as_ref().is_none_or(|identity| {
        identity.person != binding.person || identity.provider != provider.configuration.id
    }) {
        return Err(Error::Unauthorized);
    }
    sqlx::query("DELETE FROM mdm_apple.psso_password_attempts WHERE tenant_id=$1::uuid AND id IN(SELECT id FROM mdm_apple.psso_password_attempts WHERE tenant_id=$1::uuid AND expires_at<$2-86400 ORDER BY expires_at LIMIT 128)")
        .bind(&tenant).bind(now).execute(&mut *c).await.map_err(db)?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_apple.psso_password_attempts WHERE tenant_id=$1::uuid",
    )
    .bind(&tenant)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if count >= 4096 {
        return Err(Error::Unavailable(Failure::Capacity));
    }
    let accepted: Option<Uuid> = sqlx::query_scalar("UPDATE mdm_apple.psso_challenges SET consumed=true WHERE tenant_id=$1::uuid AND purpose='login' AND nonce_digest=$2 AND NOT consumed AND expires_at>$3 RETURNING id")
        .bind(&tenant).bind(crypto::digest(&claims.request_nonce)).bind(now).fetch_optional(&mut *c).await.map_err(db)?;
    let id = accepted.ok_or(Error::Unauthorized)?;
    let reservation = Reservation {
        user,
        device: parent.id,
        device_version: parent.version,
        principal: binding.person.principal,
        client_nonce: claims.nonce.clone(),
        apv: claims.jwe_crypto.apv.clone(),
    };
    let expires = claims.exp.min(now + 120);
    sqlx::query("INSERT INTO mdm_apple.psso_password_attempts(tenant_id,id,source,version,provider,provider_fingerprint,context,expires_at,state) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,'verifying')")
        .bind(&tenant).bind(id).bind(reservation.user.id).bind(reservation.user.version).bind(provider.configuration.id)
        .bind(provider.fingerprint()?).bind(serde_json::to_value(&reservation).map_err(|_| Error::Malformed)?).bind(expires)
        .execute(c).await.map_err(db)?;
    Ok(Prepared {
        id,
        expires,
        started_at: now,
        reservation,
        provider,
    })
}
async fn finish(
    app: &Context,
    c: &mut PgConnection,
    prepared: &Prepared,
    state: &str,
) -> Result<Value, Error> {
    let tenant = app.tenant.to_string();
    service::admit(app, c, &prepared.reservation.user).await?;
    let (user, parent, binding) =
        store::current_user(app, c, prepared.reservation.user.id, false).await?;
    let now = store::now(c).await?;
    super::deployment::ready(app, c, &user.object, now).await?;
    prepared.provider.check_on(c, app.tenant).await?;
    if now >= prepared.expires
        || user.version != prepared.reservation.user.version
        || user.configuration != prepared.reservation.user.configuration
        || user.login_configuration != prepared.reservation.user.login_configuration
        || user.subject != prepared.reservation.user.subject
        || user.subject_version != prepared.reservation.user.subject_version
        || parent.id != prepared.reservation.device
        || parent.version != prepared.reservation.device_version
        || binding.person.principal != prepared.reservation.principal
    {
        return Err(Error::Unauthorized);
    }
    let row = sqlx::query("SELECT state,context,provider_fingerprint FROM mdm_apple.psso_password_attempts WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
        .bind(&tenant).bind(prepared.id).fetch_one(&mut *c).await.map_err(db)?;
    if row.try_get::<String, _>("state").map_err(db)? != "verifying"
        || row.try_get::<Value, _>("context").map_err(db)?
            != serde_json::to_value(&prepared.reservation).map_err(|_| Error::Malformed)?
        || row
            .try_get::<String, _>("provider_fingerprint")
            .map_err(db)?
            != prepared.provider.fingerprint()?
    {
        return Err(Error::Conflict);
    }
    let result = if state == "succeeded" {
        let access = crypto::random()?;
        let refresh = crypto::random()?;
        sqlx::query("DELETE FROM mdm_apple.psso_tokens WHERE tenant_id=$1::uuid AND source=$2")
            .bind(&tenant)
            .bind(user.id)
            .execute(&mut *c)
            .await
            .map_err(db)?;
        sqlx::query("INSERT INTO mdm_apple.psso_tokens(tenant_id,digest,source,version,expires_at) VALUES($1::uuid,$2,$3,$4,$5)")
            .bind(&tenant).bind(crypto::digest(&access)).bind(user.id).bind(user.version).bind(now+TOKEN_SECONDS).execute(&mut *c).await.map_err(db)?;
        super::native::response(
            app.runtime()?,
            &user,
            &prepared.reservation.client_nonce,
            &prepared.reservation.apv,
            now,
            &access,
            &refresh,
        )?
    } else {
        json!({"state":state})
    };
    sqlx::query(
        "UPDATE mdm_apple.psso_password_attempts SET state=$3 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(&tenant)
    .bind(prepared.id)
    .bind(state)
    .execute(c)
    .await
    .map_err(db)?;
    Ok(result)
}
