use super::{
    enrollment,
    protocol::{self, CheckIn},
};
use crate::Failure;
use crate::HttpState;
use crate::{Error, database::db};
use axum::{Extension, body::Bytes, extract::State, http::StatusCode};
use sqlx::Row;
use std::sync::Arc;

pub async fn checkin(
    State(app): State<Arc<HttpState>>,
    Extension(peer): Extension<rss_mdm_certificate::HandshakePeer>,
    Extension(audit): Extension<RequestAudit>,
    bytes: Bytes,
) -> Result<axum::response::Response, Error> {
    use axum::response::IntoResponse;
    let apple = app.apple()?;
    let leaf = apple.authority.verify(
        peer.chain(),
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let dictionary = protocol::decode(&bytes)?;
    let input = protocol::checkin(&dictionary)?;
    let udid = match input {
        CheckIn::Authenticate { udid, topic } | CheckIn::TokenUpdate { udid, topic, .. } => {
            if topic != apple.config.apns_topic {
                return Err(Error::Unauthorized);
            }
            Some(udid)
        }
        CheckIn::CheckOut { udid } | CheckIn::UserAuthenticate { udid, .. } => Some(udid),
        CheckIn::SetBootstrapToken { .. } | CheckIn::GetBootstrapToken => dictionary
            .get("UDID")
            .map(|_| protocol::text(&dictionary, "UDID"))
            .transpose()?,
    };
    if let Some(udid) = udid {
        super::renewal::activate(&app, &leaf, udid).await?;
    }
    let credential = app.mount.credential(leaf.fingerprint());
    if matches!(input, CheckIn::Authenticate { .. })
        && authenticate(&app, &leaf, udid.ok_or(Error::Malformed)?, &audit).await?
    {
        return Ok(StatusCode::OK.into_response());
    }
    bound(&app, &leaf).await?;
    let principal = app.devices.management_principal(&credential).await?;
    audit.identify_device(principal.registration());
    audit.target(principal.device());
    audit.registration(principal.registration());
    let digest = apple
        .protection
        .mac(
            &bytes,
            &crate::material::aad(
                &principal.tenant().to_string(),
                principal.registration(),
                principal.generation(),
                "",
                0,
                "apple.checkin.replay",
            )?,
        )
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let budget = app.devices.retirement_budget();
    let control = budget.control();
    let attempt = app
        .audit_store
        .write(
            principal.tenant(),
            &control,
            (
                &app.audit_store,
                CheckinInputs {
                    retirement: app.devices.retirement(),
                    principal: &principal,
                    udid,
                    input,
                    audit: &audit,
                    digest,
                    facts: Vec::new(),
                    protection: &apple.protection,
                    response: Vec::new(),
                },
            ),
            |(store, inputs), tx| {
                Box::pin(async move {
                    let request_result = tx
                        .with_connection_context(inputs, |inputs, c| {
                            Box::pin(checkin_on(c, inputs))
                        })
                        .await?;
                    for fact in &inputs.facts {
                        store.append(tx, fact, false).await.map_err(Error::from)?;
                    }
                    if let Some(result) = request_result {
                        store
                            .append_request(tx, inputs.audit, 200, result)
                            .await
                            .map_err(Error::from)?;
                    }
                    inputs.audit.mark_commit_started();
                    Ok(std::mem::take(&mut inputs.response))
                })
            },
        )
        .await;
    let response = crate::operations::settle(attempt, &audit)?;
    Ok((
        [
            ("content-type", "application/xml"),
            ("cache-control", "no-store"),
        ],
        response,
    )
        .into_response())
}
struct CheckinInputs<'a> {
    retirement: &'a dyn rss_mdm_registration_service::Retirement,
    principal: &'a crate::device::DevicePrincipal,
    udid: Option<&'a str>,
    protection: &'a rss_mdm_native_protection::Protector,
    response: Vec<u8>,
    input: CheckIn<'a>,
    audit: &'a RequestAudit,
    digest: String,
    facts: Vec<rss_mdm_audit_integration::Fact>,
}
async fn checkin_on(
    tx: &mut sqlx::PgConnection,
    inputs: &mut CheckinInputs<'_>,
) -> Result<Option<&'static str>, Error> {
    let CheckinInputs {
        retirement,
        principal,
        udid,
        input,
        audit,
        digest,
        facts,
        protection,
        response,
    } = inputs;
    let principal = *principal;
    let udid = *udid;
    let tenant = principal.tenant().to_string();
    let registration = principal.registration().to_string();
    crate::device::store::lock_channel(tx, &tenant, principal.device(), principal.channel())
        .await?;
    // Recheck under the same registration lock used by revoke/replacement, before every mutation.
    crate::device::store::revalidate_source(
        tx,
        principal,
        rss_mdm_inventory::ReportSource::MdmApple,
    )
    .await?;
    let row=sqlx::query("SELECT udid,state FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state<>'retired' FOR UPDATE").bind(&tenant).bind(&registration).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    if udid.is_some_and(|udid| row.try_get::<String, _>("udid").ok().as_deref() != Some(udid)) {
        return Err(Error::Unauthorized);
    }
    let (key, details) = match input {
        CheckIn::Authenticate { .. } => return Ok(Some("success")),
        CheckIn::TokenUpdate {
            token, magic, user, ..
        } => {
            let scope = user.map(|id| id.to_string()).unwrap_or_default();
            let Some(revision) =
                crate::material::token(tx, protection, principal, &scope, token, magic).await?
            else {
                return Ok(Some("replay"));
            };
            (
                format!("apple-token:{registration}:{scope}:{revision}"),
                serde_json::json!({"tokenRevision":revision,"userScope":scope}),
            )
        }
        CheckIn::CheckOut { .. } => {
            rss_mdm_registration_service::retire(
                tx,
                facts,
                &tenant,
                principal.registration(),
                "revoked",
                *retirement,
            )
            .await?;
            (
                format!("apple-checkout:{registration}"),
                serde_json::json!({"state":"revoked"}),
            )
        }
        CheckIn::UserAuthenticate { user, .. } => {
            *response = protocol::xml(protocol::dictionary([("DigestChallenge", "".into())]))?;
            (
                format!("apple-user-auth:{registration}:{user}:{digest}"),
                serde_json::json!({"userScope":user.to_string()}),
            )
        }
        CheckIn::SetBootstrapToken { .. } | CheckIn::GetBootstrapToken => {
            crate::material::bootstrap_allowed(tx, principal).await?;
            let current=sqlx::query("SELECT bootstrap,bootstrap_revision FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 FOR UPDATE").bind(&tenant).bind(principal.registration()).fetch_one(&mut *tx).await.map_err(db)?;
            let revision = current
                .try_get::<i64, _>("bootstrap_revision")
                .map_err(db)?;
            if let CheckIn::SetBootstrapToken { token } = input {
                let token = token.filter(|token| !token.is_empty());
                let old = current
                    .try_get::<Option<Vec<u8>>, _>("bootstrap")
                    .map_err(db)?;
                let same = match (old.as_deref(), token) {
                    (None, None) => true,
                    (Some(sealed), Some(token)) => {
                        let plain = protection
                            .open_bytes(
                                sealed,
                                &crate::material::aad(
                                    &tenant,
                                    principal.registration(),
                                    principal.generation(),
                                    "",
                                    revision,
                                    "apple.bootstrap",
                                )?,
                            )
                            .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
                        use subtle::ConstantTimeEq;
                        bool::from(plain.expose().ct_eq(token))
                    }
                    _ => false,
                };
                if same {
                    return Ok(Some("replay"));
                }
                let revision = revision
                    .checked_add(1)
                    .ok_or(Error::Unavailable(Failure::AppleStorage))?;
                let sealed = token
                    .filter(|token| !token.is_empty())
                    .map(|token| {
                        protection
                            .seal_bytes(
                                token,
                                &crate::material::aad(
                                    &tenant,
                                    principal.registration(),
                                    principal.generation(),
                                    "",
                                    revision,
                                    "apple.bootstrap",
                                )?,
                            )
                            .map_err(|_| Error::Unavailable(Failure::AppleStorage))
                    })
                    .transpose()?;
                sqlx::query("UPDATE mdm_apple.devices SET bootstrap=$3,bootstrap_revision=$4 WHERE tenant_id=$1::uuid AND registration=$2").bind(&tenant).bind(principal.registration()).bind(sealed).bind(revision).execute(&mut *tx).await.map_err(db)?;
            } else {
                let mut body = plist::Dictionary::new();
                if let Some(sealed) = current
                    .try_get::<Option<Vec<u8>>, _>("bootstrap")
                    .map_err(db)?
                {
                    let plain = protection
                        .open_bytes(
                            &sealed,
                            &crate::material::aad(
                                &tenant,
                                principal.registration(),
                                principal.generation(),
                                "",
                                revision,
                                "apple.bootstrap",
                            )?,
                        )
                        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
                    body.insert(
                        "BootstrapToken".into(),
                        plist::Value::Data(plain.expose().to_vec()),
                    );
                }
                *response = protocol::xml(body)?;
                return Ok(Some("success"));
            }
            (
                format!("apple-bootstrap:{registration}:{revision}:{digest}"),
                serde_json::json!({"action":if matches!(input,CheckIn::GetBootstrapToken){"get"}else{"set"}}),
            )
        }
    };
    let fact = rss_mdm_audit_integration::Fact::business(
        audit,
        &key,
        digest.as_bytes(),
        200,
        "success",
        None,
    )
    .and_then(|fact| fact.with_details(details))
    .map_err(Error::from)?;
    facts.push(fact);
    Ok(None)
}

pub async fn manage(
    State(app): State<Arc<HttpState>>,
    Extension(peer): Extension<rss_mdm_certificate::HandshakePeer>,
    Extension(audit): Extension<RequestAudit>,
    bytes: Bytes,
) -> Result<axum::response::Response, Error> {
    use axum::response::IntoResponse;
    let apple = app.apple()?;
    let leaf = apple.authority.verify(
        peer.chain(),
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let dictionary = protocol::decode(&bytes)?;
    let message = protocol::management(&dictionary)?;
    if message.user.is_none() {
        super::renewal::activate(&app, &leaf, message.udid).await?;
    }
    let credential = app.mount.credential(leaf.fingerprint());
    bound(&app, &leaf).await?;
    let principal = app.devices.management_principal(&credential).await?;
    audit.identify_device(principal.registration());
    audit.target(principal.device());
    audit.registration(principal.registration());
    if message.user.is_none()
        && let Some(response) =
            super::renewal::management(&app, &principal, &dictionary, &bytes, &audit).await?
    {
        return Ok((
            [
                ("content-type", "application/xml"),
                ("cache-control", "no-store"),
            ],
            response,
        )
            .into_response());
    }
    let bytes = app
        .execution
        .apple_management(apple.clone(), &principal, &bytes, &audit)
        .await?;
    Ok((
        [
            ("content-type", "application/xml"),
            ("cache-control", "no-store"),
        ],
        bytes,
    )
        .into_response())
}

async fn bound(app: &HttpState, leaf: &super::certificate::CheckedLeaf) -> Result<(), Error> {
    let tenant = app.identity.tenant().to_string();
    let mut tx = app.access.begin(&tenant).await?;
    let row = enrollment::attempt(&mut tx, &tenant, app.apple()?, leaf).await?;
    if row.try_get::<String, _>("state").map_err(db)? != "bound" {
        return Err(Error::Unauthorized);
    }
    tx.rollback().await.map_err(db)?;
    Ok(())
}

async fn authenticate(
    app: &HttpState,
    leaf: &super::certificate::CheckedLeaf,
    udid: &str,
    audit: &RequestAudit,
) -> Result<bool, Error> {
    let tenant = app.identity.tenant().to_string();
    let mut tx = app.access.begin(&tenant).await?;
    let row = enrollment::attempt(&mut tx, &tenant, app.apple()?, leaf).await?;
    let consumed = row.try_get::<String, _>("state").map_err(db)? == "consumed";
    tx.rollback().await.map_err(db)?;
    if consumed {
        enrollment::bind(app, leaf, udid, audit).await?;
    }
    Ok(consumed)
}

use rss_mdm_audit_integration::RequestAudit;

pub async fn register_agent(
    State(app): State<Arc<HttpState>>,
    Extension(peer): Extension<rss_mdm_certificate::HandshakePeer>,
    Extension(audit): Extension<RequestAudit>,
    headers: axum::http::HeaderMap,
    bytes: Bytes,
) -> Result<axum::response::Response, Error> {
    use axum::response::IntoResponse;
    if bytes.len() > 16384
        || headers.keys().any(|k| {
            k.as_str() == "forwarded"
                || k.as_str().starts_with("x-forwarded-")
                || k.as_str().starts_with("x-ssl-")
                || matches!(k.as_str(), "x-client-cert" | "x-device-id" | "x-tenant-id")
        })
    {
        return Err(Error::Malformed);
    }
    if headers.get_all("content-type").iter().count() != 1
        || headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            != Some("application/json")
    {
        return Err(Error::Malformed);
    }
    let leaf = app.apple()?.authority.verify(
        peer.chain(),
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    bound(&app, &leaf).await?;
    let principal = app
        .devices
        .management_principal(&app.mount.credential(leaf.fingerprint()))
        .await?;
    let input = match rss_mdm_agent_wire::ManagedRegistrationRequest::decode(&bytes) {
        Ok(input) => input,
        Err(code) => {
            let mut response = Error::Malformed.into_response();
            response
                .extensions_mut()
                .insert(rss_mdm_agent_wire::ErrorBody { code });
            return Ok(response);
        }
    };
    let (receipt, replay) = app
        .execution
        .managed_registration(
            &principal,
            rss_mdm_inventory::ReportSource::MdmApple,
            &input,
            &audit,
        )
        .await?;
    Ok((
        if replay {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        axum::Json(receipt),
    )
        .into_response())
}
