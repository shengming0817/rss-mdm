use super::{
    enrollment,
    protocol::{self, CheckIn},
};
use crate::{
    Error, access_store::db, api::App, audit::Audit, device::VerifiedChannelCredential,
    native::tls::Peer,
};
use axum::{Extension, body::Bytes, extract::State, http::StatusCode};
use sqlx::Row;
use std::sync::Arc;

pub(super) async fn checkin(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Peer>,
    Extension(audit): Extension<Audit>,
    bytes: Bytes,
) -> Result<StatusCode, Error> {
    let apple = app.apple()?;
    let leaf = apple
        .authority
        .verify(peer.chain(), app.clock.unix_seconds()?)?;
    let dictionary = protocol::decode(&bytes)?;
    let input = protocol::checkin(&dictionary)?;
    let udid = match input {
        CheckIn::Authenticate { udid, topic } | CheckIn::TokenUpdate { udid, topic, .. } => {
            if topic != apple.config.apns_topic {
                return Err(Error::Unauthorized);
            }
            udid
        }
        CheckIn::CheckOut { udid } => udid,
        CheckIn::UserAuthenticate => return Ok(StatusCode::GONE),
    };
    super::renewal::activate(&app, &leaf, udid).await?;
    let credential = VerifiedChannelCredential::apple(app.identity.tenant, &leaf);
    if matches!(input, CheckIn::Authenticate { .. })
        && authenticate(&app, &leaf, udid, &audit).await?
    {
        return Ok(StatusCode::OK);
    }
    bound(&app, &leaf).await?;
    let principal = app.devices.management_principal(&credential).await?;
    audit.target(principal.device());
    audit.registration(principal.registration());
    let tenant = principal.tenant().to_string();
    let registration = principal.registration().to_string();
    let mut tx = app.access.begin(&tenant).await?;
    crate::device::store::lock_channel(&mut tx, &tenant, principal.device(), principal.channel())
        .await?;
    // Recheck under the same registration lock used by revoke/replacement, before every mutation.
    let row=sqlx::query("SELECT a.udid,a.state FROM mdm_access.registrations r JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) JOIN mdm_apple.devices a ON (a.tenant_id,a.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.generation=$3 AND r.state='active' AND c.id=$4::uuid AND c.state='active' AND a.state<>'retired' FOR UPDATE OF r,a")
        .bind(&tenant).bind(&registration).bind(principal.generation()).bind(principal.credential().to_string()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    if row.try_get::<String, _>("udid").map_err(db)? != udid {
        return Err(Error::Unauthorized);
    }
    match input {
        CheckIn::Authenticate { .. } => {}
        CheckIn::TokenUpdate { token, magic, .. } => {
            sqlx::query("UPDATE mdm_apple.devices SET state='active',token=$3,magic=$4,token_revision=token_revision+1,next_push=clock_timestamp(),push_id=NULL,push_lease_until=NULL,push_status=NULL,push_outcome=NULL,push_failures=0 WHERE tenant_id=$1::uuid AND registration=$2::uuid")
                .bind(&tenant).bind(&registration).bind(token).bind(magic).execute(&mut *tx).await.map_err(db)?;
        }
        CheckIn::CheckOut { .. } => {
            crate::device::store::retire(&mut tx, &tenant, principal.registration(), "revoked")
                .await?
        }
        CheckIn::UserAuthenticate => unreachable!("handled before device mutations"),
    }
    app.access
        .commit_audited_status(tx, &audit, None, 200)
        .await?;
    Ok(StatusCode::OK)
}

pub(super) async fn manage(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Peer>,
    Extension(audit): Extension<Audit>,
    bytes: Bytes,
) -> Result<axum::response::Response, Error> {
    use axum::response::IntoResponse;
    let apple = app.apple()?;
    let leaf = apple
        .authority
        .verify(peer.chain(), app.clock.unix_seconds()?)?;
    let dictionary = protocol::decode(&bytes)?;
    let message = protocol::management(&dictionary)?;
    super::renewal::activate(&app, &leaf, message.udid).await?;
    let credential = VerifiedChannelCredential::apple(app.identity.tenant, &leaf);
    bound(&app, &leaf).await?;
    let principal = app.devices.management_principal(&credential).await?;
    audit.target(principal.device());
    audit.registration(principal.registration());
    if let Some(response) =
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
        .commands
        .apple_management(apple, &principal, &bytes, &audit)
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

async fn bound(app: &App, leaf: &super::certificate::CheckedLeaf) -> Result<(), Error> {
    let tenant = app.identity.tenant.to_string();
    let mut tx = app.access.begin(&tenant).await?;
    let row = enrollment::attempt(&mut tx, &tenant, app.apple()?, leaf).await?;
    if row.try_get::<String, _>("state").map_err(db)? != "bound" {
        return Err(Error::Unauthorized);
    }
    tx.rollback().await.map_err(db)?;
    Ok(())
}

async fn authenticate(
    app: &App,
    leaf: &super::certificate::CheckedLeaf,
    udid: &str,
    audit: &Audit,
) -> Result<bool, Error> {
    let tenant = app.identity.tenant.to_string();
    let mut tx = app.access.begin(&tenant).await?;
    let row = enrollment::attempt(&mut tx, &tenant, app.apple()?, leaf).await?;
    let consumed = row.try_get::<String, _>("state").map_err(db)? == "consumed";
    tx.rollback().await.map_err(db)?;
    if consumed {
        enrollment::bind(app, leaf, udid, audit).await?;
    }
    Ok(consumed)
}
