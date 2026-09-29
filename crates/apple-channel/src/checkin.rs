use super::{
    enrollment,
    protocol::{self, CheckIn},
};
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
    let credential = app.mount.credential(leaf.fingerprint());
    if matches!(input, CheckIn::Authenticate { .. })
        && authenticate(&app, &leaf, udid, &audit).await?
    {
        return Ok(StatusCode::OK);
    }
    bound(&app, &leaf).await?;
    let principal = app.devices.management_principal(&credential).await?;
    audit.identify_device(principal.registration());
    audit.target(principal.device());
    audit.registration(principal.registration());
    audit.identify_device(principal.registration());
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
                    digest: rss_mdm_registration_service::enrollment::digest(&bytes.as_ref()),
                    facts: Vec::new(),
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
                    Ok(())
                })
            },
        )
        .await;
    crate::operations::settle(attempt, &audit)?;
    Ok(StatusCode::OK)
}
struct CheckinInputs<'a> {
    retirement: &'a dyn rss_mdm_registration_service::Retirement,
    principal: &'a crate::device::DevicePrincipal,
    udid: &'a str,
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
    if row.try_get::<String, _>("udid").map_err(db)? != udid {
        return Err(Error::Unauthorized);
    }
    let (key, details) = match input {
        CheckIn::Authenticate { .. } => return Ok(Some("success")),
        CheckIn::TokenUpdate { token, magic, .. } => {
            let revision: Option<i64> = sqlx::query_scalar("UPDATE mdm_apple.devices SET state='active',token=$3,magic=$4,token_revision=token_revision+1,next_push=clock_timestamp(),push_id=NULL,push_lease_until=NULL,push_status=NULL,push_outcome=NULL,push_failures=0 WHERE tenant_id=$1::uuid AND registration=$2::uuid AND (state<>'active' OR token IS DISTINCT FROM $3 OR magic IS DISTINCT FROM $4 OR push_outcome='rejected') RETURNING token_revision")
                .bind(&tenant).bind(&registration).bind(*token).bind(*magic).fetch_optional(&mut *tx).await.map_err(db)?;
            let Some(revision) = revision else {
                return Ok(Some("replay"));
            };
            crate::notify(tx, "apple").await.map_err(db)?;
            (
                format!("apple-token:{registration}:{revision}"),
                serde_json::json!({"tokenRevision":revision}),
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
        CheckIn::UserAuthenticate => return Err(Error::Malformed),
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
    let leaf = apple
        .authority
        .verify(peer.chain(), app.clock.unix_seconds()?)?;
    let dictionary = protocol::decode(&bytes)?;
    let message = protocol::management(&dictionary)?;
    super::renewal::activate(&app, &leaf, message.udid).await?;
    let credential = app.mount.credential(leaf.fingerprint());
    bound(&app, &leaf).await?;
    let principal = app.devices.management_principal(&credential).await?;
    audit.identify_device(principal.registration());
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
