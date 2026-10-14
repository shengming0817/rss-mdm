//! Session-authorized issuer lifecycle; device acknowledgements use native authenticated owners.
use crate::{Error, Failure, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use rss_mdm_agent_wire::pki::{Purpose, Trust};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_pki_service::registry::{Receipt, Registry, Rotation, Transition};
use std::sync::Arc;
pub(crate) struct HttpState {
    pub registry: Arc<Registry>,
    pub clock: Arc<dyn rss_mdm_registration_service::agent_pki::Clock>,
}
pub(crate) fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/pki/{purpose}/trust", get(trust))
        .route("/pki/rotations", post(prepare))
        .route("/pki/signing/recover", post(recover))
        .route("/pki/crls", post(publish))
        .route("/pki/{purpose}/rotations", post(transition))
}
fn purpose(value: &str) -> Result<Purpose, Error> {
    match value {
        "windows" => Ok(Purpose::Windows),
        "apple" => Ok(Purpose::Apple),
        "agent" => Ok(Purpose::Agent),
        _ => Err(Error::Malformed),
    }
}
fn error(e: rss_mdm_pki_service::Error) -> Error {
    use rss_mdm_pki_service::Error as P;
    match e {
        P::Request | P::Configuration => Error::Malformed,
        P::Conflict => Error::Conflict,
        P::Forbidden => Error::Forbidden,
        P::Unknown { .. } => Error::CommitUnknown,
        P::Audit(e) => e.into(),
        P::Storage => Error::Unavailable(Failure::Database),
    }
}
async fn trust(
    State(s): State<Arc<HttpState>>,
    Extension(a): Extension<RequestAuth>,
    Path(value): Path<String>,
) -> Result<Json<Trust>, Error> {
    a.proof
        .require_all_devices(rss_mdm_authorization_service::Permission::Credentials)?;
    let trust = s.registry.trust(purpose(&value)?).map_err(error)?;
    if trust.tenant.to_string() != a.proof.tenant_id() {
        return Err(Error::Forbidden);
    }
    Ok(Json(trust))
}
async fn prepare(
    State(s): State<Arc<HttpState>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<Json<Rotation>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Receipt>, Error> {
    let input = body.map_err(Error::from)?.0;
    let now = s
        .clock
        .unix_seconds()
        .map_err(|_| Error::Unavailable(Failure::Clock))?;
    s.registry
        .prepare(&a.proof, &input, &audit, now)
        .await
        .map(Json)
        .map_err(error)
}
async fn transition(
    State(s): State<Arc<HttpState>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(value): Path<String>,
    body: Result<Json<Transition>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Receipt>, Error> {
    let input = body.map_err(Error::from)?.0;
    let now = s
        .clock
        .unix_seconds()
        .map_err(|_| Error::Unavailable(Failure::Clock))?;
    s.registry
        .transition(&a.proof, purpose(&value)?, &input, &audit, now)
        .await
        .map(Json)
        .map_err(error)
}

async fn recover(
    State(s): State<Arc<HttpState>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<
        Json<rss_mdm_pki_service::recovery::Recovery>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_pki_service::recovery::Receipt>, Error> {
    let input = body.map_err(Error::from)?.0;
    let now = s
        .clock
        .unix_seconds()
        .map_err(|_| Error::Unavailable(Failure::Clock))?;
    s.registry
        .recover(&a.proof, &input, &audit, now)
        .await
        .map(Json)
        .map_err(error)
}

async fn publish(
    State(s): State<Arc<HttpState>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<
        Json<rss_mdm_pki_service::maintenance::PublicationSet>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<axum::http::StatusCode, Error> {
    let input = body.map_err(Error::from)?.0;
    let now = s
        .clock
        .unix_seconds()
        .map_err(|_| Error::Unavailable(Failure::Clock))?;
    s.registry
        .publish(&a.proof, &input, &audit, now)
        .await
        .map_err(error)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
