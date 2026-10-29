//! Session-authorized issuer lifecycle; device acknowledgements use native authenticated owners.
use crate::{Error, Failure, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_agent_wire::pki::{Purpose, Trust};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use rss_mdm_pki_service::registry::{Receipt, Registry, Rotation, Transition};
use std::sync::Arc;
pub struct HttpState {
    pub registry: Arc<Registry>,
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub clock: Arc<dyn rss_mdm_registration_service::agent_pki::Clock>,
}
pub fn routes() -> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { get_latest_rotation, get_read_rotation, get_rotation_blockers, get_agent_trust_observation, get_trust, post_prepare, post_recover, post_publish, post_transition } }
        RoutesModule1 {
            get_latest_rotation: rss_mdm_http_contract::module::Route::new(
                "/pki/{purpose}/rotations/latest",
                get(
                    latest_rotation,
                    &contracts::PKI_ROTATIONS,
                    &[RouteOperation::Get],
                ),
            ),
            get_read_rotation: rss_mdm_http_contract::module::Route::new(
                "/pki/{purpose}/rotations/{id}",
                get(
                    read_rotation,
                    &contracts::PKI_ROTATIONS,
                    &[RouteOperation::Get],
                ),
            ),
            get_rotation_blockers: rss_mdm_http_contract::module::Route::new(
                "/pki/{purpose}/rotations/{id}/blockers",
                get(
                    rotation_blockers,
                    &contracts::PKI_ROTATION_BLOCKERS,
                    &[RouteOperation::List],
                ),
            ),
            get_agent_trust_observation: rss_mdm_http_contract::module::Route::new(
                "/pki/agent/trust/devices/{device}/observation",
                get(
                    agent_trust_observation,
                    &contracts::PKI_OPERATIONS,
                    &[RouteOperation::Action],
                ),
            ),
            get_trust: rss_mdm_http_contract::module::Route::new(
                "/pki/{purpose}/trust",
                get(trust, &contracts::PKI_OPERATIONS, &[RouteOperation::Action]),
            ),
            post_prepare: rss_mdm_http_contract::module::Route::new(
                "/pki/rotations",
                post(
                    prepare,
                    &contracts::PKI_OPERATIONS,
                    &[RouteOperation::Action, RouteOperation::Create],
                ),
            ),
            post_recover: rss_mdm_http_contract::module::Route::new(
                "/pki/signing/recover",
                post(
                    recover,
                    &contracts::PKI_OPERATIONS,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            post_publish: rss_mdm_http_contract::module::Route::new(
                "/pki/crls",
                post(
                    publish,
                    &contracts::PKI_OPERATIONS,
                    &[RouteOperation::Action, RouteOperation::Create],
                ),
            ),
            post_transition: rss_mdm_http_contract::module::Route::new(
                "/pki/{purpose}/rotations",
                post(
                    transition,
                    &contracts::PKI_OPERATIONS,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
        }
        .assemble()
    }
}
fn purpose(value: &str) -> Result<Purpose, Error> {
    match value {
        "windows" => Ok(Purpose::Windows),
        "apple" => Ok(Purpose::Apple),
        "agent" => Ok(Purpose::Agent),
        "agent_bootstrap" => Ok(Purpose::AgentBootstrap),
        _ => Err(Error::Malformed),
    }
}
fn error(e: rss_mdm_pki_service::Error) -> Error {
    use rss_mdm_pki_service::Error as P;
    match e {
        P::Request | P::Configuration => Error::Malformed,
        P::Conflict => Error::Conflict,
        P::NotFound => Error::NotFound,
        P::ReadConflict => Error::QueryReadConflict,
        P::CursorInvalidated => Error::QueryCursorInvalidated,
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
) -> Result<rss_mdm_http_contract::signature::WithStatus<204, ()>, Error> {
    let input = body.map_err(Error::from)?.0;
    let now = s
        .clock
        .unix_seconds()
        .map_err(|_| Error::Unavailable(Failure::Clock))?;
    s.registry
        .publish(&a.proof, &input, &audit, now)
        .await
        .map_err(error)?;
    Ok(rss_mdm_http_contract::signature::WithStatus(()))
}

async fn agent_trust_observation(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(device): Path<String>,
) -> Result<Json<Option<rss_mdm_agent_wire::pki::ObservedInstallation>>, Error> {
    s.registry
        .agent_trust_observation(&auth.proof, &device)
        .await
        .map(Json)
        .map_err(error)
}

async fn latest_rotation(
    State(s): State<Arc<HttpState>>,
    Extension(a): Extension<RequestAuth>,
    Path(value): Path<String>,
) -> Result<Json<Option<rss_mdm_pki_service::rotation::View>>, Error> {
    let now = s
        .clock
        .unix_seconds()
        .map_err(|_| Error::Unavailable(Failure::Clock))?;
    s.registry
        .rotation(&a.proof, purpose(&value)?, None, now)
        .await
        .map(Json)
        .map_err(error)
}
async fn read_rotation(
    State(s): State<Arc<HttpState>>,
    Extension(a): Extension<RequestAuth>,
    Path((value, id)): Path<(String, uuid::Uuid)>,
) -> Result<Json<rss_mdm_pki_service::rotation::View>, Error> {
    let now = s
        .clock
        .unix_seconds()
        .map_err(|_| Error::Unavailable(Failure::Clock))?;
    s.registry
        .rotation(&a.proof, purpose(&value)?, Some(id), now)
        .await
        .map_err(error)?
        .map(Json)
        .ok_or(Error::NotFound)
}
struct BlockersQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for BlockersQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_pki_service::rotation::BLOCKERS
    }
}
async fn rotation_blockers(
    State(s): State<Arc<HttpState>>,
    Extension(a): Extension<RequestAuth>,
    Path((value, id)): Path<(String, uuid::Uuid)>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<BlockersQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<rss_mdm_pki_service::rotation::Blocker>,
            >,
        >,
    >,
    Error,
> {
    let now = s
        .clock
        .unix_seconds()
        .map_err(|_| Error::Unavailable(Failure::Clock))?;
    let query = query.parse().map_err(|_| Error::Malformed)?;
    s.registry
        .rotation_blockers(&a.proof, purpose(&value)?, id, now, &query, &s.cursor)
        .await
        .map(Json)
        .map(rss_mdm_http_contract::CollectionResponse)
        .map_err(error)
}
