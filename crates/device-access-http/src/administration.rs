//! DA configuration and transport authority protocols, using the original proof owner.
use crate::{business_error::Error, device_access::Services, identity::CeremonyHeaders};
use axum::{Extension, Json, extract::State};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::RequestAuth;
use rss_mdm_device_access_postgres::{
    configuration::Change, delivery::Authorization, evidence::SignedObservation,
};
use rss_mdm_http_contract::{
    Operation, Router, catalog,
    module::Route,
    routing::{post, put},
};
use std::sync::Arc;
type Body<T> = Result<Json<T>, axum::extract::rejection::JsonRejection>;
pub fn routes() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct Administration for [Browser]{configuration,configuration_step_up,delivery,step_up}}
    Administration {
        configuration_step_up: Route::new(
            "/device-access/configurations/step-up",
            post(
                configuration_step_up,
                &catalog::DA_CONFIGURATION_CHANGE,
                &[Operation::Action],
            ),
        ),
        configuration: Route::new(
            "/device-access/configurations",
            post(
                configuration,
                &catalog::DA_CONFIGURATION_CHANGE,
                &[Operation::Action],
            ),
        ),
        delivery: Route::new(
            "/device-access/agent-delivery",
            put(
                delivery,
                &catalog::DEVICE_ACCESS,
                &[Operation::Create, Operation::Update],
            ),
        ),
        step_up: Route::new(
            "/device-access/agent-delivery/step-up",
            post(step_up, &catalog::DEVICE_ACCESS, &[Operation::Action]),
        ),
    }
    .assemble()
}
async fn configuration(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    CeremonyHeaders(headers): CeremonyHeaders,
    body: Body<Change>,
) -> Result<Json<rss_mdm_policy_postgres::device_access::Publication>, Error> {
    Ok(Json(
        s.registration
            .publish_configuration(
                &auth.proof,
                &body.map_err(|_| Error::Malformed)?.0,
                crate::device_access::operation_proof(&headers)?.as_ref(),
                &a,
            )
            .await?,
    ))
}
async fn delivery(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    CeremonyHeaders(headers): CeremonyHeaders,
    body: Body<Authorization>,
) -> Result<Json<Revision>, Error> {
    let proof = crate::device_access::operation_proof(&headers)?.ok_or(Error::Unauthorized)?;
    let revision = s
        .registration
        .authorize_agent_delivery(
            &auth.proof,
            &body.map_err(|_| Error::Malformed)?.0,
            &proof,
            &a,
        )
        .await?;
    Ok(Json(Revision { revision }))
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct Revision {
    revision: i64,
}
async fn step_up(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    CeremonyHeaders(headers): CeremonyHeaders,
    body: Body<Authorization>,
) -> Result<Json<crate::identity_contract::TimedChallenge>, Error> {
    let context = body
        .map_err(|_| Error::Malformed)?
        .0
        .step_up_context(&auth.proof)?;
    let actor = s.identity.ceremony_actor(&headers).await?;
    let result = s
        .identity
        .webauthn
        .begin_authentication(
            actor,
            context,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                std::time::Duration::from_secs(10),
            ),
        )
        .await
        .map_err(crate::identity::failure)?;
    Ok(Json(crate::identity_contract::TimedChallenge(result)))
}
async fn configuration_step_up(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    CeremonyHeaders(headers): CeremonyHeaders,
    body: Body<Change>,
) -> Result<Json<crate::identity_contract::TimedChallenge>, Error> {
    let context = body
        .map_err(|_| Error::Malformed)?
        .0
        .step_up_context(&auth.proof)?;
    let actor = s.identity.ceremony_actor(&headers).await?;
    let result = s
        .identity
        .webauthn
        .begin_authentication(
            actor,
            context,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                std::time::Duration::from_secs(10),
            ),
        )
        .await
        .map_err(crate::identity::failure)?;
    Ok(Json(crate::identity_contract::TimedChallenge(result)))
}
pub fn evidence_routes()
-> Router<Arc<crate::Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct Evidence for [Da]{record}}
    Evidence {
        record: Route::new(
            "/api/v1/da/deployment-evidence",
            post(evidence, &crate::PROTOCOL, &[Operation::Action]),
        ),
    }
    .assemble()
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct Accepted {
    accepted: bool,
}
async fn evidence(
    State(s): State<Arc<crate::Services>>,
    Extension(a): Extension<RequestAudit>,
    body: Body<SignedObservation>,
) -> Result<Json<Accepted>, Error> {
    let business = s.business.as_ref().ok_or(Error::Unsupported)?;
    business
        .service
        .record_deployment(
            &business.evidence,
            &s.configurations,
            &body.map_err(|_| Error::Malformed)?.0,
            &a,
        )
        .await?;
    Ok(Json(Accepted { accepted: true }))
}
