//! Device reports and management reads share the production query declarations.
use crate::business_error::Error as BusinessError;
use crate::{Body, Error, Services, body, peer};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_agent_wire::da;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_certificate::ClientCertificateEvidence;
use rss_mdm_device_access_postgres::{configuration as config, reports};
use rss_mdm_http_contract::{
    CollectionResponse, Operation, Router, catalog,
    module::Route,
    query::{OwnedQuery, Window, WindowOwner},
    routing::{get, post},
};
use std::sync::Arc;
use uuid::Uuid;
struct Directory;
impl rss_mdm_http_contract::query::QueryOwner for Directory {
    type Parsed = (
        rss_mdm_query::directory::Query,
        std::collections::BTreeMap<String, String>,
    );
    type Error = rss_mdm_query::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Directory(
            rss_mdm_http_contract::DirectoryDeclaration::list(
                rss_mdm_policy_postgres::device_access::DIRECTORY_BINDINGS.execution(),
            ),
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let s = &rss_mdm_policy_postgres::device_access::DIRECTORY_SCHEMA;
        let mut shape =
            rss_mdm_http_contract::query::directory_parameters(s.default_limit, s.max_limit);
        shape.value["properties"]["device"] = serde_json::json!({"type":"string"});
        shape
    }
    fn parse(raw: &str) -> rss_mdm_query::Result<Self::Parsed> {
        let (parameters, context) =
            rss_mdm_query::Parameters::parse_with_context(raw, &["device"])?;
        Ok((
            rss_mdm_query::directory::Query::new(
                &rss_mdm_policy_postgres::device_access::DIRECTORY_SCHEMA,
                parameters,
            )?,
            context,
        ))
    }
}
struct Versions;
impl WindowOwner for Versions {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &config::HISTORY
    }
}
struct Reports;
impl WindowOwner for Reports {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &reports::WINDOW
    }
}
fn service(s: &Services) -> Result<&crate::Business, BusinessError> {
    s.business.as_deref().ok_or(BusinessError::Unavailable)
}
const REVOCATION: &str = "/api/v1/da/registrations/revocation";

pub fn routes() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct DeviceReports for [Da] {status, application, current, revocation, claim_credential, credential_event, claim_account, account_event}}
    DeviceReports {
        revocation: Route::new(
            REVOCATION,
            get(revocation, &crate::PROTOCOL, &[Operation::Action]),
        ),
        claim_account: Route::new(
            "/api/v1/da/account-operations/next",
            post(claim_account, &crate::PROTOCOL, &[Operation::Action]),
        ),
        account_event: Route::new(
            "/api/v1/da/account-operations/{id}/events",
            post(account_event, &crate::PROTOCOL, &[Operation::Action]),
        ),
        claim_credential: Route::new(
            "/api/v1/da/credential-operations/next",
            post(claim_credential, &crate::PROTOCOL, &[Operation::Action]),
        ),
        credential_event: Route::new(
            "/api/v1/da/credential-operations/{id}/events",
            post(credential_event, &crate::PROTOCOL, &[Operation::Action]),
        ),
        status: Route::new(
            "/api/v1/da/status-reports",
            post(status, &crate::PROTOCOL, &[Operation::Action]),
        ),
        application: Route::new(
            "/api/v1/da/configuration-reports",
            post(application, &crate::PROTOCOL, &[Operation::Action]),
        ),
        current: Route::new(
            "/api/v1/da/configuration",
            get(current, &crate::PROTOCOL, &[Operation::Action]),
        ),
    }
    .assemble()
    .authentication(device_transport)
    .layer(axum::extract::DefaultBodyLimit::max(65536))
}
fn device_transport(_: &str, path: &str) -> rss_mdm_http_contract::authentication::Description {
    use rss_mdm_http_contract::{
        authentication::{Credential, Description},
        signature::Output,
    };
    let (owner, constraint) = if path == REVOCATION {
        (
            "registration-service::agent::da::RegistrationService::revocation_receipt",
            "Possession of the exact DA certificate recorded in the committed revocation",
        )
    } else {
        (
            "registration-service::agent::da::RegistrationService::authenticate",
            "Current purpose-bound DA device certificate presented during the TLS handshake",
        )
    };
    Description {
        owner: "device-access-http::tls",
        alternatives: vec![Credential {
            kind: "mtls",
            owner,
            headers: Default::default(),
            required_headers: vec![],
            constraints: vec![constraint],
        }],
        rejections: Error::responses(),
        conditional_response_headers: vec![],
    }
}
pub(crate) fn management()
-> Router<Arc<crate::management::Services>, impl rss_mdm_http_contract::module::Declaration + use<>>
{
    rss_mdm_http_contract::route_module! {struct ConfigurationQueries for [Browser] {list, detail, versions, publication_operation, diagnostics, latest, history}}
    ConfigurationQueries {
        list: Route::new(
            "/api/v1/tenants/{tenant}/da/admin/configurations",
            get(list, &catalog::DA_CONFIGURATIONS, &[Operation::List]),
        ),
        detail: Route::new(
            "/api/v1/tenants/{tenant}/da/admin/configurations/{id}",
            get(detail, &catalog::DA_CONFIGURATIONS, &[Operation::Get]),
        ),
        versions: Route::new(
            "/api/v1/tenants/{tenant}/da/admin/configurations/{id}/versions",
            get(
                versions,
                &catalog::DA_CONFIGURATION_HISTORY,
                &[Operation::List],
            ),
        ),
        publication_operation: Route::new(
            "/api/v1/tenants/{tenant}/da/admin/configuration-operations/{id}",
            get(
                publication_operation,
                &catalog::DA_PUBLICATION_OPERATIONS,
                &[Operation::Get],
            ),
        ),
        diagnostics: Route::new(
            "/api/v1/tenants/{tenant}/da/admin/devices/{device}/configuration",
            get(
                diagnostics,
                &catalog::DA_CONFIGURATION_DIAGNOSTICS,
                &[Operation::Get],
            ),
        ),
        latest: Route::new(
            "/api/v1/tenants/{tenant}/da/admin/devices/{device}/status",
            get(latest, &catalog::DA_STATUS, &[Operation::Get]),
        ),
        history: Route::new(
            "/api/v1/tenants/{tenant}/da/admin/devices/{device}/reports",
            get(history, &catalog::DA_REPORT_HISTORY, &[Operation::List]),
        ),
    }
    .assemble()
}
async fn status(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
    v: Body<da::StatusReport>,
) -> Result<Json<reports::Receipt>, Error> {
    let p = s.registrations.authenticate(&peer(tls)?).await?;
    a.bind_scope(p.binding()).map_err(|_| Error::Unavailable)?;
    Ok(Json(
        service(&s)
            .map_err(|_| Error::Unavailable)?
            .service
            .report_status(&p, &body(v)?, &a)
            .await?,
    ))
}
async fn application(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
    v: Body<da::ApplicationReport>,
) -> Result<Json<reports::Receipt>, Error> {
    let p = s.registrations.authenticate(&peer(tls)?).await?;
    a.bind_scope(p.binding()).map_err(|_| Error::Unavailable)?;
    Ok(Json(
        service(&s)
            .map_err(|_| Error::Unavailable)?
            .service
            .report_application(&s.configurations, &p, &body(v)?, &a)
            .await?,
    ))
}
async fn revocation(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
) -> Result<Json<da::RevocationReceipt>, Error> {
    Ok(Json(
        s.registrations.revocation_receipt(&peer(tls)?, &a).await?,
    ))
}
async fn current(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
) -> Result<Json<da::CurrentConfiguration>, Error> {
    let p = s.registrations.authenticate(&peer(tls)?).await?;
    a.bind_scope(p.binding()).map_err(|_| Error::Unavailable)?;
    Ok(Json(
        service(&s)
            .map_err(|_| Error::Unavailable)?
            .service
            .retrieve_configuration(&s.configurations, &p, None, &a)
            .await?,
    ))
}
async fn list(
    Path(_tenant): Path<Uuid>,
    State(s): State<Arc<crate::management::Services>>,
    Extension(auth): Extension<rss_mdm_authorization_service::context::RequestAuth>,
    q: OwnedQuery<Directory>,
) -> Result<
    CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<rss_mdm_agent_wire::da::Publication>,
            >,
        >,
    >,
    BusinessError,
> {
    let (q, extra) = q.parse()?;
    let device = extra
        .get("device")
        .map(|value| {
            rss_mdm_agent_wire::DeviceId::parse(value)
                .map_err(|_| BusinessError::from(rss_mdm_device_access_postgres::Error::Malformed))
        })
        .transpose()?;
    Ok(CollectionResponse(Json(
        s.business
            .configurations(&auth.proof, device.as_ref(), &q)
            .await?,
    )))
}
async fn detail(
    State(s): State<Arc<crate::management::Services>>,
    Extension(auth): Extension<rss_mdm_authorization_service::context::RequestAuth>,
    Path((_tenant, id)): Path<(Uuid, Uuid)>,
) -> Result<Json<rss_mdm_agent_wire::da::Publication>, BusinessError> {
    Ok(Json(s.business.configuration(&auth.proof, id).await?))
}
async fn versions(
    State(s): State<Arc<crate::management::Services>>,
    Extension(auth): Extension<rss_mdm_authorization_service::context::RequestAuth>,
    Path((_tenant, id)): Path<(Uuid, Uuid)>,
    q: OwnedQuery<Window<Versions>>,
) -> Result<CollectionResponse<Json<config::ConfigurationPage>>, BusinessError> {
    let (q, _) = q.parse()?;
    Ok(CollectionResponse(Json(
        s.business
            .configuration_history(
                &auth.proof,
                id,
                &config::DirectoryQuery {
                    cursor: q.cursor().clone(),
                    limit: Some(q.limit() as u16),
                },
            )
            .await?,
    )))
}
async fn latest(
    State(s): State<Arc<crate::management::Services>>,
    Extension(auth): Extension<rss_mdm_authorization_service::context::RequestAuth>,
    Path((_tenant, device)): Path<(Uuid, rss_mdm_agent_wire::DeviceId)>,
) -> Result<Json<Option<reports::View>>, BusinessError> {
    Ok(Json(
        s.business
            .latest_report(&auth.proof, &device, reports::Kind::Status)
            .await?,
    ))
}
async fn history(
    State(s): State<Arc<crate::management::Services>>,
    Extension(auth): Extension<rss_mdm_authorization_service::context::RequestAuth>,
    Path((_tenant, device)): Path<(Uuid, rss_mdm_agent_wire::DeviceId)>,
    q: OwnedQuery<Window<Reports>>,
) -> Result<CollectionResponse<Json<reports::Page>>, BusinessError> {
    let (q, extra) = q.parse()?;
    let kind = match extra.get("kind").map(String::as_str) {
        Some("status") | None => reports::Kind::Status,
        Some("application") => reports::Kind::Application,
        _ => return Err(BusinessError::Malformed),
    };
    Ok(CollectionResponse(Json(
        s.business
            .report_history(
                &auth.proof,
                &device,
                &reports::Query {
                    kind,
                    cursor: q.cursor().clone(),
                    limit: Some(q.limit() as u16),
                },
            )
            .await?,
    )))
}

async fn diagnostics(
    State(s): State<Arc<crate::management::Services>>,
    Extension(auth): Extension<rss_mdm_authorization_service::context::RequestAuth>,
    Path((_tenant, device)): Path<(Uuid, rss_mdm_agent_wire::DeviceId)>,
) -> Result<Json<config::Diagnostics>, BusinessError> {
    Ok(Json(
        s.business
            .configuration_diagnostics(&s.configurations, &s.evidence, &auth.proof, &device)
            .await?,
    ))
}

async fn publication_operation(
    State(s): State<Arc<crate::management::Services>>,
    Extension(auth): Extension<rss_mdm_authorization_service::context::RequestAuth>,
    Path((_tenant, id)): Path<(Uuid, Uuid)>,
) -> Result<Json<rss_mdm_agent_wire::da::Publication>, BusinessError> {
    Ok(Json(
        s.business.publication_operation(&auth.proof, id).await?,
    ))
}

async fn credential_peer(
    s: &Services,
    tls: Option<Extension<ClientCertificateEvidence>>,
    a: &RequestAudit,
) -> Result<rss_mdm_registration_service::DevicePrincipal, BusinessError> {
    let cert = tls.ok_or(BusinessError::Unauthorized)?;
    let p = s.registrations.authenticate(&cert.0).await.map_err(|e| {
        let e = Error::from(e);
        match e.failure() {
            Some(rss_mdm_audit_integration::completion::ResponseFailure::Denied) => {
                BusinessError::Unauthorized
            }
            Some(rss_mdm_audit_integration::completion::ResponseFailure::Forbidden) => {
                BusinessError::Forbidden
            }
            Some(f) => BusinessError::Classified(f),
            None if e.status().is_client_error() => BusinessError::Unauthorized,
            None => BusinessError::Unavailable,
        }
    })?;
    a.bind_scope(p.binding())
        .map_err(|_| BusinessError::Unavailable)?;
    Ok(p)
}

async fn claim_credential(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
) -> Result<Json<Option<rss_mdm_agent_wire::runtime::CredentialTaskSpec>>, BusinessError> {
    let p = credential_peer(&s, tls, &a).await?;
    let b = service(&s)?;
    Ok(Json(
        b.service
            .claim_credential(
                b.recovery.as_deref().ok_or(BusinessError::Unavailable)?,
                &p,
                &a,
            )
            .await?,
    ))
}
async fn credential_event(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
    Path(id): Path<Uuid>,
    event: Body<rss_mdm_agent_wire::da::CredentialEvent>,
) -> Result<Json<rss_mdm_agent_wire::da::CredentialSettlement>, BusinessError> {
    let p = credential_peer(&s, tls, &a).await?;
    let b = service(&s)?;
    Ok(Json(
        b.service
            .credential_event(
                b.recovery.as_deref().ok_or(BusinessError::Unavailable)?,
                &p,
                id,
                &event?.0,
                &a,
            )
            .await?,
    ))
}

async fn claim_account(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
    axum::extract::Query(claim): axum::extract::Query<rss_mdm_agent_wire::da::AccountClaim>,
) -> Result<Json<Option<rss_mdm_agent_wire::da::AccountOffer>>, BusinessError> {
    let p = credential_peer(&s, tls, &a).await?;
    Ok(Json(
        service(&s)?
            .service
            .claim_account(&p, claim.platform, &a)
            .await?,
    ))
}
async fn account_event(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
    Path(id): Path<Uuid>,
    event: Body<rss_mdm_agent_wire::da::AccountEvent>,
) -> Result<Json<rss_mdm_agent_wire::da::AccountSettlement>, BusinessError> {
    let p = credential_peer(&s, tls, &a).await?;
    let b = service(&s)?;
    Ok(Json(b.service.account_event(&p, id, &event?.0, &a).await?))
}
