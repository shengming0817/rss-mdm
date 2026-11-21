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
pub fn routes() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct DeviceReports for [Da] {status, application, current, claim_credential, credential_event}}
    DeviceReports {
        claim_credential:Route::new("/api/v1/da/credential-operations/next",get(claim_credential,&crate::PROTOCOL,&[Operation::Action])),
        credential_event:Route::new("/api/v1/da/credential-operations/{id}/events",post(credential_event,&crate::PROTOCOL,&[Operation::Action])),
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
    .assemble().layer(axum::extract::DefaultBodyLimit::max(65536))
}
pub(crate) fn management() -> Router<Arc<crate::management::Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
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
async fn current(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
) -> Result<Json<config::CurrentConfiguration>, Error> {
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
                rss_mdm_query::directory::Projection<
                    rss_mdm_policy_postgres::device_access::Publication,
                >,
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
) -> Result<Json<rss_mdm_policy_postgres::device_access::Publication>, BusinessError> {
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
) -> Result<Json<rss_mdm_policy_postgres::device_access::Publication>, BusinessError> {
    Ok(Json(
        s.business.publication_operation(&auth.proof, id).await?,
    ))
}

async fn claim_credential(State(s):State<Arc<Services>>,Extension(a):Extension<RequestAudit>,tls:Option<Extension<ClientCertificateEvidence>>)
    ->Result<Json<Option<rss_mdm_agent_wire::runtime::CredentialTaskSpec>>,Error>{
    let p=s.registrations.authenticate(&peer(tls)?).await?;
    a.bind_scope(p.binding()).map_err(|_|Error::Unavailable)?;
    Ok(Json(s.business.as_ref().ok_or(Error::Unavailable)?.service.claim_credential(&p,&a).await?))
}
async fn credential_event(State(s):State<Arc<Services>>,Extension(a):Extension<RequestAudit>,tls:Option<Extension<ClientCertificateEvidence>>,
    Path(id):Path<Uuid>,event:Body<rss_mdm_recovery_credentials::tasks::device::Event>)->Result<Json<rss_mdm_recovery_credentials::tasks::device::Status>,Error>{
    let p=s.registrations.authenticate(&peer(tls)?).await?;
    a.bind_scope(p.binding()).map_err(|_|Error::Unavailable)?;
    let b=s.business.as_ref().ok_or(Error::Unavailable)?;
    Ok(Json(b.service.credential_event(b.recovery.as_deref().ok_or(Error::Unavailable)?,&p,id,&body(event)?,&a).await?))
}
