//! Device reports and management reads share the production query declarations.
use crate::business_error::Error as BusinessError;
use crate::{Body, Error, Services, body, boundary::Administrator, peer};
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
    type Parsed = (rss_mdm_query::directory::Query,std::collections::BTreeMap<String,String>);
    type Error = rss_mdm_query::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Directory(rss_mdm_http_contract::DirectoryDeclaration::list(rss_mdm_policy_postgres::device_access::DIRECTORY_BINDINGS.execution())))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let s=&rss_mdm_policy_postgres::device_access::DIRECTORY_SCHEMA;
        let mut shape=rss_mdm_http_contract::query::directory_parameters(s.default_limit,s.max_limit);
        shape.value["properties"]["device"]=serde_json::json!({"type":"string"}); shape
    }
    fn parse(raw:&str) -> rss_mdm_query::Result<Self::Parsed> {
        let(parameters,context)=rss_mdm_query::Parameters::parse_with_context(raw,&["device"])?;
        Ok((rss_mdm_query::directory::Query::new(&rss_mdm_policy_postgres::device_access::DIRECTORY_SCHEMA,parameters)?,context))
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
    rss_mdm_http_contract::route_module! {struct Configurations for [Da]{status,application,current,list,detail,versions,latest,history,diagnostics,publication_operation}}
    Configurations {
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
        list: Route::new(
            "/api/v1/da/admin/configurations",
            get(list, &catalog::DA_CONFIGURATIONS, &[Operation::List]),
        ),
        detail: Route::new(
            "/api/v1/da/admin/configurations/{id}",
            get(detail, &catalog::DA_CONFIGURATIONS, &[Operation::Get]),
        ),
        versions: Route::new(
            "/api/v1/da/admin/configurations/{id}/versions",
            get(
                versions,
                &catalog::DA_CONFIGURATION_HISTORY,
                &[Operation::List],
            ),
        ),
        publication_operation: Route::new(
            "/api/v1/da/admin/configuration-operations/{id}",
            get(
                publication_operation,
                &catalog::DA_PUBLICATION_OPERATIONS,
                &[Operation::Get],
            ),
        ),
        diagnostics: Route::new(
            "/api/v1/da/admin/devices/{device}/configuration",
            get(
                diagnostics,
                &catalog::DA_CONFIGURATION_DIAGNOSTICS,
                &[Operation::Get],
            ),
        ),
        latest: Route::new(
            "/api/v1/da/admin/devices/{device}/status",
            get(latest, &catalog::DA_STATUS, &[Operation::Get]),
        ),
        history: Route::new(
            "/api/v1/da/admin/devices/{device}/reports",
            get(history, &catalog::DA_REPORT_HISTORY, &[Operation::List]),
        ),
    }
    .assemble()
    .layer(axum::extract::DefaultBodyLimit::max(65536))
}
async fn status(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
    v: Body<da::StatusReport>,
) -> Result<Json<reports::Receipt>, Error> {
    let p = s.registrations.authenticate(&peer(tls)?).await?;
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
    Ok(Json(
        service(&s)
            .map_err(|_| Error::Unavailable)?
            .service
            .retrieve_configuration(&s.configurations, &p, None, &a)
            .await?,
    ))
}
async fn list(
    State(s): State<Arc<Services>>,
    Administrator(p): Administrator,
    q: OwnedQuery<Directory>,
) -> Result<CollectionResponse<Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<rss_mdm_policy_postgres::device_access::Publication>>>>, BusinessError> {
    let (q, extra) = q.parse()?;
    Ok(CollectionResponse(Json(
        service(&s)?
            .service
            .configurations(&p, extra.get("device").map(String::as_str), &q)
            .await?,
    )))
}
async fn detail(
    State(s): State<Arc<Services>>,
    Administrator(p): Administrator,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_policy_postgres::device_access::Publication>, BusinessError> {
    Ok(Json(service(&s)?.service.configuration(&p, id).await?))
}
async fn versions(
    State(s): State<Arc<Services>>,
    Administrator(p): Administrator,
    Path(id): Path<Uuid>,
    q: OwnedQuery<Window<Versions>>,
) -> Result<CollectionResponse<Json<config::ConfigurationPage>>, BusinessError> {
    let (q, _) = q.parse()?;
    Ok(CollectionResponse(Json(
        service(&s)?
            .service
            .configuration_history(
                &p,
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
    State(s): State<Arc<Services>>,
    Administrator(p): Administrator,
    Path(device): Path<String>,
) -> Result<Json<Option<reports::View>>, BusinessError> {
    Ok(Json(
        service(&s)?
            .service
            .latest_report(&p, &device, reports::Kind::Status)
            .await?,
    ))
}
async fn history(
    State(s): State<Arc<Services>>,
    Administrator(p): Administrator,
    Path(device): Path<String>,
    q: OwnedQuery<Window<Reports>>,
) -> Result<CollectionResponse<Json<reports::Page>>, BusinessError> {
    let (q, extra) = q.parse()?;
    let kind = match extra.get("kind").map(String::as_str) {
        Some("status") | None => reports::Kind::Status,
        Some("application") => reports::Kind::Application,
        _ => return Err(BusinessError::Malformed),
    };
    Ok(CollectionResponse(Json(
        service(&s)?
            .service
            .report_history(
                &p,
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
    State(s): State<Arc<Services>>,
    Administrator(p): Administrator,
    Path(device): Path<String>,
) -> Result<Json<config::Diagnostics>, BusinessError> {
    let b = service(&s)?;
    Ok(Json(
        b.service
            .configuration_diagnostics(&s.configurations, &b.evidence, &p, &device)
            .await?,
    ))
}

async fn publication_operation(
    State(s): State<Arc<Services>>,
    Administrator(p): Administrator,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_policy_postgres::device_access::Publication>, BusinessError> {
    Ok(Json(
        service(&s)?.service.publication_operation(&p, id).await?,
    ))
}
