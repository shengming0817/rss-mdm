//! Standalone Device Access ingress. The host supplies shared owners and authenticated TLS evidence.
//! No Agent/native runtime or MDM application is assembled here.
mod boundary;
mod error;
pub mod tls;
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use boundary::Administrator;
pub use error::Error;
use rss_mdm_agent_wire::{da, enroll, pki, task_trust};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_certificate::ClientCertificateEvidence;
use rss_mdm_http_contract::{
    Operation, Router,
    module::Route,
    routing::{get, post},
};
use rss_mdm_registration_service::agent::da::RegistrationService;
use rss_mdm_task_trust::configuration::ConfigurationService;
use std::sync::Arc;
use uuid::Uuid;

pub struct Services {
    pub registrations: Arc<RegistrationService>,
    pub configurations: Arc<ConfigurationService>,
    pub authorization: Arc<rss_mdm_authorization_service::Store>,
    pub sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub host: String,
    pub requests: Arc<tokio::sync::Semaphore>,
}
static PROTOCOL: rss_mdm_http_contract::Resource = rss_mdm_http_contract::Resource {
    id: "protocol_device_access",
    category: rss_mdm_http_contract::Category::Protocol,
    owner: "device-access-http",
    proof: "device_access.foundation",
    query: rss_mdm_http_contract::QueryPolicy::Protocol,
    collection: None,
};
pub fn router(
    service: Arc<Services>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    declarations()
        .bind_with(Some(&service), Arc::clone)
        .layer(axum::extract::DefaultBodyLimit::max(131072))
        .layer(axum::middleware::from_fn_with_state(
            service,
            boundary::admit,
        ))
}
fn declarations() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>>
{
    rss_mdm_http_contract::route_module! { struct DaRoutes for [Da] { grant, issue, recover_issuance, activate, status, renew, recover, revoke, pki_trust, pki_ack, configuration_trust, configuration_ack, trust_read, trust_change, trust_operation, export, export_operation, retrieve } }
    DaRoutes {
        grant: Route::new(
            "/api/v1/da/grants",
            post(grant, &PROTOCOL, &[Operation::Action]),
        ),
        issue: Route::new(
            "/api/v1/da/certificates",
            post(issue, &PROTOCOL, &[Operation::Action]),
        ),
        recover_issuance: Route::new(
            "/api/v1/da/certificates/{id}/recover",
            post(recover_issuance, &PROTOCOL, &[Operation::Action]),
        ),
        activate: Route::new(
            "/api/v1/da/activate",
            post(activate, &PROTOCOL, &[Operation::Action]),
        ),
        status: Route::new(
            "/api/v1/da/status",
            post(status, &PROTOCOL, &[Operation::Action]),
        ),
        renew: Route::new(
            "/api/v1/da/renewal-grants",
            post(renew, &PROTOCOL, &[Operation::Action]),
        ),
        recover: Route::new(
            "/api/v1/da/registrations/{id}/recovery-grants",
            post(recover, &PROTOCOL, &[Operation::Action]),
        ),
        revoke: Route::new(
            "/api/v1/da/registrations/{id}/revoke",
            post(revoke, &PROTOCOL, &[Operation::Action]),
        ),
        pki_trust: Route::new(
            "/api/v1/da/pki/trust",
            get(pki_trust, &PROTOCOL, &[Operation::Action]),
        ),
        pki_ack: Route::new(
            "/api/v1/da/pki/acknowledgements",
            post(pki_ack, &PROTOCOL, &[Operation::Action]),
        ),
        configuration_trust: Route::new(
            "/api/v1/da/configuration-trust",
            get(configuration_trust, &PROTOCOL, &[Operation::Action]),
        ),
        configuration_ack: Route::new(
            "/api/v1/da/configuration-trust/acknowledgements",
            post(configuration_ack, &PROTOCOL, &[Operation::Action]),
        ),
        trust_read: Route::new(
            "/api/v1/da/admin/configuration-trust",
            get(trust_read, &PROTOCOL, &[Operation::Action]),
        ),
        trust_change: Route::new(
            "/api/v1/da/admin/configuration-trust/{operation}",
            post(trust_change, &PROTOCOL, &[Operation::Action]),
        ),
        trust_operation: Route::new(
            "/api/v1/da/admin/configuration-trust/operations/{operation}",
            get(trust_operation, &PROTOCOL, &[Operation::Action]),
        ),
        export: Route::new(
            "/api/v1/da/configurations",
            post(export, &PROTOCOL, &[Operation::Action]),
        ),
        export_operation: Route::new(
            "/api/v1/da/configuration-operations/{operation}",
            get(export_operation, &PROTOCOL, &[Operation::Action]),
        ),
        retrieve: Route::new(
            "/api/v1/da/configurations/{operation}",
            get(retrieve, &PROTOCOL, &[Operation::Action]),
        ),
    }
    .assemble()
}
type Body<T> = Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn body<T>(v: Body<T>) -> Result<T, Error> {
    v.map(|v| v.0).map_err(|_| Error::Malformed)
}
fn peer(
    v: Option<Extension<ClientCertificateEvidence>>,
) -> Result<ClientCertificateEvidence, Error> {
    v.map(|v| v.0).ok_or(Error::Unauthorized)
}
fn trust(v: task_trust::Trust) -> da::ConfigurationTrust {
    da::ConfigurationTrust {
        service_id: v.service_id,
        tenant: v.tenant,
        revision: v.revision,
        keys: v.keys,
    }
}
async fn grant(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Administrator(p): Administrator,
    v: Body<da::GrantRequest>,
) -> Result<Json<da::Grant>, Error> {
    Ok(Json(s.registrations.grant(&p, &body(v)?, &a).await?))
}
async fn issue(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    v: Body<da::CertificateRequest>,
) -> Result<Json<enroll::Candidate>, Error> {
    Ok(Json(s.registrations.issue(&body(v)?, &a).await?))
}
async fn activate(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
    v: Body<enroll::ActivationRequest>,
) -> Result<Json<da::Registration>, Error> {
    Ok(Json(
        s.registrations.activate(&peer(tls)?, &body(v)?, &a).await?,
    ))
}
async fn status(
    State(s): State<Arc<Services>>,
    v: Body<enroll::StatusRequest>,
) -> Result<Json<da::Progress>, Error> {
    Ok(Json(s.registrations.status(&body(v)?).await?))
}
async fn renew(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
    v: Body<da::GrantRequest>,
) -> Result<Json<da::Grant>, Error> {
    Ok(Json(
        s.registrations.renew(&peer(tls)?, &body(v)?, &a).await?,
    ))
}
async fn recover(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Administrator(p): Administrator,
    Path(id): Path<Uuid>,
    v: Body<da::GrantRequest>,
) -> Result<Json<da::Grant>, Error> {
    Ok(Json(s.registrations.recover(&p, id, &body(v)?, &a).await?))
}
#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationRequest {
    operation_id: Uuid,
}
async fn revoke(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Administrator(p): Administrator,
    Path(id): Path<Uuid>,
    v: Body<OperationRequest>,
) -> Result<Json<rss_mdm_registration_service::device::RevocationReceipt>, Error> {
    Ok(Json(
        s.registrations
            .revoke(&p, id, body(v)?.operation_id, &a)
            .await?,
    ))
}
async fn pki_trust(
    State(s): State<Arc<Services>>,
    tls: Option<Extension<ClientCertificateEvidence>>,
) -> Result<Json<pki::Trust>, Error> {
    Ok(Json(
        s.registrations
            .device_trust(tls.as_ref().map(|v| &v.0))
            .await?,
    ))
}
async fn pki_ack(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
    v: Body<pki::Acknowledgement>,
) -> Result<(), Error> {
    s.registrations
        .acknowledge_trust(&peer(tls)?, &body(v)?, &a)
        .await?;
    Ok(())
}
async fn configuration_trust(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
) -> Result<Json<da::ConfigurationTrust>, Error> {
    let p = s.registrations.authenticate(&peer(tls)?).await?;
    Ok(Json(trust(
        s.configurations.trust().device_trust(&p, &a).await?,
    )))
}
async fn configuration_ack(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
    v: Body<task_trust::Acknowledgement>,
) -> Result<(), Error> {
    let p = s.registrations.authenticate(&peer(tls)?).await?;
    s.configurations
        .trust()
        .acknowledge_task_trust(&p, &a, &body(v)?)
        .await?;
    Ok(())
}
async fn trust_read(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Administrator(p): Administrator,
) -> Result<Json<da::ConfigurationTrust>, Error> {
    Ok(Json(trust(
        s.configurations.trust().task_trust(&p, &a).await?,
    )))
}
async fn trust_change(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Administrator(p): Administrator,
    Path(id): Path<Uuid>,
    v: Body<rss_mdm_task_trust::service::Change>,
) -> Result<Json<da::ConfigurationTrust>, Error> {
    Ok(Json(trust(
        s.configurations
            .trust()
            .change_task_trust(&p, &a, id, &body(v)?)
            .await?,
    )))
}
async fn trust_operation(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Administrator(p): Administrator,
    Path(id): Path<Uuid>,
) -> Result<Json<da::ConfigurationTrust>, Error> {
    Ok(Json(trust(
        s.configurations
            .trust()
            .task_trust_operation(&p, &a, id)
            .await?,
    )))
}
async fn export(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Administrator(p): Administrator,
    v: Body<da::Export>,
) -> Result<Json<da::SignedConfiguration>, Error> {
    Ok(Json(s.configurations.export(&p, &body(v)?, &a).await?))
}
async fn export_operation(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Administrator(p): Administrator,
    Path(id): Path<Uuid>,
) -> Result<Json<da::SignedConfiguration>, Error> {
    Ok(Json(s.configurations.operation(&p, id, &a).await?))
}
async fn retrieve(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    tls: Option<Extension<ClientCertificateEvidence>>,
    Path(id): Path<Uuid>,
) -> Result<Json<da::SignedConfiguration>, Error> {
    let p = s.registrations.authenticate(&peer(tls)?).await?;
    Ok(Json(s.configurations.retrieve(&p, id, &a).await?))
}

async fn recover_issuance(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Administrator(p): Administrator,
    Path(id): Path<Uuid>,
    v: Body<enroll::RecoverIssuance>,
) -> Result<Json<enroll::Candidate>, Error> {
    Ok(Json(
        s.registrations
            .recover_issuance(&p, id, &body(v)?, &a)
            .await?,
    ))
}
