//! Tenant management routes, mounted behind the host's Identity request middleware.
use super::{Body, Error, PROTOCOL, body, exports, trust};
use axum::{Extension, Json, extract::{Path, State}};
use rss_mdm_agent_wire::{da,enroll};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::RequestAuth;
use rss_mdm_http_contract::{Router, Operation, module::Route, routing::{get,post}};
use std::sync::Arc;
use uuid::Uuid;

pub struct Services {
    pub registrations: Arc<rss_mdm_registration_service::agent::da::RegistrationService>,
    pub configurations: Arc<rss_mdm_task_trust::configuration::ConfigurationService>,
    pub business: Arc<rss_mdm_device_access_postgres::Service>,
    pub evidence: Arc<rss_mdm_device_access_postgres::evidence::Authorities>,
    pub platform: Arc<crate::platform_sso::HttpState>,
}

pub fn routes() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct Management for [Browser] {lifecycle,configurations}}
    Management {lifecycle:lifecycle(),configurations:crate::configurations::management()}.assemble()
}
pub(crate) fn lifecycle() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct DaAdministration for [Browser] {grant, recover_issuance, recover, revoke, trust_read, trust_change, trust_operation, export, export_operation, templates}}
    DaAdministration {
        grant: Route::new(
            "/api/v1/tenants/{tenant}/da/grants",
            post(grant, &PROTOCOL, &[Operation::Action]),
        ),
        recover_issuance: Route::new(
            "/api/v1/tenants/{tenant}/da/certificates/{id}/recover",
            post(recover_issuance, &PROTOCOL, &[Operation::Action]),
        ),
        recover: Route::new(
            "/api/v1/tenants/{tenant}/da/devices/{id}/registration/recovery-grants",
            post(recover, &PROTOCOL, &[Operation::Action]),
        ),
        revoke: Route::new(
            "/api/v1/tenants/{tenant}/da/devices/{device}/registration/revoke",
            post(revoke, &PROTOCOL, &[Operation::Action]),
        ),
        trust_read: Route::new(
            "/api/v1/tenants/{tenant}/da/admin/configuration-trust",
            get(trust_read, &PROTOCOL, &[Operation::Action]),
        ),
        trust_change: Route::new(
            "/api/v1/tenants/{tenant}/da/admin/configuration-trust/{operation}",
            post(trust_change, &PROTOCOL, &[Operation::Action]),
        ),
        trust_operation: Route::new(
            "/api/v1/tenants/{tenant}/da/admin/configuration-trust/operations/{operation}",
            get(trust_operation, &PROTOCOL, &[Operation::Action]),
        ),
        export: Route::new(
            "/api/v1/tenants/{tenant}/da/configurations",
            post(export, &PROTOCOL, &[Operation::Action]),
        ),
        export_operation: Route::new(
            "/api/v1/tenants/{tenant}/da/configuration-operations/{operation}",
            get(export_operation, &PROTOCOL, &[Operation::Action]),
        ),
        templates: Route::new(
            "/api/v1/tenants/{tenant}/da/configuration-operations/{operation}/templates",
            get(exports::templates, &PROTOCOL, &[Operation::Action]),
        ),
    }
    .assemble()
}
async fn grant(
    Path(_tenant): Path<Uuid>,
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Extension(auth): Extension<RequestAuth>,
    v: Body<da::GrantRequest>,
) -> Result<Json<da::Grant>, Error> {
    Ok(Json(s.registrations.grant(&auth.proof, &body(v)?, &a).await?))
}
async fn recover(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, id)): Path<(Uuid, rss_mdm_agent_wire::DeviceId)>,
    v: Body<da::GrantRequest>,
) -> Result<Json<da::Grant>, Error> {
    Ok(Json(s.registrations.recover(&auth.proof, id, &body(v)?, &a).await?))
}
async fn revoke(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, id)): Path<(Uuid, rss_mdm_agent_wire::DeviceId)>,
    v: Body<OperationRequest>,
) -> Result<Json<rss_mdm_registration_service::device::RevocationReceipt>, Error> {
    Ok(Json(
        s.registrations
            .revoke(&auth.proof, id, body(v)?.operation_id, &a)
            .await?,
    ))
}
async fn trust_read(
    Path(_tenant): Path<Uuid>,
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<da::ConfigurationTrust>, Error> {
    Ok(Json(trust(
        s.configurations.trust().task_trust(&auth.proof, &a).await?,
    )))
}
async fn trust_change(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, id)): Path<(Uuid, Uuid)>,
    v: Body<rss_mdm_task_trust::service::Change>,
) -> Result<Json<da::ConfigurationTrust>, Error> {
    Ok(Json(trust(
        s.configurations
            .trust()
            .change_task_trust(&auth.proof, &a, id, &body(v)?)
            .await?,
    )))
}
async fn trust_operation(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, id)): Path<(Uuid, Uuid)>,
) -> Result<Json<da::ConfigurationTrust>, Error> {
    Ok(Json(trust(
        s.configurations
            .trust()
            .task_trust_operation(&auth.proof, &a, id)
            .await?,
    )))
}
async fn export(
    Path(_tenant): Path<Uuid>,
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Extension(auth): Extension<RequestAuth>,
    v: Body<da::Export>,
) -> Result<Json<da::SignedConfiguration>, Error> {
    Ok(Json(
        s.business
            .export_configuration(
                &s.configurations,
                &auth.proof,
                &body(v)?,
                s.platform.context.platform_sso.as_deref(),
                &a,
            )
            .await?,
    ))
}
async fn export_operation(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, id)): Path<(Uuid, Uuid)>,
) -> Result<Json<da::SignedConfiguration>, Error> {
    Ok(Json(
        s.business
            .configuration_operation(&s.configurations, &auth.proof, id)
            .await?,
    ))
}
async fn recover_issuance(
    State(s): State<Arc<Services>>,
    Extension(a): Extension<RequestAudit>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, id)): Path<(Uuid, Uuid)>,
    v: Body<enroll::RecoverIssuance>,
) -> Result<Json<enroll::Candidate>, Error> {
    Ok(Json(
        s.registrations
            .recover_issuance(&auth.proof, id, &body(v)?, &a)
            .await?,
    ))
}
#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationRequest {
    operation_id: Uuid,
}
