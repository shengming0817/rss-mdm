use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub fn previews(
    queries: Arc<rss_mdm_execution_service::queries::Queries>,
    telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router {
    Router::new()
        .route(
            "/policies/previews",
            post(super::http_preview::preview)
                .owned(
                    &contracts::POLICY_PREVIEWS,
                    &[RouteOperation::List, RouteOperation::Query],
                )
                .windowed(&rss_mdm_execution_service::queries::preview::SCHEMA),
        )
        .with_state(Arc::new(super::http_preview::StateServices {
            queries,
            telemetry,
        }))
        .layer(axum::Extension(cursor))
}

pub fn routes(
    queries: Arc<rss_mdm_execution_service::queries::Queries>,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<Arc<Policies>> {
    Router::new()
        .route(
            "/policies/resolve",
            post(resolve).owned(&contracts::POLICIES, &[RouteOperation::Action]),
        )
        .merge(
            Router::new()
                .route(
                    "/policies/{id}/assignments",
                    get(assignments)
                        .owned(&contracts::POLICY_ASSIGNMENTS, &[RouteOperation::List])
                        .windowed(&rss_mdm_execution_service::queries::assignments::SCHEMA),
                )
                .with_state(queries),
        )
        .route(
            "/policies/capabilities",
            get(capabilities).owned(&contracts::POLICIES, &[RouteOperation::Action]),
        )
        .route(
            "/policies",
            get(list)
                .owned(&contracts::POLICIES, &[RouteOperation::List])
                .queried(&rss_mdm_flow_service::planning::policies::read::SCHEMA),
        )
        .route(
            "/policies/{id}",
            get(read)
                .owned(&contracts::POLICIES, &[RouteOperation::Get])
                .post(change)
                .owned(
                    &contracts::POLICIES,
                    &[RouteOperation::Create, RouteOperation::Update],
                )
                .delete(delete)
                .owned(&contracts::POLICIES, &[RouteOperation::Delete]),
        )
        .route(
            "/policies/{id}/reruns",
            post(rerun).owned(
                &contracts::POLICIES,
                &[RouteOperation::Action, RouteOperation::Create],
            ),
        )
        .layer(axum::Extension(cursor))
}
async fn change(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: std::result::Result<
        Json<crate::http_operation::Operation<Change>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> std::result::Result<Json<Value>, Error> {
    let Json(input) = input.map_err(Error::from)?;
    audit.operation(
        input.operation_id,
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.resource_target(
        rss_mdm_audit_integration::TargetKind::Policy,
        &id.to_string(),
    );
    service
        .change(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn read(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<Value>, Error> {
    super::read::read(&service, &auth.proof, &audit, id)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn list(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<Json<Value>>, Error> {
    (async {
        let page =
            super::read::parse(raw.as_deref().unwrap_or_default()).map_err(|_| Error::Malformed)?;
        super::read::list(&service, &auth.proof, &audit, &page)
            .await
            .map(Json)
            .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

async fn rerun(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: std::result::Result<
        Json<crate::http_operation::Operation<super::rerun::Rerun>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> std::result::Result<Json<Value>, Error> {
    let Json(input) = input.map_err(Error::from)?;
    audit.operation(
        input.operation_id,
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.resource_target(
        rss_mdm_audit_integration::TargetKind::Policy,
        &id.to_string(),
    );
    service
        .rerun(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn assignments(
    State(service): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<Json<Value>>, Error> {
    (async {
        let (page, _) = rss_mdm_execution_service::queries::assignments::SCHEMA
            .parse(raw.as_deref().unwrap_or_default())
            .map_err(|_| Error::Malformed)?;
        rss_mdm_execution_service::queries::assignments::assignments(
            &service,
            &auth.proof,
            &audit,
            id,
            &page,
            &codec,
        )
        .await
        .map(|v| Json(serde_json::to_value(v).expect("assignment facts serialize")))
        .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Delete {
    operation_id: Uuid,
    expected_revision: u64,
}
async fn delete(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Delete>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    let Json(body) = body.map_err(Error::from)?;
    audit.operation(
        body.operation_id,
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.resource_target(
        rss_mdm_audit_integration::TargetKind::Policy,
        &id.to_string(),
    );
    service
        .change(
            &auth.proof,
            id,
            &crate::http_operation::Operation {
                operation_id: body.operation_id,
                expected_revision: body.expected_revision,
                input: Change::Archive,
            },
            &audit,
        )
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn capabilities(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<Value>, Error> {
    service
        .capabilities(&auth.proof, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn resolve(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Json(selector): Json<rss_mdm_agent_wire::runtime::CapabilitySelector>,
) -> std::result::Result<Json<Value>, Error> {
    super::read::resolve(&service, &auth.proof, &audit, &selector)
        .await
        .map(Json)
        .map_err(Error::from)
}
