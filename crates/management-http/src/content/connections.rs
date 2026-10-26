use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_content_service::connections::{
    Receipt, Request,
    authority::{Authority, Directory},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use std::sync::Arc;

pub fn routes(cursor: rss_mdm_query::cursor::CursorCodec) -> Router<Arc<Authority>> {
    Router::new()
        .route(
            "/storage/connections/versions",
            get(history)
                .owned(
                    &contracts::STORAGE_CONNECTION_VERSIONS,
                    &[RouteOperation::List],
                )
                .windowed(&rss_mdm_content_service::connections::authority::HISTORY),
        )
        .route(
            "/storage/connections",
            get(read)
                .owned(&contracts::STORAGE_CONNECTIONS, &[RouteOperation::Get])
                .post(create)
                .owned(&contracts::STORAGE_CONNECTIONS, &[RouteOperation::Update]),
        )
        .route(
            "/storage/connections/operations/{id}",
            get(operation).owned(&contracts::STORAGE_CONNECTIONS, &[RouteOperation::Get]),
        )
        .layer(Extension(cursor))
}
async fn read(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<Directory>, Error> {
    audit.set_action(
        "storage_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    Ok(Json(service.read(&auth.proof, &audit, None).await?))
}
async fn create(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    input: Result<Json<Request>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Receipt>), Error> {
    let operation = crate::api::write_key(&headers, &audit, "storage_provision")?;
    let input = input.map_err(Error::from)?.0;
    Ok((
        StatusCode::ACCEPTED,
        Json(
            service
                .create(&auth.proof, &audit, operation, &input)
                .await?,
        ),
    ))
}

async fn operation(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<Receipt>, Error> {
    audit.set_action(
        "storage_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    Ok(Json(service.operation(&auth.proof, &audit, id).await?))
}

async fn history(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(cursor): Extension<rss_mdm_query::cursor::CursorCodec>,
    RawQuery(raw): RawQuery,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<rss_mdm_query::Page<Receipt>>>, Error> {
    (async {
        let (q, _) = rss_mdm_content_service::connections::authority::HISTORY
            .parse(raw.as_deref().unwrap_or(""))
            .map_err(|_| Error::Malformed)?;
        service
            .history(&auth.proof, &audit, &q, &cursor)
            .await
            .map(Json)
            .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
