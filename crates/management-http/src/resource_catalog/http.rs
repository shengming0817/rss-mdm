use super::*;
use crate::authorization::{Permission, context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use serde_json::Value;
pub struct HttpState {
    pub catalog: Arc<ResourceCatalog>,
    pub content: Arc<rss_mdm_content_service::service::Access>,
}
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/resources",
            get(directory).owned(&contracts::RESOURCE, &[RouteOperation::List]),
        )
        .route(
            "/collection-blueprints",
            get(blueprints).owned(&contracts::BLUEPRINTS, &[RouteOperation::List]),
        )
        .route(
            "/resources/{id}",
            get(read)
                .owned(&contracts::RESOURCE, &[RouteOperation::Get])
                .post(write)
                .owned(
                    &contracts::RESOURCE,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Lifecycle,
                    ],
                ),
        )
}

async fn blueprints(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<Value>, Error> {
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    Ok(Json(s.catalog.blueprints(&auth.proof, &audit).await?))
}
async fn directory(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    RawQuery(raw): RawQuery,
) -> Result<Json<rss_mdm_query::Page<serde_json::Map<String, Value>>>, Error> {
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let q = rss_mdm_resource::directory::Query::parse(raw.as_deref().unwrap_or(""))
        .map_err(|_| Error::Malformed)?;
    Ok(Json(s.catalog.directory(&auth.proof, &q, &audit).await?))
}
async fn run(
    app: &HttpState,
    auth: &RequestAuth,
    audit: &RequestAudit,
    id: String,
    change: Option<Operation<Change>>,
) -> std::result::Result<Json<wire::Response>, Error> {
    let permission = if change.is_some() {
        Permission::ResourceWrite
    } else {
        Permission::ResourceRead
    };
    audit.resource_target(rss_mdm_audit_integration::TargetKind::Resource, &id);
    audit.set_action(
        if change.is_some() {
            "management_write"
        } else {
            "management_read"
        },
        if change.is_some() {
            rss_mdm_audit_integration::AuditIntent::Management
        } else {
            rss_mdm_audit_integration::AuditIntent::Routine
        },
    );
    if let Some(op) = &change {
        audit.operation(
            op.operation_id,
            "management_write",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
    }
    let command = match change {
        Some(change) => Command::Resource { id, change },
        None => Command::ResourceRead { id },
    };
    Ok(Json(wire::Response::decode(
        app.catalog
            .execute(&command, audit, &|| {
                auth.proof
                    .manage(permission)
                    .map_err(rss_mdm_flow_service::Error::from)
            })
            .await?,
    )?))
}
async fn read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
) -> std::result::Result<Json<wire::Response>, Error> {
    run(&app, &auth, &audit, id, None).await
}
async fn write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(continuation): Extension<crate::http_operation::RequestContinuation>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
    body: std::result::Result<Json<Operation<Change>>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<wire::Response>, Error> {
    let op = body.map_err(Error::from)?.0;
    let blueprint = match &op.input {
        Change::Instantiate { blueprint, version } => {
            Some(rss_mdm_resource::blueprints::get(blueprint, version).ok_or(Error::Malformed)?)
        }
        _ => None,
    };
    let operation = op.operation_id;
    // Content settles independently. Copy before the resource transaction commits,
    // so a later content rollback cannot erase the confirmed resource commit.
    let content_audit = blueprint.as_ref().map(|_| {
        audit.require_final_request();
        audit.transaction_copy()
    });
    let result = match run(&app, &auth, &audit, id.clone(), Some(op)).await {
        Ok(result) => result,
        Err(error) => {
            if let Some(content_audit) = content_audit {
                content_audit.finalize(None);
            }
            return Err(error);
        }
    };
    if let (Some(blueprint), Some(content_audit)) = (blueprint, content_audit) {
        let bytes = blueprint.definition.canonical();
        let uploaded = rss_mdm_content_service::service::upload(
            &app.content,
            rss_mdm_content_service::service::UploadAuthority::new(
                &auth.proof,
                continuation.secret(),
            ),
            &content_audit,
            &id,
            &rss_mdm_content_service::service::Selection {
                version: blueprint.label(),
                variant: "x86_64".into(),
                platform: blueprint.platform,
                architecture: rss_mdm_resource::Architecture::X86_64,
                artifact: Some(blueprint.definition.reference().into()),
                operation: Some(operation),
            },
            bytes.as_slice(),
        )
        .await;
        content_audit.finalize(uploaded.as_ref().err().and_then(|error| {
            matches!(error, rss_mdm_content_service::service::Error::Audit(_))
                .then_some(rss_mdm_audit_integration::FailureReason::Transaction)
        }));
        uploaded?;
    }
    Ok(result)
}
