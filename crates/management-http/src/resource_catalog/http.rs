use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
pub struct HttpState {
    pub catalog: Arc<ResourceCatalog>,
    pub content: Option<Arc<rss_mdm_content_service::service::Access>>,
}
pub fn routes() -> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { get_directory, get_blueprints, get_read, get_references, post_write } }
        RoutesModule1 {
            get_directory: rss_mdm_http_contract::module::Route::new(
                "/resources",
                get(directory, &contracts::RESOURCE, &[RouteOperation::List]),
            ),
            get_blueprints: rss_mdm_http_contract::module::Route::new(
                "/collection-blueprints",
                get(blueprints, &contracts::BLUEPRINTS, &[RouteOperation::List]),
            ),
            get_read: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}",
                rss_mdm_http_contract::routing::get(
                    read,
                    &contracts::RESOURCE,
                    &[RouteOperation::Get],
                ),
            ),
            get_references: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}/versions/{version}/references",
                get(
                    references,
                    &contracts::RESOURCE_REFERENCES,
                    &[RouteOperation::List],
                ),
            ),
            post_write: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}",
                rss_mdm_http_contract::routing::post(
                    write,
                    &contracts::RESOURCE,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Lifecycle,
                    ],
                ),
            ),
        }
        .assemble()
    }
}

async fn blueprints(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_resource_service::directory::Blueprints>,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "management_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        Ok(Json(s.catalog.blueprints(&auth.proof, &audit).await?))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn directory(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<ResourceDirectory>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<rss_mdm_resource::directory::Record>,
            >,
        >,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "management_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let q = query.parse().map_err(|_| Error::Malformed)?;
        Ok(Json(s.catalog.directory(&auth.proof, &q, &audit).await?))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn run(
    app: &HttpState,
    auth: &RequestAuth,
    audit: &RequestAudit,
    id: String,
    change: Option<Operation<Change>>,
) -> std::result::Result<Json<wire::Response>, Error> {
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
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Resource,
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
        app.catalog.execute(&command, audit, &auth.proof).await?,
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
        let uploaded = if let Some(content) = app.content.as_deref() {
            rss_mdm_content_service::service::upload(
                content,
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
            .await
        } else {
            Err(rss_mdm_content_service::service::Error::Unsupported)
        };
        content_audit.finalize(uploaded.as_ref().err().and_then(|error| {
            matches!(error, rss_mdm_content_service::service::Error::Audit(_))
                .then_some(rss_mdm_audit_integration::FailureReason::Transaction)
        }));
        uploaded?;
    }
    Ok(result)
}

struct ResourceDirectory;
impl rss_mdm_http_contract::query::DirectoryOwner for ResourceDirectory {
    fn execution() -> &'static rss_mdm_query::directory::Execution { rss_mdm_resource_service::directory::execution() }
}

struct ResourceReferences;
impl rss_mdm_http_contract::query::WindowOwner for ResourceReferences {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_resource_service::references::SCHEMA
    }
}
async fn references(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, version)): Path<(String, String)>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<ResourceReferences>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_resource_service::references::Entry>>,
    >,
    Error,
> {
    audit.resource_target(rss_mdm_audit_integration::TargetKind::Resource, &id);
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let (q, _) = query.parse().map_err(|_| Error::Malformed)?;
    Ok(rss_mdm_http_contract::CollectionResponse(Json(
        s.catalog.references(&auth.proof, &id, &version, &q).await?,
    )))
}
