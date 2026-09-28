//! Authenticated HTTP adapter for the enterprise software owner.
use crate::{
    Error,
    authorization::{
        Permission,
        context::{AuthorizedPrincipal, RequestAuth},
    },
    transaction::{self, TransactionOwner},
};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    routing::get,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_software_service::catalog::{
    self, Catalog, ContentPort, Operation, SourceChange, VersionChange,
};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use serde_json::Value;
use std::sync::Arc;
pub(crate) struct HttpState {
    pub runtime: Arc<PgRuntime>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub tenant: TenantId,
    pub catalog: Catalog,
    pub content: Option<Arc<crate::content::Store>>,
}
pub(crate) fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/software/resources/{id}/versions/{version}/content",
            get(download),
        )
        .route(
            "/software/sources/{id}/revisions/{revision}",
            get(read_source).post(write_source),
        )
        .route(
            "/software/resources/{id}/versions/{version}",
            get(read_version).post(write_version),
        )
        .layer(axum::extract::DefaultBodyLimit::max(1_048_576))
}
impl From<catalog::Error> for transaction::Fault {
    fn from(e: catalog::Error) -> Self {
        match e {
            catalog::Error::Storage(e) => Self::Storage(e),
            catalog::Error::Sql(e) => Self::Sql(e),
            catalog::Error::Audit(e) => Self::from(e),
            catalog::Error::Fact(e) => Self::from(e),
            catalog::Error::Input => Error::Malformed.into(),
            catalog::Error::Conflict => Error::Conflict.into(),
            catalog::Error::NotAdmitted => Error::Forbidden.into(),
            catalog::Error::Missing => {
                Error::Resource(crate::resource_catalog::error::ResourceError::Missing).into()
            }
            catalog::Error::Integrity => {
                Error::Unavailable(crate::Failure::SoftwareCatalogInvariant).into()
            }
            catalog::Error::Content => Error::Unavailable(crate::Failure::ContentInvariant).into(),
        }
    }
}
async fn authorize(
    tx: &mut PgTransaction<'_>,
    proof: &AuthorizedPrincipal,
    permission: Permission,
) -> transaction::Result<()> {
    let snapshot = crate::action_admission::current(tx, proof).await?;
    snapshot.require(proof, permission, None)?;
    proof.check_live()?;
    Ok(())
}
async fn read_source(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, revision)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    auth.proof.require(Permission::SoftwareRead, None)?;
    audit.set_action("management_read");
    audit.target(&id);
    transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        &audit,
        (&app, &auth.proof, &id, &revision, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, revision, audit) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                let value = app.catalog.source_read_in(tx, id, revision).await?;
                app.audit
                    .append_request_in(tx, audit, 200, "success")
                    .await?;
                Ok(Json(value))
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
}
async fn write_source(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, revision)): Path<(String, String)>,
    Json(op): Json<Operation<SourceChange>>,
) -> Result<Json<Value>, Error> {
    let permission = match &op.input {
        SourceChange::Register { .. } => Permission::SoftwareWrite,
        SourceChange::Approve { .. } => Permission::SoftwareApprove,
        SourceChange::Withdraw { .. } => Permission::SoftwareWithdraw,
    };
    auth.proof.require(permission, None)?;
    audit.set_action("management_write");
    audit.target(&id);
    audit.operation(op.operation_id, "management_write");
    transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        &audit,
        (&app, &auth.proof, &id, &revision, &op, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, revision, op, audit) = *ctx;
                authorize(tx, proof, permission).await?;
                let value = app.catalog.source_in(tx, audit, id, revision, op).await?;
                proof.check_live()?;
                Ok(Json(value))
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
}
async fn read_version(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, version)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    auth.proof.require(Permission::SoftwareRead, None)?;
    audit.set_action("management_read");
    audit.target(&id);
    transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        &audit,
        (&app, &auth.proof, &id, &version, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, version, audit) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                let value = app.catalog.version_read_in(tx, id, version).await?;
                app.audit
                    .append_request_in(tx, audit, 200, "success")
                    .await?;
                Ok(Json(value))
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
}
async fn write_version(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, version)): Path<(String, String)>,
    Json(op): Json<Operation<VersionChange>>,
) -> Result<Json<Value>, Error> {
    let permission = match op.input {
        VersionChange::Approve { .. } => Permission::SoftwareApprove,
        VersionChange::Withdraw { .. } => Permission::SoftwareWithdraw,
    };
    auth.proof.require(permission, None)?;
    audit.set_action("management_write");
    audit.target(&id);
    audit.operation(op.operation_id, "management_write");
    audit.require_request_settlement();
    let verified = if matches!(op.input, VersionChange::Approve { .. }) {
        let resource = transaction::inspect(
            &app.runtime,
            app.tenant,
            (&app, &auth.proof, &id, &version, &op, &audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (app, proof, id, version, op, audit) = *ctx;
                    authorize(tx, proof, permission).await?;
                    if app
                        .catalog
                        .has_version_receipt_in(tx, audit, id, version, op)
                        .await?
                    {
                        Ok(None)
                    } else {
                        Ok(Some(app.catalog.version_in(tx, id, version).await?))
                    }
                })
            },
            TransactionOwner::SoftwareCatalog,
        )
        .await?;
        if let Some(resource) = resource {
            Some(
                app.content
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .as_ref()
                    .verify(&resource)
                    .await
                    .map_err(|_| Error::Malformed)?,
            )
        } else {
            None
        }
    } else {
        None
    };
    transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        &audit,
        (
            &app,
            &auth.proof,
            &id,
            &version,
            &op,
            &audit,
            verified.as_deref(),
        ),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, version, op, audit, verified) = *ctx;
                authorize(tx, proof, permission).await?;
                let value = app
                    .catalog
                    .version_change_in(tx, audit, id, version, op, verified)
                    .await?;
                proof.check_live()?;
                Ok(Json(value))
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    platform: rss_mdm_resource::Platform,
    architecture: rss_mdm_resource::Architecture,
    variant: String,
    artifact: Option<String>,
}
async fn download(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, version)): Path<(String, String)>,
    axum::extract::Query(selection): axum::extract::Query<Selection>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, Error> {
    auth.proof.require(Permission::SoftwareRead, None)?;
    audit.require_request_settlement();
    audit.set_action("management_read");
    audit.target(&id);
    let frozen = transaction::inspect(
        &app.runtime,
        app.tenant,
        (&app, &auth.proof, &id, &version, &selection),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, version, s) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                Ok(app
                    .catalog
                    .resolve_admitted_in(
                        tx,
                        id,
                        version,
                        s.platform,
                        s.architecture,
                        &rss_mdm_resource::Id::new(&s.variant).map_err(|_| Error::Malformed)?,
                    )
                    .await?)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await?;
    let selected = frozen
        .version()
        .resolve(selection.platform, selection.architecture, frozen.variant())
        .map_err(|_| Error::Malformed)?;
    let rss_mdm_resource::Declaration::Software { definition } = selected.declaration() else {
        return Err(Error::Malformed);
    };
    let artifact = match &selection.artifact {
        Some(reference) => definition
            .spec()
            .artifacts
            .values()
            .find(|a| &a.reference == reference)
            .ok_or(Error::Malformed)?
            .artifact()
            .map_err(|_| Error::Malformed)?,
        None => definition.primary().clone(),
    };
    let content = app
        .content
        .as_ref()
        .ok_or(Error::Unsupported)?
        .verify(&artifact)
        .await?;
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (&app, &auth.proof, &frozen),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, frozen) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                app.catalog.recheck_admitted_in(tx, frozen).await?;
                Ok(())
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await?;
    crate::content::http::response(content, &headers).await
}

#[cfg(all(test, feature = "integration"))]
pub(crate) mod t2;
