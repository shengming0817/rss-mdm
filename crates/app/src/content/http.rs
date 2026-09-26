//! Resource-authorized streaming upload. Long I/O never holds a PG transaction.
use super::{Binding, Store, Upload};
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
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::post,
};
use futures::TryStreamExt;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_resource as r;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
pub(crate) struct HttpState {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) tenant: TenantId,
    pub(crate) content: Option<Arc<Store>>,
    pub(crate) clock: Arc<dyn crate::clock::Clock>,
}
pub(crate) fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/resources/{id}/content/operations/{operation}",
            axum::routing::get(receipt),
        )
        .route("/software/content/cleanup", post(cleanup))
        .route("/resources/{id}/content", post(upload))
        .route("/resources/{id}/content/mirror", post(mirror))
        .route(
            "/resources/{id}/uploads/{upload}",
            post(begin).get(status).patch(append),
        )
        .route("/resources/{id}/uploads/{upload}/complete", post(complete))
        .layer(DefaultBodyLimit::disable())
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    version: String,
    variant: String,
    platform: r::Platform,
    architecture: r::Architecture,
    artifact: Option<String>,
    operation: Option<Uuid>,
}
impl Selection {
    fn from_binding(b: &Binding) -> Self {
        Self {
            version: b.version.clone(),
            variant: b.variant.clone(),
            platform: b.platform,
            architecture: b.architecture,
            artifact: Some(b.reference.clone()),
            operation: None,
        }
    }
}
async fn resolve_in(
    tx: &mut PgTransaction<'_>,
    proof: &AuthorizedPrincipal,
    id: &str,
    input: &Selection,
) -> transaction::Result<Binding> {
    crate::action_admission::lock(tx, "action-owner").await?;
    let snapshot = crate::action_admission::current(tx, proof).await?;
    snapshot.require(proof, Permission::ResourceWrite, None)?;
    let (version, state) = rss_mdm_resource_postgres::lock_reference_in(
        tx,
        &r::Id::new(id).map_err(|_| Error::Malformed)?,
        &r::Id::new(&input.version).map_err(|_| Error::Malformed)?,
    )
    .await?
    .map_err(|_| Error::Conflict)?;
    if state == r::State::Archived {
        return Err(Error::Conflict.into());
    }
    let variant = version
        .resolve(
            input.platform,
            input.architecture,
            &r::Id::new(&input.variant).map_err(|_| Error::Malformed)?,
        )
        .map_err(|_| Error::Malformed)?;
    let artifact = match variant.declaration() {
        r::Declaration::Software { definition } => {
            if let Some(reference) = &input.artifact {
                definition
                    .spec()
                    .artifacts
                    .values()
                    .find(|a| &a.reference == reference)
                    .ok_or(Error::Malformed)?
                    .artifact()
                    .map_err(|_| Error::Malformed)?
            } else {
                definition.primary().clone()
            }
        }
        r::Declaration::Script {
            artifact,
            definition,
        } => {
            if artifact.length() > 16_777_216
                || input
                    .artifact
                    .as_ref()
                    .is_some_and(|id| id != artifact.reference().as_str())
            {
                return Err(Error::Malformed.into());
            }
            if definition.spec().profile == r::ScriptProfile::OsqueryInfoV1
                && (artifact.length() != 32
                    || artifact.digest() != r::Digest::of(b"SELECT version FROM osquery_info;\n"))
            {
                return Err(Error::Malformed.into());
            }
            artifact.clone()
        }
        _ => return Err(Error::Malformed.into()),
    };
    let (source, origin) = match variant.declaration() {
        r::Declaration::Software { definition } => (
            Some(definition.spec().source.clone()),
            definition
                .spec()
                .artifacts
                .values()
                .find(|a| a.reference == artifact.reference().as_str())
                .and_then(|a| a.origin.clone()),
        ),
        _ => (None, None),
    };
    Ok(Binding {
        source,
        origin,
        resource: id.into(),
        version: input.version.clone(),
        variant: input.variant.clone(),
        platform: input.platform,
        architecture: input.architecture,
        resource_digest: version.digest().bytes(),
        reference: artifact.reference().as_str().into(),
        length: artifact.length(),
        sha256: artifact.digest().bytes(),
        actor: format!("{}:{}", proof.instance_id(), proof.principal_id()),
    })
}
async fn resolve(
    app: &HttpState,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    input: &Selection,
) -> Result<Binding, Error> {
    audit.require_request_settlement();
    proof.require(Permission::ResourceWrite, None)?;
    audit.target(id);
    audit.set_action("management_write");
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (proof, id, input),
        |ctx, tx| {
            Box::pin(async move {
                let (proof, id, input) = *ctx;
                resolve_in(tx, proof, id, input).await
            })
        },
        TransactionOwner::ResourceCatalog,
    )
    .await
}
fn store(app: &HttpState) -> Result<&Arc<Store>, Error> {
    app.content.as_ref().ok_or(Error::Unsupported)
}
async fn current(
    app: &HttpState,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    upload: Uuid,
) -> Result<Upload, Error> {
    audit.operation(upload, "management_write");
    proof.require(Permission::ResourceWrite, None)?;
    let value = store(app)?
        .status(upload, app.clock.unix_seconds()?)
        .await?;
    if value.binding.resource != id
        || value.binding.actor != format!("{}:{}", proof.instance_id(), proof.principal_id())
    {
        return Err(Error::Forbidden);
    }
    let binding = resolve(
        app,
        proof,
        audit,
        id,
        &Selection::from_binding(&value.binding),
    )
    .await?;
    if binding != value.binding {
        return Err(Error::Conflict);
    }
    Ok(value)
}
async fn record(
    app: &HttpState,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    upload: &Upload,
) -> Result<(), Error> {
    audit.operation(upload.id, "management_write");
    let verified = store(app)?.verify(&upload.binding.artifact()?).await?;
    transaction::run(&app.audit_store,&app.runtime,app.tenant,audit,(app,proof,audit,upload,&verified),|ctx,tx|Box::pin(async move{
        let (app,proof,audit,upload,verified)=*ctx;
        tx.prepare_outbox_partitions(&[super::event::partition(app.tenant,&upload.binding.resource)?]).await?;
        let current=resolve_in(tx,proof,&upload.binding.resource,&Selection::from_binding(&upload.binding)).await?;
        if current!=upload.binding || !verified.matches(&current.artifact()?){return Err(Error::Conflict.into());}
        let tenant=tx.tenant_id().to_string();let u=upload.clone();
        let fresh=tx.with_connection(move|c|Box::pin(async move{
            let changed=sqlx::query("INSERT INTO mdm_content.bindings(tenant_id,operation,resource,version,reference,length,sha256) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,operation) DO NOTHING")
                .bind(tenant).bind(u.id.to_string()).bind(u.binding.resource).bind(u.binding.version).bind(u.binding.reference).bind(u.binding.length as i64).bind(u.binding.sha256.to_vec()).execute(c).await?.rows_affected();Ok(changed!=0)
        })).await?;
        if fresh {super::event::append(&rss_transactional_messaging_postgres::PgOutboxWriter::new(app.runtime.clone(),super::event::domain()),tx,upload).await?;}
        let hash=transaction::fingerprint(&upload.binding)?;
        let fact=rss_mdm_audit_integration::Fact::business(audit,&format!("content:{}",upload.id),&hash,201,"success",None)?;
        app.audit_store.append_in(tx,&fact,!fresh).await?;proof.check_live()?;Ok(())
    }),TransactionOwner::ResourceCatalog).await
}
async fn begin(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
    Query(input): Query<Selection>,
) -> Result<Json<Upload>, Error> {
    audit.operation(upload, "management_write");
    let binding = resolve(&app, &auth.proof, &audit, &id, &input).await?;
    let result = store(&app)?
        .begin(upload, binding, app.clock.unix_seconds()?)
        .await?;
    Ok(Json(result))
}
async fn status(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
) -> Result<Json<Upload>, Error> {
    Ok(Json(current(&app, &auth.proof, &audit, &id, upload).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Offset {
    offset: u64,
}
async fn append(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
    Query(offset): Query<Offset>,
    body: Body,
) -> Result<axum::response::Response, Error> {
    use axum::response::IntoResponse;
    let old = current(&app, &auth.proof, &audit, &id, upload).await?;
    if old.offset != offset.offset {
        return Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"code":"upload_offset_conflict","offset":old.offset})),
        )
            .into_response());
    }
    let reader =
        tokio_util::io::StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    let result = store(&app)?
        .append(upload, offset.offset, app.clock.unix_seconds()?, reader)
        .await?;
    auth.proof.check_live()?;
    Ok(Json(result).into_response())
}
async fn complete(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
) -> Result<StatusCode, Error> {
    current(&app, &auth.proof, &audit, &id, upload).await?;
    let result = store(&app)?
        .finish(upload, app.clock.unix_seconds()?)
        .await?;
    record(&app, &auth.proof, &audit, &result).await?;
    Ok(StatusCode::CREATED)
}
async fn upload(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
    Query(input): Query<Selection>,
    body: Body,
) -> Result<StatusCode, Error> {
    let operation = input.operation.ok_or(Error::Malformed)?;
    audit.operation(operation, "management_write");
    let binding = resolve(&app, &auth.proof, &audit, &id, &input).await?;
    let now = app.clock.unix_seconds()?;
    let session = store(&app)?.begin(operation, binding, now).await?;
    if !session.complete && session.offset != session.binding.length {
        let reader = tokio_util::io::StreamReader::new(
            body.into_data_stream().map_err(std::io::Error::other),
        );
        let written = store(&app)?.append(operation, 0, now, reader).await?;
        if written.offset != written.binding.length {
            return Err(Error::Malformed);
        }
    }
    let complete = store(&app)?
        .finish(operation, app.clock.unix_seconds()?)
        .await?;
    record(&app, &auth.proof, &audit, &complete).await?;
    Ok(StatusCode::CREATED)
}
/// Explicit bounded maintenance; every candidate is pinned against new upload/download readers.
async fn cleanup(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<serde_json::Value>, Error> {
    auth.proof.require(Permission::ResourceWrite, None)?;
    audit.require_request_settlement();
    audit.set_action("management_write");
    let candidates = store(&app)?.garbage(app.clock.unix_seconds()?).await?;
    let mut removed = 0usize;
    for candidate in candidates {
        let unreferenced = transaction::inspect(
            &app.runtime,
            app.tenant,
            (&auth.proof, candidate.digest),
            |ctx, tx| {
                Box::pin(async move {
                    let (proof, digest) = *ctx;
                    crate::action_admission::lock(tx, "action-owner").await?;
                    crate::action_admission::current(tx, proof).await?.require(
                        proof,
                        Permission::ResourceWrite,
                        None,
                    )?;
                    let referenced = rss_mdm_resource_postgres::artifact_referenced_in(
                        tx,
                        r::Digest::from_bytes(digest),
                    )
                    .await?;
                    proof.check_live()?;
                    Ok(!referenced)
                })
            },
            TransactionOwner::ResourceCatalog,
        )
        .await?;
        if unreferenced {
            candidate.remove().await?;
            removed += 1;
        }
    }
    Ok(Json(serde_json::json!({"removed":removed})))
}
/// Mirror only the selected frozen artifact; source credentials never reach the artifact origin.
async fn mirror(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
    Query(input): Query<Selection>,
) -> Result<StatusCode, Error> {
    let operation = input.operation.ok_or(Error::Malformed)?;
    audit.operation(operation, "management_write");
    let binding = resolve(&app, &auth.proof, &audit, &id, &input).await?;
    let source = binding.source.as_ref().ok_or(Error::Malformed)?;
    let catalog = rss_mdm_software_service::catalog::Catalog::new(
        app.runtime.clone(),
        app.tenant,
        Arc::new(crate::software_publication::host::Audit(
            app.audit_store.clone(),
        )),
    );
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (&catalog, source),
        |ctx, tx| {
            Box::pin(async move {
                let (catalog, source) = *ctx;
                let value = catalog
                    .source_read_in(tx, &source.id, &source.revision)
                    .await?;
                if value["admission"]["state"] != "approved"
                    || value["snapshot"]
                        != serde_json::to_value(source).map_err(|_| Error::Malformed)?
                {
                    return Err(Error::Forbidden.into());
                }
                Ok(())
            })
        },
        TransactionOwner::ResourceCatalog,
    )
    .await?;
    let content = store(&app)?;
    let origins = content
        .config
        .imports
        .get(&source.id)
        .ok_or(Error::Forbidden)?
        .clone();
    let reader = rss_mdm_software_service::publication::ArtifactReader::new(
        origins,
        content.config.max_artifact_bytes,
        std::time::Duration::from_secs(content.config.transfer_seconds.min(3600)),
    )
    .map_err(|_| Error::Malformed)?;
    let now = app.clock.unix_seconds()?;
    let session = content.begin(operation, binding.clone(), now).await?;
    if !session.complete {
        if session.offset != 0 {
            return Err(Error::Conflict);
        }
        let response = reader
            .open(
                binding.origin.as_deref().ok_or(Error::Malformed)?,
                binding.length,
            )
            .await
            .map_err(|_| Error::Unavailable(crate::Failure::ContentImport))?;
        let stream = tokio_util::io::StreamReader::new(
            response.bytes_stream().map_err(std::io::Error::other),
        );
        content.append(operation, 0, now, stream).await?;
    }
    let result = content.finish(operation, app.clock.unix_seconds()?).await?;
    record(&app, &auth.proof, &audit, &result).await?;
    Ok(StatusCode::CREATED)
}

/// Shared response framing for catalog and execution-authorized content.
pub(crate) async fn response(
    content: super::Verified,
    headers: &axum::http::HeaderMap,
) -> Result<axum::response::Response, Error> {
    use axum::{http::header, response::IntoResponse};
    let etag = content.etag();
    let length = content.artifact.length();
    if headers.get_all(header::RANGE).iter().count() > 1 {
        return Err(Error::Malformed);
    }
    let requested = headers
        .get(header::RANGE)
        .map(|h| h.to_str().map_err(|_| Error::Malformed))
        .transpose()?;
    let requested = if headers
        .get(header::IF_RANGE)
        .is_some_and(|value| value.as_bytes() != etag.as_bytes())
    {
        None
    } else {
        requested
    };
    let (start, end) = match super::range(requested, length) {
        Ok(range) => range,
        Err(_) => {
            let mut response = (
                StatusCode::RANGE_NOT_SATISFIABLE,
                Json(serde_json::json!({"code":"range_not_satisfiable"})),
            )
                .into_response();
            response.headers_mut().insert(
                header::CONTENT_RANGE,
                format!("bytes */{}", length)
                    .parse()
                    .map_err(|_| Error::Malformed)?,
            );
            return Ok(response);
        }
    };
    let mut response = (
        if requested.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        },
        content.body(start, end).await?,
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        (end - start)
            .to_string()
            .parse()
            .map_err(|_| Error::Malformed)?,
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().expect("constant"),
    );
    response
        .headers_mut()
        .insert(header::ETAG, etag.parse().map_err(|_| Error::Malformed)?);
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, "bytes".parse().expect("constant"));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "private, no-store".parse().expect("constant"),
    );
    if requested.is_some() {
        response.headers_mut().insert(
            header::CONTENT_RANGE,
            format!("bytes {start}-{}/{}", end - 1, length)
                .parse()
                .map_err(|_| Error::Malformed)?,
        );
    }
    Ok(response)
}
/// Durable operation lookup survives expiration of the temporary upload session.
async fn receipt(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, operation)): Path<(String, Uuid)>,
) -> Result<Json<serde_json::Value>, Error> {
    use sqlx::Row;
    auth.proof.require(Permission::ResourceRead, None)?;
    audit.set_action("management_read");
    audit.target(&id);
    transaction::run(&app.audit_store,&app.runtime,app.tenant,&audit,(&app,&auth.proof,&audit,&id,operation),|ctx,tx|Box::pin(async move{
        let(app,proof,audit,id,operation)=*ctx;
        crate::action_admission::current(tx,proof).await?.require(proof,Permission::ResourceRead,None)?;
        let tenant=tx.tenant_id().to_string();let id=id.clone();
        let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT resource,version,reference,length,sha256 FROM mdm_content.bindings WHERE tenant_id=$1::uuid AND operation=$2::uuid AND resource=$3").bind(tenant).bind(operation.to_string()).bind(id).fetch_optional(c).await})).await?.ok_or(Error::Resource(crate::resource_catalog::error::ResourceError::Missing))?;
        let value=serde_json::json!({"operationId":operation,"committed":true,"resource":row.try_get::<String,_>("resource")?,"version":row.try_get::<String,_>("version")?,"reference":row.try_get::<String,_>("reference")?,"length":row.try_get::<i64,_>("length")?,"sha256":row.try_get::<Vec<u8>,_>("sha256")?});
        app.audit_store.append_request_in(tx,audit,200,"success").await?;Ok(Json(value))
    }),TransactionOwner::ResourceCatalog).await
}
