use super::model::{Change, Create};
use crate::{
    Error,
    api::{App, RequestAuth},
    audit::Audit,
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rss_mdm_agent_wire as wire;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

type Body<T> = std::result::Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn body<T>(v: Body<T>) -> Result<T, Error> {
    v.map(|v| v.0).map_err(|_| Error::Malformed)
}
pub(crate) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/script-plans", post(create))
        .route("/script-plans/{id}", get(read))
        .route("/script-plans/{id}/runs", get(runs))
        .route("/script-plans/{id}/runs/{task}", get(run))
        .route("/script-plans/{id}/approve", post(approve))
        .route("/script-plans/{id}/cancel", post(cancel))
        .route(
            "/resources/{id}/content",
            post(upload).layer(DefaultBodyLimit::max(16_777_216)),
        )
}
pub(crate) fn agent_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/tasks/claim", post(claim))
        .route(
            "/tasks/{id}/events",
            post(event).layer(DefaultBodyLimit::max(wire::MAX_TASK_REQUEST_BYTES)),
        )
        .route("/tasks/{id}/content", get(download))
}
async fn create(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    input: Body<Create>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let input = body(input)?;
    audit.operation(input.operation_id, "command_accept");
    audit.plan(input.operation_id);
    app.commands
        .create_action_plan(&auth.proof, &input, &audit)
        .await
        .map(|v| (StatusCode::ACCEPTED, Json(v)))
}
async fn read(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, Error> {
    audit.operation(id, "command_read");
    audit.plan(id);
    app.commands
        .read_action_plan(&auth.proof, id, &audit)
        .await
        .map(Json)
}
async fn runs(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<Uuid>,
    Query(page): Query<super::history::Page>,
) -> Result<Json<Value>, Error> {
    audit.operation(id, "command_read");
    audit.plan(id);
    app.commands
        .action_runs(&auth.proof, id, &page, &audit)
        .await
        .map(Json)
}
async fn run(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path((id, task)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, Error> {
    audit.operation(task, "command_read");
    audit.plan(id);
    audit.target(&task.to_string());
    app.commands
        .action_run(&auth.proof, id, task, &audit)
        .await
        .map(Json)
}
async fn approve(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<Uuid>,
    input: Body<Change>,
) -> Result<Json<Value>, Error> {
    let input = body(input)?;
    audit.operation(input.operation_id, "command_approve");
    audit.plan(id);
    app.commands
        .approve_action_plan(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
}
async fn cancel(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<Uuid>,
    input: Body<Change>,
) -> Result<Json<Value>, Error> {
    let input = body(input)?;
    audit.operation(input.operation_id, "command_cancel");
    audit.plan(id);
    app.commands
        .cancel_action_plan(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
}
async fn authenticate(
    app: &App,
    headers: &HeaderMap,
    audit: &Audit,
) -> Result<crate::device::DevicePrincipal, crate::agent::AgentError> {
    let credential = crate::agent::agent_credential(app, headers)?;
    let principal = app
        .devices
        .authorize_task(&credential)
        .await
        .map_err(task_error)?;
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target(principal.device());
    Ok(principal)
}
fn task_error(error: Error) -> crate::agent::AgentError {
    match error {
        Error::Forbidden => crate::agent::AgentError::Wire(wire::ErrorCode::PermissionDenied),
        Error::NotFound | Error::ManagementNotFound(_) => {
            crate::agent::AgentError::Wire(wire::ErrorCode::TaskNotFound)
        }
        other => other.into(),
    }
}
async fn claim(
    State(app): State<Arc<App>>,
    Extension(audit): Extension<Audit>,
    headers: HeaderMap,
    input: Body<wire::TaskClaimRequest>,
) -> Result<Json<Value>, crate::agent::AgentError> {
    crate::agent::bounded(&app, async {
        let input = body(input)?;
        let principal = authenticate(&app, &headers, &audit).await?;
        audit.operation(input.operation_id(), "command_read");
        Ok(Json(
            app.commands
                .claim_action(&principal, &input, &audit)
                .await
                .map_err(task_error)?,
        ))
    })
    .await
}
async fn event(
    State(app): State<Arc<App>>,
    Extension(audit): Extension<Audit>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    input: Body<wire::TaskEventRequest>,
) -> Result<Json<Value>, crate::agent::AgentError> {
    crate::agent::bounded(&app, async {
        let input = body(input)?;
        let principal = authenticate(&app, &headers, &audit).await?;
        audit.operation(input.operation_id(), "command_accept");
        Ok(Json(
            app.commands
                .action_event(&principal, id, &input, &audit)
                .await
                .map_err(task_error)?,
        ))
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Download {
    attempt: Uuid,
}
async fn download(
    State(app): State<Arc<App>>,
    Extension(audit): Extension<Audit>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<Download>,
) -> Result<Response, crate::agent::AgentError> {
    crate::agent::bounded(&app, async {
        let principal = authenticate(&app, &headers, &audit).await?;
        audit.operation(id, "command_read");
        let (bytes, etag) = app
            .commands
            .action_content(&principal, id, query.attempt, &audit)
            .await
            .map_err(task_error)?;
        if headers.get_all(header::RANGE).iter().count() > 1 {
            return Err(Error::Malformed.into());
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
        let (start, end) = match super::content::range(requested, bytes.len()) {
            Ok(range) => range,
            Err(_) => {
                let mut response = (
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    Json(wire::ErrorBody {
                        code: wire::ErrorCode::RangeNotSatisfiable,
                    }),
                )
                    .into_response();
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    format!("bytes */{}", bytes.len())
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
            bytes[start..end].to_vec(),
        )
            .into_response();
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
                format!("bytes {start}-{}/{}", end - 1, bytes.len())
                    .parse()
                    .map_err(|_| Error::Malformed)?,
            );
        }
        Ok(response)
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    version: String,
    variant: String,
    platform: super::model::Platform,
    architecture: super::model::Architecture,
}
async fn upload(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<String>,
    Query(input): Query<Upload>,
    bytes: Bytes,
) -> Result<StatusCode, Error> {
    auth.proof
        .require(crate::authorization::Permission::ResourceWrite, None)?;
    audit.set_action("management_write");
    audit.target(&id);
    app.commands
        .transact(
            (&app.commands, &auth.proof, id, input, bytes, &audit),
            &audit,
            |ctx, tx| {
                Box::pin(async move {
                    let (service, proof, id, input, bytes, audit) = ctx;
                    crate::commands::storage::lock(tx, "action-owner").await?;
                    let tenant = proof.tenant_id().to_owned();
                    let instance = proof.instance_id().to_owned();
                    if tx.tenant_id().to_string() != tenant {
                        return Err(Error::Forbidden.into());
                    }
                    let snapshot = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                crate::authorization::lock_on(c, &tenant, &instance)
                                    .await
                                    .map_err(|_| {
                                        sqlx::Error::Protocol("authorization lock".into())
                                    })?;
                                Ok(crate::authorization::snapshot_on(c, &tenant, &instance).await)
                            })
                        })
                        .await??;
                    snapshot.require(
                        proof,
                        crate::authorization::Permission::ResourceWrite,
                        None,
                    )?;
                    let (version, state) = rss_mdm_resource_postgres::lock_reference_in(
                        tx,
                        &rss_mdm_resource::Id::new(id.as_str()).map_err(|_| Error::Malformed)?,
                        &rss_mdm_resource::Id::new(&input.version).map_err(|_| Error::Malformed)?,
                    )
                    .await?
                    .map_err(|_| Error::Conflict)?;
                    if state == rss_mdm_resource::State::Archived {
                        return Err(Error::Conflict.into());
                    }
                    let variant = version
                        .resolve(
                            match input.platform {
                                super::model::Platform::Windows => {
                                    rss_mdm_resource::Platform::Windows
                                }
                                super::model::Platform::Macos => rss_mdm_resource::Platform::MacOS,
                            },
                            match input.architecture {
                                super::model::Architecture::X86_64 => {
                                    rss_mdm_resource::Architecture::X86_64
                                }
                                super::model::Architecture::Aarch64 => {
                                    rss_mdm_resource::Architecture::Aarch64
                                }
                            },
                            &rss_mdm_resource::Id::new(&input.variant)
                                .map_err(|_| Error::Malformed)?,
                        )
                        .map_err(|_| Error::Malformed)?;
                    let rss_mdm_resource::Declaration::Script {
                        artifact,
                        definition,
                    } = variant.declaration()
                    else {
                        return Err(Error::Malformed.into());
                    };
                    if definition.spec().profile == rss_mdm_resource::ScriptProfile::OsqueryInfoV1
                        && bytes.as_ref() != b"SELECT version FROM osquery_info;\n"
                    {
                        return Err(Error::Malformed.into());
                    }
                    let content = service.content.clone().ok_or(Error::Unsupported)?;
                    let artifact = artifact.clone();
                    let bytes = bytes.clone();
                    tokio::task::spawn_blocking(move || content.put(&artifact, &bytes))
                        .await
                        .map_err(|_| Error::Unavailable(crate::Failure::CommandStorage))??;
                    proof.require(crate::authorization::Permission::ResourceWrite, None)?;
                    proof.check_live()?;
                    crate::commands::storage::audit(tx, audit, 201).await?;
                    Ok(())
                })
            },
        )
        .await?;
    Ok(StatusCode::CREATED)
}
