use super::*;
use crate::api::{App, RequestAuth};
use crate::authorization::Permission;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query as Params, State},
    routing::{get, post, put},
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response as HttpResponse},
};
use serde::Deserialize;
type BodyInput<T> = std::result::Result<Json<T>, axum::extract::rejection::JsonRejection>;
type ParamInput<T> = std::result::Result<Params<T>, axum::extract::rejection::QueryRejection>;
fn body<T>(v: BodyInput<T>) -> std::result::Result<T, Error> {
    v.map(|v| v.0).map_err(|_| Error::Malformed)
}
fn params<T>(v: ParamInput<T>) -> std::result::Result<T, Error> {
    v.map(|v| v.0).map_err(|_| Error::Malformed)
}

pub(crate) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/asset-fields", get(fields))
        .route("/device-queries", post(search))
        .route("/device-queries/{id}", get(query_status))
        .route("/device-queries/{id}/items", get(query_items))
        .route("/device-queries/{id}/facets/{facet}", get(query_facets))
        .route("/devices/{id}/inventory", get(detail))
        .route("/devices/{id}/manual-fields/{field}", put(manual))
        .route("/saved-queries", get(saved_list))
        .route("/saved-queries/{id}", get(saved_read).put(saved_write))
        .route("/saved-queries/{id}/execute", post(saved_execute))
}
fn owner(auth: &RequestAuth) -> Owner {
    Owner {
        instance: auth.proof.instance_id().into(),
        principal: auth.proof.principal_id().into(),
    }
}
fn authorize(auth: &RequestAuth, command: &Command) -> std::result::Result<(), Error> {
    match command {
        Command::Manual { device, .. } => auth
            .proof
            .require(Permission::InventoryAssign, Some(device)),
        Command::Detail { device, .. } => {
            auth.proof.require(Permission::InventoryRead, Some(device))
        }
        Command::QueryStatus { scope, .. }
        | Command::QueryItems { scope, .. }
        | Command::QueryFacets { scope, .. }
        | Command::Search { scope, .. }
        | Command::SavedExecute { scope, .. } => {
            if &ReadScope::from_proof(&auth.proof)? == scope {
                Ok(())
            } else {
                Err(Error::Forbidden)
            }
        }
        _ => ReadScope::from_proof(&auth.proof).map(|_| ()),
    }
}
async fn run(
    app: &App,
    auth: &RequestAuth,
    audit: &Audit,
    command: Command,
) -> std::result::Result<HttpResponse, Error> {
    audit.set_action(if command.operation().is_some() {
        "management_write"
    } else {
        "inventory_read"
    });
    match &command {
        Command::Manual { device, .. } | Command::Detail { device, .. } => audit.target(device),
        Command::QueryStatus { task, .. }
        | Command::QueryItems { task, .. }
        | Command::QueryFacets { task, .. } => audit.target(&task.to_string()),
        Command::SavedRead { id, .. }
        | Command::SavedWrite { id, .. }
        | Command::SavedExecute { id, .. } => audit.target(&id.to_string()),
        _ => {}
    }
    if let Some(id) = command.operation() {
        audit.operation(id, audit.snapshot().action);
    }
    authorize(auth, &command)?;
    let value = app
        .management
        .execute(
            &super::super::Command::Asset {
                command: command.clone(),
            },
            audit,
            &|| authorize(auth, &command),
        )
        .await?;
    let envelope: AssetEnvelope = serde_json::from_value(value)
        .map_err(|_| Error::Unavailable(Failure::ManagementStorage))?;
    let status = if matches!(&envelope.asset, Response::Accepted { .. }) {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(envelope)).into_response())
}
async fn fields(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
) -> std::result::Result<HttpResponse, Error> {
    run(&app, &auth, &audit, Command::Fields).await
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    cursor: Option<String>,
    limit: Option<usize>,
}
async fn search(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    payload: BodyInput<Operation<Query>>,
) -> std::result::Result<HttpResponse, Error> {
    let request = body(payload)?;
    let scope = ReadScope::from_proof(&auth.proof)?;
    run(&app, &auth, &audit, Command::Search { request, scope }).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
async fn detail(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(device): Path<String>,
    parameters: ParamInput<Empty>,
) -> std::result::Result<HttpResponse, Error> {
    params(parameters)?;
    let scope = ReadScope::from_proof(&auth.proof)?;
    run(&app, &auth, &audit, Command::Detail { device, scope }).await
}
async fn manual(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path((device, key)): Path<(String, String)>,
    payload: BodyInput<Operation<ManualChange>>,
) -> std::result::Result<HttpResponse, Error> {
    let change = body(payload)?;
    let field = FieldKey::parse(&key).map_err(|_| Error::Malformed)?;
    run(
        &app,
        &auth,
        &audit,
        Command::Manual {
            device,
            field,
            change,
            owner: owner(&auth),
        },
    )
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct After {
    after: Option<Uuid>,
}
async fn saved_list(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    parameters: ParamInput<After>,
) -> std::result::Result<HttpResponse, Error> {
    let after = params(parameters)?;
    run(
        &app,
        &auth,
        &audit,
        Command::SavedList {
            owner: owner(&auth),
            after: after.after,
        },
    )
    .await
}
async fn saved_read(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<Uuid>,
) -> std::result::Result<HttpResponse, Error> {
    run(
        &app,
        &auth,
        &audit,
        Command::SavedRead {
            owner: owner(&auth),
            id,
        },
    )
    .await
}
async fn saved_write(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<Uuid>,
    payload: BodyInput<Operation<SavedChange>>,
) -> std::result::Result<HttpResponse, Error> {
    let change = body(payload)?;
    run(
        &app,
        &auth,
        &audit,
        Command::SavedWrite {
            owner: owner(&auth),
            id,
            change,
        },
    )
    .await
}
async fn saved_execute(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<Uuid>,
    payload: BodyInput<Operation<Empty>>,
) -> std::result::Result<HttpResponse, Error> {
    let request = body(payload)?;
    run(
        &app,
        &auth,
        &audit,
        Command::SavedExecute {
            operation: request.operation_id,
            expected_revision: request.expected_revision,
            owner: owner(&auth),
            id,
            scope: ReadScope::from_proof(&auth.proof)?,
        },
    )
    .await
}

async fn query_status(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(task): Path<Uuid>,
) -> std::result::Result<HttpResponse, Error> {
    run(
        &app,
        &auth,
        &audit,
        Command::QueryStatus {
            task,
            scope: ReadScope::from_proof(&auth.proof)?,
        },
    )
    .await
}
async fn query_items(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(task): Path<Uuid>,
    parameters: ParamInput<Page>,
) -> std::result::Result<HttpResponse, Error> {
    let page = params(parameters)?;
    run(
        &app,
        &auth,
        &audit,
        Command::QueryItems {
            task,
            scope: ReadScope::from_proof(&auth.proof)?,
            limit: page.limit.unwrap_or(1000),
            cursor: page.cursor,
        },
    )
    .await
}
async fn query_facets(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path((task, facet)): Path<(Uuid, Facet)>,
    parameters: ParamInput<Page>,
) -> std::result::Result<HttpResponse, Error> {
    let page = params(parameters)?;
    run(
        &app,
        &auth,
        &audit,
        Command::QueryFacets {
            task,
            facet,
            scope: ReadScope::from_proof(&auth.proof)?,
            limit: page.limit.unwrap_or(1000),
            cursor: page.cursor,
        },
    )
    .await
}
