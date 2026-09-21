use super::*;
use crate::api::{App, RequestAuth};
use crate::authorization::Permission;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query as Params, State},
    routing::{get, post, put},
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
        .route("/devices", get(devices))
        .route("/devices/search", post(search))
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
        Command::Search { scope, .. } | Command::SavedExecute { scope, .. } => {
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
) -> std::result::Result<Json<AssetEnvelope>, Error> {
    audit.set_action(if command.operation().is_some() {
        "management_write"
    } else {
        "inventory_read"
    });
    match &command {
        Command::Manual { device, .. } | Command::Detail { device, .. } => audit.target(device),
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
    serde_json::from_value(value)
        .map(Json)
        .map_err(|_| Error::Unavailable(Failure::ManagementStorage))
}
async fn fields(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
) -> std::result::Result<Json<AssetEnvelope>, Error> {
    run(&app, &auth, &audit, Command::Fields).await
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    cursor: Option<String>,
    limit: Option<usize>,
}
async fn devices(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    parameters: ParamInput<Page>,
) -> std::result::Result<Json<AssetEnvelope>, Error> {
    let page = params(parameters)?;
    let scope = ReadScope::from_proof(&auth.proof)?;
    run(
        &app,
        &auth,
        &audit,
        Command::Search {
            scope,
            query: Query {
                cursor: page.cursor,
                limit: page.limit.unwrap_or(50),
                ..Default::default()
            },
        },
    )
    .await
}
async fn search(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    payload: BodyInput<Query>,
) -> std::result::Result<Json<AssetEnvelope>, Error> {
    let query = body(payload)?;
    let scope = ReadScope::from_proof(&auth.proof)?;
    run(&app, &auth, &audit, Command::Search { query, scope }).await
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
) -> std::result::Result<Json<AssetEnvelope>, Error> {
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
) -> std::result::Result<Json<AssetEnvelope>, Error> {
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
) -> std::result::Result<Json<AssetEnvelope>, Error> {
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
) -> std::result::Result<Json<AssetEnvelope>, Error> {
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
) -> std::result::Result<Json<AssetEnvelope>, Error> {
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
    payload: BodyInput<Page>,
) -> std::result::Result<Json<AssetEnvelope>, Error> {
    let page = body(payload)?;
    if page.limit.is_some() {
        return Err(Error::Malformed);
    }
    run(
        &app,
        &auth,
        &audit,
        Command::SavedExecute {
            owner: owner(&auth),
            id,
            scope: ReadScope::from_proof(&auth.proof)?,
            cursor: page.cursor,
        },
    )
    .await
}
