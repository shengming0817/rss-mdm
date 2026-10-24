use super::*;
use crate::authorization::{Permission, context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
type Response = std::result::Result<Json<Value>, Error>;
fn authorize(
    auth: &RequestAuth,
    c: &Command,
) -> std::result::Result<(), rss_mdm_inventory_service::Error> {
    let (permission, device) = match c {
        Command::Put { .. } | Command::Delete { .. } => (Permission::ComplianceWrite, None),
        Command::Recompute { .. } => (Permission::ComplianceRecompute, None),
        Command::Current { device } | Command::History { device, .. } => {
            (Permission::ComplianceRead, Some(device.as_str()))
        }
        _ => (Permission::ComplianceRuleRead, None),
    };
    auth.proof.require(permission, device)?;
    if let Command::Put { request, .. } = c
        && !request.input.groups().is_empty()
    {
        auth.proof.manage(Permission::GroupRead)?;
    }
    if matches!(c, Command::Task { .. }) {
        auth.proof.require_all_devices(Permission::ComplianceRead)?;
    }
    Ok(())
}
async fn run(s: &Compliance, a: &RequestAuth, audit: &RequestAudit, c: Command) -> Response {
    audit.set_action(if c.operation().is_some() {
        "compliance_write"
    } else {
        "compliance_read"
    });
    match &c {
        Command::Current { device } | Command::History { device, .. } => {
            audit.target_device(device)
        }
        Command::Read { id }
        | Command::Version { id, .. }
        | Command::Put { id, .. }
        | Command::Delete { id, .. }
        | Command::Recompute { id, .. }
        | Command::Task { id, .. } => audit.target(&id.to_string()),
    }
    if let Some(id) = c.operation() {
        audit.operation(id, audit.snapshot().action)
    }
    authorize(a, &c)?;
    s.execute(&c, audit, &|| authorize(a, &c))
        .await
        .map(Json)
        .map_err(Error::from)
}
pub fn routes() -> Router<Arc<Compliance>> {
    Router::new()
        .route(
            "/compliance-rules",
            get(list)
                .owned(&contracts::COMPLIANCE_RULES, &[RouteOperation::List])
                .queried(rss_mdm_inventory_service::compliance::directory::schema()),
        )
        .route(
            "/compliance-rules/{id}",
            get(read)
                .owned(&contracts::COMPLIANCE_RULES, &[RouteOperation::Get])
                .delete(remove)
                .owned(&contracts::COMPLIANCE_RULES, &[RouteOperation::Delete])
                .put(put)
                .owned(
                    &contracts::COMPLIANCE_RULES,
                    &[RouteOperation::Create, RouteOperation::Update],
                ),
        )
        .route(
            "/compliance-rules/{id}/versions/{revision}",
            get(version).owned(&contracts::COMPLIANCE_RULES, &[RouteOperation::Action]),
        )
        .route(
            "/compliance-rules/{id}/recompute",
            post(recompute).owned(&contracts::COMPLIANCE_RULES, &[RouteOperation::Action]),
        )
        .route(
            "/compliance-rules/{id}/tasks/{task}",
            get(task).owned(&contracts::COMPLIANCE_RULES, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{id}/compliance",
            get(current).owned(&contracts::DEVICES, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{id}/compliance/history",
            get(history).owned(&contracts::DEVICES, &[RouteOperation::Action]),
        )
}
async fn list(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> Response {
    let q =
        rss_mdm_inventory_service::compliance::directory::parse(raw.as_deref().unwrap_or_default())
            .map_err(|_| Error::Malformed)?;
    s.directory(&a.proof, &q, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn remove(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: std::result::Result<
        Json<rss_mdm_inventory_service::operation::Operation<Empty>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    run(
        &s,
        &a,
        &audit,
        Command::Delete {
            id,
            request: body.map_err(Error::from)?.0,
        },
    )
    .await
}
async fn read(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Response {
    run(&s, &a, &audit, Command::Read { id }).await
}
async fn put(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: std::result::Result<
        Json<rss_mdm_inventory_service::operation::Operation<Definition>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    run(
        &s,
        &a,
        &audit,
        Command::Put {
            sensitive: rss_mdm_inventory_service::assets::ReadScope::from_proof(&a.proof)?
                .sensitive,
            id,
            request: Box::new(body.map_err(Error::from)?.0),
        },
    )
    .await
}
async fn recompute(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: std::result::Result<
        Json<rss_mdm_inventory_service::operation::Operation<Empty>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    run(
        &s,
        &a,
        &audit,
        Command::Recompute {
            id,
            request: body.map_err(Error::from)?.0,
        },
    )
    .await
}
async fn task(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, task)): Path<(Uuid, Uuid)>,
) -> Response {
    run(&s, &a, &audit, Command::Task { id, task }).await
}
async fn current(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
) -> Response {
    run(&s, &a, &audit, Command::Current { device }).await
}
async fn history(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    q: std::result::Result<Query<HistoryPage>, axum::extract::rejection::QueryRejection>,
) -> Response {
    run(
        &s,
        &a,
        &audit,
        Command::History {
            device,
            subject: format!("{}:{}", a.proof.instance_id(), a.proof.principal_id()),
            page: q.map_err(|_| Error::Malformed)?.0,
        },
    )
    .await
}

async fn version(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, revision)): Path<(Uuid, i64)>,
) -> Response {
    run(&s, &a, &audit, Command::Version { id, revision }).await
}
