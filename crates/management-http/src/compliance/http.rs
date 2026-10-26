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
type Response = std::result::Result<Reply, Error>;
async fn run(s: &Compliance, a: &RequestAuth, audit: &RequestAudit, c: Command) -> Response {
    audit.set_action(
        if c.operation().is_some() {
            "compliance_write"
        } else {
            "compliance_read"
        },
        if c.operation().is_some() {
            rss_mdm_audit_integration::AuditIntent::Management
        } else {
            rss_mdm_audit_integration::AuditIntent::Routine
        },
    );
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
        audit.operation(
            id,
            audit.snapshot().action,
            rss_mdm_audit_integration::AuditIntent::Management,
        )
    }
    s.execute(&c, audit, &a.proof).await.map_err(Error::from)
}
pub fn routes() -> Router<Arc<Compliance>> {
    Router::new()
        .route(
            "/compliance-rules",
            get(list).owned(&contracts::COMPLIANCE_RULES, &[RouteOperation::List]),
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
            post(recompute).owned(
                &contracts::COMPLIANCE_RULES,
                &[RouteOperation::Action, RouteOperation::Create],
            ),
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
            get(history).owned(&contracts::COMPLIANCE_HISTORY, &[RouteOperation::List]),
        )
}
async fn list(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<ComplianceDirectoryQuery>,
    >,
) -> std::result::Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<directory::DirectoryRow>>>,
    >,
    Error,
> {
    (async {
        let q = query.parse().map_err(|_| Error::Malformed)?;
        s.directory(&a.proof, &q, &audit)
            .await
            .map(Json)
            .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
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
) -> std::result::Result<Json<Deleted>, Error> {
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
    .and_then(|v| v.deleted().map_err(Error::from))
    .map(Json)
}
async fn read(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<RuleView>, Error> {
    run(&s, &a, &audit, Command::Read { id })
        .await
        .and_then(|v| v.rule().map_err(Error::from))
        .map(Json)
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
) -> std::result::Result<Json<Changed>, Error> {
    run(
        &s,
        &a,
        &audit,
        Command::Put {
            id,
            request: Box::new(body.map_err(Error::from)?.0),
        },
    )
    .await
    .and_then(|v| v.changed().map_err(Error::from))
    .map(Json)
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
) -> std::result::Result<Json<Accepted>, Error> {
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
    .and_then(|v| v.accepted().map_err(Error::from))
    .map(Json)
}
async fn task(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, task)): Path<(Uuid, Uuid)>,
) -> std::result::Result<Json<TaskView>, Error> {
    run(&s, &a, &audit, Command::Task { id, task })
        .await
        .and_then(|v| v.task().map_err(Error::from))
        .map(Json)
}
async fn current(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
) -> std::result::Result<Json<CurrentView>, Error> {
    run(&s, &a, &audit, Command::Current { device })
        .await
        .and_then(|v| v.current().map_err(Error::from))
        .map(Json)
}
async fn history(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    params: rss_mdm_http_contract::query::OwnedQuery<ComplianceHistoryQuery>,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<Json<History>>, Error> {
    (async {
        run(
            &s,
            &a,
            &audit,
            Command::History {
                device,
                subject: format!("{}:{}", a.proof.instance_id(), a.proof.principal_id()),
                page: params.parse().map_err(Error::from)?,
            },
        )
        .await
        .and_then(|v| v.history().map_err(Error::from))
        .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

async fn version(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, revision)): Path<(Uuid, i64)>,
) -> std::result::Result<Json<RuleView>, Error> {
    run(&s, &a, &audit, Command::Version { id, revision })
        .await
        .and_then(|v| v.rule().map_err(Error::from))
        .map(Json)
}

struct ComplianceDirectoryQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ComplianceDirectoryQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        rss_mdm_inventory_service::compliance::directory::schema()
    }
    fn parse(raw: &str) -> rss_mdm_query::Result<rss_mdm_query::directory::Query> {
        rss_mdm_inventory_service::compliance::directory::parse(raw)
    }
}

struct ComplianceHistoryQuery;
impl rss_mdm_http_contract::query::QueryOwner for ComplianceHistoryQuery {
    type Parsed = HistoryQuery;
    type Error = crate::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Window(&HISTORY))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let mut schema = rss_mdm_http_contract::query::window_parameters(&HISTORY);
        for name in ["from", "until"] {
            schema.value["properties"][name] =
                serde_json::json!({"type":"integer","format":"int64"});
        }
        schema
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        HistoryQuery::parse(raw).map_err(Into::into)
    }
}
