use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::routing::get;
use rss_mdm_http_contract::{Operation as RouteOperation, Router, catalog as contracts};
use std::sync::Arc;
use uuid::Uuid;
pub fn routes(
    cursor: Option<rss_mdm_query::cursor::CursorCodec>,
) -> Router<Arc<dyn super::Reads>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct Routes for [Browser]{get_runs,get_run}}
    let router = Routes {
        get_runs: rss_mdm_http_contract::module::Route::new(
            "/policies/{id}/runs",
            get(runs, &contracts::POLICY_RUNS, &[RouteOperation::List]),
        ),
        get_run: rss_mdm_http_contract::module::Route::new(
            "/policies/{id}/runs/{task}",
            get(run, &contracts::POLICIES, &[RouteOperation::Action]),
        ),
    }
    .assemble();
    match cursor {
        Some(codec) => router.layer(Extension(codec)),
        None => router,
    }
}
async fn runs(
    State(app): State<Arc<dyn super::Reads>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, id)): Path<(uuid::Uuid, Uuid)>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<RunsQuery>,
    >,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<crate::policy_task_reads::RunPage>>, Error>
{
    (async {
        audit.operation(
            id,
            "command_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        audit.plan(id);
        let (page, _) = query.parse().map_err(|_| Error::Malformed)?;
        app.runs(&auth, &audit, id, &page, &codec).await.map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn run(
    State(app): State<Arc<dyn super::Reads>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, id, task)): Path<(uuid::Uuid, Uuid, Uuid)>,
) -> Result<Json<crate::policy_task_reads::RunDetail>, Error> {
    audit.operation(
        task,
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.plan(id);
    audit.target(&task.to_string());
    app.run(&auth, &audit, id, task).await.map(Json)
}
struct RunsQuery;
impl rss_mdm_http_contract::query::WindowOwner for RunsQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &crate::policy_task_reads::RUNS_SCHEMA
    }
}
