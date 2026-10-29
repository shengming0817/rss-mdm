use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_execution_service::queries::Queries;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use std::sync::Arc;
use uuid::Uuid;

pub fn routes(
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<Arc<Queries>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    register(Some(cursor))
}
pub(crate) fn register(
    cursor: Option<rss_mdm_query::cursor::CursorCodec>,
) -> Router<
    Arc<rss_mdm_execution_service::queries::Queries>,
    impl rss_mdm_http_contract::module::Declaration + use<>,
> {
    let router = {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_runs, get_rollout, get_run } }
        RegisterModule1 {
            get_runs: rss_mdm_http_contract::module::Route::new(
                "/policies/{id}/runs",
                get(runs, &contracts::POLICY_RUNS, &[RouteOperation::List]),
            ),
            get_rollout: rss_mdm_http_contract::module::Route::new(
                "/policies/{id}/software/rollout",
                get(rollout, &contracts::POLICIES, &[RouteOperation::Action]),
            ),
            get_run: rss_mdm_http_contract::module::Route::new(
                "/policies/{id}/runs/{task}",
                get(run, &contracts::POLICIES, &[RouteOperation::Action]),
            ),
        }
        .assemble()
    };
    match cursor {
        Some(cursor) => router.layer(axum::Extension(cursor)),
        None => router,
    }
}
async fn rollout(
    State(app): State<Arc<Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_execution_service::queries::records::Rollout>, Error> {
    audit.operation(
        id,
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    app.software_rollout(&auth.proof, id, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn runs(
    State(app): State<Arc<Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<RunsQuery>,
    >,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_execution_service::queries::records::RunPage>,
    >,
    Error,
> {
    (async {
        audit.operation(
            id,
            "command_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        audit.plan(id);
        let (page, _) = query.parse().map_err(|_| Error::Malformed)?;
        app.action_runs(&auth.proof, id, &page, &codec, &audit)
            .await
            .map(Json)
            .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn run(
    State(app): State<Arc<Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, task)): Path<(Uuid, Uuid)>,
) -> Result<Json<rss_mdm_execution_service::queries::records::RunDetail>, Error> {
    audit.operation(
        task,
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.plan(id);
    audit.target(&task.to_string());
    app.action_run(&auth.proof, id, task, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

use rss_mdm_audit_integration::RequestAudit;

struct RunsQuery;
impl rss_mdm_http_contract::query::WindowOwner for RunsQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &super::history::SCHEMA
    }
}
