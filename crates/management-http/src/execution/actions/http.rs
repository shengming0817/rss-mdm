use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
pub struct StateServices {
    pub software: std::sync::Arc<rss_mdm_software_service::deployment::queries::Queries>,
    pub tasks: std::sync::Arc<dyn crate::execution::task_reads::Reads>,
}
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use std::sync::Arc;
use uuid::Uuid;

pub fn routes(
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<Arc<StateServices>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    register(Some(cursor))
}
pub(crate) fn register(
    cursor: Option<rss_mdm_query::cursor::CursorCodec>,
) -> Router<Arc<StateServices>, impl rss_mdm_http_contract::module::Declaration + use<>> {
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
    State(app): State<Arc<StateServices>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_software_service::deployment::queries::records::Rollout>, Error> {
    audit.operation(
        id,
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    app.software
        .software_rollout(&auth.proof, id, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn runs(
    State(app): State<Arc<StateServices>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<RunsQuery>,
    >,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<Json<crate::execution::task_reads::RunPage>>,
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
        app.tasks
            .runs(&auth.proof, &audit, id, &page, &codec)
            .await
            .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn run(
    State(app): State<Arc<StateServices>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, task)): Path<(Uuid, Uuid)>,
) -> Result<Json<crate::execution::task_reads::RunDetail>, Error> {
    audit.operation(
        task,
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.plan(id);
    audit.target(&task.to_string());
    app.tasks.run(&auth.proof, &audit, id, task).await.map(Json)
}

use rss_mdm_audit_integration::RequestAudit;

struct RunsQuery;
impl rss_mdm_http_contract::query::WindowOwner for RunsQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &crate::execution::task_reads::RUNS_SCHEMA
    }
}
