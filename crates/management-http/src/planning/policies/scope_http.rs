//! Policy-owned Scope routes share the existing evaluation and recovery owners.
use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_http_contract::{
    Operation, Router, catalog as contracts,
    routing::{get, post},
};
use rss_mdm_policy_service::management::scopes::{Preview, Recompute};
use rss_mdm_scope::ScopeOwner;
use rss_mdm_scope_service::{pages, wire};
type Body<T> = Result<Json<T>, axum::extract::rejection::JsonRejection>;

async fn read_main(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(policy): Path<Uuid>,
) -> Result<Json<wire::ScopeRead>, Error> {
    Ok(Json(
        s.scope_read(
            &a.proof,
            &audit,
            ScopeOwner {
                policy,
                stage: None,
            },
        )
        .await?,
    ))
}
async fn preview_main(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(policy): Path<Uuid>,
    body: Body<Preview>,
) -> Result<Json<rss_mdm_scope_service::preview::Response>, Error> {
    let Json(body) = body.map_err(Error::from)?;
    Ok(Json(
        s.scope_preview(
            &a.proof,
            &audit,
            ScopeOwner {
                policy,
                stage: None,
            },
            &body,
        )
        .await?,
    ))
}
async fn recompute_main(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(policy): Path<Uuid>,
    body: Body<Recompute>,
) -> Result<Json<wire::ScopeReceipt>, Error> {
    let Json(body) = body.map_err(Error::from)?;
    Ok(Json(
        s.scope_recompute(
            &a.proof,
            &audit,
            ScopeOwner {
                policy,
                stage: None,
            },
            &body,
        )
        .await?,
    ))
}
async fn task_main(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((policy, task)): Path<(Uuid, Uuid)>,
) -> Result<Json<rss_mdm_inventory_service::tasks::TaskRead>, Error> {
    Ok(Json(
        s.scope_task(
            &a.proof,
            &audit,
            ScopeOwner {
                policy,
                stage: None,
            },
            task,
        )
        .await?,
    ))
}
async fn page_main(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((policy, result, kind)): Path<(Uuid, Uuid, pages::ScopePageKind)>,
    query: rss_mdm_http_contract::query::OwnedQuery<ScopeResultQuery>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<pages::ScopePage>>, Error> {
    let query = query.parse().map_err(|_| Error::Malformed)?;
    Ok(rss_mdm_http_contract::CollectionResponse(Json(
        s.scope_page(
            &a.proof,
            &audit,
            ScopeOwner {
                policy,
                stage: None,
            },
            result,
            kind,
            query,
        )
        .await?,
    )))
}
async fn read_stage(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((policy, stage)): Path<(Uuid, Uuid)>,
) -> Result<Json<wire::ScopeRead>, Error> {
    Ok(Json(
        s.scope_read(
            &a.proof,
            &audit,
            ScopeOwner {
                policy,
                stage: Some(stage),
            },
        )
        .await?,
    ))
}
async fn preview_stage(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((policy, stage)): Path<(Uuid, Uuid)>,
    body: Body<Preview>,
) -> Result<Json<rss_mdm_scope_service::preview::Response>, Error> {
    let Json(body) = body.map_err(Error::from)?;
    Ok(Json(
        s.scope_preview(
            &a.proof,
            &audit,
            ScopeOwner {
                policy,
                stage: Some(stage),
            },
            &body,
        )
        .await?,
    ))
}
async fn recompute_stage(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((policy, stage)): Path<(Uuid, Uuid)>,
    body: Body<Recompute>,
) -> Result<Json<wire::ScopeReceipt>, Error> {
    let Json(body) = body.map_err(Error::from)?;
    Ok(Json(
        s.scope_recompute(
            &a.proof,
            &audit,
            ScopeOwner {
                policy,
                stage: Some(stage),
            },
            &body,
        )
        .await?,
    ))
}
async fn task_stage(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((policy, stage, task)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<rss_mdm_inventory_service::tasks::TaskRead>, Error> {
    Ok(Json(
        s.scope_task(
            &a.proof,
            &audit,
            ScopeOwner {
                policy,
                stage: Some(stage),
            },
            task,
        )
        .await?,
    ))
}
async fn page_stage(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((policy, stage, result, kind)): Path<(Uuid, Uuid, Uuid, pages::ScopePageKind)>,
    query: rss_mdm_http_contract::query::OwnedQuery<ScopeResultQuery>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<pages::ScopePage>>, Error> {
    let query = query.parse().map_err(|_| Error::Malformed)?;
    Ok(rss_mdm_http_contract::CollectionResponse(Json(
        s.scope_page(
            &a.proof,
            &audit,
            ScopeOwner {
                policy,
                stage: Some(stage),
            },
            result,
            kind,
            query,
        )
        .await?,
    )))
}

pub fn routes() -> Router<Arc<Policies>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! { struct ScopeRoutes for [Browser] { main_read,stage_read,main_preview,stage_preview,main_recompute,stage_recompute,main_task,stage_task,main_page,stage_page } }
    ScopeRoutes {
        main_read: rss_mdm_http_contract::module::Route::new(
            "/policies/{policy}/scope",
            get(read_main, &contracts::POLICY_SCOPES, &[Operation::Get]),
        ),
        stage_read: rss_mdm_http_contract::module::Route::new(
            "/policies/{policy}/stages/{stage}/scope",
            get(read_stage, &contracts::POLICY_SCOPES, &[Operation::Get]),
        ),
        main_preview: rss_mdm_http_contract::module::Route::new(
            "/policies/{policy}/scope/previews",
            post(
                preview_main,
                &contracts::POLICY_SCOPES,
                &[Operation::Action],
            ),
        ),
        stage_preview: rss_mdm_http_contract::module::Route::new(
            "/policies/{policy}/stages/{stage}/scope/previews",
            post(
                preview_stage,
                &contracts::POLICY_SCOPES,
                &[Operation::Action],
            ),
        ),
        main_recompute: rss_mdm_http_contract::module::Route::new(
            "/policies/{policy}/scope/recomputations",
            post(
                recompute_main,
                &contracts::POLICY_SCOPES,
                &[Operation::Action],
            ),
        ),
        stage_recompute: rss_mdm_http_contract::module::Route::new(
            "/policies/{policy}/stages/{stage}/scope/recomputations",
            post(
                recompute_stage,
                &contracts::POLICY_SCOPES,
                &[Operation::Action],
            ),
        ),
        main_task: rss_mdm_http_contract::module::Route::new(
            "/policies/{policy}/scope/tasks/{task}",
            get(task_main, &contracts::POLICY_SCOPES, &[Operation::Action]),
        ),
        stage_task: rss_mdm_http_contract::module::Route::new(
            "/policies/{policy}/stages/{stage}/scope/tasks/{task}",
            get(task_stage, &contracts::POLICY_SCOPES, &[Operation::Action]),
        ),
        main_page: rss_mdm_http_contract::module::Route::new(
            "/policies/{policy}/scope/results/{result}/{kind}",
            get(page_main, &contracts::SCOPE_RESULTS, &[Operation::List]),
        ),
        stage_page: rss_mdm_http_contract::module::Route::new(
            "/policies/{policy}/stages/{stage}/scope/results/{result}/{kind}",
            get(page_stage, &contracts::SCOPE_RESULTS, &[Operation::List]),
        ),
    }
    .assemble()
}
struct ScopeResultQuery;
impl rss_mdm_http_contract::query::QueryOwner for ScopeResultQuery {
    type Parsed = pages::ResultQuery;
    type Error = Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Window(
            &pages::SCHEMA,
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let mut schema = rss_mdm_http_contract::query::window_parameters(&pages::SCHEMA);
        schema.value["properties"]["channel"] =
            rss_mdm_http_contract::signature::Schema::request::<rss_mdm_inventory::Channel>().value;
        schema.value["required"] = serde_json::json!(["channel"]);
        schema
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Error> {
        pages::ResultQuery::parse(raw).map_err(|_| Error::Malformed)
    }
}
