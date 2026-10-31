//! Application composition port for Policy task reads across concrete business owners.
use crate::Error;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_query::{cursor::CursorCodec, window::Query};
use std::{future::Future, pin::Pin};
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
pub trait Reads: Send + Sync {
    fn preview<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        audit: &'a RequestAudit,
        input: &'a rss_mdm_policy::pages::Preview,
        query: &'a Query,
        codec: &'a CursorCodec,
    ) -> Pending<'a, rss_mdm_execution_service::queries::records::Preview>;
    fn runs<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        audit: &'a RequestAudit,
        policy: uuid::Uuid,
        page: &'a Query,
        codec: &'a CursorCodec,
    ) -> Pending<'a, RunPage>;
    fn run<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        audit: &'a RequestAudit,
        policy: uuid::Uuid,
        id: uuid::Uuid,
    ) -> Pending<'a, RunDetail>;
    fn assignments<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        audit: &'a RequestAudit,
        policy: uuid::Uuid,
        page: &'a Query,
        codec: &'a CursorCodec,
    ) -> Pending<'a, rss_mdm_execution_service::queries::records::AssignmentPage>;
}

pub static RUNS_SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "policy_runs",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "available_at DESC, task_id DESC",
    context: &[],
};
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunSummary {
    Execution(rss_mdm_execution_service::queries::records::RunSummary),
    Script(rss_mdm_script_service::queries::Summary),
    Collection(rss_mdm_inventory_service::collection::execution::queries::Summary),
}
impl RunSummary {
    pub fn position(&self) -> (i64, uuid::Uuid) {
        match self {
            Self::Execution(r) => (r.available_at, r.task_id),
            Self::Script(r) => (r.available_at, r.task_id),
            Self::Collection(r) => {
                let r = r.metadata();
                (r.available_at, r.task_id)
            }
        }
    }
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunDetail {
    Execution(rss_mdm_execution_service::queries::records::RunDetail),
    Script(rss_mdm_script_service::queries::Detail),
    Collection(rss_mdm_inventory_service::collection::execution::queries::Detail),
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunPage {
    pub items: Vec<RunSummary>,
    pub next_cursor: Option<String>,
}
