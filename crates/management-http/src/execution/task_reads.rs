//! Application composition port for Policy task reads across concrete business owners.
use crate::Error;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_query::{cursor::CursorCodec, window::Query};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
pub trait Reads: Send + Sync {
    fn preview<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        audit: &'a RequestAudit,
        input: &'a rss_mdm_policy::pages::Preview,
        query: &'a Query,
        codec: &'a CursorCodec,
    ) -> Pending<'a, Preview>;
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
    ) -> Pending<'a, AssignmentPage>;
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
    Software(rss_mdm_software_service::deployment::queries::records::RunSummary),
    Access(rss_mdm_device_access_postgres::device_access::execution::queries::Record),
    Credential(rss_mdm_recovery_credentials::tasks::queries::Record),
    Enrollment(rss_mdm_registration_service::enrollment::tasks::queries::Record),
    Execution(rss_mdm_device_service::control::queries::records::RunSummary),
    Script(rss_mdm_script_service::queries::Summary),
    Collection(rss_mdm_inventory_service::collection::execution::queries::Summary),
}
impl RunSummary {
    pub fn position(&self) -> (i64, uuid::Uuid) {
        match self {
            Self::Software(r) => (r.available_at, r.task_id),
            Self::Access(r) => (r.available_at, r.task_id),
            Self::Credential(r) => (r.available_at, r.task_id),
            Self::Enrollment(r) => (r.available_at, r.task_id),
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
    Software(rss_mdm_software_service::deployment::queries::records::RunDetail),
    Access(rss_mdm_device_access_postgres::device_access::execution::queries::Record),
    Credential(rss_mdm_recovery_credentials::tasks::queries::Record),
    Enrollment(rss_mdm_registration_service::enrollment::tasks::queries::Record),
    Execution(rss_mdm_device_service::control::queries::records::RunDetail),
    Script(rss_mdm_script_service::queries::Detail),
    Collection(rss_mdm_inventory_service::collection::execution::queries::Detail),
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunPage {
    pub items: Vec<RunSummary>,
    pub next_cursor: Option<String>,
}

#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    pub object: rss_mdm_scope_service::channels::ObjectRef,
    pub channel: Option<rss_mdm_inventory::Channel>,
    pub availability: rss_mdm_scope_service::channels::Availability,
    pub reason: Option<String>,
    pub target: Option<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
    pub qualification: rss_mdm_scope_service::channels::ScopeAdmission,
    pub sources: Vec<rss_mdm_scope_service::channels::DeviceObject>,
    pub scope_result: Option<Uuid>,
    pub task_admission: Option<rss_mdm_policy::pages::TaskAdmission>,
    pub execution: AssignmentExecution,
}
/// A single action-specific execution view; restricted never means that the device is ineligible.
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AssignmentExecution {
    Operations {
        operation_ids: Vec<Uuid>,
    },
    Recurring {
        latest_run: Option<Box<RecurringRun>>,
        current_record: rss_mdm_policy::pages::CurrentRecord,
    },
    Restricted,
}
/// Reuse the same redacted summaries as the original Policy history and global directory.
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecurringRun {
    Script(rss_mdm_script_service::queries::Summary),
    Collection(rss_mdm_inventory_service::collection::execution::queries::Summary),
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignmentPage {
    pub items: Vec<Assignment>,
    pub next_cursor: Option<String>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub action: rss_mdm_policy::Action,
    pub scope_result: Uuid,
    pub items: Vec<PreviewTarget>,
    pub next_cursor: Option<String>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewTarget {
    pub object: rss_mdm_scope_service::channels::ObjectRef,
    pub channel: Option<rss_mdm_inventory::Channel>,
    pub availability: rss_mdm_scope_service::channels::Availability,
    pub reason: Option<String>,
    pub target: Option<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
    pub eligibility: rss_mdm_scope_service::channels::ScopeAdmission,
    pub task_admission: Option<rss_mdm_policy::pages::TaskAdmission>,
}
