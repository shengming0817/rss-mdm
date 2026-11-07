//! Aggregate operation HTTP contract; App composes the final producer reads.
use super::task_reads::Pending;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::RequestAuth;
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema {
    id: "executions",
    keys: &["id", "kind"],
    default_limit: 64,
    max_limit: 1000,
    fields: vec![
        Field::scalar("id", Kind::Uuid),
        Field::scalar("kind", Kind::enumeration(&["command", "action_run"])),
        Field::scalar("device", Kind::Text),
        Field::scalar("policy", Kind::Uuid),
        Field::scalar("status", Kind::Text),
        Field::scalar("registrationId", Kind::Uuid),
        Field::scalar("generation", Kind::Integer),
        Field::scalar("origin", Kind::enumeration(&["direct", "policy"])),
        Field::scalar("deadline", Kind::Integer),
        Field::output("authorization"),
        Field::output("reauthorization"),
        Field::filter_only(
            "authorization.state",
            Kind::enumeration(&["authorized", "blocked", "not_applicable"]),
        ),
        Field::filter_only(
            "authorization.reason",
            Kind::enumeration(&[
                "lifecycle_blocked",
                "registration_changed",
                "input_mismatch",
                "source_invalid",
            ]),
        ),
        Field::filter_only(
            "reauthorization.state",
            Kind::enumeration(&["available", "unavailable", "not_applicable"]),
        ),
        Field::output("evidence"),
        Field::output("detailUrl"),
    ],
});

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Page<T = Item> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Statistics {
    pub total: u64,
    pub commands: u64,
    pub action_runs: u64,
    pub unknown: u64,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub id: Uuid,
    pub kind: KindOfOperation,
    pub device: String,
    pub registration_id: Uuid,
    pub generation: i64,
    pub origin: String,
    pub policy: Option<Uuid>,
    pub deadline: i64,
    pub status: String,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KindOfOperation {
    Command,
    ActionRun,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    #[serde(flatten)]
    pub metadata: Metadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reauthorization: Option<Reauthorization>,
    pub detail_url: String,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(tag = "owner", rename_all = "snake_case")]
pub enum Detail {
    Configuration(
        rss_mdm_policy_service::configuration::queries::records::Detail<
            super::projection::Observation,
        >,
    ),
    Device(
        rss_mdm_device_service::control::queries::records::CommandDetail<
            super::projection::Observation,
        >,
    ),
    Software(
        Box<
            rss_mdm_software_service::deployment::queries::records::CommandDetail<
                super::projection::Observation,
            >,
        >,
    ),
    Recovery(rss_mdm_recovery_credentials::native::queries::Detail<super::projection::Observation>),
    Registration(
        rss_mdm_registration_service::installation::queries::Detail<super::projection::Observation>,
    ),
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(tag = "owner", rename_all = "snake_case")]
pub enum Evidence {
    Retirement(Box<rss_mdm_device_service::lifecycle::Retirement>),
    Pki(rss_mdm_pki_service::registry::OperationProgress),
    Offboarding(rss_mdm_device_access_postgres::device_access::lifecycle::DiagnosticProgress),
    Native { detail: Box<Detail> },
    Device(rss_mdm_device_service::control::queries::records::RunEvidence),
    Software(rss_mdm_software_service::deployment::queries::records::RunEvidence),
    Enrollment(rss_mdm_registration_service::enrollment::tasks::queries::Record),
    Access(rss_mdm_device_access_postgres::device_access::execution::queries::Record),
    Credential(rss_mdm_recovery_credentials::tasks::queries::Record),
    Script(Box<rss_mdm_script_service::queries::Summary>),
    Collection(Box<rss_mdm_inventory_service::collection::execution::queries::Summary>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    LifecycleBlocked,
    RegistrationChanged,
    InputMismatch,
    SourceInvalid,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authorization {
    Authorized,
    Blocked { reason: BlockReason },
    NotApplicable,
}
impl Authorization {
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorized)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReauthorizationReason {
    PermissionDenied,
    Terminal,
    AlreadyReceived,
    Expired,
    RegistrationChanged,
    InputMismatch,
    Unsupported,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Reauthorization {
    Available { confirmation_required: bool },
    Unavailable { reason: ReauthorizationReason },
    NotApplicable,
}

pub trait Reads: Send + Sync {
    fn declarations<'a>(
        &'a self,
        proof: &'a RequestAuth,
        device: &'a str,
        query: &'a rss_mdm_query::window::Query,
        audit: &'a RequestAudit,
        codec: &'a CursorCodec,
    ) -> Pending<'a, super::declarations::Page>;

    fn directory<'a>(
        &'a self,
        proof: &'a RequestAuth,
        q: &'a Query,
        codec: &'a CursorCodec,
        audit: &'a RequestAudit,
    ) -> Pending<'a, Page>;
    fn statistics<'a>(
        &'a self,
        proof: &'a RequestAuth,
        q: &'a Query,
        audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_query::Statistics<Statistics>>;
    fn detail<'a>(
        &'a self,
        proof: &'a RequestAuth,
        device: &'a str,
        id: Uuid,
        audit: &'a RequestAudit,
    ) -> Pending<'a, Detail>;
    fn change<'a>(
        &'a self,
        proof: &'a RequestAuth,
        device: &'a str,
        id: Uuid,
        change: &'a rss_mdm_device_service::control::Change,
        reauthorization: Option<
            &'a rss_mdm_device_service::control::device_control::Reauthorization,
        >,
        audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_device_service::control::ChangedReceipt>;
}
