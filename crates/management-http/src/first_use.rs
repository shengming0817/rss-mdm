//! Authenticated tenant setup intent. Configuration and observations retain their domain owners.
use crate::{Error, authorization::context::RequestAuth, http_operation::RequestContinuation};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use rss_mdm_registration_service::quotas::Channel;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    AgentPackage,
    TaskSigning,
    WindowsPush,
    AppleAde,
    AppleAccount,
    Oidc,
    Smtp,
    S3,
    Webhook,
    RecoveryCredentials,
}
impl Capability {
    /// References into the existing settings directory, not another settings catalog.
    pub fn items(self) -> &'static [&'static str] {
        match self {
            Self::AgentPackage => &["agent-package"],
            Self::TaskSigning => &["task-key"],
            Self::WindowsPush => &["wns"],
            Self::AppleAde => &["ade-token"],
            Self::AppleAccount => &["apple-account", "managed-key"],
            Self::Oidc => &["oidc"],
            Self::Smtp => &["smtp"],
            Self::S3 => &["storage"],
            Self::Webhook => &["webhook-own"],
            Self::RecoveryCredentials => &["recovery-key", "recovery-rsa"],
        }
    }
    pub fn channel(self) -> Option<Channel> {
        match self {
            Self::AgentPackage | Self::TaskSigning => Some(Channel::Agent),
            Self::WindowsPush => Some(Channel::WindowsMdm),
            Self::AppleAde | Self::AppleAccount => Some(Channel::MacosMdm),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Decision {
    Configure,
    Skip { reason: String },
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Intent {
    pub channels: Vec<Channel>,
    pub capabilities: BTreeMap<Capability, Decision>,
    /// Explicit confirmation of this exact selection. It does not freeze health.
    pub completion_requested: bool,
}
impl Intent {
    pub fn validate(&self) -> Result<(), Error> {
        if self.channels.len() > 3
            || self
                .channels
                .iter()
                .enumerate()
                .any(|(i, c)| self.channels[..i].contains(c))
        {
            return Err(Error::Malformed);
        }
        for (capability, decision) in &self.capabilities {
            match decision {
                Decision::Skip { reason }
                    if reason.trim().is_empty()
                        || reason.len() > 1024
                        || reason.chars().any(char::is_control) =>
                {
                    return Err(Error::Malformed);
                }
                Decision::Configure
                    if capability
                        .channel()
                        .is_some_and(|c| !self.channels.contains(&c)) =>
                {
                    return Err(Error::Malformed);
                }
                _ => (),
            }
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Update {
    pub expected_revision: i64,
    pub intent: Intent,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Saved {
    pub revision: i64,
    pub intent: Intent,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub saved: Saved,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ready,
    Unconfigured,
    Pending,
    Unknown,
    Unavailable,
    Forbidden,
    Skipped,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Step {
    pub id: String,
    pub status: Status,
    pub reason: Option<String>,
    /// Only permission-filtered original owner projections may appear here.
    pub evidence: Vec<crate::settings::Entry>,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub tenant_id: String,
    pub saved: Saved,
    pub steps: Vec<Step>,
    pub can_complete: bool,
    pub complete: bool,
}
impl Progress {
    pub fn new(tenant_id: String, saved: Saved, steps: Vec<Step>) -> Self {
        let expected_steps = saved.intent.channels.len()
            + usize::from(saved.intent.channels.contains(&Channel::Agent))
            + usize::from(saved.intent.channels.contains(&Channel::MacosMdm))
            + saved.intent.capabilities.len();
        let can_complete = !saved.intent.channels.is_empty()
            && steps.len() == expected_steps
            && steps
                .iter()
                .all(|s| matches!(s.status, Status::Ready | Status::Skipped));
        let complete = can_complete && saved.intent.completion_requested;
        Self {
            tenant_id,
            saved,
            steps,
            can_complete,
            complete,
        }
    }
}
pub enum Command {
    Read,
    Update(Uuid, Update),
    Operation(Uuid),
}
pub enum Output {
    Progress(Progress),
    Receipt(Receipt),
}
pub trait Source: Send + Sync {
    fn execute<'a>(
        &'a self,
        auth: RequestAuth,
        audit: RequestAudit,
        continuation: RequestContinuation,
        command: Command,
    ) -> futures::future::BoxFuture<'a, Result<Output, Error>>;
}
pub fn routes(source: Arc<dyn Source>) -> Router {
    Router::new()
        .route(
            "/settings/first-use",
            get(read)
                .owned(&contracts::FIRST_USE, &[RouteOperation::Get])
                .put(update)
                .owned(&contracts::FIRST_USE, &[RouteOperation::Update]),
        )
        .route(
            "/settings/first-use/operations/{id}",
            get(operation).owned(&contracts::FIRST_USE, &[RouteOperation::Get]),
        )
        .layer(axum::extract::DefaultBodyLimit::max(16384))
        .with_state(source)
}
async fn run(
    source: Arc<dyn Source>,
    auth: RequestAuth,
    audit: RequestAudit,
    continuation: RequestContinuation,
    command: Command,
) -> Result<Json<serde_json::Value>, Error> {
    let value = match source.execute(auth, audit, continuation, command).await? {
        Output::Progress(value) => serde_json::to_value(value),
        Output::Receipt(value) => serde_json::to_value(value),
    }
    .map_err(|_| Error::Malformed)?;
    Ok(Json(value))
}
async fn read(
    State(source): State<Arc<dyn Source>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(continuation): Extension<RequestContinuation>,
) -> Result<Json<serde_json::Value>, Error> {
    audit.set_action("first_use_read");
    run(source, auth, audit, continuation, Command::Read).await
}
async fn operation(
    State(source): State<Arc<dyn Source>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(continuation): Extension<RequestContinuation>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, Error> {
    audit.set_action("first_use_operation_read");
    run(source, auth, audit, continuation, Command::Operation(id)).await
}
async fn update(
    State(source): State<Arc<dyn Source>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(continuation): Extension<RequestContinuation>,
    headers: HeaderMap,
    input: Result<Json<Update>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, Error> {
    let id = crate::api::write_key(&headers, &audit, "first_use_update")?;
    run(
        source,
        auth,
        audit,
        continuation,
        Command::Update(id, input.map_err(Error::from)?.0),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_first_use_schema_matches_runtime_dtos() {
        let actual = serde_json::json!({"Update":schemars::schema_for!(Update),"Progress":schemars::schema_for!(Progress),"Receipt":schemars::schema_for!(Receipt)});
        let published: serde_json::Value =
            serde_json::from_str(include_str!("../schema/FirstUse.json")).unwrap();
        assert_eq!(actual, published);
    }
    #[test]
    fn decisions_are_closed_and_cannot_skip_required_channels() {
        assert!(serde_json::from_value::<Intent>(serde_json::json!({"channels":["skip"],"capabilities":{},"completionRequested":true})).is_err());
        let mut intent = Intent::default();
        intent
            .capabilities
            .insert(Capability::Smtp, Decision::Skip { reason: " ".into() });
        assert!(intent.validate().is_err());
        intent.capabilities.insert(
            Capability::Smtp,
            Decision::Skip {
                reason: "later".into(),
            },
        );
        assert!(intent.validate().is_ok());
        intent
            .capabilities
            .insert(Capability::TaskSigning, Decision::Configure);
        assert!(intent.validate().is_err());
        intent.channels = vec![Channel::Agent];
        assert!(intent.validate().is_ok());
        intent.channels.push(Channel::Agent);
        assert!(intent.validate().is_err());
    }
    #[test]
    fn unknown_faults_and_empty_selection_cannot_complete() {
        for status in [
            Status::Unconfigured,
            Status::Pending,
            Status::Unknown,
            Status::Unavailable,
            Status::Forbidden,
        ] {
            let saved = Saved {
                revision: 1,
                intent: Intent {
                    channels: vec![Channel::WindowsMdm],
                    completion_requested: true,
                    ..Default::default()
                },
            };
            let p = Progress::new(
                "tenant".into(),
                saved,
                vec![Step {
                    id: "windows_mdm".into(),
                    status,
                    reason: None,
                    evidence: vec![],
                }],
            );
            assert!(!p.complete && !p.can_complete);
        }
        let ready = Progress::new(
            "tenant".into(),
            Saved {
                revision: 1,
                intent: Intent {
                    channels: vec![Channel::WindowsMdm],
                    completion_requested: true,
                    ..Default::default()
                },
            },
            vec![Step {
                id: "windows_mdm".into(),
                status: Status::Ready,
                reason: None,
                evidence: vec![],
            }],
        );
        assert!(ready.can_complete && ready.complete);
        let p = Progress::new(
            "tenant".into(),
            Saved {
                revision: 0,
                intent: Intent::default(),
            },
            vec![],
        );
        assert!(!p.complete && !p.can_complete);
    }
}
