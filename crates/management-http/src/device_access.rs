//! Device-scoped administrator operations. Self-enrollment is authenticated on the Agent channel.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use rss_mdm_agent_wire::runtime::{AccessAccount, TaskPlatform};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_registration_service::{agent::Service, device_access as access};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;
struct Services {
    registration: Arc<Service>,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
}
pub fn routes(
    registration: Option<Arc<Service>>,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
) -> Router {
    let Some(registration) = registration else {
        return Router::new();
    };
    Router::new()
        .route("/devices/{device}/device-access", get(list))
        .route(
            "/devices/{device}/device-access/bindings/{id}",
            axum::routing::put(change),
        )
        .route(
            "/devices/{device}/device-access/operations/{id}",
            get(operation),
        )
        .with_state(Arc::new(Services {
            registration,
            execution,
        }))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    after: Option<Uuid>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChangeInput {
    operation_id: Uuid,
    expected_revision: i64,
    action: ActionInput,
}
#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ActionInput {
    Put {
        instance: Uuid,
        principal: Uuid,
        account: AccountInput,
        policy: Uuid,
    },
    ResetFactors,
    Unbind,
}
#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum AccountInput {
    Existing {
        account: AccessAccount,
    },
    Create {
        platform: TaskPlatform,
        name: String,
    },
}
fn view(b: access::Binding) -> Value {
    json!({"id":b.id,"device":b.device,"registration":b.registration,"registrationGeneration":b.registration_generation,
        "instance":b.person.instance,"principal":b.person.principal,"bindingGeneration":b.generation,"factorGeneration":b.factor_generation,"revision":b.revision,
        "serverState":b.state,"account":b.account,"accountIntent":b.intent,"createdByRss":b.created_by_rss,
        "policy":b.policy,"policyVersion":b.policy_version,"desired":b.configuration,"receivedRevision":b.received_revision,
        "appliedRevision":b.applied_revision,"effect":b.effect})
}
async fn list(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path(device): Path<String>,
    Query(q): Query<Page>,
) -> Result<Json<Value>, Error> {
    let values = s
        .registration
        .device_access_bindings(&auth.proof, &device, q.after)
        .await?;
    Ok(Json(Value::Array(values.into_iter().map(view).collect())))
}
async fn change(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    body: Result<Json<ChangeInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    let input = body.map_err(Error::from)?.0;
    let action = match input.action {
        ActionInput::ResetFactors => access::Action::ResetFactors,
        ActionInput::Unbind => access::Action::Unbind,
        ActionInput::Put {
            instance,
            principal,
            account,
            policy,
        } => access::Action::Put {
            person: access::Person {
                instance,
                principal,
            },
            intent: match account {
                AccountInput::Existing { account } => access::AccountIntent::Existing { account },
                AccountInput::Create { platform, name } => {
                    access::AccountIntent::Create { platform, name }
                }
            },
            policy,
        },
    };
    let input = access::Change {
        operation_id: input.operation_id,
        expected_revision: input.expected_revision,
        action,
    };
    Ok(Json(view(
        s.registration
            .change_device_access(
                &auth.proof,
                &device,
                id,
                &input,
                s.execution.as_ref(),
                &audit,
            )
            .await?,
    )))
}
async fn operation(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((device, id)): Path<(String, Uuid)>,
) -> Result<Json<Value>, Error> {
    Ok(Json(view(
        s.registration
            .device_access_operation(&auth.proof, &device, id)
            .await?,
    )))
}
