//! Device-scoped administrator operations. Self-enrollment is authenticated on the Agent channel.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use rss_mdm_agent_wire::runtime::{AccessAccount, TaskPlatform};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use rss_mdm_registration_service::{agent::Service, device_access as access};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;
struct Services {
    recovery: Option<Arc<rss_mdm_recovery_credentials::Credentials>>,
    registration: Arc<Service>,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
    identity: Arc<crate::identity::Identity>,
}
pub fn routes(
    recovery: Option<Arc<rss_mdm_recovery_credentials::Credentials>>,
    registration: Option<Arc<Service>>,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
    identity: Arc<crate::identity::Identity>,
) -> Router {
    let Some(registration) = registration else {
        return Router::new();
    };
    Router::new()
        .route(
            "/devices/{device}/device-access/materials/{id}/versions/{version}/step-up",
            rss_mdm_http_contract::routing::post(material_step_up)
                .owned(&contracts::DEVICE_ACCESS, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{device}/device-access/materials/{id}/versions/{version}/secret",
            rss_mdm_http_contract::routing::post(material_disclose)
                .owned(&contracts::DEVICE_ACCESS, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{device}/device-access",
            get(list).owned(&contracts::DEVICE_ACCESS, &[RouteOperation::List]),
        )
        .route(
            "/devices/{device}/device-access/bindings/{id}",
            rss_mdm_http_contract::routing::put(change).owned(
                &contracts::DEVICE_ACCESS,
                &[
                    RouteOperation::Create,
                    RouteOperation::Update,
                    RouteOperation::Lifecycle,
                ],
            ),
        )
        .route(
            "/devices/{device}/device-access/bindings/{id}/step-up",
            rss_mdm_http_contract::routing::post(step_up)
                .owned(&contracts::DEVICE_ACCESS, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{device}/device-access/operations/{id}",
            get(operation).owned(&contracts::DEVICE_ACCESS, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{device}/device-access/operations/{id}/offboarding",
            get(offboarding).owned(&contracts::DEVICE_ACCESS, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{device}/device-access/operations/{id}/offboarding/identity",
            rss_mdm_http_contract::routing::post(offboarding_identity)
                .owned(&contracts::DEVICE_ACCESS, &[RouteOperation::Action]),
        )
        .route(
            "/device-access/enterprise/configuration",
            get(enterprise_list).post(enterprise_change).owned(
                &contracts::DEVICE_ACCESS,
                &[RouteOperation::List, RouteOperation::Action],
            ),
        )
        .route(
            "/device-access/enterprise/configuration/step-up",
            rss_mdm_http_contract::routing::post(enterprise_step_up)
                .owned(&contracts::DEVICE_ACCESS, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{device}/device-access/operations/{id}/offboarding/idp",
            rss_mdm_http_contract::routing::post(offboarding_idp)
                .owned(&contracts::DEVICE_ACCESS, &[RouteOperation::Action]),
        )
        .with_state(Arc::new(Services {
            recovery,
            registration,
            execution,
            identity,
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
    Reinstate {
        instance: Uuid,
        principal: Uuid,
        account: AccountInput,
        policy: Uuid,
    },
    Offboard {
        disposition: rss_mdm_agent_wire::runtime::AccessAccountDisposition,
    },
    Put {
        instance: Uuid,
        principal: Uuid,
        account: AccountInput,
        policy: Uuid,
    },
    ResetFactors,
    Unbind {
        disposition: rss_mdm_agent_wire::runtime::AccessAccountDisposition,
    },
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
    json!({"id":b.id,"operationId":b.operation_id,"device":b.device,"registration":b.registration,"registrationGeneration":b.registration_generation,
        "instance":b.person.instance,"principal":b.person.principal,"bindingGeneration":b.generation,"factorGeneration":b.factor_generation,"revision":b.revision,
        "serverState":b.state,"accountDisposition":b.account_disposition,"account":b.account,"accountIntent":b.intent,"createdByRss":b.created_by_rss,
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
    headers: axum::http::HeaderMap,
    body: Result<Json<ChangeInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    let input = body.map_err(Error::from)?.0;
    let input = input.into_change();
    let proof = operation_proof(&headers)?;
    let idp_fingerprints = offboarding_providers(&s, &input);
    Ok(Json(view(
        s.registration
            .change_device_access(
                &auth.proof,
                &device,
                id,
                &input,
                proof.as_ref(),
                &idp_fingerprints,
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

impl ChangeInput {
    fn into_change(self) -> access::Change {
        let action = match self.action {
            ActionInput::Offboard { disposition } => access::Action::Offboard { disposition },
            ActionInput::ResetFactors => access::Action::ResetFactors,
            ActionInput::Unbind { disposition } => access::Action::Unbind { disposition },
            ActionInput::Reinstate {
                instance,
                principal,
                account,
                policy,
            } => access::Action::Reinstate {
                person: access::Person {
                    instance,
                    principal,
                },
                intent: match account {
                    AccountInput::Existing { account } => {
                        access::AccountIntent::Existing { account }
                    }
                    AccountInput::Create { platform, name } => {
                        access::AccountIntent::Create { platform, name }
                    }
                },
                policy,
            },
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
                    AccountInput::Existing { account } => {
                        access::AccountIntent::Existing { account }
                    }
                    AccountInput::Create { platform, name } => {
                        access::AccountIntent::Create { platform, name }
                    }
                },
                policy,
            },
        };
        access::Change {
            operation_id: self.operation_id,
            expected_revision: self.expected_revision,
            action,
        }
    }
}
fn operation_proof(
    headers: &axum::http::HeaderMap,
) -> Result<Option<rss_mdm_agent_wire::runtime::Secret>, Error> {
    let mut found = None;
    for header in headers.get_all(axum::http::header::COOKIE) {
        for part in header.to_str().map_err(|_| Error::Malformed)?.split(';') {
            if let Some(("__Host-identity-operation", value)) = part.trim().split_once('=') {
                if found.is_some() {
                    return Err(Error::Malformed);
                }
                found = Some(
                    rss_mdm_agent_wire::runtime::Secret::parse(value)
                        .map_err(|_| Error::Unauthorized)?,
                );
            }
        }
    }
    Ok(found)
}
async fn step_up(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((device, id)): Path<(String, Uuid)>,
    headers: axum::http::HeaderMap,
    body: Result<Json<ChangeInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    let input = body.map_err(Error::from)?.0.into_change();
    let context =
        input.step_up_context(&auth.proof, &device, id, &offboarding_providers(&s, &input))?;
    let challenge = s
        .identity
        .webauthn
        .begin_authentication(
            s.identity.ceremony_actor(&headers).await?,
            context,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                std::time::Duration::from_secs(10),
            ),
        )
        .await
        .map_err(crate::identity::failure)?;
    Ok(Json(
        serde_json::to_value(challenge).map_err(|_| Error::Malformed)?,
    ))
}

async fn offboarding(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((device, id)): Path<(String, Uuid)>,
) -> Result<Json<access::lifecycle::Progress>, Error> {
    s.registration
        .offboarding_progress(&auth.proof, &device, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum IdentityDisposition {
    Execute,
    Reconcile { after: Option<Uuid> },
}
async fn offboarding_identity(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    headers: axum::http::HeaderMap,
    body: Result<Json<IdentityDisposition>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    use access::lifecycle::{ExternalComponent as C, ExternalPhase as P};
    let input = body.map_err(Error::from)?.0;
    let original = s.registration.offboarding(&auth.proof, &device, id).await?;
    if original.identity == P::Confirmed {
        return Ok(Json(json!({"operation":original,"nextCursor":null})));
    }
    let principal = rss_identity_core::PrincipalId::parse(&original.person.principal.to_string())
        .map_err(|_| Error::Malformed)?;
    let deadline = || {
        rss_transactional_messaging::policy::OperationDeadline::from_remaining(
            std::time::Duration::from_secs(10),
        )
    };
    match input {
        IdentityDisposition::Reconcile { after } => {
            let actor = s.identity.ceremony_actor(&headers).await?;
            let cursor = after
                .map(|id| rss_identity_core::PrincipalId::parse(&id.to_string()))
                .transpose()
                .map_err(|_| Error::Malformed)?;
            let page = s
                .identity
                .authority
                .list_accounts(actor, cursor, 100, deadline())
                .await
                .map_err(crate::identity::failure)?;
            let observed = page
                .accounts
                .iter()
                .find(|account| account.principal_id == principal);
            let value = if let Some(account) = observed {
                // This records observed inactivity, not proof that a particular remote call committed.
                let phase = if !account.enabled || !account.member_active {
                    P::Confirmed
                } else {
                    P::Pending
                };
                s.registration
                    .observe_offboarding(
                        &auth.proof,
                        &device,
                        id,
                        C::Identity,
                        original.attempt(C::Identity),
                        phase == P::Confirmed,
                        &audit,
                    )
                    .await?
            } else {
                original
            };
            Ok(Json(
                json!({"operation":value,"nextCursor":page.next_cursor.map(|id|id.as_uuid().to_string())}),
            ))
        }
        IdentityDisposition::Execute => {
            if matches!(original.identity, P::Executing | P::Unknown) {
                return Err(Error::Conflict);
            }
            let actor = s.identity.ceremony_actor(&headers).await?;
            let Some(attempt) = s
                .registration
                .claim_offboarding(&auth.proof, &device, id, C::Identity, &audit)
                .await?
            else {
                return Ok(Json(
                    json!({"operation":s.registration.offboarding(&auth.proof,&device,id).await?,"nextCursor":null}),
                ));
            };
            let target = rss_identity_core::account::AccountKey {
                tenant: s.identity.tenant,
                principal,
            };
            let outcome = s
                .identity
                .authority
                .set_account_membership(actor, target, false, deadline())
                .await;
            let phase = match outcome {
                Ok(_) => P::Confirmed,
                Err(
                    rss_identity_postgres::AuthorityError::ReauthenticationFailed
                    | rss_identity_postgres::AuthorityError::Rejected,
                ) => P::RequiresAuthentication,
                Err(
                    rss_identity_postgres::AuthorityError::CommitUnknown(_)
                    | rss_identity_postgres::AuthorityError::RollbackFailed(_),
                ) => P::Unknown,
                Err(_) => P::Failed,
            };
            let value = s
                .registration
                .settle_offboarding(
                    &auth.proof,
                    &device,
                    id,
                    C::Identity,
                    attempt,
                    phase,
                    &audit,
                )
                .await?;
            Ok(Json(json!({"operation":value,"nextCursor":null})))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnterprisePage {
    after: Option<String>,
}
async fn enterprise_list(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Query(page): Query<EnterprisePage>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        serde_json::to_value(
            s.registration
                .enterprise_configuration(&auth.proof, page.after.as_deref())
                .await?,
        )
        .map_err(|_| Error::Malformed)?,
    ))
}
fn enterprise_target(
    s: &Services,
    input: &rss_mdm_registration_service::enterprise::Change,
) -> Result<Option<String>, Error> {
    match &input.configuration {
        rss_mdm_registration_service::enterprise::Configuration::RelyingParty { id, .. } => {
            let target = s
                .identity
                .enterprise_clients
                .get(id)
                .ok_or(Error::Malformed)?;
            Ok(Some(target.fingerprint().to_owned()))
        }
        rss_mdm_registration_service::enterprise::Configuration::Subject { .. }
        | rss_mdm_registration_service::enterprise::Configuration::WindowsKey { .. } => Ok(None),
    }
}
async fn enterprise_step_up(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    headers: axum::http::HeaderMap,
    body: Result<
        Json<rss_mdm_registration_service::enterprise::Change>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<Value>, Error> {
    let input = body.map_err(Error::from)?.0;
    let target = enterprise_target(&s, &input)?;
    let context = input.context(&auth.proof, target.as_deref())?;
    let actor = s.identity.ceremony_actor(&headers).await?;
    let started = s
        .identity
        .webauthn
        .begin_authentication(
            actor,
            context,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                std::time::Duration::from_secs(10),
            ),
        )
        .await
        .map_err(crate::identity::failure)?;
    Ok(Json(json!({"id":started.id,"options":started.options})))
}
async fn enterprise_change(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: axum::http::HeaderMap,
    body: Result<
        Json<rss_mdm_registration_service::enterprise::Change>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_registration_service::enterprise::Record>, Error> {
    let input = body.map_err(Error::from)?.0;
    let target = enterprise_target(&s, &input)?;
    let proof = operation_proof(&headers)?;
    s.registration
        .change_enterprise_configuration(
            &auth.proof,
            &input,
            target.as_deref(),
            proof.as_ref(),
            &audit,
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

fn offboarding_providers(
    s: &Services,
    input: &access::Change,
) -> std::collections::BTreeMap<Uuid, String> {
    if matches!(input.action, access::Action::Offboard { .. }) {
        s.identity
            .enterprise_administrators
            .iter()
            .map(|(id, admin)| (*id, admin.fingerprint().to_owned()))
            .collect()
    } else {
        Default::default()
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum IdpDisposition {
    Execute {
        target: Uuid,
        action: access::lifecycle::IdpAction,
    },
    Reconcile {
        target: Uuid,
    },
}
async fn offboarding_idp(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    body: Result<Json<IdpDisposition>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<access::lifecycle::Progress>, Error> {
    use access::lifecycle::{ExternalComponent as C, ExternalPhase as P, IdpAction as A};
    let input = body.map_err(Error::from)?.0;
    let original = s.registration.offboarding(&auth.proof, &device, id).await?;
    let target_id = match input {
        IdpDisposition::Execute { target, .. } | IdpDisposition::Reconcile { target } => target,
    };
    let target = original
        .idp
        .iter()
        .find(|v| v.id == target_id)
        .ok_or(Error::Malformed)?;
    let admin = s
        .identity
        .enterprise_administrators
        .get(&target.identity.provider)
        .ok_or(Error::Unsupported)?;
    if admin.fingerprint() != target.fingerprint {
        return Err(Error::Conflict);
    }
    match input {
        IdpDisposition::Reconcile { .. } => {
            let observed = admin.observe(&target.identity.subject).await?;
            for (action, confirmed) in [
                (A::DisableAccount, observed.account_disabled),
                (A::RevokeSessions, observed.sessions_revoked),
            ] {
                let component = C::Idp {
                    target: target_id,
                    action,
                };
                s.registration
                    .observe_offboarding(
                        &auth.proof,
                        &device,
                        id,
                        component,
                        original.attempt(component),
                        confirmed,
                        &audit,
                    )
                    .await?;
            }
        }
        IdpDisposition::Execute { action, .. } => {
            let phase = match action {
                A::DisableAccount => target.account,
                A::RevokeSessions => target.sessions,
            };
            if phase != P::Confirmed {
                if matches!(phase, P::Executing | P::Unknown)
                    || matches!(action, A::RevokeSessions) && target.account != P::Confirmed
                {
                    return Err(Error::Conflict);
                }
                let component = C::Idp {
                    target: target_id,
                    action,
                };
                let Some(attempt) = s
                    .registration
                    .claim_offboarding(&auth.proof, &device, id, component, &audit)
                    .await?
                else {
                    return s
                        .registration
                        .offboarding_progress(&auth.proof, &device, id)
                        .await
                        .map(Json)
                        .map_err(Into::into);
                };
                let outcome = admin.execute(&target.identity.subject, action).await;
                let phase = match outcome {
                    Ok(()) => match admin.observe(&target.identity.subject).await {
                        Ok(facts)
                            if match action {
                                A::DisableAccount => facts.account_disabled,
                                A::RevokeSessions => facts.sessions_revoked,
                            } =>
                        {
                            P::Confirmed
                        }
                        Ok(_) => P::Failed,
                        Err(_) => P::Unknown,
                    },
                    Err(rss_mdm_registration_service::Error::CommitUnknown) => P::Unknown,
                    Err(rss_mdm_registration_service::Error::Unauthorized) => {
                        P::RequiresAuthentication
                    }
                    Err(_) => P::Failed,
                };
                s.registration
                    .settle_offboarding(&auth.proof, &device, id, component, attempt, phase, &audit)
                    .await?;
            }
        }
    }
    s.registration
        .offboarding_progress(&auth.proof, &device, id)
        .await
        .map(Json)
        .map_err(Into::into)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MaterialRequest {
    operation_id: Uuid,
}
async fn material_step_up(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((device, id, version)): Path<(String, Uuid, i64)>,
    headers: axum::http::HeaderMap,
    Json(input): Json<MaterialRequest>,
) -> Result<Json<Value>, Error> {
    s.recovery.as_ref().ok_or(Error::Unsupported)?;
    let input = rss_mdm_recovery_credentials::DisclosureRequest {
        operation_id: input.operation_id,
        proof: None,
    };
    let context = input.context(&auth.proof, &device, id, version)?;
    let actor = s.identity.ceremony_actor(&headers).await?;
    let started = s
        .identity
        .webauthn
        .begin_authentication(
            actor,
            context,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                std::time::Duration::from_secs(10),
            ),
        )
        .await
        .map_err(crate::identity::failure)?;
    Ok(Json(json!({"id":started.id,"options":started.options})))
}
async fn material_disclose(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id, version)): Path<(String, Uuid, i64)>,
    headers: axum::http::HeaderMap,
    Json(input): Json<MaterialRequest>,
) -> Result<Json<rss_mdm_recovery_credentials::Disclosure>, Error> {
    let input = rss_mdm_recovery_credentials::DisclosureRequest {
        operation_id: input.operation_id,
        proof: operation_proof(&headers)?,
    };
    Ok(Json(
        s.recovery
            .as_ref()
            .ok_or(Error::Unsupported)?
            .disclose_device_access(&auth.proof, &device, id, version, &input, &audit)
            .await?,
    ))
}
