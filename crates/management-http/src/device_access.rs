//! Device-scoped administrator operations. Self-enrollment is authenticated on the Agent channel.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_agent_wire::runtime::{AccessAccount, TaskPlatform};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use rss_mdm_registration_service::{agent::Service, device_access as access};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
pub(crate) struct Services {
    pub(crate) cursor: rss_mdm_query::cursor::CursorCodec,
    pub(crate) recovery: Option<Arc<rss_mdm_recovery_credentials::Credentials>>,
    pub(crate) registration: Arc<Service>,
    pub(crate) execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub(crate) identity: Arc<crate::identity::Identity>,
}
pub fn routes(
    cursor: rss_mdm_query::cursor::CursorCodec,
    recovery: Option<Arc<rss_mdm_recovery_credentials::Credentials>>,
    registration: Option<Arc<Service>>,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
    identity: Arc<crate::identity::Identity>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    let enabled = registration.is_some();
    mount(
        registration.map(|registration| {
            Arc::new(Services {
                cursor,
                recovery,
                registration,
                execution,
                identity,
            })
        }),
        enabled,
    )
}
pub(crate) fn mount(
    runtime: Option<Arc<Services>>,
    enabled: bool,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register()
        .bind_with(runtime.as_ref(), Clone::clone)
        .when("agent_enrollment", enabled)
}
fn register() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { post_material_step_up, post_material_disclose, get_list, get_binding, put_change, post_step_up, get_operation, get_offboarding, post_offboarding_identity, get_enterprise_list, post_enterprise_change, get_enterprise_detail, post_enterprise_step_up, post_offboarding_idp } }
        RegisterModule1 {
            post_material_step_up: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/materials/{id}/versions/{version}/step-up",
                rss_mdm_http_contract::routing::post(
                    material_step_up,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action],
                ),
            ),
            post_material_disclose: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/materials/{id}/versions/{version}/secret",
                rss_mdm_http_contract::routing::post(
                    material_disclose,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action],
                ),
            ),
            get_list: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access",
                get(list, &contracts::DEVICE_ACCESS, &[RouteOperation::List]),
            ),
            get_binding: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/bindings/{id}",
                rss_mdm_http_contract::routing::get(
                    binding,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Get],
                ),
            ),
            put_change: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/bindings/{id}",
                rss_mdm_http_contract::routing::put(
                    change,
                    &contracts::DEVICE_ACCESS,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Lifecycle,
                    ],
                ),
            ),
            post_step_up: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/bindings/{id}/step-up",
                rss_mdm_http_contract::routing::post(
                    step_up,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action],
                ),
            ),
            get_operation: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/operations/{id}",
                get(
                    operation,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action],
                ),
            ),
            get_offboarding: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/operations/{id}/offboarding",
                get(
                    offboarding,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action],
                ),
            ),
            post_offboarding_identity: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/operations/{id}/offboarding/identity",
                rss_mdm_http_contract::routing::post(
                    offboarding_identity,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            get_enterprise_list: rss_mdm_http_contract::module::Route::new(
                "/device-access/enterprise/configuration",
                rss_mdm_http_contract::routing::get(
                    enterprise_list,
                    &contracts::ENTERPRISE_CONFIGURATION,
                    &[RouteOperation::List],
                ),
            ),
            post_enterprise_change: rss_mdm_http_contract::module::Route::new(
                "/device-access/enterprise/configuration",
                rss_mdm_http_contract::routing::post(
                    enterprise_change,
                    &contracts::ENTERPRISE_CONFIGURATION,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Lifecycle,
                    ],
                ),
            ),
            get_enterprise_detail: rss_mdm_http_contract::module::Route::new(
                "/device-access/enterprise/configuration/{id}",
                get(
                    enterprise_detail,
                    &contracts::ENTERPRISE_CONFIGURATION,
                    &[RouteOperation::Get],
                ),
            ),
            post_enterprise_step_up: rss_mdm_http_contract::module::Route::new(
                "/device-access/enterprise/configuration/step-up",
                rss_mdm_http_contract::routing::post(
                    enterprise_step_up,
                    &contracts::ENTERPRISE_CONFIGURATION,
                    &[RouteOperation::Action],
                ),
            ),
            post_offboarding_idp: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/operations/{id}/offboarding/idp",
                rss_mdm_http_contract::routing::post(
                    offboarding_idp,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
        }
        .assemble()
    }
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChangeInput {
    operation_id: Uuid,
    expected_revision: i64,
    action: ActionInput,
}
#[derive(schemars::JsonSchema, Deserialize)]
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
#[derive(schemars::JsonSchema, Deserialize)]
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
use access::directory::view;
async fn list(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path(device): Path<String>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<ListQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<access::directory::BindingView>,
            >,
        >,
    >,
    Error,
> {
    (async {
        let q = query.parse().map_err(|_| Error::Malformed)?;
        s.registration
            .device_access_bindings(&auth.proof, &device, &q, &s.cursor)
            .await
            .map(Json)
            .map_err(Into::into)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn binding(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((device, id)): Path<(String, Uuid)>,
) -> Result<Json<access::directory::BindingView>, Error> {
    s.registration
        .device_access_binding(&auth.proof, &device, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn enterprise_detail(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<String>,
) -> Result<Json<rss_mdm_registration_service::enterprise::directory::RecordView>, Error> {
    s.registration
        .enterprise_configuration_record(&auth.proof, &id)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn change(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    OperationProofHeaders(headers): OperationProofHeaders,
    body: Result<Json<ChangeInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<access::directory::BindingView>, Error> {
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
) -> Result<Json<access::directory::BindingView>, Error> {
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
    crate::identity::CeremonyHeaders(headers): crate::identity::CeremonyHeaders,
    body: Result<Json<ChangeInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::identity_contract::TimedChallenge>, Error> {
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
    Ok(Json(crate::identity_contract::TimedChallenge(challenge)))
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
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum IdentityDisposition {
    Execute {},
    Reconcile {},
}
struct IdentityOffboardingHeaders(axum::http::HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for IdentityOffboardingHeaders {
    type Rejection = Error;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        if parts.uri.query().is_some() {
            return Err(Error::Malformed);
        }
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for IdentityOffboardingHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        <crate::identity::CeremonyHeaders as rss_mdm_http_contract::signature::Input>::request()
    }
}
async fn offboarding_identity(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    IdentityOffboardingHeaders(headers): IdentityOffboardingHeaders,
    body: Result<Json<IdentityDisposition>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<OffboardingIdentity>, Error> {
    use access::lifecycle::{ExternalComponent as C, ExternalPhase as P};
    let input = body.map_err(Error::from)?.0;
    audit.operation(
        id,
        "device_access_external_phase",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(&device);
    let original = s.registration.offboarding(&auth.proof, &device, id).await?;
    if original.identity == P::Confirmed {
        return Ok(Json(OffboardingIdentity {
            operation: original,
        }));
    }
    let principal = rss_identity_core::PrincipalId::parse(&original.person.principal.to_string())
        .map_err(|_| Error::Malformed)?;
    let deadline = || {
        rss_transactional_messaging::policy::OperationDeadline::from_remaining(
            std::time::Duration::from_secs(10),
        )
    };
    match input {
        IdentityDisposition::Reconcile {} => {
            let actor = s.identity.ceremony_actor(&headers).await?;
            let account = s
                .identity
                .authority
                .read_account(
                    actor,
                    rss_identity_core::account::AccountKey {
                        tenant: s.identity.tenant,
                        principal,
                    },
                    deadline(),
                )
                .await
                .map_err(crate::identity::failure)?;
            let value = {
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
            };
            Ok(Json(OffboardingIdentity { operation: value }))
        }
        IdentityDisposition::Execute {} => {
            if matches!(original.identity, P::Executing | P::Unknown) {
                return Err(Error::Conflict);
            }
            let actor = s.identity.ceremony_actor(&headers).await?;
            let Some(attempt) = s
                .registration
                .claim_offboarding(&auth.proof, &device, id, C::Identity, &audit)
                .await?
            else {
                return Ok(Json(OffboardingIdentity {
                    operation: s.registration.offboarding(&auth.proof, &device, id).await?,
                }));
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
            Ok(Json(OffboardingIdentity { operation: value }))
        }
    }
}

async fn enterprise_list(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<EnterpriseListQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_registration_service::enterprise::directory::RecordView,
                >,
            >,
        >,
    >,
    Error,
> {
    (async {
        let q = query.parse().map_err(|_| Error::Malformed)?;
        s.registration
            .enterprise_configuration(&auth.proof, &q, &s.cursor)
            .await
            .map(Json)
            .map_err(Into::into)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
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
    crate::identity::CeremonyHeaders(headers): crate::identity::CeremonyHeaders,
    body: Result<
        Json<rss_mdm_registration_service::enterprise::Change>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<crate::identity_contract::Challenge>, Error> {
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
    Ok(Json(crate::identity_contract::Challenge {
        id: started.id,
        options: started.options,
    }))
}
async fn enterprise_change(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    OperationProofHeaders(headers): OperationProofHeaders,
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

#[derive(schemars::JsonSchema, Deserialize)]
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
    audit.operation(
        id,
        "device_access_external_phase",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(&device);
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

#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MaterialRequest {
    operation_id: Uuid,
}
async fn material_step_up(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((device, id, version)): Path<(String, Uuid, i64)>,
    crate::identity::CeremonyHeaders(headers): crate::identity::CeremonyHeaders,
    Json(input): Json<MaterialRequest>,
) -> Result<Json<crate::identity_contract::Challenge>, Error> {
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
    Ok(Json(crate::identity_contract::Challenge {
        id: started.id,
        options: started.options,
    }))
}
async fn material_disclose(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id, version)): Path<(String, Uuid, i64)>,
    OperationProofHeaders(headers): OperationProofHeaders,
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

struct ListQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ListQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &access::directory::SCHEMA
    }
}

struct EnterpriseListQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for EnterpriseListQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_registration_service::enterprise::directory::SCHEMA
    }
}

struct OperationProofHeaders(pub(crate) axum::http::HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for OperationProofHeaders {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for OperationProofHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        use rss_mdm_http_contract::signature::{Direction, Request, Schema};
        Request { headers:[("cookie".into(), Schema { direction: Direction::Request, value: serde_json::json!({"type":"string", "description":"Optional __Host-identity-operation proof; the selected operation decides whether it is required"}) })].into(), required_headers:vec![], ..Request::default() }
    }
}

#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct OffboardingIdentity {
    operation: access::lifecycle::Offboarding,
}
