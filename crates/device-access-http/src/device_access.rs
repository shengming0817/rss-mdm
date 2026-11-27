//! Device-scoped administrator operations. Self-enrollment is authenticated on the Agent channel.
use crate::business_error::Error;
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_agent_wire::runtime::{AccessAccount, TaskPlatform};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::RequestAuth;
use rss_mdm_device_access_postgres::{Service, device_access as access};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
pub struct Services {
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub recovery: Option<Arc<rss_mdm_recovery_credentials::Credentials>>,
    pub registration: Arc<Service>,
    pub admission: Arc<dyn rss_mdm_device_access_postgres::device_access::Admission>,
    pub identity: Arc<crate::identity::Identity>,
}
pub fn routes(
    cursor: rss_mdm_query::cursor::CursorCodec,
    recovery: Option<Arc<rss_mdm_recovery_credentials::Credentials>>,
    registration: Option<Arc<Service>>,
    admission: Arc<dyn rss_mdm_device_access_postgres::device_access::Admission>,
    identity: Arc<crate::identity::Identity>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    let enabled = registration.is_some();
    mount(
        registration.map(|registration| {
            Arc::new(Services {
                cursor,
                recovery,
                registration,
                admission,
                identity,
            })
        }),
        enabled,
    )
}
pub fn mount(
    runtime: Option<Arc<Services>>,
    enabled: bool,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register()
        .bind_with(runtime.as_ref(), Clone::clone)
        .when("device_access", enabled)
}
fn register() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { publish_credential_policy, credential_policy, request_credential, credential_status, get_materials, post_material_step_up, post_material_disclose, get_list, get_binding, put_change, post_step_up, post_oidc_step_up, get_operation, get_execution, get_offboarding, post_offboarding_identity, get_enterprise_list, post_enterprise_change, get_enterprise_detail, get_enterprise_operation, post_enterprise_step_up, post_offboarding_idp } }
        RegisterModule1 {
            publish_credential_policy: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/credential-policies",
                rss_mdm_http_contract::routing::post(
                    publish_credential_policy,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action],
                ),
            ),
            credential_policy: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/credential-policies/{version}",
                get(
                    credential_policy,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Get],
                ),
            ),
            request_credential: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/credential-operations",
                rss_mdm_http_contract::routing::post(
                    request_credential,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action],
                ),
            ),
            credential_status: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/credential-operations/{id}",
                get(
                    credential_status,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action],
                ),
            ),
            get_materials: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/materials",
                get(
                    materials,
                    &contracts::RECOVERY_CREDENTIALS,
                    &[RouteOperation::List],
                ),
            ),
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
            post_oidc_step_up: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/bindings/{id}/step-up/oidc/{provider}",
                rss_mdm_http_contract::routing::post(
                    oidc_step_up,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action],
                )
                .settles_transaction(),
            ),
            post_step_up: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/bindings/{id}/step-up",
                rss_mdm_http_contract::routing::post(
                    step_up,
                    &contracts::DEVICE_ACCESS,
                    &[RouteOperation::Action],
                ),
            ),
            get_execution: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/device-access/operations/{id}/execution",
                get(execution, &contracts::DEVICE_ACCESS, &[RouteOperation::Get]),
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
            get_enterprise_operation: rss_mdm_http_contract::module::Route::new(
                "/device-access/enterprise/configuration/operations/{operationId}",
                get(
                    enterprise_operation,
                    &contracts::ENTERPRISE_CONFIGURATION,
                    &[RouteOperation::Action],
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
    RepairBinding,
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
    Path((_tenant, device)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId)>,
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
            .device_access_bindings(&auth, &device, &q, &s.cursor)
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
    Path((_tenant, device, id)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
) -> Result<Json<access::directory::BindingView>, Error> {
    s.registration
        .device_access_binding(&auth, &device, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplicationOperationQuery {
    application_id: Option<String>,
}
async fn enterprise_operation(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, operation)): Path<(Uuid, Uuid)>,
    axum::extract::Query(query): axum::extract::Query<ApplicationOperationQuery>,
) -> Result<Json<rss_mdm_device_access_postgres::enterprise::ApplicationReceipt>, Error> {
    s.registration
        .application_operation(&auth.proof, operation, query.application_id.as_deref())
        .await
        .map(Json)
        .map_err(|e| match e {
            rss_mdm_device_access_postgres::Error::NotFound => Error::OperationNotFound,
            e => e.into(),
        })
}
async fn enterprise_detail(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, id)): Path<(uuid::Uuid, String)>,
) -> Result<Json<rss_mdm_device_access_postgres::enterprise::directory::RecordView>, Error> {
    s.registration
        .enterprise_configuration_record(&auth, &id)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn change(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, device, id)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
    OperationProofHeaders(headers): OperationProofHeaders,
    body: Result<Json<ChangeInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<access::directory::BindingView>, Error> {
    let input = body.map_err(Error::from)?.0;
    let input = input.into_change();
    let proof = operation_proof(&headers)?;
    let idp_fingerprints = offboarding_providers(&s, auth.proof.binding(), &input);
    Ok(Json(view(
        s.registration
            .change_device_access(
                &auth.proof,
                &device,
                id,
                &input,
                proof.as_ref(),
                &idp_fingerprints,
                s.admission.as_ref(),
                &audit,
            )
            .await?,
    )))
}
async fn execution(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, device, id)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
) -> Result<Json<access::account_delivery::Progress>, Error> {
    Ok(Json(
        s.registration
            .account_progress(&auth.proof, &device, id)
            .await?,
    ))
}
async fn operation(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, device, id)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
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
            ActionInput::RepairBinding => access::Action::RepairBinding,
            ActionInput::Unbind { disposition } => access::Action::Unbind { disposition },
            ActionInput::Reinstate {
                instance,
                principal,
                account,
                policy,
            } => access::Action::Reinstate {
                person: rss_mdm_device_access::Person {
                    instance,
                    principal,
                },
                intent: match account {
                    AccountInput::Existing { account } => {
                        rss_mdm_device_access::AccountIntent::Existing { account }
                    }
                    AccountInput::Create { platform, name } => {
                        rss_mdm_device_access::AccountIntent::Create { platform, name }
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
                person: rss_mdm_device_access::Person {
                    instance,
                    principal,
                },
                intent: match account {
                    AccountInput::Existing { account } => {
                        rss_mdm_device_access::AccountIntent::Existing { account }
                    }
                    AccountInput::Create { platform, name } => {
                        rss_mdm_device_access::AccountIntent::Create { platform, name }
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
pub(crate) fn operation_proof(
    headers: &axum::http::HeaderMap,
) -> Result<Option<rss_mdm_agent_wire::runtime::Secret>, Error> {
    if !headers.contains_key(axum::http::header::COOKIE) {
        return Ok(None);
    }
    let value = rss_identity_web_credentials::read_operation_cookie(headers)
        .map_err(|_| Error::Malformed)?;
    value
        .as_deref()
        .map(rss_mdm_agent_wire::runtime::Secret::parse)
        .transpose()
        .map_err(|_| Error::Unauthorized)
}
async fn step_up(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, device, id)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
    crate::identity::CeremonyHeaders(headers): crate::identity::CeremonyHeaders,
    body: Result<Json<ChangeInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::identity_contract::TimedChallenge>, Error> {
    let input = body.map_err(Error::from)?.0.into_change();
    let (context, _) = s
        .registration
        .change_step_up_context(
            &auth.proof,
            &device,
            id,
            &input,
            &offboarding_providers(&s, auth.proof.binding(), &input),
            s.admission.as_ref(),
        )
        .await?;
    let challenge = s
        .identity
        .webauthn
        .begin_authentication(
            s.identity
                .ceremony_actor(auth.proof.binding(), &headers, auth.cutoff())
                .await?,
            s.identity.rp_generation,
            context,
            auth.cutoff(),
        )
        .await
        .map_err(crate::identity::failure)?;
    Ok(Json(crate::identity_contract::TimedChallenge(challenge)))
}

#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FederatedChange {
    change: ChangeInput,
    return_target: String,
}

enum StepUpError {
    Device(Error),
    Identity(rss_mdm_identity_http::HttpError),
}
impl From<Error> for StepUpError {
    fn from(e: Error) -> Self {
        Self::Device(e)
    }
}
impl From<rss_mdm_identity_http::HttpError> for StepUpError {
    fn from(e: rss_mdm_identity_http::HttpError) -> Self {
        Self::Identity(e)
    }
}
impl axum::response::IntoResponse for StepUpError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Device(e) => e.into_response(),
            Self::Identity(e) => {
                let mut response = e.into_response();
                let failure = match response
                    .extensions()
                    .get::<rss_mdm_identity_http::HttpFailure>()
                {
                    Some(rss_mdm_identity_http::HttpFailure::RequestTimeout) => {
                        Some(rss_mdm_audit_integration::completion::ResponseFailure::Deadline)
                    }
                    Some(rss_mdm_identity_http::HttpFailure::Authority(e)) => {
                        crate::identity::failure(*e).failure()
                    }
                    None => None,
                };
                if let Some(failure) = failure {
                    response.extensions_mut().insert(failure);
                }
                response
            }
        }
    }
}
impl rss_mdm_http_contract::signature::Output for StepUpError {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        let mut r = Error::responses();
        r.extend(rss_mdm_identity_http::HttpError::responses());
        r
    }
}
async fn oidc_step_up(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(peer): Extension<rss_mdm_identity_http::ClientAddress>,
    Path((_tenant, device, id, provider)): Path<(Uuid, rss_mdm_agent_wire::DeviceId, Uuid, Uuid)>,
    crate::identity::CeremonyHeaders(headers): crate::identity::CeremonyHeaders,
    body: Result<Json<FederatedChange>, axum::extract::rejection::JsonRejection>,
) -> Result<rss_mdm_identity_http::CookieJson<rss_mdm_identity_http::AuthorizationUrl>, StepUpError>
{
    let input = body.map_err(Error::from)?.0;
    let federation = s.identity.federation.as_ref().ok_or(Error::Unsupported)?;
    let change = input.change.into_change();
    let deadline = auth.cutoff().capped(
        s.identity.authority.execution_timer(),
        s.identity.http.timeout(),
    );
    let (context, employee) = tokio::time::timeout_at(
        deadline.instant().into(),
        s.registration.change_step_up_context(
            &auth.proof,
            &device,
            id,
            &change,
            &offboarding_providers(&s, auth.proof.binding(), &change),
            s.admission.as_ref(),
        ),
    )
    .await
    .map_err(|_| {
        Error::Classified(rss_mdm_audit_integration::completion::ResponseFailure::Deadline)
    })?
    .map_err(Error::from)?;
    if employee.is_none() {
        return Err(Error::Forbidden.into());
    }
    let binding = auth.proof.binding();
    if s.identity.excluded_federation_tenant == Some(binding.tenant()) {
        return Err(Error::Forbidden.into());
    }
    let state = rss_mdm_identity_http::AppState {
        authority: s.identity.authority.clone(),
        config: s.identity.http.clone(),
    };
    let actor = rss_mdm_identity_http::operation_actor(&state, binding, &headers, deadline).await?;
    let browser = rss_identity_web_credentials::BrowserBinding::start(&headers)
        .map_err(rss_mdm_identity_http::HttpError::from)?;
    let source = rss_identity_postgres::AttemptSource::parse(&peer.0.to_string())
        .map_err(rss_mdm_identity_http::HttpError::from)?;
    let provider = rss_identity_core::federation::ProviderId::parse(&provider.to_string())
        .map_err(|_| Error::Malformed)?;
    let redirect = federation
        .begin_step_up(
            rss_identity_postgres::LoginRequest {
                binding,
                provider,
                browser: browser.value,
                target: input.return_target,
                replacement: Some(actor),
                source,
            },
            context,
            deadline,
        )
        .await
        .map_err(rss_mdm_identity_http::HttpError::from)?;
    Ok(rss_mdm_identity_http::authorization_redirect(
        redirect,
        browser.set_cookie,
    ))
}

async fn offboarding(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, device, id)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
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
    Path((_tenant, device, id)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
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
    match input {
        IdentityDisposition::Reconcile {} => {
            let actor = s
                .identity
                .ceremony_actor(auth.proof.binding(), &headers, auth.cutoff())
                .await?;
            let account = s
                .identity
                .authority
                .read_account(
                    actor,
                    rss_identity_core::account::AccountKey {
                        tenant: auth.proof.binding().tenant(),
                        principal,
                    },
                    auth.cutoff(),
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
            let actor = s
                .identity
                .ceremony_actor(auth.proof.binding(), &headers, auth.cutoff())
                .await?;
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
                tenant: auth.proof.binding().tenant(),
                principal,
            };
            let outcome = s
                .identity
                .authority
                .set_account_membership(actor, target, false, auth.cutoff())
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
    axum::extract::Path(_tenant): axum::extract::Path<uuid::Uuid>,
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
                    rss_mdm_device_access_postgres::enterprise::directory::RecordView,
                >,
            >,
        >,
    >,
    Error,
> {
    (async {
        let q = query.parse().map_err(|_| Error::Malformed)?;
        s.registration
            .enterprise_configuration(&auth, &q, &s.cursor)
            .await
            .map(Json)
            .map_err(Into::into)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
fn enterprise_target(
    s: &Services,
    execution: rss_transactional_messaging::fence::ExecutionBinding,
    input: &rss_mdm_device_access_postgres::enterprise::Change,
) -> Result<Option<String>, Error> {
    match &input.configuration {
        rss_mdm_device_access_postgres::enterprise::Configuration::RelyingParty { id, .. } => {
            let target = s
                .identity
                .enterprise_clients
                .get(id)
                .ok_or(Error::Malformed)?;
            if target.tenant() != execution.tenant() {
                return Err(Error::Forbidden);
            }
            Ok(Some(target.fingerprint().to_owned()))
        }
        rss_mdm_device_access_postgres::enterprise::Configuration::Subject { .. }
        | rss_mdm_device_access_postgres::enterprise::Configuration::WindowsKey { .. } => Ok(None),
    }
}
async fn enterprise_step_up(
    axum::extract::Path(_tenant): axum::extract::Path<uuid::Uuid>,
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    crate::identity::CeremonyHeaders(headers): crate::identity::CeremonyHeaders,
    body: Result<
        Json<rss_mdm_device_access_postgres::enterprise::Change>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<crate::identity_contract::Challenge>, Error> {
    let input = body.map_err(Error::from)?.0;
    let target = enterprise_target(&s, auth.proof.binding(), &input)?;
    let context = input.context(&auth.proof, target.as_deref())?;
    let actor = s
        .identity
        .ceremony_actor(auth.proof.binding(), &headers, auth.cutoff())
        .await?;
    let started = s
        .identity
        .webauthn
        .begin_authentication(actor, s.identity.rp_generation, context, auth.cutoff())
        .await
        .map_err(crate::identity::failure)?;
    Ok(Json(crate::identity_contract::Challenge {
        id: started.id,
        options: started.options,
    }))
}
async fn enterprise_change(
    axum::extract::Path(_tenant): axum::extract::Path<uuid::Uuid>,
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    OperationProofHeaders(headers): OperationProofHeaders,
    body: Result<
        Json<rss_mdm_device_access_postgres::enterprise::Change>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_device_access_postgres::enterprise::Record>, Error> {
    let input = body.map_err(Error::from)?.0;
    let target = enterprise_target(&s, auth.proof.binding(), &input)?;
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
    execution: rss_transactional_messaging::fence::ExecutionBinding,
    input: &access::Change,
) -> std::collections::BTreeMap<Uuid, String> {
    if matches!(input.action, access::Action::Offboard { .. }) {
        s.identity
            .enterprise_administrators
            .iter()
            .filter(|(_, admin)| admin.tenant.to_string() == execution.tenant().to_string())
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
    Path((_tenant, device, id)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
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
    if admin.tenant.to_string() != auth.proof.tenant_id()
        || admin.fingerprint() != target.fingerprint
    {
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
                    Err(rss_mdm_device_access_postgres::Error::CommitUnknown) => P::Unknown,
                    Err(rss_mdm_device_access_postgres::Error::Unauthorized) => {
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
    Path((_tenant, device, id, version)): Path<(
        uuid::Uuid,
        rss_mdm_agent_wire::DeviceId,
        Uuid,
        i64,
    )>,
    crate::identity::CeremonyHeaders(headers): crate::identity::CeremonyHeaders,
    Json(input): Json<MaterialRequest>,
) -> Result<Json<crate::identity_contract::Challenge>, Error> {
    s.recovery.as_ref().ok_or(Error::Unsupported)?;
    let input = rss_mdm_recovery_credentials::DisclosureRequest {
        operation_id: input.operation_id,
        proof: None,
    };
    let context = input.context(&auth.proof, &device, id, version)?;
    let actor = s
        .identity
        .ceremony_actor(auth.proof.binding(), &headers, auth.cutoff())
        .await?;
    let started = s
        .identity
        .webauthn
        .begin_authentication(actor, s.identity.rp_generation, context, auth.cutoff())
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
    Path((_tenant, device, id, version)): Path<(
        uuid::Uuid,
        rss_mdm_agent_wire::DeviceId,
        Uuid,
        i64,
    )>,
    RequiredOperationProof(proof): RequiredOperationProof,
    Json(input): Json<MaterialRequest>,
) -> Result<
    rss_mdm_http_contract::signature::NoStore<Json<rss_mdm_recovery_credentials::Disclosure>>,
    Error,
> {
    let input = rss_mdm_recovery_credentials::DisclosureRequest {
        operation_id: input.operation_id,
        proof: Some(proof),
    };
    Ok(rss_mdm_http_contract::signature::NoStore(Json(
        s.recovery
            .as_ref()
            .ok_or(Error::Unsupported)?
            .disclose_device_access(&auth.proof, &device, id, version, &input, &audit)
            .await?,
    )))
}

async fn materials(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, device)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId)>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<MaterialQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<rss_mdm_recovery_credentials::Material>,
            >,
        >,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "recovery_credential_list",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        audit.target_device(&device);
        let q = query.parse().map_err(|_| Error::Malformed)?;
        s.recovery
            .as_ref()
            .ok_or(Error::Unsupported)?
            .list(&auth, &device, &q, &s.cursor)
            .await
            .map(Json)
            .map_err(Into::into)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
struct MaterialQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for MaterialQuery {
    fn execution() -> &'static rss_mdm_query::directory::Execution {
        rss_mdm_recovery_credentials::directory::BINDINGS.execution()
    }
}

struct ListQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ListQuery {
    fn execution() -> &'static rss_mdm_query::directory::Execution {
        access::directory::BINDINGS.execution()
    }
}

struct EnterpriseListQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for EnterpriseListQuery {
    fn execution() -> &'static rss_mdm_query::directory::Execution {
        rss_mdm_device_access_postgres::enterprise::directory::BINDINGS.execution()
    }
}

struct RequiredOperationProof(rss_mdm_agent_wire::runtime::Secret);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for RequiredOperationProof {
    type Rejection = Error;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        operation_proof(&parts.headers)?
            .map(Self)
            .ok_or(Error::Unauthorized)
    }
}
impl rss_mdm_http_contract::signature::Input for RequiredOperationProof {
    fn request() -> rss_mdm_http_contract::signature::Request {
        use rss_mdm_http_contract::signature::{Direction, Request, Schema};
        Request { headers: [("cookie".into(), Schema { direction: Direction::Request, value: serde_json::json!({"type":"string","description":"Requires the __Host-identity-operation proof bound to this session, operation, device and material version"}) })].into(), required_headers: vec!["cookie"], ..Request::default() }
    }
}
struct OperationProofHeaders(pub axum::http::HeaderMap);
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

use rss_mdm_policy_postgres::device_access::CredentialPublication;
async fn publish_credential_policy(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    Path((_tenant, device)): Path<(Uuid, rss_mdm_agent_wire::DeviceId)>,
    Json(input): Json<CredentialPublication>,
) -> Result<Json<CredentialPublication>, Error> {
    Ok(Json(
        s.registration
            .publish_credential_policy(&auth.proof, &device, &input, &a)
            .await?,
    ))
}
async fn credential_policy(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, device, version)): Path<(Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
) -> Result<Json<CredentialPublication>, Error> {
    Ok(Json(
        s.registration
            .credential_policy(&auth.proof, &device, version)
            .await?,
    ))
}
use rss_mdm_recovery_credentials::tasks::device as credential;
async fn request_credential(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    Path((_tenant, device)): Path<(Uuid, rss_mdm_agent_wire::DeviceId)>,
    Json(input): Json<credential::Request>,
) -> Result<Json<credential::Status>, Error> {
    Ok(Json(
        s.registration
            .request_credential(
                s.recovery.as_deref().ok_or(Error::Unsupported)?,
                &auth.proof,
                &device,
                &input,
                &a,
            )
            .await?,
    ))
}
async fn credential_status(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Path((_tenant, device, id)): Path<(Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
) -> Result<Json<credential::Status>, Error> {
    Ok(Json(
        s.registration
            .credential_status(&auth.proof, &device, id)
            .await?,
    ))
}
