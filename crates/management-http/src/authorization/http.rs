use super::*;
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_authorization_service::directory::{self, Directory};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use std::sync::Arc;
use uuid::Uuid;

pub fn routes() -> Router<Arc<HttpState>> {
    rule_routes()
        .route(
            "/authorization/user-groups",
            get(groups).owned(&contracts::USER_GROUPS, &[RouteOperation::List]),
        )
        .route(
            "/authorization/user-groups/{id}",
            get(group_detail)
                .owned(&contracts::USER_GROUPS, &[RouteOperation::Get])
                .put(group_write)
                .owned(
                    &contracts::USER_GROUPS,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
        )
        .route(
            "/authorization/user-groups/{id}/members",
            get(members).owned(&contracts::USER_GROUP_MEMBERS, &[RouteOperation::List]),
        )
        .route(
            "/authorization/departments",
            get(departments).owned(
                &contracts::AUTHORIZATION_DEPARTMENTS,
                &[RouteOperation::Get],
            ),
        )
}
/// The same rule protocol is used within the installation management tenant.
pub fn rule_routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/authorization",
            get(effective).owned(&contracts::EFFECTIVE_AUTHORITY, &[RouteOperation::Get]),
        )
        .route(
            "/authorization/rules",
            get(rules).owned(&contracts::AUTHORIZATION_RULES, &[RouteOperation::List]),
        )
        .route(
            "/authorization/rules/{id}",
            get(rule_detail)
                .owned(&contracts::AUTHORIZATION_RULES, &[RouteOperation::Get])
                .put(rule_write)
                .owned(
                    &contracts::AUTHORIZATION_RULES,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
        )
}
async fn effective(Extension(auth): Extension<RequestAuth>) -> Result<Json<Effective>, Error> {
    let proof = &auth.proof;
    Ok(Json(Effective {
        instance_id: proof.instance_id().to_owned(),
        tenant_id: proof.tenant_id().to_owned(),
        principal_id: proof.principal_id().to_owned(),
        grants: proof.authorization()?.effective(proof)?,
    }))
}
async fn listing(
    app: &HttpState,
    auth: &RequestAuth,
    q: rss_mdm_query::directory::Query,
    kind: Directory,
) -> Result<directory::DirectoryPage, Error> {
    directory::list(&app.audit_store, &auth.proof, &app.cursor, kind, &q)
        .await?
        .ok_or(Error::NotFound)
}

async fn rules(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<RulesQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<directory::RuleRow>>>,
    >,
    Error,
> {
    let page = listing(
        &app,
        &auth,
        query.parse().map_err(|_| Error::Malformed)?,
        Directory::Rules,
    )
    .await?
    .rules()?;
    Ok(rss_mdm_http_contract::CollectionResponse(Json(page)))
}
async fn groups(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<GroupsQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<directory::GroupRow>>>,
    >,
    Error,
> {
    let page = listing(
        &app,
        &auth,
        query.parse().map_err(|_| Error::Malformed)?,
        Directory::Groups,
    )
    .await?
    .groups()?;
    Ok(rss_mdm_http_contract::CollectionResponse(Json(page)))
}
async fn rule_detail(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_authorization_service::Revision<rss_mdm_authorization_service::Rule>>, Error>
{
    Ok(Json(
        directory::detail(&app.audit_store, &auth.proof, false, id)
            .await?
            .ok_or(Error::NotFound)?
            .rule()?,
    ))
}
async fn group_detail(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<
    Json<rss_mdm_authorization_service::Revision<rss_mdm_authorization_service::UserGroup>>,
    Error,
> {
    Ok(Json(
        directory::detail(&app.audit_store, &auth.proof, true, id)
            .await?
            .ok_or(Error::NotFound)?
            .group()?,
    ))
}
async fn rule_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Change<Rule>>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Receipt>, Error> {
    let Json(change) = body.map_err(Error::from)?;
    audit.operation(
        change.operation_id,
        "authorization_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target(&id.to_string());
    crate::authorization::store::change_rule(&app.audit_store, &auth.proof, id, change, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn group_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Change<UserGroup>>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Receipt>, Error> {
    let Json(change) = body.map_err(Error::from)?;
    audit.operation(
        change.operation_id,
        "authorization_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target(&id.to_string());
    crate::authorization::store::change_group(&app.audit_store, &auth.proof, id, change, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn members(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<MembersQuery>,
    >,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<directory::GroupMembers>>, Error> {
    let page = listing(
        &app,
        &auth,
        query.parse().map_err(|_| Error::Malformed)?,
        Directory::Members(id),
    )
    .await?
    .members()?;
    Ok(rss_mdm_http_contract::CollectionResponse(Json(page)))
}
async fn departments(
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<crate::identity_contract::Departments>, Error> {
    use crate::identity_contract::{DepartmentSource, Departments};
    use rss_identity_postgres::VerifiedDepartmentSnapshot as Department;
    auth.proof.require(Permission::DepartmentRead, None)?;
    let value = match auth
        .proof
        .session()?
        .department_snapshot()
        .map_err(|_| Error::Unauthorized)?
    {
        Department::Available(view) => match view.snapshot() {
            Ok(snapshot) => Departments::Available {
                source: DepartmentSource {
                    provider_id: view.provider_id(),
                    issuer: view.issuer().into(),
                    configuration_version: view.provider_config_version(),
                },
                snapshot_id: view.snapshot_id(),
                observed_at: view.observed_at(),
                expires_at: view.expires_at(),
                snapshot: snapshot.clone(),
            },
            Err(rss_identity_postgres::DepartmentAccessError::SnapshotExpired) => {
                Departments::Expired
            }
            Err(_) => return Err(Error::Unauthorized),
        },
        Department::Unavailable(reason) => Departments::Unavailable { reason },
        Department::Expired => Departments::Expired,
    };
    Ok(Json(value))
}

pub struct HttpState {
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
}

use crate::{Failure, authorization::context::AuthorizedPrincipal};
use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::time::Duration;
pub async fn protect(
    State(app): State<Arc<AuthenticationState>>,
    request: Request,
    next: Next,
) -> Response {
    authenticate_and_run(app, request, next, true, false).await
}
pub async fn protect_management(
    State(app): State<Arc<AuthenticationState>>,
    request: Request,
    next: Next,
) -> Response {
    authenticate_and_run(app, request, next, true, true).await
}
pub async fn identity_only(
    State(app): State<Arc<AuthenticationState>>,
    request: Request,
    next: Next,
) -> Response {
    authenticate_and_run(app, request, next, false, false).await
}
pub async fn management_identity_only(
    State(app): State<Arc<AuthenticationState>>,
    request: Request,
    next: Next,
) -> Response {
    authenticate_and_run(app, request, next, false, true).await
}
async fn authenticate_inner(
    app: Arc<AuthenticationState>,
    request: Request,
    next: Next,
    authorization: bool,
    management: bool,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let path = parts
        .extensions
        .get::<axum::extract::OriginalUri>()
        .map_or_else(|| parts.uri.path(), |original| original.0.path())
        .to_owned();
    let activity =
        if parts.method == axum::http::Method::GET || parts.method == axum::http::Method::HEAD {
            rss_identity_http_axum::SessionActivity::Passive
        } else {
            rss_identity_http_axum::SessionActivity::Active
        };
    let _global = match app.requests.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return Error::Unavailable(Failure::Capacity).into_response();
        }
    };
    match app
        .identity
        .authenticate_request(
            &parts.headers,
            activity,
            &app.access,
            parts
                .extensions
                .get::<rss_identity_http_axum::ClientAddress>()
                .map(|address| address.0),
            !management
                && authorization
                && !path.starts_with("/api/v1/self-")
                && !path.starts_with("/api/v1/identity-host/")
                && path != "/api/v1/registration-quotas/me",
        )
        .await
    {
        Ok((proof, credential)) => {
            let proof = AuthorizedPrincipal::from_identity(proof);
            if let Some(audit) = parts.extensions.get::<RequestAudit>()
                && let Err(error) = proof.bind_audit(audit)
            {
                return Error::from(error).into_response();
            }
            // Authentication has settled. Authorization I/O and the handler share the host budget.
            let Some(clock) = parts.extensions.get::<Arc<dyn rss_observation::Clock>>() else {
                return Error::Unavailable(Failure::Runtime).into_response();
            };
            let deadline = clock.now() + Duration::from_secs(8);
            parts
                .extensions
                .insert(crate::runtime_diagnostics::RequestDeadline(deadline));
            let content_owned = parts
                .extensions
                .get::<axum::extract::MatchedPath>()
                .is_some_and(|path| {
                    crate::body_policy::content_owned(path.as_str(), &parts.method)
                });
            let authorization = tokio::time::timeout_at(deadline.into(), async {
                app.access
                    .require_tenant_purpose(&proof, management)
                    .await
                    .map_err(Error::from)?;
                let proof = if authorization {
                    proof
                        .load_authorization(&app.access)
                        .await
                        .map_err(Error::from)?
                } else {
                    proof
                };
                Ok::<_, Error>(proof)
            })
            .await;
            let proof = match authorization {
                Ok(Ok(proof)) => proof,
                Ok(Err(error)) => return error.into_response(),
                Err(_) => return Error::Unavailable(Failure::RequestDeadline).into_response(),
            };
            parts
                .extensions
                .insert(crate::http_operation::RequestContinuation::new(credential));
            parts.extensions.insert(RequestAuth {
                proof: Arc::new(proof),
            });
            let request = Request::from_parts(parts, body);
            if content_owned {
                // These exact routes hand off to the content owner's bounded operation.
                next.run(request).await
            } else {
                tokio::time::timeout_at(deadline.into(), next.run(request))
                    .await
                    .unwrap_or_else(|_| {
                        Error::Unavailable(Failure::RequestDeadline).into_response()
                    })
            }
        }
        Err(response) => response,
    }
}
pub struct AuthenticationState {
    pub identity: Arc<crate::identity::Identity>,
    pub access: Arc<rss_mdm_authorization_service::Store>,
    pub requests: Arc<tokio::sync::Semaphore>,
}

use rss_mdm_audit_integration::RequestAudit;

async fn authenticate_and_run(
    app: Arc<AuthenticationState>,
    request: Request,
    next: Next,
    authorization: bool,
    management: bool,
) -> Response {
    let challenge = if request.headers().contains_key("authorization") {
        Some("Bearer")
    } else if request.headers().contains_key("x-api-key") {
        Some("ApiKey")
    } else {
        None
    };
    let mut response = authenticate_inner(app, request, next, authorization, management).await;
    if response.status() == axum::http::StatusCode::UNAUTHORIZED
        && let Some(challenge) = challenge
    {
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static(challenge),
        );
    }
    response
}

struct RulesQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for RulesQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &directory::RULES
    }
}

struct GroupsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for GroupsQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &directory::GROUPS
    }
}

struct MembersQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for MembersQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &directory::MEMBERS
    }
}

#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct Effective {
    instance_id: String,
    tenant_id: String,
    principal_id: String,
    grants: Vec<rss_mdm_authorization_service::EffectiveGrant>,
}
