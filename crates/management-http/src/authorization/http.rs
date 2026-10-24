use super::*;
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, put},
};
use serde::Deserialize;
use serde_json::{Value, json};
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
            put(group_write).owned(
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
                &[RouteOperation::List],
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
            put(rule_write).owned(
                &contracts::AUTHORIZATION_RULES,
                &[
                    RouteOperation::Create,
                    RouteOperation::Update,
                    RouteOperation::Delete,
                ],
            ),
        )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    after: Option<Uuid>,
}
fn page<T: serde::Serialize>(items: &[Revision<T>], after: Option<Uuid>) -> Value {
    let selected = items
        .iter()
        .filter(|r| after.is_none_or(|after| r.id > after))
        .take(101)
        .collect::<Vec<_>>();
    let next = (selected.len() > 100).then(|| selected[99].id);
    json!({"items":selected.into_iter().take(100).collect::<Vec<_>>(),"nextCursor":next})
}
async fn effective(Extension(auth): Extension<RequestAuth>) -> Result<Json<Value>, Error> {
    let proof = &auth.proof;
    Ok(Json(
        json!({"instanceId":proof.instance_id(),"tenantId":proof.tenant_id(),"principalId":proof.principal_id(),"grants":proof.authorization()?.effective(proof)?}),
    ))
}
async fn rules(
    Extension(auth): Extension<RequestAuth>,
    Query(page_request): Query<Page>,
) -> Result<Json<Value>, Error> {
    auth.proof.require(Permission::AuthorizationRead, None)?;
    Ok(Json(page(
        &auth.proof.authorization()?.rules,
        page_request.after,
    )))
}
async fn groups(
    Extension(auth): Extension<RequestAuth>,
    Query(page_request): Query<Page>,
) -> Result<Json<Value>, Error> {
    auth.proof.require(Permission::UserGroupRead, None)?;
    // Memberships have a separately bounded, revision-bearing projection.
    let groups =
        auth.proof
            .authorization()?
            .groups
            .iter()
            .map(|r| Revision {
                id: r.id,
                revision: r.revision,
                value: r.value.as_ref().map(
                    |g| json!({"name":g.name,"enabled":g.enabled,"memberCount":g.members.len()}),
                ),
            })
            .collect::<Vec<_>>();
    Ok(Json(page(&groups, page_request.after)))
}
async fn rule_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Change<Rule>>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Receipt>, Error> {
    let Json(change) = body.map_err(Error::from)?;
    audit.operation(change.operation_id, "authorization_write");
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
    audit.operation(change.operation_id, "authorization_write");
    audit.target(&id.to_string());
    crate::authorization::store::change_group(&app.audit_store, &auth.proof, id, change, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MemberPage {
    offset: Option<usize>,
    expected_revision: Option<u64>,
}
async fn members(
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(page): Query<MemberPage>,
) -> Result<Json<Value>, Error> {
    audit.target(&id.to_string());
    auth.proof.require(Permission::UserGroupRead, None)?;
    let record = auth
        .proof
        .authorization()?
        .groups
        .iter()
        .find(|r| r.id == id)
        .ok_or(Error::NotFound)?;
    let group = record.value.as_ref().ok_or(Error::NotFound)?;
    let offset = page.offset.unwrap_or(0);
    if offset > 10000 {
        return Err(Error::Malformed);
    }
    if page.expected_revision.is_some_and(|v| v != record.revision)
        || (offset > 0 && page.expected_revision.is_none())
    {
        return Err(Error::Conflict);
    }
    let items = group
        .members
        .iter()
        .skip(offset)
        .take(100)
        .collect::<Vec<_>>();
    Ok(Json(
        json!({"id":id,"revision":record.revision,"items":items,"nextOffset":(offset + 100 < group.members.len()).then_some(offset + 100)}),
    ))
}
async fn departments(Extension(auth): Extension<RequestAuth>) -> Result<Json<Value>, Error> {
    use rss_identity_postgres::VerifiedDepartmentSnapshot as Department;
    auth.proof.require(Permission::DepartmentRead, None)?;
    let value = match auth
        .proof
        .session()?
        .department_snapshot()
        .map_err(|_| Error::Unauthorized)?
    {
        Department::Available(view) => match view.snapshot() {
            Ok(snapshot) => {
                json!({"status":"available","source":{"providerId":view.provider_id(),"issuer":view.issuer(),"configurationVersion":view.provider_config_version()},"snapshotId":view.snapshot_id(),"observedAt":view.observed_at(),"expiresAt":view.expires_at(),"snapshot":snapshot})
            }
            Err(rss_identity_postgres::DepartmentAccessError::SnapshotExpired) => {
                json!({"status":"expired"})
            }
            Err(_) => return Err(Error::Unauthorized),
        },
        Department::Unavailable(reason) => json!({"status":"unavailable","reason":reason}),
        Department::Expired => json!({"status":"expired"}),
    };
    Ok(Json(value))
}

pub struct HttpState {
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
