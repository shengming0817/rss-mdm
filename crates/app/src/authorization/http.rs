use super::*;
use crate::{
    Error,
    api::{App, RequestAuth},
    audit::Audit,
};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    routing::{get, put},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/authorization", get(effective))
        .route("/authorization/rules", get(rules))
        .route("/authorization/rules/{id}", put(rule_write))
        .route("/authorization/user-groups", get(groups))
        .route("/authorization/user-groups/{id}", put(group_write))
        .route("/authorization/user-groups/{id}/members", get(members))
        .route("/authorization/departments", get(departments))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
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
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<Uuid>,
    Json(change): Json<Change<Rule>>,
) -> Result<Json<Receipt>, Error> {
    audit.operation(change.operation_id, "authorization_write");
    audit.target(&id.to_string());
    app.access
        .change_rule(&auth.proof, id, change, &audit)
        .await
        .map(Json)
}
async fn group_write(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<Uuid>,
    Json(change): Json<Change<UserGroup>>,
) -> Result<Json<Receipt>, Error> {
    audit.operation(change.operation_id, "authorization_write");
    audit.target(&id.to_string());
    app.access
        .change_group(&auth.proof, id, change, &audit)
        .await
        .map(Json)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MemberPage {
    offset: Option<usize>,
    expected_revision: Option<u64>,
}
async fn members(
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
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
        .session()
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
