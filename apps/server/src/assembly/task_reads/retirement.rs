//! Lifecycle queries preserve complete device targets and reuse Policy query endpoints.
use super::*;
use rss_mdm_management_http::execution::task_reads as records;
type Result<T> = std::result::Result<T, Error>;
use rss_mdm_policy::Policy;
use rss_mdm_scope_service::channels::{DeviceAssignment, ScopeAdmission};
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

async fn objects_on(
    s: &Reads,
    c: &mut PgConnection,
    scope: Uuid,
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<DeviceAssignment>> {
    s.source
        .lifecycle_objects_on(c, s.tenant, scope, after, limit)
        .await
        .map_err(source)
}

fn item(input: &DeviceAssignment, enabled: bool) -> Value {
    let eligible = matches!(input.admission, ScopeAdmission::Eligible { .. });
    json!({"object":input.object.object,"channel":null,"target":null,
        "availability":if enabled&&eligible{"ready"}else{"unavailable"},
        "reason":if !enabled {Some("policy_disabled")}else if !input.object.verified {Some("association_unverified")}else if !eligible{Some("scope_not_eligible")}else{None},
        "qualification":input.admission,"eligibility":input.admission,
        "sources":[input.object],"scopeResult":input.scope_result,"taskAdmission":null,"execution":{"kind":"operations","operationIds":[]}})
}
pub async fn assignments_on(
    s: &Reads,
    c: &mut PgConnection,
    p: &Policy,
    after: Option<&str>,
    limit: usize,
    codec: &rss_mdm_query::cursor::CursorCodec,
    binding: &str,
) -> Result<records::AssignmentPage> {
    let objects = objects_on(s, c, p.definition.scope, after, limit).await?;
    let mut rows = objects
        .iter()
        .map(|o| (o.cursor.clone(), item(o, p.state.is_enabled())))
        .collect::<Vec<_>>();
    let retained =
        rss_mdm_device_service::lifecycle::retained_targets_on(c, s.tenant, p.id, after, limit)
            .await?;
    for target in retained {
        let object: rss_mdm_scope_service::channels::DeviceObject =
            serde_json::from_value(target).map_err(|_| Error::Malformed)?;
        if !rows
            .iter()
            .any(|(_, v)| v["object"] == json!(object.object))
        {
            rows.push((object.object.key(), json!({"object":object.object,"channel":null,"target":null,"availability":"unavailable","reason":"source_removed","qualification":{"state":"excluded"},"sources":[object],"scopeResult":null,"taskAdmission":null,"execution":{"kind":"operations","operationIds":[]}})));
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next = if more {
        rows.last().map(|r| r.0.clone())
    } else {
        None
    };
    let mut items = Vec::new();
    for (_, mut value) in rows {
        let tenant = s.tenant;
        let policy = p.id;
        let object: rss_mdm_scope_service::channels::ObjectRef =
            serde_json::from_value(value["object"].clone()).map_err(|_| Error::Malformed)?;
        let key = object.key();
        let ids = rss_mdm_device_service::lifecycle::policy_operations_in(c, tenant, policy, &key)
            .await
            .map_err(Error::from)?;
        value["execution"]["operationIds"] =
            serde_json::to_value(ids).map_err(|_| Error::Malformed)?;
        items.push(value);
    }
    decode(
        json!({"items":items,"nextCursor":rss_mdm_scope_service::window::next(codec,binding,next).map_err(window)?}),
    )
}

pub async fn preview_on(
    s: &Reads,
    c: &mut PgConnection,
    input: &rss_mdm_policy::pages::Preview,
    after: Option<&str>,
    limit: usize,
    codec: &rss_mdm_query::cursor::CursorCodec,
    binding: &str,
) -> Result<records::Preview> {
    let mut objects = objects_on(s, c, input.definition.scope, after, limit).await?;
    let tenant = s.tenant.to_string();
    let scope = input.definition.scope;
    let result:Option<Uuid>=sqlx::query_scalar("SELECT resolution FROM mdm_scope.scopes WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted")
            .bind(tenant).bind(scope).fetch_optional(&mut *c).await.map(Option::flatten).map_err(sql)?;
    let result = result.ok_or(Error::Conflict)?;
    if input.scope_result.is_some_and(|r| r != result) {
        return Err(Error::Conflict);
    }
    let more = objects.len() > limit;
    objects.truncate(limit);
    let next = if more {
        objects.last().map(|o| o.cursor.clone())
    } else {
        None
    };
    decode(
        json!({"action":input.definition.action,"scopeResult":result,"items":objects.iter().map(|i|item(i,true)).collect::<Vec<_>>(),"nextCursor":rss_mdm_scope_service::window::next(codec,binding,next).map_err(window)?}),
    )
}

fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| Error::Unavailable(Failure::CommandInvariant))
}
