//! Lifecycle queries preserve complete device targets and reuse Policy query endpoints.
use super::{Queries, records};
use crate::source_authority::{DeviceAssignment, ScopeAdmission};
use crate::{Error, transaction::*};
use rss_mdm_policy::Policy;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::{Value, json};
use uuid::Uuid;

async fn objects_in(
    s: &Queries,
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
    after: Option<&str>,
) -> Result<Vec<DeviceAssignment>> {
    let source = s.source.clone();
    let tenant = tx.tenant_id();
    let after = after.map(str::to_owned);
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(source
                    .lifecycle_objects_on(c, tenant, scope, after.as_deref())
                    .await)
            })
        })
        .await??)
}
fn item(input: &DeviceAssignment, enabled: bool) -> Value {
    let eligible = matches!(input.admission, ScopeAdmission::Eligible { .. });
    json!({"object":input.object.object,"channel":null,"target":null,
        "availability":if enabled&&eligible{"ready"}else{"unavailable"},
        "reason":if !enabled {Some("policy_disabled")}else if !input.object.verified {Some("association_unverified")}else if !eligible{Some("scope_not_eligible")}else{None},
        "qualification":input.admission,"eligibility":input.admission,
        "sources":[input.object],"scopeResult":input.scope_result,"taskAdmission":null,"operationIds":[]})
}
pub async fn assignments_in(
    s: &Queries,
    tx: &mut PgTransaction<'_>,
    p: &Policy,
    after: Option<&str>,
) -> Result<records::AssignmentPage> {
    let objects = objects_in(s, tx, p.definition.scope, after).await?;
    let mut rows = objects
        .iter()
        .map(|o| (o.cursor.clone(), item(o, p.state.is_enabled())))
        .collect::<Vec<_>>();
    let tenant = tx.tenant_id().to_string();
    let policy = p.id;
    let cursor = after.map(str::to_owned);
    let retained: Vec<Value> = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT DISTINCT ON(object) target FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND policy=$2 AND object>coalesce($3,'') COLLATE \"C\" ORDER BY object,created_at DESC LIMIT 65")
            .bind(tenant).bind(policy).bind(cursor).fetch_all(c).await
    })).await?;
    for target in retained {
        let object: crate::source_authority::DeviceObject =
            serde_json::from_value(target).map_err(|_| Error::Malformed)?;
        if !rows
            .iter()
            .any(|(_, v)| v["object"] == json!(object.object))
        {
            rows.push((object.object.key(), json!({"object":object.object,"channel":null,"target":null,"availability":"unavailable","reason":"source_removed","qualification":{"state":"excluded"},"sources":[object],"scopeResult":null,"taskAdmission":null,"operationIds":[]})));
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let more = rows.len() > 64;
    rows.truncate(64);
    let next = if more {
        rows.last().map(|r| r.0.clone())
    } else {
        None
    };
    let mut items = Vec::new();
    for (_, mut value) in rows {
        let tenant = tx.tenant_id();
        let policy = p.id;
        let object: crate::source_authority::ObjectRef =
            serde_json::from_value(value["object"].clone()).map_err(|_| Error::Malformed)?;
        let key = object.key();
        let ids = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(rss_mdm_device_service::lifecycle::policy_operations_in(
                        c, tenant, policy, &key,
                    )
                    .await)
                })
            })
            .await?
            .map_err(Error::from)?;
        value["operationIds"] = checked_input(serde_json::to_value(ids))?;
        items.push(value);
    }
    records::decode(json!({"items":items,"nextCursor":next}))
}

pub async fn preview_in(
    s: &Queries,
    tx: &mut PgTransaction<'_>,
    input: &super::preview::Preview,
) -> Result<records::Preview> {
    let mut objects = objects_in(s, tx, input.definition.scope, input.after.as_deref()).await?;
    let tenant = tx.tenant_id().to_string();
    let scope = input.definition.scope;
    let result:Option<Uuid>=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar("SELECT resolution FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted")
            .bind(tenant).bind(scope).fetch_optional(c).await.map(Option::flatten)
    })).await?;
    let result = result.ok_or(Error::Conflict)?;
    if input.scope_result.is_some_and(|r| r != result) {
        return Err(Error::Conflict.into());
    }
    let more = objects.len() > 64;
    objects.truncate(64);
    let next = if more {
        objects.last().map(|o| o.cursor.clone())
    } else {
        None
    };
    records::decode(
        json!({"action":input.definition.action,"scopeResult":result,"items":objects.iter().map(|i|item(i,true)).collect::<Vec<_>>(),"nextCursor":next}),
    )
}
