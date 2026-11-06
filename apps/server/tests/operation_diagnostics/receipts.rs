//! Minimal legal immutable owner rows; no current configuration or audit-index dependency.
use crate::authority_t2_support::Context;
use anyhow::Result;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use serde_json::{Value, json};
use uuid::Uuid;
#[path = "progress.rs"]
mod progress;

pub(super) const ACTOR_OWNERS: &[&str] = &[
    "resource",
    "scope",
    "group",
    "asset",
    "software_publication",
];
pub(super) async fn actor_receipts(
    c: &Context,
    p: &AuthorizedPrincipal,
    id: Uuid,
    instance: Uuid,
) -> Result<()> {
    let rows = [
        (
            "mdm_resource_catalog.operations",
            json!({"resource":"original-resource","request":id.to_string(),"storage_revision":7}),
        ),
        (
            "mdm_scope.operations",
            json!({"id":Uuid::new_v4(),"revision":8}),
        ),
        (
            "mdm_assets.group_operations",
            json!({"task":Uuid::new_v4(),"kind":"group","target":"original-group","status_url":"/original-task"}),
        ),
        (
            "mdm_assets.operations",
            json!({"tenantId":c.tenant.to_string(),"asset":{"kind":"field_layout_written","revision":9}}),
        ),
        (
            "mdm_publication.operations",
            json!({"record":"original-publication","as_of":1700000000}),
        ),
    ];
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    for (table, response) in rows {
        let query = format!(
            "INSERT INTO {table}(tenant_id,id,actor,instance,fingerprint,response) VALUES($1::uuid,$2,$3,$4,$5,$6)"
        );
        sqlx::query(&query)
            .bind(c.tenant.to_string())
            .bind(id)
            .bind(p.principal_id())
            .bind(instance)
            .bind(vec![17_u8; 32])
            .bind(response)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
pub(super) async fn seed(
    c: &Context,
    p: &AuthorizedPrincipal,
    id: Uuid,
) -> Result<Vec<(&'static str, Uuid, String, Value)>> {
    actor_receipts(c, p, id, Uuid::parse_str(p.instance_id())?).await?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_compliance.operations(tenant_id,id,fingerprint,response) VALUES($1::uuid,$2,$3,$4)")
        .bind(c.tenant.to_string()).bind(id).bind(vec![17_u8;32]).bind(json!({"id":Uuid::new_v4(),"revision":10})).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.registration_operations(tenant_id,actor,instance,operation_id,digest,result,action,device,self_enrollment) VALUES($1::uuid,$2,$3,$4,$5,$6,'agent_settings_update',NULL,false)")
        .bind(c.tenant.to_string()).bind(p.principal_id()).bind(p.instance_id()).bind(id).bind("a".repeat(64)).bind(json!({"revision":11}).to_string()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_devices.operations(tenant_id,operation_id,actor,instance,digest,result) VALUES($1::uuid,$2,$3,$4,$5,$6)")
        .bind(c.tenant.to_string()).bind(id).bind(p.principal_id()).bind(p.instance_id()).bind(vec![17_u8;32]).bind(json!({"operationId":id,"devices":["original-device"],"state":"active"})).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_pki.operations(tenant_id,actor,instance,operation,phase,digest,receipt) VALUES($1::uuid,'service:device-pki','',$2,'admit',$3,$4)")
        .bind(c.tenant.to_string()).bind(id).bind(vec![17_u8;32]).bind(b"null".to_vec()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_pki.signing(tenant_id,attempt,purpose,issuer,binding,deadline,digest,state) VALUES($1::uuid,$2,'agent',$3,$4,1700000900,$5,'unknown')")
        .bind(c.tenant.to_string()).bind(id).bind("a".repeat(64)).bind(b"retained opaque signing intent".to_vec()).bind(vec![17_u8;32]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_pki.revocations(tenant_id,attempt,purpose,issuer,serial,state) VALUES($1::uuid,$2,'agent',$3,'1','submitted')")
        .bind(c.tenant.to_string()).bind(id).bind("a".repeat(64)).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_webhook.operations(tenant_id,id,fingerprint,response) VALUES($1::uuid,$2,$3,$4)")
        .bind(c.tenant.to_string()).bind(id).bind(vec![17_u8;32]).bind(json!({"id":Uuid::new_v4(),"revision":12,"enabled":false})).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_certificate_archive.operations(tenant_id,actor,instance,id,action,digest,result,created_at) VALUES($1::uuid,$2,$3::uuid,$4,'settings',$5,$6,1700000000)")
        .bind(c.tenant.to_string()).bind(p.principal_id()).bind(p.instance_id()).bind(id).bind(vec![17_u8;32]).bind(json!({"operationId":id,"action":"settings","entryId":null,"version":null,"revision":13})).execute(&mut *tx).await?;
    let registration = Uuid::new_v4();
    let mut invocations = Vec::new();
    for (owner, table, revision) in [
        ("script_invocation", "mdm_script.receipts", 14),
        (
            "software_invocation",
            "mdm_software_deployment.action_receipts",
            15,
        ),
        (
            "enrollment_invocation",
            "mdm_registration_tasks.receipts",
            16,
        ),
    ] {
        let actor = format!(
            "self-service:{}:{}:{registration}:1",
            p.instance_id(),
            Uuid::new_v4()
        );
        let response = json!({"requestId":id,"runId":Uuid::new_v4(),"policyId":Uuid::new_v4(),"policyRevision":revision,"policyVersion":Uuid::new_v4()});
        let query = format!(
            "INSERT INTO {table}(tenant_id,actor,id,fingerprint,response,device,registration,generation) VALUES($1::uuid,$2,$3,$4,$5,'original-device',$6,1)"
        );
        sqlx::query(&query)
            .bind(c.tenant.to_string())
            .bind(&actor)
            .bind(id)
            .bind(vec![17_u8; 32])
            .bind(response)
            .bind(registration)
            .execute(&mut *tx)
            .await?;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("actor", &actor)
            .append_pair("device", "original-device")
            .append_pair("registration", &registration.to_string())
            .append_pair("generation", "1")
            .finish();
        invocations.push((
            owner,
            format!("?{query}"),
            json!({"accepted":true,"revision":revision}),
        ));
    }
    tx.commit().await?;
    let mut cases = vec![
        ("resource", "".into(), json!({"revision":7})),
        ("scope", "".into(), json!({"revision":8})),
        ("group", "".into(), json!({"accepted":true})),
        ("asset", "".into(), json!({"revision":9})),
        (
            "software_publication",
            "".into(),
            json!({"recordedAt":1700000000}),
        ),
        ("compliance", "".into(), json!({"revision":10})),
        ("registration", "".into(), json!({"revision":11})),
        ("device_management", "".into(), json!({"state":"active"})),
        (
            "pki",
            "?actor=service%3Adevice-pki".into(),
            json!({"stages":[{"phase":"admit","revision":null,"state":null}]}),
        ),
        ("pki_signing", "".into(), json!({"accepted":true})),
        ("pki_revocation", "".into(), json!({"accepted":true})),
        ("webhook", "".into(), json!({"revision":12})),
        ("certificate_archive", "".into(), json!({"revision":13})),
    ];
    cases.extend(invocations);
    let mut cases: Vec<_> = cases
        .into_iter()
        .map(|(owner, query, expected)| (owner, id, query, expected))
        .collect();
    cases.extend(progress::seed(c, p, id).await?);
    Ok(cases)
}
