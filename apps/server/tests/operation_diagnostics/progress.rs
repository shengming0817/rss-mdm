//! Retained original tasks/material results, selected without running their mutation paths.
use super::*;
use sha2::{Digest, Sha256};
pub(super) async fn seed(
    c: &Context,
    p: &AuthorizedPrincipal,
    id: Uuid,
) -> Result<Vec<(&'static str, Uuid, String, Value)>> {
    let endpoint = crate::planning_t2_support::endpoint(c).await?;
    let published = crate::planning_t2_support::published(c, &endpoint).await?;
    let scope_task = crate::planning_t2_support::staged(c, &published, &endpoint).await?;
    let device = &endpoint.members[0].device;
    let registration = endpoint.members[0].registration_id;
    let cut = &published.cut;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("UPDATE mdm_scope.tasks SET completed=true,failure='superseded' WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(scope_task).execute(&mut *tx).await?;
    let group = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_assets.group_tasks(tenant_id,id,target,kind,input,completed,failure) VALUES($1::uuid,$2,$3,'group',$4,true,'superseded')")
        .bind(c.tenant.to_string()).bind(id).bind(group).bind(json!({"kind":"calculation","authority":[],"group":group,"base_revision":1,"asset_cut":cut,"automatic":true})).execute(&mut *tx).await?;
    let rule = Uuid::new_v4();
    let definition: rss_mdm_compliance_service::Definition = serde_json::from_value(
        json!({"presentation":{"name":"retained"},"severity":"low","enabled":true,"platform":"all","target":{"kind":"all"},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"device.os.name","op":"eq","value":{"kind":"string","value":"Windows"}}}}),
    )?;
    let input = rss_mdm_compliance_service::Input {
        rule,
        revision: 1,
        definition: definition.clone(),
        asset_cut: cut.clone(),
        evaluated_at: 1700000000,
        groups: vec![],
    };
    input.validate()?;
    sqlx::query("INSERT INTO mdm_compliance.rules(tenant_id,id,revision,enabled) VALUES($1::uuid,$2,1,true)").bind(c.tenant.to_string()).bind(rule).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_compliance.versions(tenant_id,rule_id,revision,definition) VALUES($1::uuid,$2,1,$3)").bind(c.tenant.to_string()).bind(rule).bind(serde_json::to_value(definition)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_compliance.runs(tenant_id,id,rule_id,rule_revision,input,completed,failure) VALUES($1::uuid,$2,$3,1,$4,true,'superseded')").bind(c.tenant.to_string()).bind(id).bind(rule).bind(serde_json::to_value(input)?).execute(&mut *tx).await?;
    let scope = rss_mdm_inventory_service::assets::ReadScope::from_proof(p)?;
    sqlx::query("INSERT INTO mdm_assets.asset_query_runs(tenant_id,id,input,completed) VALUES($1::uuid,$2,$3,true)").bind(c.tenant.to_string()).bind(id)
        .bind(json!({"query":{},"scope":scope,"asset_cut":cut,"as_of":1700000000})).execute(&mut *tx).await?;
    let policy = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_policy.requests(tenant_id,id,fingerprint,receipt) VALUES($1::uuid,$2,$3,$4)").bind(c.tenant.to_string()).bind(id).bind(vec![17_u8;32])
        .bind(json!({"operationId":id,"policyId":policy,"versionId":Uuid::new_v4(),"deadline":1700000010})).execute(&mut *tx).await?;
    let work = rss_mdm_policy_postgres::work::Work::PolicyReconcile { policy };
    sqlx::query("INSERT INTO mdm_policy.work(tenant_id,id,kind,target,input,completed) VALUES($1::uuid,$2,$3,$4,$5,true)").bind(c.tenant.to_string()).bind(id).bind(work.kind()).bind(work.target()).bind(serde_json::to_value(work)?).execute(&mut *tx).await?;
    let caller = rss_mdm_policy_service::events::Caller::Management { actor: p.actor() };
    sqlx::query("INSERT INTO mdm_policy.event_batches(tenant_id,id,request,actor,caller,device,input,fingerprint,created_at,deadline) VALUES($1::uuid,$2,$2,$3,$4,$5,$6,$7,1700000000,1700000010)")
        .bind(c.tenant.to_string()).bind(id).bind(serde_json::to_string(&caller)?).bind(serde_json::to_value(caller)?).bind(device).bind(json!({"operationId":id,"event":"diagnostic","source":"human","executionContext":null})).bind(vec![17_u8;32]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.event_members(tenant_id,batch,id,policy,revision,version,target,authority,decision) VALUES($1::uuid,$2,$2,$3,1,$4,$5,$6,$7)")
        .bind(c.tenant.to_string()).bind(id).bind(policy).bind(Uuid::new_v4()).bind(json!({"device":device,"registration":registration,"generation":1}))
        .bind(json!({"permissions":[],"retirement_target":null})).bind(json!({"state":"expired"})).execute(&mut *tx).await?;
    let organization = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_apple.organizations(tenant_id,id) VALUES($1::uuid,$2)")
        .bind(c.tenant.to_string())
        .bind(organization)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mdm_apple.ade_operations(tenant_id,organization,id,kind,digest,actor,instance,server_revision,token_revision,request,state,receipt,created_at) VALUES($1::uuid,$2,$3,'configuration',$4,$5,$6,1,0,'{}','succeeded',$7,1700000000)")
        .bind(c.tenant.to_string()).bind(organization).bind(id).bind("a".repeat(64)).bind(p.principal_id()).bind(p.instance_id()).bind(json!({"revision":17})).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_apple_runtime.operations(tenant_id,operation_id,fingerprint_key,fingerprint,receipt) VALUES($1::uuid,$2,'original-key',$3,$4)").bind(c.tenant.to_string()).bind(id).bind(vec![17_u8;32]).bind(json!({"state":"revoked","operationId":id,"revision":18,"materialRevision":1})).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_wns.heads(tenant_id,revision) VALUES($1::uuid,19)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mdm_wns.versions(tenant_id,revision,operation_id,actor,fingerprint_key,fingerprint,pfn,sid_digest,configuration,material,revoked) VALUES($1::uuid,19,$2,$3,'original-key',$4,'original-package',$4,$4,$5,true)").bind(c.tenant.to_string()).bind(id).bind(p.principal_id()).bind(vec![17_u8;32]).bind(b"opaque retired material".to_vec()).execute(&mut *tx).await?;
    let fv = rss_mdm_agent_wire::filevault::Configuration {
        enabled: false,
        revision: 20,
        custody_id: None,
        custody_epoch: 0,
        recipient_id: None,
        recipient_certificate: None,
        material_revision: 0,
    };
    sqlx::query("INSERT INTO mdm_recovery.filevault_receipts(tenant_id,registration,generation,operation,purpose,digest,receipt,devices) VALUES($1::uuid,$2,1,$3,'configure',$4,$5,$6)").bind(c.tenant.to_string()).bind(registration).bind(id).bind(vec![17_u8;32]).bind(serde_json::to_value(fv)?).bind(vec![device.clone()]).execute(&mut *tx).await?;
    let maintenance = rss_mdm_telemetry_service::maintenance::Request {
        id,
        device: device.clone(),
        field: "device.cpu.percent".into(),
        resource: "original-metrics".into(),
        start_micros: 0,
        end_micros: 1,
        action: rss_mdm_telemetry_service::maintenance::Action::Delete {
            restore_until_micros: 10,
        },
    };
    sqlx::query("INSERT INTO mdm_telemetry.maintenance(tenant_id,id,binding,request,result) VALUES($1::uuid,$2,$3,$4,NULL)").bind(c.tenant.to_string()).bind(id).bind(Sha256::digest(serde_json::to_vec(&maintenance)?).to_vec()).bind(serde_json::to_value(maintenance)?).execute(&mut *tx).await?;
    // The request-channel report and its current collection definition have separate lifetimes.
    let epoch: Uuid = sqlx::query_scalar(
        "SELECT epoch FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(registration)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,evidence) VALUES($1::uuid,$2,$3,'mdm.windows',$4,'device',0,1700000000,'{\"fields\":{}}','pending','{}')").bind(c.tenant.to_string()).bind(id).bind(registration).bind(epoch).execute(&mut *tx).await?;
    let enterprise = Uuid::new_v4();
    let enterprise_result = rss_mdm_device_access_postgres::enterprise::Record::RelyingParty(
        rss_mdm_device_access_postgres::enterprise::RelyingParty {
            id: "original-party".into(),
            revision: 21,
            enabled: false,
            callback: "https://example.test/return".into(),
            target_fingerprint: "a".repeat(64),
            capabilities: vec![rss_mdm_device_access_postgres::enterprise::ProofKind::NativeKey],
        },
    );
    let delivery = Uuid::new_v4();
    for (operation, result) in [
        (enterprise, serde_json::to_string(&enterprise_result)?),
        (delivery, "22".into()),
    ] {
        sqlx::query("INSERT INTO rss_da.operations(tenant_id,instance,actor,operation_id,digest,result) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6)").bind(c.tenant.to_string()).bind(p.instance_id()).bind(p.principal_id()).bind(operation).bind("a".repeat(64)).bind(result).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let q = format!("?device={device}");
    Ok(vec![
        (
            "collection",
            id,
            format!("{q}&registration={registration}&generation=1"),
            json!({"state":"pending"}),
        ),
        (
            "enterprise_configuration",
            enterprise,
            "".into(),
            json!({"revision":21}),
        ),
        (
            "agent_delivery",
            delivery,
            "".into(),
            json!({"revision":22}),
        ),
        (
            "scope_task",
            scope_task,
            "".into(),
            json!({"state":"superseded"}),
        ),
        ("group_task", id, "".into(), json!({"state":"superseded"})),
        (
            "compliance_task",
            id,
            "".into(),
            json!({"state":"superseded"}),
        ),
        ("asset_query", id, "".into(), json!({"state":"completed"})),
        ("policy", id, "".into(), json!({"accepted":true})),
        ("policy_work", id, "".into(), json!({"state":"completed"})),
        (
            "policy_event",
            id,
            q.clone(),
            json!({"recordedAt":1700000000}),
        ),
        (
            "policy_event_member",
            id,
            q.clone(),
            json!({"state":"expired"}),
        ),
        ("apple_ade", id, "".into(), json!({"revision":17})),
        (
            "apple_runtime_material",
            id,
            "".into(),
            json!({"revision":18}),
        ),
        ("windows_wns", id, "".into(), json!({"revision":19})),
        (
            "filevault",
            id,
            format!("{q}&registration={registration}&generation=1"),
            json!({"revision":20,"enabled":false}),
        ),
        ("telemetry", id, "".into(), json!({"state":"accepted"})),
    ])
}
