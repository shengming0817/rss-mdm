//! Agent owns the authenticated claim/signature/attempt seam; no Policy publication journey.
use crate::{
    authority_t2_support::Context, command_runtime_t2_support as command,
    device_material_support as material,
};
use anyhow::Result;
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;
async fn accepted(c: &Context, registration: Uuid, device: &str) -> Result<Uuid> {
    use sha2::{Digest, Sha256};
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let retirement = Uuid::new_v4();
    let run = Uuid::new_v4();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let actor = rss_mdm_authorization_service::Actor::Account {
        user: c.user(Uuid::new_v4()),
    };
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":Uuid::new_v4(),"action":{"kind":"unmanage_device","runLifetimeSeconds":300,"schedule":{"trigger":{"kind":"manual"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null}}}),
    )?;
    definition.validate()?;
    let rss_mdm_policy::Action::UnmanageDevice { schedule, .. } = &definition.action else {
        unreachable!()
    };
    let frozen = serde_json::to_value(rss_mdm_execution_service::frozen::Frozen::UnmanageDevice {
        schedule: schedule.clone(),
        run_lifetime_seconds: 300,
        actor: actor.clone(),
    })?;
    let fingerprint = Sha256::digest(serde_json::to_vec(&frozen)?).to_vec();
    let target = json!({"object":{"kind":"endpoint","id":device},"associationVersion":null,"verified":true,"members":[{"device":device,"channel":"agent","registrationId":registration,"generation":2}]});
    let object = rss_mdm_inventory_service::objects::ObjectRef::Endpoint(device.into()).key();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'enabled',$4,$5,$6)").bind(c.tenant.to_string()).bind(policy).bind(version).bind(serde_json::to_value(definition)?).bind(serde_json::to_value(&actor)?).bind(now).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,'unmanage_device',$4,$5)").bind(c.tenant.to_string()).bind(version).bind(policy).bind(frozen).bind(fingerprint).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_devices.retirements(tenant_id,id,policy,version,object,occurrence,target,authority,delivery_seconds,created_at,origin) VALUES($1::uuid,$2,$3,$4,$5,'once',$6,$7,300,$8,'\"policy\"')").bind(c.tenant.to_string()).bind(retirement).bind(policy).bind(version).bind(object).bind(target).bind(serde_json::to_value(actor)?).bind(now).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_devices.retirement_channels(tenant_id,operation,device,channel,registration,generation,stage,effect,execution) VALUES($1::uuid,$2,$3,'agent',$4,2,'unenroll','pending',$5)").bind(c.tenant.to_string()).bind(retirement).bind(device).bind(registration).bind(run).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_devices.retirement_work(tenant_id,operation,registration,execution) VALUES($1::uuid,$2,$3,$4)").bind(c.tenant.to_string()).bind(retirement).bind(registration).bind(run).execute(&mut *tx).await?;
    sqlx::query("UPDATE mdm_access.devices SET retirement=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(device)
        .bind(retirement)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,origin,source_objects,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,dispatch_fingerprint,gateway_accepted) VALUES($1::uuid,$2,'\"policy\"','[]',$3,$4,$5,2,'once',$6,$6,$7,$8,$9,true)").bind(c.tenant.to_string()).bind(run).bind(version).bind(device).bind(registration).bind(now).bind(now+300).bind(serde_json::to_value(rss_mdm_task_state::RunState::new(now+300,now)?)?).bind(vec![0u8;32]).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(run)
}
#[tokio::test]
#[ignore = "T2: authenticated claim through real business participant, durable attempt and signature"]
async fn claim_offer_matches_only_the_current_registration_task() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let protection = material::protection(&c)?;
    let trust = material::seed_trust(
        &c,
        &protection,
        &[rss_mdm_agent_wire::task_trust::KeyState::Active],
    )
    .await?;
    let (registration, grant, device) = material::seed_registration(&c).await?;
    let capabilities = vec![
        w::Capability::InventoryCollectionV1,
        w::Capability::DeviceUnmanageV1,
    ];
    let p = material::authenticated_agent(&c, registration, grant, &device, capabilities.clone())
        .await?;
    material::seed_ack(&c, &trust, registration, 2).await?;
    let context = w::SoftwareExecutionContext {
        revision: 1,
        msix_sideload: false,
        msix_unsigned: false,
        os_version: [10, 0, 26100, 0],
        system_broker: true,
        user_helper: false,
        interactive_user: None,
        source_credentials: vec![],
    };
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture,execution_context) VALUES($1::uuid,$2,1,$3,'windows','x86_64',$4)").bind(c.tenant.to_string()).bind(registration).bind(serde_json::to_string(&capabilities)?).bind(serde_json::to_value(&context)?).execute(&mut *tx).await?;
    tx.commit().await?;
    let target = accepted(&c, registration, &device).await?;
    let (other, _, other_device) = material::seed_registration(&c).await?;
    let sentinel = accepted(&c, other, &other_device).await?;
    let state = |id| {
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(c.tenant.to_string())
        .bind(id)
        .fetch_one(&c.operator)
    };
    let untouched = state(sentinel).await?;
    let a = command::open(&c, true).await?;
    let audit = Arc::new(
        c.audit
            .on_runtime(
                a.runtime.clone(),
                c.tenant,
                &rss_mdm_audit_integration::budget::AuditBudget::new(
                    std::time::Duration::from_secs(5),
                )
                .control(),
            )
            .await?,
    );
    let delivery = rss_mdm_agent_channel::delivery::Delivery {
        runtime: a.runtime.clone(),
        tenant: c.tenant,
        audit,
        signing: a.signing.clone(),
        tasks: Arc::new(crate::assembly::agent_tasks::AgentTasks {
            software: a.software.service.clone(),
            registration: a.registration.enrollment.clone(),
            content: a.content.clone(),
            requests: a.self_service.clone(),
            execution: a.service.clone(),
            scripts: a.scripts.clone(),
            collections: a.collections.clone(),
        }),
        content: None,
    };
    let input = w::TaskClaimRequest::new(Uuid::new_v4(), vec![], context)?;
    let request =
        || RequestAudit::new(c.tenant.to_string(), "agent_claim", AuditIntent::Management);
    let response = delivery.claim(&p, &input, &request()).await?;
    let signed = response.task().expect("accepted target must be offered");
    assert_eq!(signed.payload.task_id(), target);
    let stored:serde_json::Value=sqlx::query_scalar("SELECT offer FROM mdm_agent.task_attempts WHERE tenant_id=$1::uuid AND id=$2 AND run=$3 AND registration=$4").bind(c.tenant.to_string()).bind(signed.payload.attempt_id()).bind(target).bind(registration).fetch_one(&c.operator).await?;
    assert_eq!(stored, serde_json::to_value(signed)?);
    let deadline: i64 = sqlx::query_scalar(
        "SELECT deadline FROM mdm_agent.task_attempts WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(signed.payload.attempt_id())
    .fetch_one(&c.operator)
    .await?;
    let expected: i64 = sqlx::query_scalar(
        "SELECT deadline FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(target)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(deadline, expected);

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let key = trust.keys.iter().find(|k| k.id == signed.key_id).unwrap();
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        URL_SAFE_NO_PAD.decode(&key.public_key)?,
    )
    .verify(
        &signed.payload.signing_bytes(&signed.key_id)?,
        &URL_SAFE_NO_PAD.decode(&signed.signature)?,
    )
    .map_err(|_| anyhow::anyhow!("Offer signature invalid"))?;
    assert_eq!(state(sentinel).await?, untouched);
    assert_ne!(state(target).await?["delivery"]["kind"], "queued");
    let replay = delivery.claim(&p, &input, &request()).await?;
    assert_eq!(
        serde_json::to_value(response)?,
        serde_json::to_value(replay)?
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_agent.task_attempts WHERE tenant_id=$1::uuid AND run=ANY($2)",
    )
    .bind(c.tenant.to_string())
    .bind(vec![target, sentinel])
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(count, 1);
    drop(delivery);
    command::close(a).await?;
    c.close().await;
    Ok(())
}
