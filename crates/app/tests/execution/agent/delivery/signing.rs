//! A valid native collection still cannot produce an unsigned offer.
use super::*;
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_resource as r;

#[tokio::test]
#[ignore = "MODULE=execution.agent.delivery: unsigned claim rolls back real collection admission"]
async fn collection_claim_requires_signer_and_recovers_without_republication() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        f.grants.extend(crate::test_support::identity::device_grants(None,&["inventory_collect"])?);
        f.grants.push(crate::authorization::Grant { operation:crate::authorization::Permission::InventorySensitiveRead,scope:crate::authorization::Scope::Tenant });
        crate::test_support::identity::set_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        let context=crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs);
        let registration=seed_profile(&f.base,f.execution.clone(),case_credential(),case_device_id(),json!({"capabilities":["inventory.collect.v1","inventory.native.v1"],"platform":"macos","architecture":"aarch64","executionContext":context})).await?;
        let device=registration["deviceId"].as_str().unwrap();
        f.scope(case_task_scope(),json!([{"kind":"device","id":device}])).await?;
        let (id,engines)=collection(&mut f).await?;
        let policy=Uuid::new_v4();
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":case_task_scope(),"action":{"kind":"agent_collection","resource":{"id":id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"runLifetimeSeconds":300}}}})).await?;
        let input:w::TaskClaimRequest=serde_json::from_value(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"profiles":[],"environment":{"edition":null,"tools":{},"nativeEngines":engines},"executionContext":context}))?;
        let mut authority=crate::test_support::authority::Authority::open().await?;
        let authority_resources=std::mem::take(&mut authority.resources);
        authority_resources.finish(async {
            let agent=crate::test_support::agent::service(&authority).await?;
            let principal=agent.authenticate(&evidence(case_credential()).unwrap()).await?;
            let mut config:Config=serde_json::from_value(f.base.clone())?;
            config.task_signing=None;
            let (unsigned_resources,unsigned)=Resources::build(|resources|Box::pin(async {
                let unsigned=crate::execution_assembly::open(
                    &config,config.native_protector()?,authority.audit.clone(),f.content.clone(),
                    std::collections::BTreeMap::new(),rss_device_command_postgres::CommandClock::Postgres,
                    Arc::new(crate::authorization::session::SessionAuthority::new(authority.identity.authority.clone(),authority.identity.tenant)),
                ).await?;
                resources.resource(rss_mdm_execution_service::Resource(unsigned.service.clone()));
                Ok(unsigned)
            })).await?;
            unsigned_resources.finish(async {
                ensure!(unsigned.service.loaded_task_signing_key().is_none());
                let before=effects()?;
                let audit=rss_mdm_audit_integration::RequestAudit::new(case_tenant().into(),"agent_task_claim");
                let rejected=unsigned.service.claim_action(&principal,&input,&audit).await;
                ensure!(matches!(rejected,Err(rss_mdm_execution_service::Error::Unsupported)),"claim did not reach missing signer: {rejected:?}");
                ensure!(effects()?==before,"unsigned claim persisted execution or collection effects");
                Ok(())
            }).await?;
            // The same policy and operation must now reach a real, correctly signed offer.
            let audit=rss_mdm_audit_integration::RequestAudit::new(case_tenant().into(),"agent_task_claim");
            let response=f.execution.claim_action(&principal,&input,&audit).await?;
            let task:w::SignedTask=serde_json::from_value(response["task"].clone())?;
            let w::TaskPayload::Collection(spec)=&task.payload else { anyhow::bail!("wrong task family") };
            crate::test_support::task_signature::verify(&task,&crate::test_support::task_signature::TaskVerification {
                key_id:"t2",public_key:f.key.public_key().as_ref(),tenant_id:Uuid::parse_str(case_tenant())?,device_id:device,
                platform:w::TaskPlatform::Macos,architecture:w::TaskArchitecture::Aarch64,
                registration_id:serde_json::from_value(registration["registrationId"].clone())?,generation:registration["generation"].as_u64().unwrap(),
                task_id:spec.task_id,attempt_id:spec.attempt_id,permit:w::TaskPermit::Offer,now:crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?,
            })?;
            ensure!(pg(&format!("SELECT revision FROM mdm_policy.policies WHERE tenant_id='{}' AND id='{policy}'",case_tenant()))?.trim()=="1");
            Ok(())
        }).await
    }).await
}

fn effects() -> Result<String> {
    pg(&format!(
        "SELECT jsonb_build_array((SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{t}'),(SELECT count(*) FROM mdm_commands.action_attempts WHERE tenant_id='{t}'),(SELECT count(*) FROM mdm_commands.action_receipts WHERE tenant_id='{t}'),(SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{t}'))",
        t = case_tenant()
    ))
}

async fn collection(f: &mut Fixture) -> Result<(Uuid, w::NativeEngines)> {
    let r::blueprints::Definition::AgentCollection {
        template: definition,
    } = r::blueprints::get("macos.agent.memory", "1")
        .unwrap()
        .definition
    else {
        anyhow::bail!("expected collection blueprint")
    };
    let engines = definition.spec().plan.requirements();
    let id = Uuid::new_v4();
    let bytes = definition.canonical();
    let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    resource(
        &mut f.author,
        &f.router,
        id,
        0,
        json!({"action":"create","kind":"agent_collection"}),
    )
    .await?;
    resource(&mut f.author,&f.router,id,1,json!({"action":"version","version":"v1","kind":"agent_collection","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"agent_collection","artifact":{"reference":"native.json","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
    ensure!(
        upload_for(&f.author, &f.router, id, &bytes, "macos", "aarch64").await?
            == StatusCode::CREATED
    );
    resource(
        &mut f.author,
        &f.router,
        id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    Ok((id, engines))
}
