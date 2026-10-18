use crate::test_support::agent_execution::{Fixture, case_credential};
use crate::test_support::*;
use rss_mdm_agent_wire::task_trust::{Acknowledgement, KeyState, Trust};

#[tokio::test]
#[ignore = "MODULE=execution.agent.task_trust: prepared trust requires an authenticated durable ACK before activation"]
async fn rotation_requires_exact_generation_ack_and_keeps_original_operation() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        for operation in [crate::authorization::Permission::RegistrationConfigurationRead,crate::authorization::Permission::RegistrationConfigurationWrite] {
            f.grants.push(crate::authorization::Grant {operation,scope:crate::authorization::Scope::Tenant});
        }
        let registration=f.register().await?;
        let prepared_operation=Uuid::new_v4();
        f.author.operation=Some(prepared_operation);
        let prepare=json!({"action":"prepare","expectedRevision":1,"origin":"https://mdm.example.test:9445"});
        let (status,body)=f.author.call(&f.router,Method::POST,"/api/v1/task-signing/trust",Some(prepare.clone())).await?;
        ensure!(status==StatusCode::OK,"prepare: {status} {body}");
        let prepared:Trust=serde_json::from_value(body.clone())?;
        prepared.validate()?;
        ensure!(prepared.revision==2);
        let key=prepared.keys.iter().find(|k|k.state==KeyState::Prepared).unwrap().id.clone();
        ensure!(f.author.call(&f.router,Method::POST,"/api/v1/task-signing/trust",Some(prepare)).await?==(StatusCode::OK,body.clone()));
        let activation_operation=Uuid::new_v4();
        f.author.operation=Some(activation_operation);
        let activate=json!({"action":"activate","expectedRevision":2,"keyId":key});
        ensure!(f.author.call(&f.router,Method::POST,"/api/v1/task-signing/trust",Some(activate.clone())).await?.0==StatusCode::CONFLICT);
        let (status,distribution)=agent_call(&f.router,Method::GET,"/api/v1/agent/runtime/task-trust",Some(case_credential()),None).await?;
        ensure!(status==StatusCode::OK && distribution==body);
        let mut ack=Acknowledgement {operation:Uuid::new_v4(),version:1,registration:Uuid::parse_str(registration["registrationId"].as_str().unwrap())?,generation:registration["generation"].as_u64().unwrap(),revision:prepared.revision,digest:prepared.installation_digest()?};
        ack.generation+=1;
        ensure!(agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/task-trust",Some(case_credential()),Some(serde_json::to_value(&ack)?)).await?.0==StatusCode::FORBIDDEN);
        ack.generation-=1;
        let payload=serde_json::to_value(&ack)?;
        ensure!(agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/task-trust",Some(case_credential()),Some(payload.clone())).await?==(StatusCode::OK,payload.clone()));
        ensure!(agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/task-trust",Some(case_credential()),Some(payload.clone())).await?==(StatusCode::OK,payload));
        let (status,activated)=f.author.call(&f.router,Method::POST,"/api/v1/task-signing/trust",Some(activate.clone())).await?;
        ensure!(status==StatusCode::OK,"activate: {status} {activated}");
        let current:Trust=serde_json::from_value(activated.clone())?;
        ensure!(current.revision==3 && current.keys.iter().any(|k|k.id==key && k.state==KeyState::Active) && current.keys.iter().any(|k|k.id=="t2" && k.state==KeyState::VerifyOnly));
        ensure!(f.author.call(&f.router,Method::POST,"/api/v1/task-signing/trust",Some(activate)).await?==(StatusCode::OK,activated));
        ensure!(f.author.call(&f.router,Method::GET,&format!("/api/v1/task-signing/operations/{prepared_operation}"),None).await?==(StatusCode::OK,body));
        let config=identity::config(case_tenant())?;
        ensure!(crate::task_signing::open(&crate::task_signing::Config {revision:1},&config.access_database,rss_request_context::TenantId::parse(case_tenant())?,config.native_protector()?.as_ref()).await.is_err());
        let protection=config.native_protector()?;
        let loaded=crate::task_signing::open(&crate::task_signing::Config {revision:3},&config.access_database,rss_request_context::TenantId::parse(case_tenant())?,&protection).await?;
        ensure!(loaded.task.key_id()==key);
        Ok(())
    }).await
}
