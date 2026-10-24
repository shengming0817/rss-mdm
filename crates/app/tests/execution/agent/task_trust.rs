use crate::test_support::agent_execution::{Fixture, case_credential};
use crate::test_support::{agent::*, process::*, runtime::*, *};
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
        let prepare=json!({"action":"prepare","expectedRevision":1});
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
        let observation_path="/api/v1/agent/runtime/task-trust/observations";
        let query_path=format!("/api/v1/task-signing/trust/devices/{}/observation",registration["deviceId"].as_str().unwrap());
        ensure!(f.author.call(&f.router,Method::GET,&query_path,None).await?==(StatusCode::OK,Value::Null));
        let mut observation=json!({"operation":Uuid::new_v4(),"version":1,"registration":registration["registrationId"],"generation":registration["generation"],"sequence":2,"target_revision":prepared.revision,"target_digest":prepared.installation_digest()?,"actual_revision":prepared.revision,"actual_digest":prepared.installation_digest()?,"state":"applied","reason":null,"observed_at":2});
        let mut invalid=observation.clone();invalid["generation"]=json!(registration["generation"].as_u64().unwrap()+1);
        ensure!(agent_call(&f.router,Method::POST,observation_path,Some(case_credential()),Some(invalid)).await?.0==StatusCode::FORBIDDEN);
        for _ in 0..2 {
            ensure!(agent_call(&f.router,Method::POST,observation_path,Some(case_credential()),Some(observation.clone())).await?==(StatusCode::OK,observation.clone()));
        }
        let (status,latest)=f.author.call(&f.router,Method::GET,&query_path,None).await?;
        ensure!(status==StatusCode::OK && latest["observation"]==observation && latest["received_at"].as_i64().unwrap()>0);
        let denied_grants=f.grants.iter().filter(|g|g.operation!=crate::authorization::Permission::InventoryRead).cloned().collect();
        crate::test_support::identity::change_grants(case_tenant(),&f.author_id,denied_grants).await?;
        ensure!(f.author.call(&f.router,Method::GET,&query_path,None).await?.0==StatusCode::FORBIDDEN);
        crate::test_support::identity::change_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        let mut conflict=observation.clone();conflict["observed_at"]=json!(3);
        ensure!(agent_call(&f.router,Method::POST,observation_path,Some(case_credential()),Some(conflict)).await?.0==StatusCode::CONFLICT);
        observation["operation"]=json!(Uuid::new_v4());observation["sequence"]=json!(1);observation["state"]=json!("failed");observation["reason"]=json!("storage");observation["observed_at"]=json!(999999);
        ensure!(agent_call(&f.router,Method::POST,observation_path,Some(case_credential()),Some(observation)).await?.0==StatusCode::OK);
        ensure!(f.author.call(&f.router,Method::GET,&query_path,None).await?==(StatusCode::OK,latest.clone()));
        ensure!(f.author.call(&f.router,Method::POST,"/api/v1/task-signing/trust",Some(activate.clone())).await?.0==StatusCode::CONFLICT,"applied observation must not satisfy activation");
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
        // Query lifecycle is independent of authenticated intake: retain old rows while changing only the registration fixture.
        let registration_id=registration["registrationId"].as_str().unwrap();
        pg(&format!("UPDATE mdm_access.registrations SET state='revoked' WHERE tenant_id='{}' AND id='{registration_id}'",case_tenant()))?;
        ensure!(f.author.call(&f.router,Method::GET,&query_path,None).await?==(StatusCode::OK,Value::Null));
        pg(&format!("UPDATE mdm_access.registrations SET state='active',generation=generation+1 WHERE tenant_id='{}' AND id='{registration_id}'",case_tenant()))?;
        ensure!(f.author.call(&f.router,Method::GET,&query_path,None).await?==(StatusCode::OK,Value::Null));
        let mut next:rss_mdm_agent_wire::task_trust::Observation=serde_json::from_value(latest["observation"].clone())?;
        next.operation=Uuid::new_v4();next.generation+=1;next.sequence=1;
        use sqlx::Connection;
        let mut c=sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)").bind(case_tenant()).execute(&mut c).await?;
        rss_mdm_execution_service::task_signing::observations::record_in(&mut c,case_tenant(),&next).await?;
        let (status,current)=f.author.call(&f.router,Method::GET,&query_path,None).await?;
        ensure!(status==StatusCode::OK && current["observation"]==serde_json::to_value(next)?);
        c.close().await?;

        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=execution.agent.task_trust: settings directory reads the actual task authority and filters inaccessible owners"]
async fn settings_catalog_projects_authority_without_cross_session_or_secret_exposure() -> Result<()>
{
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let (router, resources) = app(&base).await?;
    let mut author = authority::Authority::prepared_browser("other")?;
    let subject = crate::test_support::http::prepared_subject(&author)?;
    identity::seed_grants(case_tenant(), &subject, vec![]).await?;
    resources
        .finish(async {
            let (status, before) = author
                .call(&router, Method::GET, "/api/v1/settings/catalog", None)
                .await?;
            ensure!(status == StatusCode::OK, "catalog: {status} {before}");
            ensure!(
                !before["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|i| i["id"] == "task-key")
            );
            let grants = vec![crate::authorization::Grant {
                operation: crate::authorization::Permission::RegistrationConfigurationRead,
                scope: crate::authorization::Scope::Tenant,
            }];
            crate::test_support::identity::change_grants(
                case_tenant(),
                &subject,
                grants,
            )
            .await?;
            let (status, after) = author
                .call(&router, Method::GET, "/api/v1/settings/catalog", None)
                .await?;
            ensure!(status == StatusCode::OK, "catalog: {status} {after}");
            let items = after["items"].as_array().unwrap();
            let task = items.iter().find(|i| i["id"] == "task-key").unwrap();
            ensure!(task["revision"] == 1 && task["status"] == "configured");
            ensure!(task["actions"][0]["href"] == "/api/v1/task-signing/trust");
            ensure!(
                !items
                    .iter()
                    .any(|i| i["id"] == "storage" || i["id"] == "s3-key" || i["id"] == "instance")
            );
            let text = serde_json::to_string(&after)?;
            ensure!(
                !text.contains("private_key")
                    && !text.contains("password")
                    && !text.contains("active_file")
            );
            let (status, _) = author
                .call(
                    &router,
                    Method::GET,
                    "/api/v1/tenant-administration/settings/catalog",
                    None,
                )
                .await?;
            ensure!(status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED);
            Ok(())
        })
        .await
}

#[tokio::test]
#[ignore = "MODULE=execution.agent.task_trust: selected persisted material binds tenant, revision and digest"]
async fn selected_material_corruption_is_fatal_even_with_a_matching_active_key() -> Result<()> {
    use rss_mdm_execution_service::task_signing::trust;
    use sqlx::Connection;
    let mut fixture = crate::test_support::authority::Authority::open().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
        let config: crate::config::Config = serde_json::from_value(fixture.base.clone())?;
        let tenant = fixture.identity.tenant;
        let protection = config.native_protector()?;
        let mut connection = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        let mut tx = connection.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(tenant.to_string()).execute(&mut *tx).await?;
        let original = trust::current(&mut tx, tenant).await?;
        trust::prepare(&mut tx, tenant, Uuid::new_v4(), 1, &protection, "fixture").await?;
        trust::check_revision(&mut tx, tenant, 1).await?;
        for mode in 0..3 {
            let mut changed = original.clone();
            if mode == 0 { changed.tenant = Uuid::new_v4(); }
            if mode == 1 { changed.revision = 99; }
            let digest = if mode == 2 { "0".repeat(64) } else { changed.installation_digest()? };
            sqlx::query("UPDATE mdm_task_signing.versions SET body=$2,digest=$3 WHERE tenant_id=$1::uuid AND revision=1")
                .bind(tenant.to_string()).bind(serde_json::to_value(&changed)?).bind(digest).execute(&mut *tx).await?;
            ensure!(matches!(trust::check_revision(&mut tx,tenant,1).await, Err(rss_mdm_execution_service::Error::Unavailable(rss_mdm_execution_service::Failure::CommandInvariant))));
        }
        tx.rollback().await?;
        connection.close().await?;
        Ok(())
    }).await
}
