use crate::test_support::{http::*, runtime::*, *};
#[tokio::test]
#[ignore = "MODULE=settings.recent_auth: six consumers reject old authentication on a newly issued live session"]
async fn sensitive_operations_use_authentication_time() -> Result<()> {
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    identity::seed_grants(case_tenant(), case_admin(), [
        crate::authorization::Permission::RegistrationConfigurationRead,
        crate::authorization::Permission::RegistrationConfigurationWrite,
        crate::authorization::Permission::StorageConfigurationRead,
        crate::authorization::Permission::StorageConfigurationWrite,
        crate::authorization::Permission::WebhookRead,
        crate::authorization::Permission::WebhookWrite,
    ].into_iter().map(|operation| crate::authorization::Grant { operation, scope: crate::authorization::Scope::Tenant }).collect()).await?;
    let (router, resources) = app(&base).await?;
    resources.finish(async {
        let mut browser=Browser::default();
        ensure!(browser.login_password(&router,"admin",identity::PASSWORD).await?==StatusCode::OK);
        let session_path=format!("/api/v1/identity/tenants/{}/session",case_tenant());
        let before=browser.call(&router,Method::GET,&session_path,None).await?;
        ensure!(before.0==StatusCode::OK);
        let catalog=browser.call(&router,Method::GET,"/api/v1/settings/catalog",None).await?;
        ensure!(catalog.0==StatusCode::OK);
        let ids=["apns-key","wns","storage","smtp","task-key","webhook-own"];
        for id in ids {
            let entry = catalog.1["items"].as_array().unwrap().iter().find(|e| e["id"] == id).expect("required settings entry");
            ensure!(entry["actions"].as_array().unwrap().iter().any(|a| a["name"] == "configure"), "fresh configure action missing: {id}");
        }
        identity::age_prepared_admin_session()?;
        let after=browser.call(&router,Method::GET,&session_path,None).await?;
        ensure!(after.0==StatusCode::OK && after.1["session"]["issuedAt"]==before.1["session"]["issuedAt"]);
        let cases=[
            ("/api/v1/apple/materials/apns/keys",json!({"expectedRevision":1000000,"source":{"kind":"generate"}}),StatusCode::UNAUTHORIZED),
            ("/api/v1/windows/wns",json!({"expectedRevision":1000000,"packageFamilyName":"fixture","sid":"fixture","clientSecret":"fixture"}),StatusCode::UNAUTHORIZED),
            ("/api/v1/storage/connections",json!({"expectedRevision":1000000,"profile":"fixture","source":{"kind":"generate"}}),StatusCode::FORBIDDEN),
            ("/api/v1/smtp",json!({"expectedRevision":1000000,"profile":"fixture","sender":"a@example.test","recipient":"b@example.test","username":"fixture","password":"fixture"}),StatusCode::FORBIDDEN),
            ("/api/v1/task-signing/trust",json!({"action":"prepare","expectedRevision":1000000}),StatusCode::UNAUTHORIZED),
            ("/api/v1/webhooks/materials",json!({"reference":"fixture","expectedRevision":1000000,"configurationSha256":"00".repeat(32),"endpoint":"https://example.test/hook","networkReference":"fixture","source":{"kind":"generate"}}),StatusCode::FORBIDDEN),
        ];
        for (path,input,status) in &cases {
            browser.operation=Some(uuid::Uuid::new_v4());
            let response=browser.call(&router,Method::POST,path,Some(input.clone())).await?;
            ensure!(response.0==*status,"recent authentication at {path}: {}",response.0);
        }
        let catalog=browser.call(&router,Method::GET,"/api/v1/settings/catalog",None).await?;
        ensure!(catalog.0==StatusCode::OK);
        for id in ids {
            let entry = catalog.1["items"].as_array().unwrap().iter().find(|e| e["id"] == id).expect("required settings entry");
            ensure!(!entry["actions"].as_array().unwrap().iter().any(|a|a["name"]=="configure"), "old authentication offered configuration: {id}");
        }
        // Restore only authentication time; the same session, permissions and request reach CAS.
        crate::test_support::process::pg(&format!(
            "UPDATE identity_authority.sessions SET local_authenticated_at=local_authenticated_at+301 WHERE tenant_id='{}' AND principal_id='{}'",
            case_tenant(), case_admin(),
        ))?;
        for (path,input,_) in cases {
            browser.operation=Some(uuid::Uuid::new_v4());
            let response=browser.call(&router,Method::POST,path,Some(input)).await?;
            ensure!(response.0==StatusCode::CONFLICT, "fresh authentication must reach owner revision/configuration conflict at {path}: {response:?}");
        }
        Ok(())
    }).await
}
