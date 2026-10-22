use crate::test_support::{http::*, runtime::*, *};
#[tokio::test]
#[ignore = "MODULE=settings.recent_auth: seven consumers reject old authentication on a newly issued live session"]
async fn sensitive_operations_use_authentication_time() -> Result<()> {
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
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
        ensure!(catalog.1["items"].as_array().unwrap().iter().any(|e|ids.contains(&e["id"].as_str().unwrap_or_default()) && e["actions"].as_array().is_some_and(|a|a.iter().any(|a|a["name"]=="configure"))));
        identity::age_prepared_admin_session()?;
        let after=browser.call(&router,Method::GET,&session_path,None).await?;
        ensure!(after.0==StatusCode::OK && after.1["session"]["issuedAt"]==before.1["session"]["issuedAt"]);
        let cases=[
            ("/api/v1/apple/materials/apns/keys",json!({"expectedRevision":0,"source":{"kind":"generate"}}),StatusCode::UNAUTHORIZED),
            ("/api/v1/windows/wns",json!({"expectedRevision":0,"packageFamilyName":"fixture","sid":"fixture","clientSecret":"fixture"}),StatusCode::UNAUTHORIZED),
            ("/api/v1/storage/connections",json!({"expectedRevision":0,"profile":"fixture","source":{"kind":"generate"}}),StatusCode::FORBIDDEN),
            ("/api/v1/smtp",json!({"expectedRevision":0,"profile":"fixture","sender":"a@example.test","recipient":"b@example.test","username":"fixture","password":"fixture"}),StatusCode::FORBIDDEN),
            ("/api/v1/task-signing/trust",json!({"action":"prepare","expectedRevision":0,"origin":"generated"}),StatusCode::UNAUTHORIZED),
            ("/api/v1/webhooks/materials",json!({"reference":"fixture","expectedRevision":0,"configurationSha256":"00".repeat(32),"endpoint":"https://example.test/hook","networkReference":"fixture","source":{"kind":"generate"}}),StatusCode::FORBIDDEN),
        ];
        for (path,input,status) in cases {
            browser.operation=Some(uuid::Uuid::new_v4());
            let response=browser.call(&router,Method::POST,path,Some(input)).await?;
            ensure!(response.0==status,"recent authentication at {path}: {}",response.0);
        }
        let catalog=browser.call(&router,Method::GET,"/api/v1/settings/catalog",None).await?;
        ensure!(catalog.0==StatusCode::OK);
        for entry in catalog.1["items"].as_array().unwrap() {
            if ids.contains(&entry["id"].as_str().unwrap_or_default()) {
                ensure!(!entry["actions"].as_array().unwrap().iter().any(|a|a["name"]=="configure"));
            }
        }
        Ok(())
    }).await
}
