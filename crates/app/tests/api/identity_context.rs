#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios preserve distinct recovery assertions"
)]
use crate::test_support::*;
pub(crate) async fn host_context_matrix(
    base: &Value,
    reader: Arc<InventoryReader>,
    browser: &Browser,
    subject: &str,
) -> Result<()> {
    let path = format!(
        "/api/identity-host/v1/tenants/{TENANT}/context",
        TENANT = case_tenant()
    );
    for permissions in [
        json!([]),
        json!(["accounts"]),
        json!(["providers"]),
        json!(["accounts", "providers"]),
    ] {
        let mut config = base.clone();
        config["identity_management"] = if permissions.as_array().unwrap().is_empty() {
            json!([])
        } else {
            json!([{"tenant_id":case_tenant(),"instance_id":INSTANCE,"principal_id":subject,"permissions":permissions}])
        };
        let router = app(&config, reader.clone()).await?;
        ensure!(
            Browser::default()
                .call(&router, Method::GET, &path, None)
                .await?
                .0
                == StatusCode::UNAUTHORIZED
        );
        let mut member = browser.clone();
        let before = member
            .call(
                &router,
                Method::GET,
                &format!("/api/v2/tenants/{TENANT}/session", TENANT = case_tenant()),
                None,
            )
            .await?
            .1;
        let (status, context) = member.call(&router, Method::GET, &path, None).await?;
        ensure!(status == StatusCode::OK);
        ensure!(
            context
                == json!({"tenantId":case_tenant(),"principalId":subject,"sessionId":before["session"]["id"],"navigation":{
            "manageAccounts":permissions.as_array().unwrap().contains(&json!("accounts")),
            "manageProviders":permissions.as_array().unwrap().contains(&json!("providers"))}})
        );
        let after = member
            .call(
                &router,
                Method::GET,
                &format!("/api/v2/tenants/{TENANT}/session", TENANT = case_tenant()),
                None,
            )
            .await?
            .1;
        ensure!(before["session"]["idleExpiresAt"] == after["session"]["idleExpiresAt"]);
        let wrong = path.replace(case_tenant(), crate::test_support::case::peer());
        ensure!(
            member.call(&router, Method::GET, &wrong, None).await?.0 == StatusCode::UNAUTHORIZED
        );
    }
    let router = app(base, reader).await?;
    let (_, context) = browser
        .clone()
        .call(&router, Method::GET, &path, None)
        .await?;
    ensure!(context["navigation"] == json!({"manageAccounts":false,"manageProviders":false}));
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=api.identity_context: real capability boundary"]
async fn navigation_uses_current_identity_management_policy() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let reader = authority::reader(&fixture.base).await?;
    let browser = fixture.browser("other")?;
    let router = fixture.router(fixture.authorization())?;
    let subject = browser_subject(&browser, &router).await?;
    host_context_matrix(&fixture.base, reader.clone(), &browser, &subject).await?;
    reader.close().await;
    Ok(())
}
