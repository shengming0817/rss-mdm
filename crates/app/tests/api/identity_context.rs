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
        "/api/v1/identity-host/tenants/{TENANT}/context",
        TENANT = case_tenant()
    );
    let (router, app_resources) = app(base, reader.clone()).await?;
    app_resources.finish(async {
    let rule_id = uuid::Uuid::new_v4();
    for permissions in [
        json!([]),
        json!(["accounts"]),
        json!(["providers"]),
        json!(["accounts", "providers"]),
    ] {
        let grants: Vec<_> = permissions.as_array().unwrap().iter().map(|permission| json!({
            "operation": if permission == "accounts" { "identity_accounts_manage" } else { "identity_providers_manage" },
            "scope": {"kind":"tenant"}
        })).collect();
        // Change persisted rules under the same running router: no restart/config grant path.
        pg(&format!(
            "DELETE FROM mdm_access.authorization_rules WHERE tenant_id='{}' AND id='{}'",
            case_tenant(),
            rule_id
        ))?;
        if !grants.is_empty() {
            let rule = json!({"subject":{"kind":"user","user":{"tenantId":case_tenant(),"instanceId":INSTANCE,"principalId":subject}},"grants":grants});
            pg(&format!(
                "INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) VALUES('{}','{}','{}',1,'{}'::jsonb)",
                case_tenant(),
                INSTANCE,
                rule_id,
                rule.to_string().replace('\'', "''")
            ))?;
        }
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
                &format!(
                    "/api/v1/identity/tenants/{TENANT}/session",
                    TENANT = case_tenant()
                ),
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
                &format!(
                    "/api/v1/identity/tenants/{TENANT}/session",
                    TENANT = case_tenant()
                ),
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
    pg(&format!(
        "DELETE FROM mdm_access.authorization_rules WHERE tenant_id='{}' AND id='{}'",
        case_tenant(),
        rule_id
    ))?;
    let (_, context) = browser
        .clone()
        .call(&router, Method::GET, &path, None)
        .await?;
    ensure!(context["navigation"] == json!({"manageAccounts":false,"manageProviders":false}));
    Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=api.identity_context: real capability boundary"]
async fn navigation_uses_current_identity_management_policy() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources
        .finish(async {
            let reader = authority::reader(&fixture.base).await?;
            let browser = fixture.browser("other")?;
            let router = fixture.router(fixture.authorization())?;
            let subject = browser_subject(&browser, &router).await?;
            host_context_matrix(&fixture.base, reader.clone(), &browser, &subject).await?;
            reader.close().await;
            Ok(())
        })
        .await
}
