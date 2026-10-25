#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios preserve distinct recovery assertions"
)]
use crate::test_support::{http::*, process::*, runtime::*, *};
pub(crate) async fn host_context_matrix(
    base: &Value,
    browser: &Browser,
    subject: &str,
) -> Result<()> {
    let path = format!(
        "/api/v1/identity-host/tenants/{TENANT}/context",
        TENANT = case_tenant()
    );
    let mut authority = authority::Authority::from_config(base.clone()).await?;
    let router = authority.router(rss_mdm_management_http::identity_context_routes(Arc::new(
        crate::authorization::identity_management::IdentityManagementPolicy::new(INSTANCE)?,
    )))?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
    let rule_id = uuid::Uuid::new_v4();
    for permissions in [
        json!(["accounts"]),
        json!(["providers"]),
        json!([]),
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
        let (before_status, before) = member
            .call(
                &router,
                Method::GET,
                &format!(
                    "/api/v1/identity/tenants/{TENANT}/session",
                    TENANT = case_tenant()
                ),
                None,
            )
            .await?;
        let (status, context) = member.call(&router, Method::GET, &path, None).await?;
        ensure!(status == StatusCode::OK);
        ensure!(
            context
                == json!({"tenantId":case_tenant(),"principalId":subject,"sessionId":before["session"]["id"],"navigation":{
            "manageAccounts":permissions.as_array().unwrap().contains(&json!("accounts")),
            "manageProviders":permissions.as_array().unwrap().contains(&json!("providers"))}})
        );
        let (after_status, after) = member
            .call(
                &router,
                Method::GET,
                &format!(
                    "/api/v1/identity/tenants/{TENANT}/session",
                    TENANT = case_tenant()
                ),
                None,
            )
            .await?;
        ensure!(before_status == StatusCode::OK && after_status == StatusCode::OK);
        ensure!(before["session"]["idleExpiresAt"].as_u64().is_some_and(|expiry| expiry > 0));
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
            let browser = fixture.browser("other")?;
            let subject = prepared_subject(&browser)?;
            host_context_matrix(&fixture.base, &browser, &subject).await?;
            Ok(())
        })
        .await
}
