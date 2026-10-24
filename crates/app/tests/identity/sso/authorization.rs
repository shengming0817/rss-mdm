#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use super::*;
use uuid::Uuid;
const SECURITY_GROUP: &str = "7bb94be2-8f62-4bd6-93e7-7ec1f79b2363";
async fn put(
    admin: &mut Browser,
    router: &Router,
    path: &str,
    revision: u64,
    value: Value,
) -> Result<Value> {
    let (status, result) = admin
        .call(
            router,
            Method::PUT,
            path,
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"value":value})),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "authorization write: {status} {result}"
    );
    Ok(result)
}
async fn grants(browser: &Browser, router: &Router) -> Result<Value> {
    let (status, result) = browser
        .clone()
        .call(router, Method::GET, "/api/v1/authorization", None)
        .await?;
    ensure!(status == StatusCode::OK);
    Ok(result["grants"].clone())
}
fn allows(grants: &Value, operation: &str) -> bool {
    grants
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["operation"] == operation)
}
pub(super) async fn trusted_facts_and_independent_expiry(
    router: &Router,
    admin: &mut Browser,
    alice: &mut Browser,
    bob: &Browser,
    provider: &str,
    version: i64,
    clock: &rss_identity_postgres::ControlledFactTime,
) -> Result<()> {
    let principal = authorization_subject(alice, router).await?;
    let user = json!({"instanceId":INSTANCE,"tenantId":case_tenant(),"principalId":principal});
    let source = json!({"providerId":provider,"issuer":std::env::var("MDM_TEST_SSO_ISSUER")?,"configurationVersion":version});
    let cases = [
        (
            json!({"kind":"user","user":user}),
            "inventory_read",
            json!({"kind":"device","id":"user-device"}),
        ),
        (
            json!({"kind":"idp_group","source":source,"id":SECURITY_GROUP}),
            "credentials",
            json!({"kind":"device","id":"group-device"}),
        ),
        (
            json!({"kind":"department","source":source,"id":"team","matching":"exact"}),
            "enrollment",
            json!({"kind":"device","id":"department-device"}),
        ),
        (
            json!({"kind":"idp_group","source":{"providerId":Uuid::new_v4(),"issuer":source["issuer"],"configurationVersion":version},"id":SECURITY_GROUP}),
            "resource_read",
            json!({"kind":"tenant"}),
        ),
        (
            json!({"kind":"department","source":{"providerId":provider,"issuer":source["issuer"],"configurationVersion":version+1},"id":"team","matching":"exact"}),
            "scope_read",
            json!({"kind":"tenant"}),
        ),
    ];
    let mut paths = Vec::new();
    for (subject, operation, scope) in cases {
        let path = format!("/api/v1/authorization/rules/{}", Uuid::new_v4());
        put(
            admin,
            router,
            &path,
            0,
            json!({"subject":subject,"grants":[{"operation":operation,"scope":scope}]}),
        )
        .await?;
        paths.push(path);
    }
    let initial = grants(alice, router).await?;
    for operation in ["inventory_read", "credentials", "enrollment"] {
        ensure!(
            allows(&initial, operation),
            "missing {operation}: {initial}"
        );
    }
    for operation in ["resource_read", "scope_read"] {
        ensure!(!allows(&initial, operation));
    }
    ensure!(grants(bob, router).await?.as_array().unwrap().is_empty());
    let group_deadline = initial
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["operation"] == "credentials")
        .unwrap()["observation"]["expiresAt"]
        .as_i64()
        .unwrap();
    let department_deadline = initial
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["operation"] == "enrollment")
        .unwrap()["observation"]["expiresAt"]
        .as_i64()
        .unwrap();
    clock.advance_to(group_deadline)?;
    let group_expired = grants(alice, router).await?;
    ensure!(
        !allows(&group_expired, "credentials")
            && allows(&group_expired, "enrollment")
            && allows(&group_expired, "inventory_read")
    );
    clock.advance_to(department_deadline)?;
    let expired = grants(alice, router).await?;
    ensure!(!allows(&expired, "enrollment") && allows(&expired, "inventory_read"));
    for path in paths {
        put(admin, router, &path, 1, Value::Null).await?;
    }
    Ok(())
}
