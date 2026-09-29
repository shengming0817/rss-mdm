//! Real Router and PostgreSQL rules, membership, CAS, receipts and one-time initialization.
use crate::test_support::*;
use uuid::Uuid;

async fn put(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    operation: Uuid,
    revision: u64,
    value: Value,
) -> Result<(StatusCode, Value)> {
    browser
        .call(
            router,
            Method::PUT,
            path,
            Some(json!({"operationId":operation,"expectedRevision":revision,"value":value})),
        )
        .await
}
fn user(subject: &str) -> Value {
    json!({"kind":"user","user":{"instanceId":INSTANCE,"tenantId":case_tenant(),"principalId":subject}})
}
fn grant(operation: &str, scope: Value) -> Value {
    json!({"operation":operation,"scope":scope})
}

struct Fixture {
    base: Value,
    config: Config,
    reader: Arc<InventoryReader>,
    router: Router,
    admin: Browser,
    member: Browser,
    subject: String,
    store: Arc<crate::Database>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
}
async fn fixture() -> Result<Fixture> {
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let config: Config = serde_json::from_value(base.clone())?;
    let reader = Arc::new(
        InventoryReader::connect(
            config
                .access_database
                .options()?
                .username("mdm_api")
                .password("api-fixture"),
        )
        .await?,
    );
    let router = app(&base, reader.clone()).await?;
    let mut admin = Browser::default();
    identity::age_prepared_admin_session()?;
    ensure!(admin.login_password(&router, "admin", PASSWORD).await? == StatusCode::OK);
    let mut member = Browser::default();
    ensure!(
        admin
            .call(
                &router,
                Method::POST,
                &format!("/api/v2/tenants/{TENANT}/accounts", TENANT = case_tenant()),
                Some(json!({"login":crate::test_support::case::name("authorization-member"),"password":PASSWORD}))
            )
            .await?
            .0
            == StatusCode::CREATED
    );
    ensure!(
        member
            .login(
                &router,
                crate::test_support::case::name("authorization-member")
            )
            .await?
            == StatusCode::OK
    );
    let subject = browser_subject(&member, &router).await?;
    let store = database(&base).await?;
    let audit_store = store
        .audit_store(&crate::config::AuditConfig::Plain)
        .await?;
    Ok(Fixture {
        base,
        config,
        reader,
        router,
        admin,
        member,
        subject,
        store,
        audit_store,
    })
}
mod admission;
mod capacity;
mod initialization;
mod membership;
mod rules;
