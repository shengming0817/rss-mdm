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
    resources: Resources,
    router: Router,
    admin: Browser,
    member: Browser,
    subject: String,
    store: Arc<crate::Database>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
}
async fn fixture() -> Result<Fixture> {
    let (resources, mut fixture) = Resources::build(|resources| {
        Box::pin(async move {
            let base: Value =
                serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
            let config: Config = serde_json::from_value(base.clone())?;
            let store = database(&base).await?;
            resources.resource(crate::lifecycle::AccessResource(store.clone()));
            let (router, audit_store, application_resources) =
                app_with_access(&base, store.clone()).await?;
            resources.extend(application_resources);
            let mut admin = Browser::default();
            ensure!(admin.login(&router, "admin").await? == StatusCode::OK);
            let mut member = Browser::default();
            ensure!(member.login(&router, "other").await? == StatusCode::OK);
            let subject = browser_subject(&member, &router).await?;
            Ok(Fixture {
                resources: Default::default(),
                base,
                config,
                router,
                admin,
                member,
                subject,
                store,
                audit_store,
            })
        })
    })
    .await?;
    fixture.resources = resources;
    Ok(fixture)
}

mod admission;
mod capacity;
mod initialization;
mod membership;
mod programmatic;
mod rules;
