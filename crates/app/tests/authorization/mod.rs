//! Real Router and PostgreSQL rules, membership, CAS, receipts and one-time initialization.
use crate::test_support::{http::*, process::*, runtime::*, *};
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
    resources: Resources,
    router: Router,
    admin: Browser,
    store: Arc<crate::Database>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
}
async fn fixture() -> Result<Fixture> {
    let (resources, mut fixture) = Resources::build(|resources| {
        Box::pin(async move {
            let base: Value =
                serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
            let store = database(&base).await?;
            resources.resource(crate::lifecycle::AccessResource(store.clone()));
            let (router, audit_store, application_resources) =
                app_with_access(&base, store.clone()).await?;
            resources.extend(application_resources);
            let admin = crate::test_support::authority::Authority::prepared_browser("admin")?;
            Ok(Fixture {
                resources: Default::default(),
                router,
                admin,
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
