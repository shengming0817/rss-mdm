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

mod admission;
mod capacity;
mod initialization;
mod membership;
mod programmatic;
mod rules;
