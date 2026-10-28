//! Real Resource application settlement; unrelated declarations are deliberately unsupported.
#[allow(dead_code)]
#[path = "../../../tests/support/software/pg.rs"]
mod pg;
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_resource_service::{self as s, inputs::*, transaction::Fault};
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction, PgTransactionFault};
use std::sync::Arc;
struct Clock;
impl s::clock::Clock for Clock {
    fn unix_seconds(&self) -> Option<i64> {
        Some(100)
    }
}
struct CreateDependencies;
impl CollectionValidator for CreateDependencies {
    fn fence_in<'a>(&'a self, tx: &'a mut PgTransaction<'_>) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_inventory_service::collection::resource_authoring::fence_in(tx)
                .await
                .map_err(|e| match e {
                    rss_mdm_inventory_service::transaction::Fault::Storage(e) => Fault::Storage(e),
                    rss_mdm_inventory_service::transaction::Fault::Sql(e) => Fault::Sql(e),
                    _ => s::Error::Unavailable(s::Failure::ResourceStorage).into(),
                })
        })
    }
    fn validate_in<'a>(
        &'a self,
        _: &'a mut PgTransaction<'_>,
        _: &'a rss_mdm_resource::Version,
    ) -> Pending<'a, ()> {
        panic!("creation must not validate an absent version")
    }
}
impl TelemetryProfileValidator for CreateDependencies {
    fn validate_in<'a>(
        &'a self,
        _: &'a mut PgTransaction<'_>,
        _: &'a rss_mdm_resource::Version,
        _: &'a rss_mdm_resource::TelemetryProfile,
    ) -> Pending<'a, ()> {
        panic!("creation must not validate an absent profile")
    }
}
impl SoftwareAuthoringValidator for CreateDependencies {
    fn validate_in<'a>(
        &'a self,
        _: &'a mut PgTransaction<'_>,
        _: &'a rss_mdm_resource::Version,
    ) -> Pending<'a, ()> {
        panic!("creation must not validate absent software")
    }
}
impl UsageReader for CreateDependencies {
    type Error = Fault;
    fn count_in<'a>(
        &'a self,
        _: &'a mut PgTransaction<'_>,
        _: &'a str,
        _: &'a str,
    ) -> Pending<'a, u64> {
        panic!("creation must not query archive references")
    }
}
async fn service(
    runtime: Arc<PgRuntime>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
) -> s::ResourceCatalog {
    s::ResourceCatalog::new(s::Dependencies {
        runtime,
        audit_store: audit,
        tenant: pg::tenant(),
        clock: Arc::new(Clock),
        cursor_key: vec![42; 32],
        references: Arc::new(CreateDependencies),
        collections: Arc::new(CreateDependencies),
        telemetry: Arc::new(CreateDependencies),
        software: Arc::new(CreateDependencies),
    })
    .await
    .unwrap()
}
fn request() -> s::Command {
    s::Command::Resource {
        id: uuid::Uuid::new_v4().to_string(),
        change: s::Operation {
            operation_id: uuid::Uuid::new_v4(),
            expected_revision: 0,
            input: s::Change::Create {
                kind: s::Kind::Script,
            },
        },
    }
}
fn audit() -> RequestAudit {
    let a = RequestAudit::new(
        pg::tenant().to_string(),
        "management_write",
        AuditIntent::Management,
    );
    a.set_principal("operator", "00000000-0000-0000-0000-000000000001");
    a
}
async fn run(
    service: &s::ResourceCatalog,
    command: &s::Command,
) -> std::result::Result<serde_json::Value, s::Error> {
    let a = audit();
    let result = service.execute(command, &a, &|| Ok(())).await;
    a.finalize(None);
    result
}
fn facts(command: &s::Command) -> String {
    let s::Command::Resource { id, change } = command else {
        unreachable!()
    };
    pg::sql(&format!(
        "SELECT (SELECT revision FROM mdm_resource.aggregates WHERE tenant_id='{tenant}' AND id='{id}')::text||':'||(SELECT count(*) FROM mdm_resource_catalog.operations WHERE tenant_id='{tenant}' AND id='{op}')::text||':'||(SELECT count(*) FROM rss_audit.records WHERE tenant_id='{tenant}' AND event_id='resource_catalog:operator:{op}')::text",
        tenant = pg::tenant(),
        op = change.operation_id
    ))
}
#[tokio::test]
#[ignore = "MODULE=resource.application: real PG same-operation concurrency and complete application receipt"]
async fn concurrent_receipt_replay_is_atomic_and_survives_reconstruction() {
    let runtime = pg::runtime_at(None, "mdm_flow_runtime").await;
    let (audit_store, pool) = pg::audit_store_for(runtime.clone(), "mdm_flow_runtime").await;
    let svc = service(runtime.clone(), audit_store.clone()).await;
    let command = request();
    let (first, second) = tokio::join!(run(&svc, &command), run(&svc, &command));
    let first = first.unwrap();
    assert_eq!(first, second.unwrap());
    assert_eq!(facts(&command), "1:1:1");
    let reopened = service(runtime.clone(), audit_store).await;
    assert_eq!(first, run(&reopened, &command).await.unwrap());
    let s::Command::Resource { id, change } = &command else {
        unreachable!()
    };
    let changed = s::Command::Resource {
        id: id.clone(),
        change: s::Operation {
            operation_id: change.operation_id,
            expected_revision: 1,
            input: s::Change::Create {
                kind: s::Kind::Configuration,
            },
        },
    };
    assert!(matches!(
        run(&reopened, &changed).await,
        Err(s::Error::Conflict)
    ));
    let revoked = audit();
    assert!(matches!(
        reopened
            .execute(&command, &revoked, &|| Err(s::Error::Forbidden))
            .await,
        Err(s::Error::Forbidden)
    ));
    revoked.finalize(None);
    assert_eq!(facts(&command), "1:1:1");
    pool.close().await;
    runtime.close().await;
}
#[tokio::test]
#[ignore = "MODULE=resource.application: Resource owner settlement preserves unknown and rollback outcomes"]
async fn resource_settlement_recovers_exact_receipt_without_duplicate_audit() {
    let runtime = pg::runtime_at(None, "mdm_flow_runtime").await;
    let (audit_store, pool) = pg::audit_store_for(runtime.clone(), "mdm_flow_runtime").await;
    let svc = service(runtime.clone(), audit_store).await;
    for unknown in [true, false] {
        let command = request();
        let a = audit();
        runtime.inject_next_transaction_fault(if unknown {
            PgTransactionFault::CommitUnknownAfterAck
        } else {
            PgTransactionFault::RollbackFailedAfterAck
        });
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let first = svc
            .execute(&command, &a, &|| {
                if !unknown && calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                    Err(s::Error::Forbidden)
                } else {
                    Ok(())
                }
            })
            .await;
        assert!(
            matches!(
                (&first, unknown),
                (Err(s::Error::CommitUnknown), true) | (Err(s::Error::RollbackFailed), false)
            ),
            "{first:?}"
        );
        a.finalize(None);
        let value = run(&svc, &command).await.unwrap();
        assert_eq!(value, run(&svc, &command).await.unwrap());
        assert_eq!(facts(&command), "1:1:1");
    }
    pool.close().await;
    runtime.close().await;
}
