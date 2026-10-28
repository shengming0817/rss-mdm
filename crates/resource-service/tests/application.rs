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

struct Authority {
    store: rss_mdm_authorization_service::Store,
    pool: sqlx::PgPool,
    secret: rss_mdm_authorization_service::credential::ApiKeySecret,
}
impl Authority {
    async fn new() -> Self {
        use sha2::{Digest, Sha256};
        let instance =
            pg::sql("SELECT instance_id::text FROM public.mdm_installation WHERE singleton");
        let id = uuid::Uuid::new_v4();
        let secret = rss_mdm_authorization_service::credential::ApiKeySecret::parse(format!(
            "{id}.{}",
            "42".repeat(32)
        ))
        .unwrap();
        let mut digest = Sha256::new();
        digest.update(b"rss-mdm/api-key/v1\0");
        digest.update(instance.as_bytes());
        digest.update([0]);
        digest.update(pg::tenant().to_string().as_bytes());
        digest.update([0]);
        digest.update(secret.expose().as_bytes());
        let hex = format!("{:x}", digest.finalize());
        let metadata = serde_json::json!({"name":id.to_string(),"enabled":true,"expiresAt":null,"grants":[{"operation":"resource_read","scope":{"kind":"tenant"}},{"operation":"resource_write","scope":{"kind":"tenant"}}]});
        let creator = serde_json::json!({"tenantId":pg::tenant().to_string(),"instanceId":instance,"principalId":uuid::Uuid::new_v4().to_string()});
        pg::sql(&format!(
            "INSERT INTO mdm_access.api_keys(tenant_id,instance,id,revision,authority_revision,credential_revision,metadata,secret_digest,created_by,created_at) VALUES('{tenant}','{instance}','{id}',1,1,1,'{metadata}',decode('{hex}','hex'),'{creator}',100)",
            tenant = pg::tenant()
        ));
        let c = pg::config();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                sqlx::postgres::PgConnectOptions::new()
                    .host("localhost")
                    .port(c["port"].as_u64().unwrap() as u16)
                    .database(c["database"].as_str().unwrap())
                    .username("mdm_access")
                    .password("access-fixture")
                    .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
                    .ssl_root_cert(c["ca"].as_str().unwrap()),
            )
            .await
            .unwrap();
        let store =
            rss_mdm_authorization_service::Store::from_pool(pool.clone(), Arc::new(pg::Timer));
        Self {
            store,
            pool,
            secret,
        }
    }
    async fn proof(&self) -> rss_mdm_authorization_service::context::AuthorizedPrincipal {
        let principal = self
            .store
            .authenticate_key(&pg::tenant().to_string(), &self.secret)
            .await
            .unwrap();
        rss_mdm_authorization_service::context::AuthorizedPrincipal::from_identity(principal)
            .load_authorization(&self.store)
            .await
            .unwrap()
    }
    fn audit(&self) -> RequestAudit {
        RequestAudit::new(
            pg::tenant().to_string(),
            "management_write",
            AuditIntent::Management,
        )
    }
    fn facts(&self, command: &s::Command) -> String {
        let s::Command::Resource { id, change } = command else {
            unreachable!()
        };
        pg::sql(&format!(
            "SELECT coalesce((SELECT revision FROM mdm_resource.aggregates WHERE tenant_id='{tenant}' AND id='{id}'),0)::text||':'||(SELECT count(*) FROM mdm_resource_catalog.operations WHERE tenant_id='{tenant}' AND id='{op}')::text||':'||(SELECT count(*) FROM rss_audit.records WHERE tenant_id='{tenant}' AND event_id='e-'||encode(sha256(convert_to('resource_catalog:api-key:{key}:{op}','UTF8')),'hex'))::text",
            tenant = pg::tenant(),
            op = change.operation_id,
            key = self.secret.id()
        ))
    }
}
async fn run(
    service: &s::ResourceCatalog,
    command: &s::Command,
    authority: &Authority,
) -> std::result::Result<serde_json::Value, s::Error> {
    let proof = authority.proof().await;
    let audit = authority.audit();
    let result = service.execute(command, &audit, &proof).await;
    audit.finalize(None);
    result
}
#[tokio::test]
#[ignore = "MODULE=resource.application: real PG same-operation concurrency and complete application receipt"]
async fn concurrent_receipt_replay_is_atomic_and_survives_reconstruction() {
    let runtime = pg::runtime_at(None, "mdm_flow_runtime").await;
    let (audit_store, pool) = pg::audit_store_for(runtime.clone(), "mdm_flow_runtime").await;
    let svc = service(runtime.clone(), audit_store.clone()).await;
    let authority = Authority::new().await;
    let command = request();
    let (first, second) = tokio::join!(
        run(&svc, &command, &authority),
        run(&svc, &command, &authority)
    );
    let first = first.unwrap();
    assert_eq!(first, second.unwrap());
    assert_eq!(authority.facts(&command), "1:1:1");
    let reopened = service(runtime.clone(), audit_store).await;
    assert_eq!(first, run(&reopened, &command, &authority).await.unwrap());
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
        run(&reopened, &changed, &authority).await,
        Err(s::Error::Conflict)
    ));
    let stale = authority.proof().await;
    pg::sql(&format!(
        "UPDATE mdm_access.api_keys SET revoked=true,authority_revision=authority_revision+1 WHERE tenant_id='{}' AND id='{}'",
        pg::tenant(),
        authority.secret.id()
    ));
    let revoked = authority.audit();
    assert!(matches!(
        reopened.execute(&command, &revoked, &stale).await,
        Err(s::Error::Unauthorized) | Err(s::Error::Forbidden)
    ));
    revoked.finalize(None);
    assert_eq!(authority.facts(&command), "1:1:1");
    authority.pool.close().await;
    pool.close().await;
    runtime.close().await;
}
#[tokio::test]
#[ignore = "MODULE=resource.application: Resource owner settlement preserves unknown and rollback outcomes"]
async fn resource_settlement_recovers_exact_receipt_without_duplicate_audit() {
    let runtime = pg::runtime_at(None, "mdm_flow_runtime").await;
    let (audit_store, pool) = pg::audit_store_for(runtime.clone(), "mdm_flow_runtime").await;
    let svc = service(runtime.clone(), audit_store).await;
    let authority = Authority::new().await;
    for unknown in [true, false] {
        let command = request();
        let proof = authority.proof().await;
        // Invalid audit action fails after Resource mutation and application receipt insertion.
        let a = if unknown {
            authority.audit()
        } else {
            RequestAudit::new(pg::tenant().to_string(), "", AuditIntent::Management)
        };
        runtime.inject_next_transaction_fault(if unknown {
            PgTransactionFault::CommitUnknownAfterAck
        } else {
            PgTransactionFault::RollbackFailedAfterAck
        });
        let first = svc.execute(&command, &a, &proof).await;
        assert!(
            matches!(
                (&first, unknown),
                (Err(s::Error::CommitUnknown), true) | (Err(s::Error::RollbackFailed), false)
            ),
            "{first:?}"
        );
        a.finalize(None);
        assert_eq!(
            authority.facts(&command),
            if unknown { "1:1:1" } else { "0:0:0" }
        );
        let value = run(&svc, &command, &authority).await.unwrap();
        assert_eq!(value, run(&svc, &command, &authority).await.unwrap());
        assert_eq!(authority.facts(&command), "1:1:1");
    }
    authority.pool.close().await;
    pool.close().await;
    runtime.close().await;
}
