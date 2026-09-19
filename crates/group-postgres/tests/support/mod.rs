use rss_contract::Timepoint;
use rss_mdm_group_postgres::*;
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::OperationDeadline,
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
use std::{sync::Arc, time::Duration};
pub struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)]
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, d: Deadline) {
        tokio::time::sleep_until(d.instant().into()).await;
    }
}
pub fn deadline() -> OperationDeadline {
    OperationDeadline::from_cutoff(
        Deadline::from_timeout(&Timer, Duration::from_secs(10)).unwrap(),
        &Timer,
    )
}
pub fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap()
}
pub fn foreign() -> TenantId {
    TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap()
}
pub fn at() -> Timepoint {
    Timepoint::try_from(10).unwrap()
}
pub fn op() -> OperationId {
    OperationId::parse(&uuid::Uuid::new_v4().to_string()).unwrap()
}
pub fn group_id() -> GroupId {
    GroupId::parse(&uuid::Uuid::new_v4().to_string()).unwrap()
}
pub fn fixture_config() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(std::env::var("GROUP_PG_CONFIG").unwrap()).unwrap())
        .unwrap()
}
pub async fn connect_runtime() -> Arc<PgRuntime> {
    connect_runtime_at(None).await
}
pub async fn connect_runtime_at(port: Option<u16>) -> Arc<PgRuntime> {
    let config = fixture_config();
    let config = PgConfig::new(
        "localhost",
        port.unwrap_or(config["port"].as_u64().unwrap() as u16),
        "group_test",
        "mdm_group_runtime",
        PgPassword::new("group-fixture"),
        PgPrivateCa::from_pem(std::fs::read(config["ca"].as_str().unwrap()).unwrap()).unwrap(),
    );
    Arc::new(
        PgRuntime::connect_producer(
            config,
            Timer,
            ExecutionBinding::new(
                StorageIdentity::new([1; 16], [2; 16]).unwrap(),
                vec![
                    (tenant(), Epoch::new(1).unwrap()),
                    (foreign(), Epoch::new(1).unwrap()),
                ],
            )
            .unwrap(),
        )
        .await
        .unwrap(),
    )
}
pub async fn store(r: Arc<PgRuntime>, t: TenantId) -> GroupStore {
    GroupStore::new(r, t, deadline()).await.unwrap()
}

use rss_mdm_group_postgres::core::*;
use std::collections::{BTreeMap, BTreeSet};
pub fn inputs() -> (Rule, Snapshot) {
    let field = Field {
        key: "model".into(),
        kind: FieldType::Scalar(ScalarType::String),
        unit: None,
        operations: BTreeSet::from([Op::Eq]),
        nullable: true,
    };
    let rule = Rule::new(
        tenant(),
        "rule-1",
        "dictionary-1",
        vec![field],
        Criteria::predicate(Predicate {
            field: "model".into(),
            op: Op::Eq,
            operand: Some(Operand {
                value: Value::Scalar(Scalar::String("laptop".into())),
                unit: None,
            }),
        })
        .unwrap(),
    )
    .unwrap();
    let snapshot = Snapshot {
        tenant: tenant(),
        id: "inventory".into(),
        version: "v1".into(),
        dictionary_version: "dictionary-1".into(),
        complete: true,
        coverage: BTreeSet::from(["model".into()]),
        objects: vec![ObjectSnapshot {
            key: ObjectKey::new(tenant(), "device-1").unwrap(),
            facts: BTreeMap::from([(
                "model".into(),
                Fact {
                    state: FactState::Known(Value::Scalar(Scalar::String("laptop".into()))),
                    source: "fixture".into(),
                    snapshot_id: "capture".into(),
                    observed_at: at(),
                    valid_until: None,
                },
            )]),
        }],
    };
    (rule, snapshot)
}

/// Controlled fixture host; production N12 additionally checks references and writes success audit.
pub async fn execute_companion(
    runtime: &PgRuntime,
    store: &GroupStore,
    operation: OperationId,
    command: &Command,
) -> std::result::Result<Receipt, rss_mdm_group_postgres::Error> {
    use rss_mdm_group_postgres::Error;
    runtime
        .local_tx_with_context(
            store.tenant(),
            deadline(),
            (store, command),
            move |(s, c), tx| {
                Box::pin(async move {
                    tx.prepare_outbox_partitions(&[s.partition(&c.group().to_string())?])
                        .await?;
                    s.execute_in(tx, operation, at(), c).await
                })
            },
        )
        .await
        .fold(
            |v| v.map_err(Error::Rejected),
            |e| Err(Error::NotStarted(e)),
            |e| Err(Error::RolledBack(e)),
            |e| Err(Error::RollbackFailed(e)),
            |source| {
                Err(Error::CommitUnknown {
                    operation: Some(operation),
                    source,
                })
            },
            |e| Err(Error::Fenced(e)),
        )
}
