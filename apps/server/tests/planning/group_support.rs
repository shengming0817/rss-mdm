//! Real Group actor and worker preparation; no OwnerFixture dispatcher executes Group tasks.
use super::*;

pub(crate) async fn group_proof(
    m: &OwnerFixture,
) -> crate::authorization::context::AuthorizedPrincipal {
    use crate::authorization::{Grant, Permission, Rule, Scope, Subject};
    let config = crate::test_support::identity::config(&m.tenant.to_string()).unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(config.access_options().unwrap())
        .await
        .unwrap();
    let actor = crate::test_support::case::admin();
    let mut grants = vec![Grant {
        operation: Permission::InventoryRead,
        scope: Scope::AllDevices,
    }];
    for operation in [
        Permission::ScopeRead,
        Permission::GroupRead,
        Permission::GroupWrite,
        Permission::GroupRecompute,
    ] {
        grants.push(Grant {
            operation,
            scope: Scope::Tenant,
        });
    }
    let rule = Rule {
        subject: Subject::User {
            user: crate::test_support::identity::user(&m.tenant.to_string(), actor),
        },
        grants,
    };
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(m.tenant.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,md5('group-use-cases:'||$1||':'||$3)::uuid,1,$4) ON CONFLICT DO NOTHING")
        .bind(m.tenant.to_string()).bind(crate::test_support::INSTANCE).bind(actor).bind(serde_json::to_value(rule).unwrap()).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let access = crate::authorization::Store::from_pool(
        pool.clone(),
        Arc::new(crate::lifecycle::RuntimeTimer),
    );
    let (identity, resources) = crate::test_support::identity::identity(&m.tenant.to_string())
        .await
        .unwrap();
    let proof = crate::authorization::context::AuthorizedPrincipal::new(
        identity
            .authority
            .inspect_session(
                m.tenant,
                crate::test_support::identity::credential_for(&m.tenant.to_string(), "admin")
                    .unwrap(),
                crate::identity::deadline(),
            )
            .await
            .unwrap(),
    )
    .unwrap()
    .load_authorization(&access)
    .await
    .unwrap();
    pool.close().await;
    resources.finish(async { Ok(proof) }).await.unwrap()
}

pub(crate) struct GroupWorker {
    pub worker: rss_mdm_inventory_service::groups::runtime::GroupWork,
    store: rss_reconcile_postgres::PgStore,
}
impl std::ops::Deref for GroupWorker {
    type Target = rss_mdm_inventory_service::groups::runtime::GroupWork;
    fn deref(&self) -> &Self::Target {
        &self.worker
    }
}
impl GroupWorker {
    pub(crate) fn as_ref(&self) -> &rss_mdm_inventory_service::groups::runtime::GroupWork {
        &self.worker
    }
    pub(crate) async fn open(service: &OwnerFixture) -> Self {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options())
            .await
            .unwrap();
        let timer = automation::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let store = rss_reconcile_postgres::PgStore::new(pool, &control)
            .await
            .unwrap();
        Self {
            worker: rss_mdm_inventory_service::groups::runtime::GroupWork::new(
                Arc::new(groups(service).await),
                store.clone(),
            ),
            store,
        }
    }
    pub(crate) async fn close(&self) {
        let timer = automation::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        assert!(matches!(
            self.store.close(&control).await,
            rss_reconcile_postgres::CloseOutcome::Drained
        ));
    }
}
pub(crate) async fn claim_group(
    worker: &rss_mdm_inventory_service::groups::runtime::GroupWork,
    task: Uuid,
    lease: Duration,
) -> rss_reconcile_postgres::PgClaim {
    use rss_reconcile::DurableStore;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    let claims = worker
        .claim_due(
            &rss_reconcile::Scope::new(tenant(), "mdm.groups").unwrap(),
            64,
            lease,
            &control,
        )
        .await
        .unwrap()
        .claims;
    let mut selected = None;
    for claim in claims {
        if claim.target().entity() == format!("task:{task}") {
            selected = Some(claim);
        } else {
            worker.release(&claim, &control).await.unwrap();
        }
    }
    selected.expect("Group task must be claimable")
}
pub(crate) async fn finish_group_claim(
    worker: &rss_mdm_inventory_service::groups::runtime::GroupWork,
    claim: &rss_reconcile_postgres::PgClaim,
) {
    use rss_reconcile::{DurableStore, Reconciler};
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(60), &cancel);
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let diff = crate::test_support::runtime::reconcile_ready(
                worker.observe(claim, &control).await.unwrap(),
            );
            if diff.drift() == rss_reconcile::DriftKind::Converged {
                break;
            }
            if let Err(error) = worker.apply(claim, diff, &control).await {
                assert_eq!(error.kind(), rss_reconcile::ErrorKind::Transient);
                tokio::task::yield_now().await;
            }
        }
        worker
            .finish(claim, rss_reconcile::Completion::Converged, &control)
            .await
            .unwrap();
    })
    .await
    .unwrap();
}

pub(crate) async fn scope_group_components(
    service: &OwnerFixture,
    schedule: rss_reconcile_postgres::PgStore,
) -> (
    Arc<rss_mdm_inventory_service::groups::runtime::GroupWork>,
    Arc<rss_mdm_scope_service::runtime::ScopeWork>,
    Arc<crate::scope_group_changes::Delivery>,
) {
    let config = crate::test_support::identity::config(&service.tenant.to_string()).unwrap();
    let delivery = crate::scope_group_changes::Delivery::open(
        &config,
        config.native_protector().unwrap(),
        Arc::default(),
    )
    .await
    .unwrap();
    (
        Arc::new(rss_mdm_inventory_service::groups::runtime::GroupWork::new(
            Arc::new(groups(service).await),
            schedule.clone(),
        )),
        Arc::new(rss_mdm_scope_service::runtime::ScopeWork::new(
            scopes(service).await,
            schedule,
        )),
        delivery,
    )
}
