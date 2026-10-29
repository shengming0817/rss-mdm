//! Real authenticated Router, formal PostgreSQL schema and the current Group consumer.
mod group_support;
use crate::test_support::http::ok;
use crate::test_support::inventory::seed_source;
use crate::test_support::{http::*, process::*, runtime::*, *};
use group_support::preview;
use uuid::Uuid;
fn request(revision: u64, input: Value) -> Value {
    json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input})
}
fn predicate(field: &str, kind: &str, value: Value) -> Value {
    json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":field,"op":"eq","value":{"kind":kind,"value":value}}})
}
fn rsql_query(condition: Value) -> Value {
    let definition = rss_mdm_inventory_service::assets::Query {
        criteria: Some(serde_json::from_value(condition).unwrap()),
        fields: vec![],
        sort: vec![],
    };
    serde_json::to_value(
        rss_mdm_inventory_service::assets::rsql::QueryInput::from_query(definition).unwrap(),
    )
    .unwrap()
}
fn permissions(device: Option<&str>, write: bool) -> Result<Vec<crate::authorization::Grant>> {
    let mut grants = crate::test_support::identity::device_grants(
        device,
        if write {
            &["inventory_read", "inventory_assign"]
        } else {
            &["inventory_read"]
        },
    )?;
    for operation in [
        crate::authorization::Permission::GroupRead,
        crate::authorization::Permission::GroupWrite,
        crate::authorization::Permission::GroupRecompute,
    ] {
        grants.push(crate::authorization::Grant {
            operation,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    Ok(grants)
}

struct AssetRuntime(Arc<rss_transactional_messaging_postgres::PgRuntime>);
impl rss_runtime::ManagedResource for AssetRuntime {
    fn name(&self) -> &str {
        "asset-test-runtime"
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.0.close().await;
        Ok(())
    }
}
// Only asset routes and the real authentication/audit boundary; no Agent or Planning.
struct AssetHttp {
    assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    resources: Resources,
    router: Router,
    author: Browser,
    author_id: String,
    grants: Vec<crate::authorization::Grant>,
}
impl AssetHttp {
    async fn open() -> Result<Self> {
        let mut authority = authority::Authority::open().await?;
        let tenant = rss_request_context::TenantId::parse(case_tenant())?;
        let runtime = crate::planning::test_support::runtime(tenant).await;
        authority.resources.resource(AssetRuntime(runtime.clone()));
        let inventory = crate::planning::test_support::inventory_runtime(tenant).await;
        authority
            .resources
            .resource(InventoryFixtureResource(inventory.clone()));
        let key = crate::cursor_keys::load(&runtime, tenant).await?;
        let budget =
            rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(5));
        let audit = Arc::new(
            authority
                .audit
                .on_runtime(runtime.clone(), tenant, &budget.control())
                .await?,
        );
        let assets = Arc::new(rss_mdm_inventory_service::assets::AssetService::new(
            inventory,
            audit,
            runtime.clone(),
            tenant,
            Arc::new(crate::clock::SystemClock),
            &key,
            rss_reconcile_postgres::PgMessagingStore::new(
                runtime.clone(),
                tenant,
                rss_mdm_inventory_service::transaction::deadline(),
            )
            .await
            .unwrap(),
        ));
        let routes = rss_mdm_http_contract::Router::new()
            .nest(
                "/api/v1",
                rss_mdm_management_http::assets::routes().with_state(Arc::new(
                    rss_mdm_management_http::assets::http::HttpState {
                        assets: assets.clone(),
                    },
                )),
            )
            .merge(authority.authorization());
        let router = authority.router(routes)?;
        let author = authority.browser("other")?;
        let author_id = prepared_subject(&author)?;
        let grants = crate::test_support::identity::device_grants(
            None,
            &["inventory_read", "inventory_assign"],
        )?;
        crate::test_support::identity::seed_grants(case_tenant(), &author_id, grants.clone())
            .await?;
        Ok(Self {
            assets,
            runtime,
            resources: authority.resources,
            router,
            author,
            author_id,
            grants,
        })
    }
}

struct Fixture {
    resources: crate::test_support::runtime::Resources,
    authority: authority::Authority,
    automation: crate::planning::test_support::RunningAutomation,
    router: Router,
    browser: Browser,
}
impl Fixture {
    async fn open() -> Result<Self> {
        let mut authority = authority::Authority::open().await?;
        let mut resources = std::mem::take(&mut authority.resources);
        let planning = Arc::new(
            crate::planning::test_support::planning(rss_request_context::TenantId::parse(
                case_tenant(),
            )?)
            .await,
        );
        resources.resource(SourceResource(planning.runtime.clone()));
        let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
        let automation =
            crate::planning::test_support::RunningAutomation::start(planning.clone()).await;
        let routes = rss_mdm_http_contract::Router::new().nest(
            "/api/v1",
            rss_mdm_management_http::assets::routes()
                .with_state(Arc::new(rss_mdm_management_http::assets::http::HttpState {
                    assets: automation.assets.clone(),
                }))
                .merge(
                    rss_mdm_management_http::planning::http::routes().with_state(Arc::new(
                        rss_mdm_management_http::planning::http::HttpState {
                            scopes: crate::planning::test_support::scopes(&planning).await,
                            groups,
                        },
                    )),
                ),
        );
        let router = authority.router(routes.merge(authority.authorization()))?;
        let browser = authority::Authority::prepared_browser("admin")?;
        let subject = prepared_subject(&browser)?;
        identity::seed_grants(case_tenant(), &subject, permissions(None, true)?).await?;
        pg(&format!(
            "INSERT INTO mdm_access.devices VALUES('{TENANT}','asset-a'),('{TENANT}','asset-b');",
            TENANT = case_tenant()
        ))?;
        pg_tenant(
            case::peer(),
            &format!(
                "INSERT INTO mdm_access.devices VALUES('{}','{}');",
                case::peer(),
                case::name("foreign-asset")
            ),
        )?;
        Ok(Self {
            resources,
            authority,
            automation,
            router,
            browser,
        })
    }
    async fn close(self) -> Result<()> {
        self.automation.stop().await;
        self.resources.finish(async { Ok(()) }).await?;
        Ok(())
    }
}
mod group_input;
mod http;
mod queries;
mod sources;
