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
async fn permissions(subject: &str, device: Option<&str>, write: bool) -> Result<()> {
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
    crate::test_support::identity::change_grants(case_tenant(), subject, grants).await
}

struct Fixture {
    resources: crate::test_support::runtime::Resources,
    authority: authority::Authority,
    automation: crate::planning::test_support::RunningAutomation,
    router: Router,
    browser: Browser,
    subject: String,
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
        let routes = Router::new().nest(
            "/api/v1",
            rss_mdm_management_http::assets::routes()
                .with_state(Arc::new(rss_mdm_management_http::assets::http::HttpState {
                    assets: automation.assets.clone(),
                }))
                .into_axum()
                .merge(
                    rss_mdm_management_http::planning::http::routes()
                        .with_state(Arc::new(
                            rss_mdm_management_http::planning::http::HttpState { planning, groups },
                        ))
                        .into_axum(),
                ),
        );
        let router = authority.router(routes.merge(authority.authorization()))?;
        let browser = authority::Authority::prepared_browser("admin")?;
        let subject = browser_subject(&browser, &router).await?;
        permissions(&subject, None, true).await?;
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
            subject,
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
