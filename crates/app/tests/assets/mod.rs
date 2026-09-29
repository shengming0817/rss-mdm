//! Real authenticated Router, formal PostgreSQL schema and the current Group consumer.
mod group_support;
use crate::test_support::http::ok;
use crate::test_support::inventory::seed_source;
use crate::test_support::*;
use group_support::preview;
use uuid::Uuid;
fn request(revision: u64, input: Value) -> Value {
    json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input})
}
fn predicate(field: &str, kind: &str, value: Value) -> Value {
    json!({"kind":"predicate","field":field,"op":"eq","value":{"kind":kind,"value":value}})
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
    crate::test_support::identity::set_grants(case_tenant(), subject, grants).await
}

struct Fixture {
    base: Value,
    reader: Arc<InventoryReader>,
    automation: Option<rss_runtime::ShutdownStack>,
    router: Router,
    browser: Browser,
    subject: String,
}
impl Fixture {
    async fn open() -> Result<Self> {
        let base: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
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
        let automation = start_automation(&base).await?;
        let router = app(&base, reader.clone()).await?;
        let browser = authority::Authority::open().await?.browser("admin")?;
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
            base,
            reader,
            automation,
            router,
            browser,
            subject,
        })
    }
    async fn close(self) -> Result<()> {
        crate::test_support::stop_worker(self.automation).await?;
        self.reader.close().await;
        Ok(())
    }
}
mod group_input;
mod http;
mod queries;
mod sources;
