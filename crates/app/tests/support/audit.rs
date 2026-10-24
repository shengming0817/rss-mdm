pub(crate) use crate::publication_support::pg::projection;
// Business assertions read committed source facts without driving projections.
use rss_audit_core::AuditEventV1;
use serde_json::Value;

pub(crate) struct Record {
    pub event: AuditEventV1,
    pub payload: Value,
}
impl Record {
    fn from_source(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::from_event(rss_mdm_audit_integration::decode_source_event(bytes)?)
    }
    fn from_event(event: AuditEventV1) -> anyhow::Result<Self> {
        let payload = serde_json::from_slice(event.context().payload().as_bytes())?;
        Ok(Self { event, payload })
    }
    pub fn action(&self) -> &str {
        self.event.facts().action().as_str()
    }
    pub fn target(&self) -> &str {
        self.event.facts().resource().id().as_str()
    }
    pub fn actor(&self) -> Option<&str> {
        (self.event.facts().actor().kind().as_str() != "unidentified")
            .then(|| self.event.facts().actor().id().as_str())
    }
    pub fn operation(&self) -> Option<&str> {
        self.event
            .context()
            .coordinates()
            .operation_id()
            .map(|v| v.as_str())
    }
    pub fn request(&self) -> Option<&str> {
        self.event
            .context()
            .coordinates()
            .request_id()
            .map(|v| v.as_str())
    }
    pub fn source(&self) -> &str {
        self.event.identity().source().source_id().as_str()
    }
    pub fn result(&self) -> &str {
        self.payload["result"].as_str().expect("product result")
    }
    pub fn status(&self) -> u16 {
        u16::try_from(self.payload["status"].as_u64().expect("HTTP status"))
            .expect("HTTP status width")
    }
}
pub(crate) async fn read(connection: &mut sqlx::PgConnection) -> anyhow::Result<Vec<Record>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT source_bytes FROM mdm_audit.receipts ORDER BY tenant_id,source_id",
    )
    .fetch_all(connection)
    .await?;
    rows.iter().map(|row| Record::from_source(row)).collect()
}
pub(crate) async fn request_store() -> anyhow::Result<(
    sqlx::PgPool,
    std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
    std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
)> {
    use rss_audit_postgres::{Control, Integrity};
    use rss_mdm_audit_integration::AuditStore;
    use rss_request_context::Deadline;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
    use std::{str::FromStr, time::Duration};
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .username("mdm_access")
        .password("access-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = Deadline::from_timeout(&timer, Duration::from_secs(2))?;
    let control = {
        let cutoff = deadline;
        Control::new(&timer, cutoff, cutoff, &cancel)
    };
    let tenant = rss_request_context::TenantId::parse(crate::test_support::case::tenant())?;
    let runtime = source_runtime(&pool, tenant).await?;
    let store = AuditStore::new(
        pool.clone(),
        Integrity::Plain,
        runtime.clone(),
        tenant,
        Default::default(),
        &control,
    )
    .await?;
    Ok((pool, runtime, std::sync::Arc::new(store)))
}

pub(crate) async fn audit_records() -> anyhow::Result<Vec<Record>> {
    let lines = crate::test_support::process::pg(&format!(
        "SELECT convert_from(source_bytes,'UTF8') FROM mdm_audit.receipts WHERE tenant_id='{TENANT}' ORDER BY source_id,event_id",
        TENANT = crate::test_support::runtime::case_tenant()
    ))?;
    lines
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| Record::from_source(line.as_bytes()))
        .collect()
}

pub(crate) async fn audit_count(
    predicate: impl Fn(&crate::audit_test_support::Record) -> bool,
) -> anyhow::Result<usize> {
    Ok(audit_records()
        .await?
        .iter()
        .filter(|r| predicate(r))
        .count())
}

// Existing application fixtures share the case tenant and installed storage identity.
impl crate::Database {
    pub(crate) async fn audit_store_fixture(
        &self,
        config: &crate::config::AuditConfig,
    ) -> Result<std::sync::Arc<rss_mdm_audit_integration::AuditStore>, crate::Error> {
        let tenant = rss_request_context::TenantId::parse(crate::test_support::case::tenant())
            .map_err(|_| crate::Error::Unavailable(crate::Failure::Database))?;
        let runtime = self
            .fixture_source_runtime
            .get_or_try_init(|| async { source_runtime(&self.archive_pool(), tenant).await })
            .await
            .map_err(|_| crate::Error::Unavailable(crate::Failure::Database))?;
        self.audit_store(config, runtime.clone(), tenant, Default::default())
            .await
    }
}

pub(crate) async fn source_runtime(
    pool: &sqlx::PgPool,
    tenant: rss_request_context::TenantId,
) -> anyhow::Result<std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>> {
    use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
    use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
    let options = pool.connect_options();
    let ca = match std::env::var("PG_CA_FILE") {
        Ok(path) => std::fs::read(path)?,
        Err(_) => {
            let fixture: Value =
                serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG")?)?)?;
            std::fs::read(
                fixture["ca"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("fixture CA"))?,
            )?
        }
    };
    let password = if options.get_username() == "mdm_access" {
        "access-fixture"
    } else {
        "runtime-fixture"
    };
    let config = PgConfig::new(
        options.get_host(),
        options.get_port(),
        options
            .get_database()
            .ok_or_else(|| anyhow::anyhow!("fixture database"))?,
        options.get_username(),
        PgPassword::new(password),
        PgPrivateCa::from_pem(ca)?,
    );
    let mut tenants = vec![(tenant, Epoch::new(1)?)];
    if tenant.to_string() == crate::test_support::case::tenant() {
        let peer = rss_request_context::TenantId::parse(crate::test_support::case::peer())?;
        if peer != tenant {
            tenants.push((peer, Epoch::new(1)?));
        }
    }
    if options.get_username() == "mdm_access" {
        let management: String =
            sqlx::query_scalar("SELECT management_tenant_id::text FROM public.mdm_installation")
                .fetch_one(pool)
                .await?;
        let management = rss_request_context::TenantId::parse(&management)?;
        if !tenants.iter().any(|(tenant, _)| *tenant == management) {
            tenants.push((
                management,
                Epoch::new(rss_mdm_authorization_service::tenancy::MANAGEMENT_EPOCH)?,
            ));
        }
    }
    let binding = ExecutionBinding::new(StorageIdentity::new([1; 16], [2; 16])?, tenants)?;
    let runtime = if options.get_username() == "mdm_command_runtime" {
        PgRuntime::connect(config, crate::lifecycle::RuntimeTimer, binding).await?
    } else {
        PgRuntime::connect_producer(config, crate::lifecycle::RuntimeTimer, binding).await?
    };
    Ok(std::sync::Arc::new(runtime))
}
