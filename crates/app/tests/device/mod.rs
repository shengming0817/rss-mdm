use super::test_support::*;
use super::*;
use anyhow::Context;
use sqlx::{Connection, Executor, PgConnection};

async fn fixture() -> anyhow::Result<(
    Arc<Database>,
    DeviceService,
    AuthorizedPrincipal,
    PgConnection,
)> {
    anyhow::ensure!(
        cfg!(feature = "integration"),
        "device T2 requires integration"
    );
    let admin_a = admin(case_a(), "admin-a").await?;
    let access = Arc::new(Database::connect(options("mdm_access")?).await?);
    let service = DeviceService::new(
        access.clone(),
        case_a().into(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    );
    let mut root = PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_a())
        .execute(&mut root)
        .await?;
    Ok((access, service, admin_a, root))
}

mod admission;
mod binding;
mod recovery;
pub(crate) mod revocation;
