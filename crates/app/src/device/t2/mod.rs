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
    let admin_a = admin(A, "admin-a").await?;
    let access = Arc::new(Database::connect(options("mdm_access")?).await?);
    let service = DeviceService::new(
        access.clone(),
        A.into(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    );
    let mut root = PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(A)
        .execute(&mut root)
        .await?;
    Ok((access, service, admin_a, root))
}

mod admission;
mod binding;
mod recovery;
pub(crate) mod revocation;
