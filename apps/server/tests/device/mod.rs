use super::test_support::*;
use super::*;
use anyhow::Context;
use sqlx::{Connection, Executor, PgConnection};

async fn fixture() -> anyhow::Result<(
    crate::test_support::runtime::Resources,
    DeviceService,
    AuthorizedPrincipal,
    PgConnection,
)> {
    anyhow::ensure!(
        cfg!(feature = "integration"),
        "device T2 requires integration"
    );
    let admin_a = admin(case_a(), "admin-a").await?;
    let (pool, source, audit) = crate::audit_test_support::request_store().await?;
    let mut access = crate::test_support::runtime::Resources::default();
    access.resource(crate::test_support::runtime::PoolResource(pool.clone()));
    access.resource(crate::test_support::runtime::SourceResource(source));
    let service = DeviceService::new(
        Arc::new(rss_mdm_registration_service::Store::from_pool(
            pool,
            Arc::new(crate::registration_lifecycle::Bridge),
        )),
        case_a().into(),
        audit,
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

pub(crate) mod associations;
mod views;
