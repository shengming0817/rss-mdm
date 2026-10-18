//! Authorization borrows the host-owned pool; it never exposes a connection owner.
use crate::Error;
use sqlx::{Connection, PgPool, Postgres, Transaction};
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
    pub(crate) clock: std::sync::Arc<dyn rss_request_context::Clock>,
}
impl Store {
    pub fn from_pool(pool: PgPool, clock: std::sync::Arc<dyn rss_request_context::Clock>) -> Self {
        Self { pool, clock }
    }
    pub(crate) async fn acquire(&self) -> Result<sqlx::pool::PoolConnection<Postgres>, Error> {
        self.pool.acquire().await.map_err(db)
    }
    /// Startup validates the persisted recovery principal using the existing restricted pool.
    pub async fn require_management_initializer(&self) -> Result<(), Error> {
        let mut connection = None;
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            connection = Some(self.acquire().await?);
            let connection = connection.as_mut().expect("acquired connection");
            let mut tx = connection.begin().await.map_err(db)?;
            let binding = crate::tenancy::InstallationTenants::load(&mut tx).await?;
            Self::configure_transaction(&mut tx, binding.management_tenant()).await?;
            let principal: Option<String> = sqlx::query_scalar("SELECT a.principal::text FROM mdm_access.authorization_initializations a JOIN public.mdm_installation i ON a.instance=i.instance_id AND a.tenant_id=i.management_tenant_id WHERE i.singleton")
                .fetch_optional(&mut *tx).await.map_err(db)?;
            let validation = if let Some(principal) = principal {
                let instance: String = sqlx::query_scalar("SELECT instance_id::text FROM public.mdm_installation WHERE singleton")
                    .fetch_one(&mut *tx).await.map_err(db)?;
                let snapshot = crate::snapshot_on(&mut tx, binding.management_tenant(), &instance).await?;
                let valid = [crate::Permission::AuthorizationRead, crate::Permission::AuthorizationWrite, crate::Permission::IdentityAccountsManage]
                    .into_iter().all(|permission| snapshot.rules.iter().filter_map(|r| r.value.as_ref()).any(|rule|
                        matches!(&rule.subject, crate::Subject::User { user } if user.principal_id == principal)
                            && rule.grants.iter().any(|g| g.covers(permission, None))));
                if valid { Ok(()) } else { Err(Error::Configuration) }
            } else { Ok(()) };
            tx.rollback().await.map_err(db)?;
            validation
        }).await;
        if !matches!(result, Ok(Ok(())))
            && let Some(connection) = &mut connection
        {
            connection.close_on_drop();
        }
        result.map_err(|_| Error::Deadline)?
    }
    /// Purpose is installation-owned, even for routes requiring identity but no grants.
    pub async fn require_tenant_purpose(
        &self,
        proof: &crate::context::AuthorizedPrincipal,
        management: bool,
    ) -> Result<(), Error> {
        let mut connection = None;
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            proof.check_live()?;
            connection = Some(self.acquire().await?);
            let binding = crate::tenancy::InstallationTenants::load(
                connection.as_mut().expect("acquired connection"),
            )
            .await?;
            binding.require(proof, crate::Permission::AuthorizationRead)?;
            if binding.is_management(proof.tenant_id()) != management {
                return Err(Error::Forbidden);
            }
            Ok(())
        })
        .await;
        if !matches!(result, Ok(Ok(())))
            && let Some(connection) = &mut connection
        {
            connection.close_on_drop();
        }
        result.map_err(|_| Error::Deadline)?
    }
    pub(crate) async fn configure_transaction(
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
    ) -> Result<(), Error> {
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)")
            .bind(tenant).execute(&mut **tx).await.map_err(db)?;
        Ok(())
    }
}
pub(crate) fn db(_: sqlx::Error) -> Error {
    Error::Storage
}
