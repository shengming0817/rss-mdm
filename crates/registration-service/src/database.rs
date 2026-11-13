use crate::{Error, Retirement};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;

pub struct Store {
    profile: rss_mdm_install_support::StorageProfile,
    pool: PgPool,
    pub(crate) retirement: Arc<dyn Retirement>,
}
impl Store {
    /// Standalone certificate registration needs only the shared PKI retirement owner.
    pub fn for_device_access(pool: PgPool) -> Self {
        Self::from_pool(
            rss_mdm_install_support::StorageProfile::Da,
            pool,
            Arc::new(CertificateRetirement),
        )
    }
    pub fn from_pool(
        profile: rss_mdm_install_support::StorageProfile,
        pool: PgPool,
        retirement: Arc<dyn Retirement>,
    ) -> Self {
        Self {
            profile,
            pool,
            retirement,
        }
    }
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub async fn begin(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, Error> {
        self.begin_mode(tenant, false).await
    }
    pub async fn snapshot(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, Error> {
        self.begin_mode(tenant, true).await
    }
    /// Check current authorization only after the data snapshot has been released.
    pub async fn confirm_query(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        expected: &str,
    ) -> Result<(), Error> {
        let proof = request.proof.as_ref();
        let fresh = request.revalidate().await?;
        if proof.profile() != self.profile {
            return Err(Error::Forbidden);
        }
        proof.check_live()?;
        let mut tx = self.begin(proof.tenant_id()).await?;
        rss_mdm_authorization_service::lock_shared_on(
            proof.authority_profile(),
            &mut tx,
            proof.tenant_id(),
            proof.instance_id(),
        )
        .await?;
        let current = rss_mdm_authorization_service::snapshot_on(
            proof.authority_profile(),
            &mut tx,
            proof.tenant_id(),
            proof.instance_id(),
        )
        .await?;
        if request.current_binding(&current, fresh.as_ref())? != expected {
            return Err(Error::ReadConflict);
        }
        if proof.profile() != self.profile {
            return Err(Error::Forbidden);
        }
        proof.check_live()?;
        tx.rollback().await.map_err(db)
    }

    async fn begin_mode(
        &self,
        tenant: &str,
        read_only: bool,
    ) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        if read_only {
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)")
            .bind(tenant).execute(&mut *tx).await.map_err(db)?;
        Ok(tx)
    }
}
pub(crate) fn db(_: sqlx::Error) -> Error {
    Error::Storage
}

struct CertificateRetirement;
impl crate::Retirement for CertificateRetirement {
    fn events(&self) -> Option<&dyn crate::EventSink> {
        None
    }
    fn retire<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        _facts: &'a mut Vec<rss_mdm_audit_integration::Fact>,
        tenant: &'a str,
        registration: &'a rss_mdm_agent_wire::DeviceId,
        _state: &'a str,
    ) -> crate::agent::Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_pki_service::certificates::revoke_registration_in(
                rss_mdm_install_support::StorageProfile::Da,
                c,
                tenant,
                registration,
            )
            .await
            .map_err(|_| Error::Storage)
        })
    }
}

/// Validate a native PostgreSQL UUID at the registration storage boundary.
pub(crate) fn device_id(id: uuid::Uuid) -> Result<rss_mdm_agent_wire::DeviceId, sqlx::Error> {
    rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}
pub(crate) fn device_ids(
    ids: Vec<uuid::Uuid>,
) -> Result<Vec<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    ids.into_iter().map(device_id).collect()
}
