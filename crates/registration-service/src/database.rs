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
        _execution: rss_transactional_messaging::fence::ExecutionBinding,
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

impl Store {
    /// A locator reveals no authority or material; callers must run the original verifier afterwards.
    pub async fn locate_request(
        &self,
        id: uuid::Uuid,
    ) -> Result<
        Option<(
            rss_request_context::TenantId,
            rss_transactional_messaging::fence::Epoch,
        )>,
        Error,
    > {
        let query = match self.profile {
            rss_mdm_install_support::StorageProfile::Mdm => {
                "SELECT tenant_id,expected_epoch FROM mdm_access.request_tenants($1)"
            }
            rss_mdm_install_support::StorageProfile::Da => {
                "SELECT tenant_id,expected_epoch FROM rss_da.request_tenants($1)"
            }
        };
        unique_original(
            sqlx::query_as(query)
                .bind(id)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?,
        )
    }
    pub async fn locate_certificate(
        &self,
        fingerprint: [u8; 32],
    ) -> Result<Option<rss_request_context::TenantId>, Error> {
        let fingerprint = fingerprint
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let query = match self.profile {
            rss_mdm_install_support::StorageProfile::Mdm => {
                "SELECT tenant_id FROM mdm_access.certificate_tenants($1)"
            }
            rss_mdm_install_support::StorageProfile::Da => {
                "SELECT tenant_id FROM rss_da.certificate_tenants($1)"
            }
        };
        unique_tenant(
            sqlx::query_scalar(query)
                .bind(fingerprint)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?,
        )
    }
    pub async fn locate_grant(
        &self,
        id: uuid::Uuid,
    ) -> Result<
        Option<(
            rss_request_context::TenantId,
            rss_transactional_messaging::fence::Epoch,
        )>,
        Error,
    > {
        let query = match self.profile {
            rss_mdm_install_support::StorageProfile::Mdm => {
                "SELECT tenant_id,expected_epoch FROM mdm_access.grant_tenants($1)"
            }
            rss_mdm_install_support::StorageProfile::Da => {
                "SELECT tenant_id,expected_epoch FROM rss_da.grant_tenants($1)"
            }
        };
        unique_original(
            sqlx::query_as(query)
                .bind(id)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?,
        )
    }
    pub async fn locate_configuration(
        &self,
        id: uuid::Uuid,
    ) -> Result<
        Option<(
            rss_request_context::TenantId,
            rss_transactional_messaging::fence::Epoch,
        )>,
        Error,
    > {
        let query = match self.profile {
            rss_mdm_install_support::StorageProfile::Mdm => {
                "SELECT tenant_id,expected_epoch FROM mdm_access.configuration_tenants($1)"
            }
            rss_mdm_install_support::StorageProfile::Da => {
                "SELECT tenant_id,expected_epoch FROM rss_da.configuration_tenants($1)"
            }
        };
        unique_original(
            sqlx::query_as(query)
                .bind(id)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?,
        )
    }
    pub async fn locate_issuance(
        &self,
        id: uuid::Uuid,
    ) -> Result<
        Option<(
            rss_request_context::TenantId,
            rss_transactional_messaging::fence::Epoch,
        )>,
        Error,
    > {
        let query = match self.profile {
            rss_mdm_install_support::StorageProfile::Mdm => {
                "SELECT * FROM mdm_access.issuance_tenants($1)"
            }
            rss_mdm_install_support::StorageProfile::Da => {
                "SELECT * FROM rss_da.issuance_tenants($1)"
            }
        };
        let rows: Vec<(uuid::Uuid, i64)> = sqlx::query_as(query)
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        unique_original(rows)
    }
    pub async fn locate_bootstrap(
        &self,
        id: uuid::Uuid,
    ) -> Result<
        Option<(
            rss_request_context::TenantId,
            rss_transactional_messaging::fence::Epoch,
        )>,
        Error,
    > {
        let query = match self.profile {
            rss_mdm_install_support::StorageProfile::Mdm => {
                "SELECT * FROM mdm_access.bootstrap_tenants($1)"
            }
            rss_mdm_install_support::StorageProfile::Da => {
                "SELECT * FROM rss_da.bootstrap_tenants($1)"
            }
        };
        let rows: Vec<(uuid::Uuid, i64)> = sqlx::query_as(query)
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        unique_original(rows)
    }
}
fn unique_tenant(tenants: Vec<uuid::Uuid>) -> Result<Option<rss_request_context::TenantId>, Error> {
    match tenants.as_slice() {
        [] => Ok(None),
        [tenant] => rss_request_context::TenantId::parse(&tenant.to_string())
            .map(Some)
            .map_err(|_| Error::Storage),
        _ => Err(Error::Unauthorized),
    }
}

fn unique_original(
    rows: Vec<(uuid::Uuid, i64)>,
) -> Result<
    Option<(
        rss_request_context::TenantId,
        rss_transactional_messaging::fence::Epoch,
    )>,
    Error,
> {
    match rows.as_slice() {
        [] => Ok(None),
        [(tenant, epoch)] => Ok(Some((
            rss_request_context::TenantId::parse(&tenant.to_string())
                .map_err(|_| Error::Corrupt)?,
            rss_transactional_messaging::fence::Epoch::new(*epoch).map_err(|_| Error::Corrupt)?,
        ))),
        _ => Err(Error::Unauthorized),
    }
}
