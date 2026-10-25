//! Private connection ownership and tenant transaction configuration.
//! Capability admission checks are composed here on the same connection.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
use crate::{Error, Failure};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
#[cfg(test)]
use sqlx::{Postgres, Transaction};
use std::time::Duration;
pub(crate) struct Database {
    inventory: std::sync::Arc<rss_mdm_inventory_service::Store>,
    registration: std::sync::Arc<rss_mdm_registration_service::Store>,
    authorization: std::sync::Arc<rss_mdm_authorization_service::Store>,
    pool: PgPool,
    #[cfg(test)]
    pub(crate) fixture_source_runtime:
        tokio::sync::OnceCell<std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>>,
}
impl Database {
    pub(crate) fn archive_pool(&self) -> PgPool {
        self.pool.clone()
    }
    pub(crate) fn authorization_store(
        &self,
    ) -> std::sync::Arc<rss_mdm_authorization_service::Store> {
        self.authorization.clone()
    }
    pub(crate) fn apple_store(&self) -> std::sync::Arc<rss_mdm_apple_channel::Store> {
        std::sync::Arc::new(rss_mdm_apple_channel::Store::from_pool(
            self.pool.clone(),
            self.registration.clone(),
            self.authorization.clone(),
        ))
    }
    pub(crate) fn windows_store(&self) -> std::sync::Arc<rss_mdm_windows_channel::Store> {
        std::sync::Arc::new(rss_mdm_windows_channel::Store::from_pool(
            self.pool.clone(),
            self.registration.clone(),
            self.authorization.clone(),
        ))
    }
    pub(crate) fn inventory(&self) -> std::sync::Arc<rss_mdm_inventory_service::Store> {
        self.inventory.clone()
    }
    pub(crate) fn registration(&self) -> std::sync::Arc<rss_mdm_registration_service::Store> {
        self.registration.clone()
    }

    pub async fn connect(
        options: PgConnectOptions,
        audit: &crate::config::AuditConfig,
    ) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(1))
            .connect_with(options)
            .await
            .map_err(db)?;
        if let Err(e) = admission(&pool, audit).await {
            pool.close().await;
            return Err(e);
        }
        Ok(Self {
            inventory: std::sync::Arc::new(rss_mdm_inventory_service::Store::from_pool(
                pool.clone(),
            )),
            registration: std::sync::Arc::new(rss_mdm_registration_service::Store::from_pool(
                pool.clone(),
                std::sync::Arc::new(crate::registration_lifecycle::Bridge),
            )),
            authorization: std::sync::Arc::new(rss_mdm_authorization_service::Store::from_pool(
                pool.clone(),
                std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
            )),
            pool,
            #[cfg(test)]
            fixture_source_runtime: tokio::sync::OnceCell::new(),
        })
    }
    /// Host assembly shares this pool with Audit; Database remains its shutdown owner.
    pub(crate) async fn audit_store(
        &self,
        config: &crate::config::AuditConfig,
        runtime: std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
        tenant: rss_request_context::TenantId,
    ) -> Result<std::sync::Arc<rss_mdm_audit_integration::AuditStore>, Error> {
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(2));
        let control = budget.control();
        rss_mdm_audit_integration::AuditStore::new(
            self.pool.clone(),
            config.integrity()?,
            runtime,
            tenant,
            &control,
        )
        .await
        .map(std::sync::Arc::new)
        .map_err(Error::from)
    }
    pub(crate) fn timeline(
        &self,
        audit: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
        tenant: rss_request_context::TenantId,
        key: &[u8],
    ) -> Result<std::sync::Arc<rss_mdm_timeline_service::Timeline>, Error> {
        rss_mdm_timeline_service::Timeline::new(self.pool.clone(), audit, tenant, key)
            .map(std::sync::Arc::new)
            .map_err(|_| Error::Unavailable(Failure::Database))
    }
    pub(crate) async fn claim_tenant_use(
        &self,
        config: &crate::config::Config,
    ) -> Result<(), Error> {
        let identity = crate::migration::Installation {
            instance_id: config.identity.instance_id.clone(),
            target: config.flow.storage.target,
            lineage: config.flow.storage.lineage,
            audit_mode: config.audit.mode(),
        };
        let mut conn = self.pool.acquire().await.map_err(db)?;
        let management: String =
            sqlx::query_scalar("SELECT management_tenant_id::text FROM public.mdm_installation")
                .fetch_one(&mut *conn)
                .await
                .map_err(db)?;
        if management == config.identity.tenant_id {
            return Err(Error::Configuration(crate::ConfigIssue::Tenant));
        }
        crate::tenant_registry::claim_use(
            &mut conn,
            &identity,
            &config.identity.tenant_id,
            config.flow.storage.epoch,
        )
        .await
    }
    pub async fn close(&self) {
        #[cfg(test)]
        if let Some(runtime) = self.fixture_source_runtime.get() {
            runtime.close().await;
        }
        self.pool.close().await;
    }
    #[cfg(test)]
    pub(crate) async fn configure_transaction(
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
    ) -> Result<(), Error> {
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)")
            .bind(tenant).execute(&mut **tx).await.map_err(db)?;
        Ok(())
    }
}

pub(crate) fn db(error: sqlx::Error) -> Error {
    #[cfg(test)]
    eprintln!(
        "test PG error category: {:?}",
        error.as_database_error().and_then(|e| e.code())
    );
    let _ = error;
    Error::Unavailable(Failure::Database)
}

async fn admission(pool: &PgPool, audit: &crate::config::AuditConfig) -> Result<(), Error> {
    let mut tx = pool.begin().await.map_err(db)?;
    sqlx::query("SET LOCAL statement_timeout='1s'")
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    verify_product_storage(&mut tx)
        .await
        .map_err(|_| Error::Unavailable(Failure::AccessAdmission))?;
    let mut contracts = vec![
        crate::first_use::ACCESS_CONTRACT,
        crate::user_profiles::ACCESS_CONTRACT,
        crate::tenant_registry::ACCESS_CONTRACT,
        rss_mdm_mail_service::ACCESS_CONTRACT,
        rss_mdm_content_service::connections::ACCESS_CONTRACT,
        rss_mdm_webhook_service::ACCESS_CONTRACT,
        rss_mdm_authorization_service::ACCESS_CONTRACT,
        rss_mdm_registration_service::ACCESS_CONTRACT,
        rss_mdm_software_service::agent_packages::ACCESS_CONTRACT,
        r#"{"tables":[],"functions":[],"external_relations":["mdm_initialization.baselines"],"verified_schemas":[]}"#,
        rss_mdm_execution_service::ACCESS_CONTRACT,
        rss_mdm_inventory_service::ACCESS_CONTRACT,
        rss_mdm_agent_channel::ACCESS_CONTRACT,
        rss_mdm_windows_channel::ACCESS_CONTRACT,
        rss_mdm_pki_service::ACCESS_CONTRACT,
        rss_mdm_apple_channel::ACCESS_CONTRACT,
        rss_mdm_audit_integration::ACCESS_CONTRACT,
        rss_mdm_flow_service::ACCESS_CONTRACT,
        rss_mdm_timeline_service::ACCESS_CONTRACT,
        rss_mdm_device_service::ACCESS_CONTRACT,
        rss_mdm_certificate_archive_service::ACCESS_CONTRACT,
        rss_mdm_recovery_credentials::ACCESS_CONTRACT,
    ];
    if matches!(audit, crate::config::AuditConfig::Ledger { .. }) {
        contracts.push(r#"{"tables":[],"functions":[{"name":"rss_ledger.prepare_append","search_path":"search_path=pg_catalog, rss_ledger"},{"name":"rss_ledger.insert_entry","search_path":"search_path=pg_catalog, rss_ledger"}],"external_relations":["rss_ledger.heads","rss_ledger.entries"],"verified_schemas":[]}"#);
    }
    let valid = rss_mdm_backend_postgres_support::access_admission::verify(
        &mut tx,
        "mdm_access",
        &contracts,
    )
    .await
    .map_err(db)?;
    crate::tenant_registry::verify_read_profile(&mut tx).await?;
    let instance: String =
        sqlx::query_scalar("SELECT instance_id::text FROM public.mdm_installation")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
    rss_identity_postgres::verify_platform_subject_admission(
        &mut tx,
        rss_identity_core::InstanceId::parse(&instance)
            .map_err(|_| Error::Unavailable(Failure::AccessAdmission))?,
    )
    .await
    .map_err(|_| Error::Unavailable(Failure::AccessAdmission))?;

    rss_mdm_inventory_postgres::verify_collections(&mut tx)
        .await
        .map_err(|error| {
            #[cfg(feature = "integration")]
            eprintln!("collection admission: {error}");
            let _ = error;
            Error::Unavailable(Failure::Database)
        })?;
    rss_mdm_inventory_postgres::verify_watermark_fence(&mut tx)
        .await
        .map_err(db)?;
    if !rss_mdm_content_service::connections::verify_reservation(&mut tx)
        .await
        .map_err(|_| Error::Unavailable(Failure::AccessAdmission))?
    {
        return Err(Error::Unavailable(Failure::AccessAdmission));
    }
    let apple: bool = sqlx::query_scalar(rss_mdm_apple_channel::ACCESS_ADMISSION_SQL)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
    let flow: bool = sqlx::query_scalar(rss_mdm_flow_service::ACCESS_ADMISSION_SQL)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
    let timeline: bool = sqlx::query_scalar(rss_mdm_timeline_service::ACCESS_ADMISSION_SQL)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
    if !valid || !apple || !flow || !timeline {
        #[cfg(feature = "integration")]
        eprintln!(
            "access admission: aggregate={valid}, apple={apple}, flow={flow}, timeline={timeline}"
        );
        return Err(Error::Unavailable(Failure::AccessAdmission));
    }
    tx.rollback().await.map_err(db)
}

impl Database {
    pub(crate) fn agent_store(&self) -> rss_mdm_agent_channel::Store {
        rss_mdm_agent_channel::Store::from_pool(self.pool.clone())
    }
}

/// Full installed-product drift belongs to composition, not capability constructors.
/// Each borrower still verifies its own role and transaction contract separately.
pub(crate) async fn verify_product_storage(
    connection: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    // Deparsers must not abbreviate same-name schemas through the role's "$user" path.
    sqlx::query("SET LOCAL search_path=pg_catalog,public")
        .execute(&mut *connection)
        .await?;
    let actual: String = sqlx::query_scalar(include_str!("product-storage.sql"))
        .fetch_one(connection)
        .await?;
    let actual: serde_json::Value = serde_json::from_str(&actual)
        .map_err(|_| sqlx::Error::Protocol("product storage catalog".into()))?;
    let expected: serde_json::Value = serde_json::from_str(include_str!("product-storage.json"))
        .expect("installed product catalog");
    if actual != expected {
        return Err(sqlx::Error::Protocol(
            "installed product storage drift".into(),
        ));
    }
    Ok(())
}
