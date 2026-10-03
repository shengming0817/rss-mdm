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
}
impl Database {
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

    #[cfg(test)]
    pub(crate) fn authorization(&self) -> &rss_mdm_authorization_service::Store {
        &self.authorization
    }

    pub async fn connect(options: PgConnectOptions) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(1))
            .connect_with(options)
            .await
            .map_err(db)?;
        if let Err(e) = admission(&pool).await {
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
            )),
            pool,
        })
    }
    /// Host assembly shares this pool with Audit; Database remains its shutdown owner.
    pub(crate) async fn audit_store(
        &self,
        config: &crate::config::AuditConfig,
    ) -> Result<std::sync::Arc<rss_mdm_audit_integration::AuditStore>, Error> {
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(2));
        let control = budget.control();
        rss_mdm_audit_integration::AuditStore::new(self.pool.clone(), config.integrity()?, &control)
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
    pub async fn close(&self) {
        self.pool.close().await;
    }
    #[cfg(test)]
    pub(crate) async fn begin(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        Self::configure_transaction(&mut tx, tenant).await?;
        Ok(tx)
    }
    /// Pure work discovery uses the normal tenant boundary without Audit head ownership.
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

async fn admission(pool: &PgPool) -> Result<(), Error> {
    let mut tx = pool.begin().await.map_err(db)?;
    sqlx::query("SET LOCAL statement_timeout='1s'")
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    let contracts = [
        rss_mdm_authorization_service::ACCESS_CONTRACT,
        rss_mdm_registration_service::ACCESS_CONTRACT,
        rss_mdm_execution_service::ACCESS_CONTRACT,
        rss_mdm_inventory_service::ACCESS_CONTRACT,
        rss_mdm_agent_channel::ACCESS_CONTRACT,
        rss_mdm_windows_channel::ACCESS_CONTRACT,
        rss_mdm_apple_channel::ACCESS_CONTRACT,
        rss_mdm_audit_integration::ACCESS_CONTRACT,
        rss_mdm_flow_service::ACCESS_CONTRACT,
        rss_mdm_timeline_service::ACCESS_CONTRACT,
    ];
    let valid = rss_mdm_backend_postgres_support::access_admission::verify(
        &mut tx,
        "mdm_access",
        &contracts,
    )
    .await
    .map_err(db)?;
    rss_mdm_inventory_postgres::verify_collections(&mut tx)
        .await
        .map_err(|error| {
            #[cfg(feature = "integration")]
            eprintln!("collection admission: {error}");
            let _ = error;
            Error::Unavailable(Failure::Database)
        })?;
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

/// Probe each borrowed transaction owner at startup without changing its isolation or pool.
pub(crate) async fn admit_audit_runtime(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    store: &rss_mdm_audit_integration::AuditStore,
    tenant: rss_request_context::TenantId,
) -> Result<(), Error> {
    let failure = std::sync::Mutex::new(None);
    runtime
        .local_tx_with_context(
            tenant,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_secs(5),
            ),
            (store, &failure),
            |(store, failure), tx| {
                Box::pin(async move {
                    match store.lock_in(tx).await {
                        Ok(()) => Ok(()),
                        Err(error) => {
                            *failure.lock().expect("startup audit failure") =
                                Some(Error::from(error));
                            Err(rss_audit_postgres::Error::StorageContract.into())
                        }
                    }
                })
            },
        )
        .await
        .fold(
            Ok,
            |_| Err(Error::Unavailable(Failure::Audit)),
            |_| {
                Err(failure
                    .into_inner()
                    .expect("startup audit failure")
                    .unwrap_or(Error::Unavailable(Failure::Audit)))
            },
            |_| Err(Error::RollbackFailed),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::Audit)),
        )
}

impl Database {
    pub(crate) fn agent_store(&self) -> rss_mdm_agent_channel::Store {
        rss_mdm_agent_channel::Store::from_pool(
            self.pool.clone(),
            self.registration.clone(),
            self.authorization.clone(),
        )
    }
}
