use super::*;
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::{collections::BTreeMap, path::PathBuf};
#[derive(serde::Deserialize)]
pub struct Database {
    host: String,
    port: u16,
    name: String,
    user: String,
    ca_file: PathBuf,
    password_file: PathBuf,
}
impl Database {
    pub fn options(&self) -> Result<PgConnectOptions> {
        Ok(PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.name)
            .username(&self.user)
            .password(std::fs::read_to_string(&self.password_file)?.trim())
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert(&self.ca_file))
    }
    pub async fn pool(&self) -> Result<sqlx::PgPool> {
        Ok(PgPoolOptions::new()
            .max_connections(4)
            .connect_with(self.options()?)
            .await?)
    }
}
#[derive(serde::Deserialize)]
pub struct Identity {
    pub instance_id: String,
    pub target: [u8; 16],
    pub lineage: [u8; 16],
}
#[derive(serde::Deserialize)]
pub struct Inputs {
    pub installation: Identity,
    pub databases: BTreeMap<String, BTreeMap<String, Database>>,
    pub directory: PathBuf,
}
impl Inputs {
    pub fn database(&self, role: &str) -> &Database {
        &self.databases["agent_foundation"][role]
    }
    pub async fn runtime(
        &self,
        role: &str,
        tenant: rss_request_context::TenantId,
    ) -> Result<Arc<PgRuntime>> {
        let db = self.database(role);
        let config = PgConfig::new(
            &db.host,
            db.port,
            &db.name,
            &db.user,
            PgPassword::new(std::fs::read_to_string(&db.password_file)?.trim()),
            PgPrivateCa::from_pem(std::fs::read(&db.ca_file)?)?,
        )
        .with_pool_limits(0, 4);
        let binding = ExecutionBinding::new(
            StorageIdentity::new(self.installation.target, self.installation.lineage)?,
            vec![(tenant, Epoch::new(1)?)],
        )?;
        Ok(Arc::new(
            PgRuntime::connect_producer(config, Timer, binding).await?,
        ))
    }
}
pub struct Timer;
impl rss_request_context::Clock for Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "fixture clock shares the Tokio runtime time domain"
    )]
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl rss_request_context::ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: rss_request_context::Deadline) {
        tokio::time::sleep_until(deadline.instant().into()).await;
    }
}
pub struct Context {
    pub inputs: Inputs,
    pub tenant: rss_request_context::TenantId,
    pub operator: sqlx::PgPool,
    pub access: sqlx::PgPool,
    pub runtime: Arc<PgRuntime>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    identity_runtime: Arc<PgRuntime>,
    audit_pool: sqlx::PgPool,
    pub sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
}
impl Context {
    pub async fn open() -> Result<Self> {
        let inputs: Inputs =
            serde_json::from_slice(&std::fs::read(std::env::var("RSS_MDM_T2_ENV")?)?)?;
        let operator = inputs.database("postgres").pool().await?;
        let fail = installation::Installation {
            inputs: &inputs,
            fail_before: Some("agent"),
        };
        let binding = fail.binding()?;
        let failed = rss_mdm_install_support::install(
            &inputs.database("da_owner").options()?,
            &binding,
            &installation::units(),
            &fail,
        )
        .await
        .unwrap_err();
        assert_eq!(failed.unit(), "agent");
        assert_eq!(failed.phase(), "injected interruption before unit");
        let mut check = operator.acquire().await?;
        let before = rss_mdm_install_support::read_receipts(&mut check, DA).await?;
        let units = installation::units();
        let prefix = &units[..units.iter().position(|u| u.0 == "agent").unwrap()];
        assert_eq!(before.len(), prefix.len());
        assert!(rss_mdm_install_support::accepted_ledger(&before, prefix));
        drop(check);
        let host = installation::Installation {
            inputs: &inputs,
            fail_before: None,
        };
        rss_mdm_install_support::install(
            &inputs.database("da_owner").options()?,
            &binding,
            &installation::units(),
            &host,
        )
        .await?;
        let mut check = operator.acquire().await?;
        let after = rss_mdm_install_support::read_receipts(&mut check, DA).await?;
        for row in before {
            assert!(after.contains(&row));
        }
        drop(check);
        // Reentry validates all receipts and never reruns a completed owner unit.
        rss_mdm_install_support::install(
            &inputs.database("da_owner").options()?,
            &binding,
            &installation::units(),
            &host,
        )
        .await?;
        let wrong = rss_mdm_install_support::Binding::new(
            DA,
            Uuid::new_v4(),
            inputs.installation.target,
            inputs.installation.lineage,
            "agent-foundation-plain-v1".into(),
        )?;
        assert!(
            rss_mdm_install_support::install(
                &inputs.database("da_owner").options()?,
                &wrong,
                &installation::units(),
                &host
            )
            .await
            .is_err()
        );
        let tenant = rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?;
        let management = Uuid::new_v4();
        let mut tx = operator.begin().await?;
        sqlx::query(
            "INSERT INTO rss_transactional_messaging.storage_lineage(target,lineage) VALUES($1,$2)",
        )
        .bind(inputs.installation.target.as_slice())
        .bind(inputs.installation.lineage.as_slice())
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch(tenant_id,epoch) VALUES($1::uuid,1),($2,1)").bind(tenant.to_string()).bind(management).execute(&mut *tx).await?;
        rss_mdm_authorization_service::installation::bind_da_in(
            &mut tx,
            Uuid::parse_str(&inputs.installation.instance_id)?,
            management,
        )
        .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        rss_mdm_inventory_postgres::initialize_fields_in(&mut tx, tenant).await?;
        tx.commit().await?;
        let access = inputs.database("da_access").pool().await?;
        let runtime = inputs.runtime("da_command_runtime", tenant).await?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(10));
        let audit_pool = inputs.database("da_command_runtime").pool().await?;
        let audit = Arc::new(
            rss_mdm_audit_integration::AuditStore::new(
                audit_pool.clone(),
                rss_audit_postgres::Integrity::Plain,
                runtime.clone(),
                tenant,
                &budget.control(),
            )
            .await?,
        );
        let identity_runtime = inputs.runtime("da_identity_runtime", tenant).await?;
        let authority = rss_identity_postgres::Authority::connect_runtime(
            identity_runtime.clone(),
            Arc::new(rss_identity_core::account::PasswordKdf::new()),
            rss_identity_postgres::AuthorityConfig::new(
                rss_identity_core::InstanceId::parse(&inputs.installation.instance_id)?,
                vec![tenant],
                rss_identity_core::session::SessionPolicy::new(900, 14400)?,
                rss_audit_postgres::Integrity::Plain,
            )?,
            Arc::new(
                rss_mdm_authorization_service::identity_management::IdentityManagementPolicy::new(
                    DA,
                    &inputs.installation.instance_id,
                )?,
            ),
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_secs(10),
            ),
        )
        .await?;
        let sessions = Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(authority, tenant),
        );
        Ok(Self {
            inputs,
            tenant,
            operator,
            access,
            runtime,
            audit,
            sessions,
            identity_runtime,
            audit_pool,
        })
    }
    pub async fn close(&self) {
        self.identity_runtime.close().await;
        self.runtime.close().await;
        self.audit_pool.close().await;
        self.access.close().await;
        self.operator.close().await;
    }
    pub async fn seed(&self) -> Result<sqlx::Transaction<'_, sqlx::Postgres>> {
        let mut tx = self.operator.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(self.tenant.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
}
