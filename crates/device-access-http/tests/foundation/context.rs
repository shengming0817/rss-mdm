use super::*;
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::{collections::BTreeMap, path::PathBuf};
#[derive(serde::Serialize, serde::Deserialize)]
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
        &self.databases["da_foundation"][role]
    }
    pub async fn runtime(&self, role: &str) -> Result<Arc<PgRuntime>> {
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
        let storage = StorageIdentity::new(self.installation.target, self.installation.lineage)?;
        let runtime = PgRuntime::connect_producer(config, Timer, storage).await;
        Ok(Arc::new(
            runtime.map_err(|e| anyhow::anyhow!("DA runtime {role}: {e}"))?,
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
#[path = "../../../../hack/test-support/device_oidc.rs"]
pub(super) mod device_oidc;
pub struct Context {
    pub oidc: std::sync::OnceLock<device_oidc::Keycloak>,
    pub browser_origin: String,
    pub platform: Arc<rss_mdm_device_access_postgres::platform_sso::bridge::Verifier>,
    pub business: std::sync::OnceLock<Arc<rss_mdm_device_access_http::Business>>,
    pub inputs: Inputs,
    pub tenant: rss_request_context::TenantId,
    pub operator: sqlx::PgPool,
    pub access: sqlx::PgPool,
    pub runtime: Arc<PgRuntime>,
    pub(super) identity_runtime: Arc<PgRuntime>,
    pub proof_audit: Arc<rss_mdm_audit_integration::AuditStore>,
    access_runtime: Arc<PgRuntime>,
    pub access_audit: Arc<rss_mdm_audit_integration::AuditStore>,
    audit_pool: sqlx::PgPool,
    pub sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    pub authority: rss_identity_postgres::Authority,
    pub authorization: Arc<rss_mdm_authorization_service::Store>,
}
impl Context {
    pub fn execution(&self) -> ExecutionBinding {
        ExecutionBinding::new(
            StorageIdentity::new(
                self.inputs.installation.target,
                self.inputs.installation.lineage,
            )
            .unwrap(),
            self.tenant,
            Epoch::new(1).unwrap(),
        )
    }
    pub fn management_base(&self) -> String {
        format!("{}/api/v1/tenants/{}/da", self.browser_origin, self.tenant)
    }
    pub async fn open(browser_origin: String) -> Result<Self> {
        let inputs: Inputs =
            serde_json::from_slice(&std::fs::read(std::env::var("RSS_MDM_T2_ENV")?)?)?;
        let operator = inputs.database("postgres").pool().await?;
        let tenant = rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?;
        let management = Uuid::new_v4();
        let host = installation::host(&inputs, tenant, management)?;
        let binding = host.binding()?;
        // Interrupt the real unit executor after Observation commits, before Projection can start.
        sqlx::query("CREATE SCHEMA rss_projection")
            .execute(&operator)
            .await?;
        let interrupted = rss_mdm_install_support::install(
            &inputs.database("da_owner").options()?,
            &binding,
            &installation::units(),
            &host,
        )
        .await;
        anyhow::ensure!(
            interrupted.is_err(),
            "conflicting schema must stop installation"
        );
        let prefix_query = "SELECT name,digest,xmin::text FROM rss_da.installation_units WHERE complete ORDER BY name";
        let prefix: Vec<(String, String, String)> =
            sqlx::query_as(prefix_query).fetch_all(&operator).await?;
        anyhow::ensure!(
            prefix.iter().map(|r| r.0.as_str()).collect::<Vec<_>>()
                == ["audit-v1", "observation-v1"]
        );
        sqlx::query("DROP SCHEMA rss_projection")
            .execute(&operator)
            .await?;
        rss_mdm_install_support::install(
            &inputs.database("da_owner").options()?,
            &binding,
            &installation::units(),
            &host,
        )
        .await?;
        let installed: Vec<(String, String, String)> =
            sqlx::query_as(prefix_query).fetch_all(&operator).await?;
        anyhow::ensure!(
            prefix.iter().all(|r| installed.contains(r)),
            "replayed prefix was rewritten"
        );
        let revisions: (String, String) = sqlx::query_as(
            "SELECT obj_description('rss_observation'::regnamespace,'pg_namespace'), obj_description('rss_projection'::regnamespace,'pg_namespace')"
        ).fetch_one(&operator).await?;
        assert_eq!(
            revisions,
            (
                "rss-observation-postgres:5".into(),
                "rss-projection-postgres:5".into()
            )
        );
        let mut check = operator.acquire().await?;
        let after = rss_mdm_install_support::read_receipts(&mut check, DA).await?;
        assert_eq!(after.len(), installation::units().len());
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
            "da-foundation-plain-v1".into(),
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
        let absent:bool=sqlx::query_scalar("SELECT to_regnamespace('mdm') IS NULL AND to_regclass('rss_da.inventory_assets') IS NOT NULL").fetch_one(&operator).await?;
        anyhow::ensure!(absent, "standalone DA uses only its own asset schema");
        let access = inputs.database("da_access").pool().await?;
        let runtime = inputs.runtime("da_access").await?;
        let binding = ExecutionBinding::new(
            StorageIdentity::new(inputs.installation.target, inputs.installation.lineage)?,
            tenant,
            Epoch::new(1)?,
        );
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(10));
        let audit_pool = inputs.database("da_access").pool().await?;
        let audit = Arc::new(
            rss_mdm_audit_integration::AuditStore::new(
                audit_pool.clone(),
                rss_audit_postgres::Integrity::Plain,
                runtime.clone(),
                binding,
                &budget.control(),
            )
            .await?,
        );
        let access_runtime = inputs.runtime("da_access").await?;
        let access_audit = Arc::new(
            audit
                .on_runtime(access_runtime.clone(), binding, &budget.control())
                .await?,
        );
        let identity_runtime = inputs.runtime("da_identity_runtime").await?;
        let proof_audit = Arc::new(
            audit
                .on_runtime(identity_runtime.clone(), binding, &budget.control())
                .await?,
        );
        let platform = Arc::new(
            rss_mdm_device_access_postgres::platform_sso::bridge::Verifier::new(&browser_origin),
        );
        let authority = rss_identity_postgres::Authority::connect_runtime(
            identity_runtime.clone(),
            Arc::new(rss_identity_core::account::PasswordKdf::new(
                std::num::NonZeroUsize::new(4).unwrap(),
                std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
            )?),
            rss_identity_postgres::AuthorityConfig::new(
                rss_identity_core::InstanceId::parse(&inputs.installation.instance_id)?,
                rss_identity_core::session::SessionPolicy::new(900, 14400)?,
                rss_audit_postgres::Integrity::Plain,
                rss_mdm_audit_integration::budget::write_budget(4)?,
            )?
            .with_platform(platform.clone()),
            binding,
            Arc::new(
                rss_mdm_authorization_service::identity_management::IdentityManagementPolicy::new(
                    DA,
                    &inputs.installation.instance_id,
                )?,
            ),
            rss_request_context::Deadline::at(std::time::Instant::now() + Duration::from_secs(10)),
        )
        .await?;
        let sessions = Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(authority.clone()),
        );
        let authorization = Arc::new(rss_mdm_authorization_service::Store::from_pool(
            DA,
            access.clone(),
            Arc::new(Timer),
        ));
        Ok(Self {
            browser_origin,
            oidc: Default::default(),
            platform,
            business: std::sync::OnceLock::new(),
            proof_audit,
            authority,
            authorization,
            inputs,
            tenant,
            operator,
            access,
            runtime,
            sessions,
            identity_runtime,
            access_runtime,
            access_audit,
            audit_pool,
        })
    }
    pub async fn close(&self) {
        self.identity_runtime.close().await;
        self.access_runtime.close().await;
        self.runtime.close().await;
        self.audit_pool.close().await;
        self.access.close().await;
        self.operator.close().await;
    }
    pub async fn seed(&self) -> Result<sqlx::Transaction<'_, sqlx::Postgres>> {
        let mut tx = self.operator.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.execution_epoch',$2,true),set_config('rss.storage_target',$3,true),set_config('rss.storage_lineage',$4,true)")
            .bind(self.tenant.to_string()).bind(self.execution().epoch().get().to_string()).bind(self.execution().storage().target().iter().map(|b|format!("{b:02x}")).collect::<String>()).bind(self.execution().storage().lineage().iter().map(|b|format!("{b:02x}")).collect::<String>())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
}
