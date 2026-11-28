//! Legal tenant, subject and connection inputs shared by real product consumer proofs.
use crate::{config, identity, migration};
use anyhow::{Context as _, Result};
use rss_identity_core::{
    InstanceId,
    account::{LoginKey, Password, PasswordKdf},
};
use rss_identity_postgres::{AttemptSource, Authority};
use rss_mdm_audit_integration::{AuditIntent, AuditStore, RequestAudit};
use rss_mdm_authorization_service::{self as access, Permission, User};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::PgRuntime;
use serde::Deserialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use uuid::Uuid;

pub fn identity_cutoff() -> rss_request_context::Deadline {
    rss_request_context::Deadline::from_timeout(
        &rss_mdm_audit_integration::budget::RuntimeTimer,
        Duration::from_secs(10),
    )
    .expect("bounded fixture deadline")
}

pub fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(10))
}

#[derive(Deserialize)]
pub struct Inputs {
    pub installation: migration::Installation,
    pub databases: BTreeMap<String, BTreeMap<String, config::Database>>,
    pub directory: PathBuf,
}
impl Inputs {
    pub fn load() -> Result<Self> {
        let path = std::env::var("RSS_MDM_T2_ENV")?;
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
    pub fn database(&self, profile: &str, role: &str) -> config::Database {
        self.databases[profile][role].clone()
    }
    pub fn installation(&self) -> migration::Installation {
        migration::Installation {
            audit_mode: self.installation.audit_mode,
            instance_id: self.installation.instance_id.clone(),
            target: self.installation.target,
            lineage: self.installation.lineage,
        }
    }
    pub fn options(&self, profile: &str, role: &str) -> Result<sqlx::postgres::PgConnectOptions> {
        Ok(self.database(profile, role).options()?.options([
            (
                "rss.storage_target",
                self.installation
                    .target
                    .iter()
                    .map(|v| format!("{v:02x}"))
                    .collect::<String>(),
            ),
            (
                "rss.storage_lineage",
                self.installation
                    .lineage
                    .iter()
                    .map(|v| format!("{v:02x}"))
                    .collect::<String>(),
            ),
            ("rss.execution_epoch", "1".to_owned()),
        ]))
    }
    pub async fn pool(&self, profile: &str, role: &str) -> Result<PgPool> {
        Ok(PgPoolOptions::new()
            .max_connections(2)
            .connect_with(self.options(profile, role)?)
            .await?)
    }
}

pub struct Context {
    pub inputs: Inputs,
    pub profile: String,
    pub tenant: TenantId,
    pub operator: PgPool,
    pub database: crate::Database,
    pub runtime: Arc<PgRuntime>,
    identity_runtime: Arc<PgRuntime>,
    pub authority: Authority,
    kdf: Arc<PasswordKdf>,
    pub audit: Arc<AuditStore>,
}
pub fn telemetry_intake(
    binding: rss_transactional_messaging::fence::ExecutionBinding,
) -> rss_mdm_telemetry_service::IntakeRequest {
    let budget = std::sync::Arc::new(rss_mdm_audit_integration::budget::AuditBudget::new(
        std::time::Duration::from_secs(12),
    ));
    rss_mdm_telemetry_service::IntakeRequest {
        deadline: budget.deadline(),
        cancellation: budget,
        audit: rss_mdm_audit_integration::RequestAudit::new(
            rss_mdm_audit_integration::Origin::Request,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            binding,
            "telemetry",
            rss_mdm_audit_integration::AuditIntent::Routine,
        ),
    }
}
impl Context {
    pub fn execution(&self) -> rss_transactional_messaging::fence::ExecutionBinding {
        use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
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

    pub async fn open(profile: &str, additional_tenants: &[TenantId]) -> Result<Self> {
        let inputs = Inputs::load()?;
        let operator = inputs.pool(profile, "postgres").await?;
        let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
        seed_tenant(&operator, tenant).await?;
        for additional in additional_tenants {
            seed_tenant(&operator, *additional).await?;
        }
        Self::connect(
            profile,
            inputs,
            operator,
            tenant,
            &config::AuditConfig::Plain,
        )
        .await
    }
    pub async fn open_with_audit(profile: &str, audit: &config::AuditConfig) -> Result<Self> {
        let mut inputs = Inputs::load()?;
        inputs.installation.audit_mode = audit.mode();
        let operator = inputs.pool(profile, "postgres").await?;
        let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
        seed_tenant(&operator, tenant).await?;
        Self::connect(profile, inputs, operator, tenant, audit).await
    }
    pub async fn management(profile: &str) -> Result<Self> {
        let inputs = Inputs::load()?;
        let operator = inputs.pool(profile, "postgres").await?;
        let tenant = identity::management_tenant(
            &inputs.database(profile, "mdm_identity_runtime"),
            InstanceId::parse(&inputs.installation.instance_id)?,
        )
        .await?;
        sqlx::query("INSERT INTO identity_authority.tenants(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING")
            .bind(tenant.to_string()).execute(&operator).await?;
        Self::connect(
            profile,
            inputs,
            operator,
            tenant,
            &config::AuditConfig::Plain,
        )
        .await
    }
    pub(crate) async fn connect(
        profile: &str,
        inputs: Inputs,
        operator: PgPool,
        tenant: TenantId,
        audit_config: &config::AuditConfig,
    ) -> Result<Self> {
        let database =
            crate::Database::connect(inputs.options(profile, "mdm_access")?, audit_config)
                .await
                .map_err(|e| anyhow::anyhow!("MDM connection admission: {e:?}"))?;
        let runtime = identity::open_runtime(
            &inputs.database(profile, "mdm_access"),
            &inputs.installation.target,
            &inputs.installation.lineage,
            4,
        )
        .await
        .map_err(|e| anyhow::anyhow!("MDM messaging runtime: {e:?}"))?;
        let binding = inputs.installation.execution(tenant, 1)?;
        let policy = identity::policy::RuntimePolicy::installation();
        let compiled = policy.compile(
            InstanceId::parse(&inputs.installation.instance_id)?,
            audit_config.integrity()?,
        )?;
        let audit = database
            .audit_store(
                audit_config,
                compiled.write_budget.clone(),
                runtime.clone(),
                binding,
            )
            .await?;
        let identity_runtime = identity::open_runtime(
            &inputs.database(profile, "mdm_identity_runtime"),
            &inputs.installation.target,
            &inputs.installation.lineage,
            4,
        )
        .await?;
        let kdf = compiled.kdf.clone();
        let authority = Authority::connect_runtime(
            identity_runtime.clone(),
            kdf.clone(),
            compiled.authority,
            binding,
            Arc::new(access::identity_management::IdentityManagementPolicy::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                &inputs.installation.instance_id,
            )?),
            crate::authority_t2_support::identity_cutoff(),
        )
        .await?;
        Ok(Self {
            inputs,
            profile: profile.to_owned(),
            tenant,
            operator,
            database,
            runtime,
            identity_runtime,
            authority,
            kdf,
            audit,
        })
    }
    pub fn access(&self) -> Arc<access::Store> {
        self.database.authorization_store()
    }
    pub fn user(&self, principal: Uuid) -> User {
        User {
            instance_id: self.inputs.installation.instance_id.clone(),
            tenant_id: self.tenant.to_string(),
            principal_id: principal.to_string(),
        }
    }
    pub async fn authority_with_policy(
        &self,
        policy: &crate::identity::policy::RuntimePolicy,
    ) -> Result<Authority> {
        Ok(Authority::connect_runtime(
            self.identity_runtime.clone(),
            self.kdf.clone(),
            policy
                .compile(
                    InstanceId::parse(&self.inputs.installation.instance_id)?,
                    self.audit.integrity().clone(),
                )?
                .authority,
            self.execution(),
            Arc::new(access::identity_management::IdentityManagementPolicy::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                &self.inputs.installation.instance_id,
            )?),
            crate::authority_t2_support::identity_cutoff(),
        )
        .await?)
    }
    pub async fn account(&self, permissions: &[Permission]) -> Result<Account> {
        let principal = Uuid::new_v4();
        let login = format!("foundation-{principal}");
        let password = "foundation-only-valid-password";
        let hash = self.kdf.hash(Password::new(password.into())?).await?;
        seed_account(
            &self.operator,
            self.tenant,
            principal,
            &login,
            hash.as_str(),
        )
        .await?;
        let rule = Uuid::new_v4();
        seed_rule(&self.operator, &self.user(principal), rule, permissions).await?;
        let issued = self
            .authority
            .login_local(
                self.execution(),
                LoginKey::parse(&login)?,
                Password::new(password.into())?,
                AttemptSource::parse("foundation-t2")?,
                None,
                crate::authority_t2_support::identity_cutoff(),
            )
            .await?;
        Ok(Account {
            user: self.user(principal),
            rule,
            secret: issued.secret().expose().to_owned(),
        })
    }
    pub async fn authenticate(
        &self,
        account: &Account,
    ) -> Result<access::context::AuthorizedPrincipal> {
        Ok(
            access::session::SessionAuthority::new(self.authority.clone())
                .authenticate(
                    self.execution(),
                    &self.access(),
                    account.credential()?,
                    crate::authority_t2_support::identity_cutoff(),
                )
                .await?,
        )
    }
    /// Observe the actual PostgreSQL wait graph; elapsed time is never a synchronization signal.
    pub async fn wait_blocked(&self, pid: i32) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))").bind(pid).fetch_one(&self.operator).await?;
                if blocked { return Ok::<_,anyhow::Error>(()); }
                tokio::task::yield_now().await;
            }
        }).await?
    }
    pub fn read_auth(
        &self,
        proof: Arc<access::context::AuthorizedPrincipal>,
    ) -> access::context::RequestAuth {
        let budget = Arc::new(rss_mdm_audit_integration::budget::AuditBudget::new(
            Duration::from_secs(8),
        ));
        access::context::RequestAuth {
            proof,
            sessions: access::session::SessionAuthority::new(self.authority.clone()),
            deadline: budget.deadline().instant(),
            cancellation: budget,
        }
    }
    pub fn request(&self, proof: &access::context::AuthorizedPrincipal) -> Result<RequestAudit> {
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Request,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            self.execution(),
            "foundation",
            AuditIntent::Management,
        );
        proof.bind_audit(&audit)?;
        Ok(audit)
    }
    pub async fn audit_count(&self, source: &str, coordinate: &str) -> Result<i64> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT canonical FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id=$2",
        )
        .bind(self.tenant.to_string())
        .bind(source)
        .fetch_all(&self.operator)
        .await?;
        let mut count = 0;
        for bytes in rows {
            let decoded = rss_audit_core::decode_untrusted(&bytes)?;
            let coordinates = decoded.event().context().coordinates();
            let id = if source == "mdm.business" {
                coordinates.operation_id().map(|id| id.as_str())
            } else {
                coordinates.request_id().map(|id| id.as_str())
            };
            count += i64::from(id == Some(coordinate));
        }
        Ok(count)
    }
    pub async fn authority_valid(
        &self,
        authority: &access::OperationAuthority,
        permission: Permission,
    ) -> Result<bool> {
        // The SQL authority predicate consumes the caller's real scoped transaction.
        let mut tx = self.database.archive_pool().begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(self.tenant.to_string())
            .execute(&mut *tx)
            .await?;
        let now = sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::bigint")
            .fetch_one(&mut *tx)
            .await?;
        let valid = authority
            .valid(
                rss_mdm_install_support::StorageProfile::Mdm,
                &mut tx,
                permission,
                now,
            )
            .await?;
        tx.rollback().await?;
        Ok(valid)
    }
    pub async fn disable_audit(&self) -> Result<()> {
        sqlx::raw_sql("REVOKE EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) FROM mdm_access")
            .execute(&self.operator).await?;
        Ok(())
    }
    pub async fn close(self) {
        self.database.close().await;
        self.runtime.close().await;
        self.identity_runtime.close().await;
        self.kdf.close();
        self.kdf.wait_closed().await;
        self.operator.close().await;
    }
}

pub struct Account {
    pub user: User,
    pub rule: Uuid,
    secret: String,
}
impl Account {
    pub fn cookie_session(&self) -> Result<rss_identity_core::session::SessionSecret> {
        Ok(rss_identity_core::session::SessionSecret::parse(
            self.secret.clone(),
        )?)
    }
    pub fn credential(&self) -> Result<access::credential::RequestCredential> {
        Ok(access::credential::RequestCredential::Cookie(
            self.cookie_session()?,
        ))
    }
}

pub async fn seed_tenant(pool: &PgPool, tenant: TenantId) -> Result<()> {
    // Legal rows, not another test or the registration/initialization journey.
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO public.mdm_tenants(tenant_id,initial_epoch,name) VALUES($1::uuid,1,'Foundation isolated tenant')")
        .bind(tenant.to_string()).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO rss_transactional_messaging.tenant_epoch(tenant_id,epoch) VALUES($1::uuid,1)",
    )
    .bind(tenant.to_string())
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO identity_authority.tenants(tenant_id) VALUES($1::uuid)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn seed_account(
    pool: &PgPool,
    tenant: TenantId,
    principal: Uuid,
    login: &str,
    hash: &str,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO identity_authority.tenants(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING",
    )
    .bind(tenant.to_string())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO identity_authority.accounts(tenant_id,principal_id) VALUES($1::uuid,$2)",
    )
    .bind(tenant.to_string())
    .bind(principal)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO identity_authority.local_credentials(tenant_id,principal_id,login_key,password_hash) VALUES($1::uuid,$2,$3,$4)")
        .bind(tenant.to_string()).bind(principal).bind(login).bind(hash).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO identity_authority.memberships(tenant_id,principal_id) VALUES($1::uuid,$2)",
    )
    .bind(tenant.to_string())
    .bind(principal)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn seed_rule(
    pool: &PgPool,
    user: &User,
    id: Uuid,
    permissions: &[Permission],
) -> Result<()> {
    let rule = access::Rule {
        subject: access::Subject::User { user: user.clone() },
        grants: permissions
            .iter()
            .map(|operation| access::Grant {
                operation: *operation,
                scope: if operation.device() {
                    access::Scope::AllDevices
                } else {
                    access::Scope::Tenant
                },
            })
            .collect(),
    };
    rule.validate(&user.tenant_id, &user.instance_id)?;
    sqlx::query("INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3,1,$4)")
        .bind(&user.tenant_id).bind(&user.instance_id).bind(id).bind(serde_json::to_value(rule)?)
        .execute(pool).await?;
    Ok(())
}

/// Current host policy for focused fixtures that do not open a complete application.
pub(crate) fn background() -> Result<crate::background::Compiled> {
    let config: crate::config::Config =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
    Ok(config.background.compile(&config)?)
}
pub(crate) fn inventory_policy() -> Result<rss_mdm_inventory_service::inventory_runtime::Policy> {
    let config: crate::config::Config =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
    Ok(config.inventory_runtime.compile()?)
}

/// Identify the exact PostgreSQL transaction waiting on a held business row.
pub(crate) async fn blocked_attempt(
    pool: &PgPool,
    blocker: i32,
    statement: &str,
) -> Result<Option<(i32, String)>> {
    Ok(sqlx::query_as("SELECT pid,extract(epoch FROM xact_start)::text FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND strpos(query,$2)>0 ORDER BY pid LIMIT 1")
        .bind(blocker).bind(statement).fetch_optional(pool).await?)
}
pub(crate) async fn wait_for_blocked_attempt(
    pool: &PgPool,
    blocker: i32,
    statement: &str,
) -> Result<(i32, String)> {
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        loop {
            if let Some(attempt) = blocked_attempt(pool, blocker, statement).await? {
                return Ok(attempt);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .with_context(|| format!("owner did not wait on {statement}"))?
}
