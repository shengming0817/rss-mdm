use crate::{ConfigIssue, Error, Failure, config, identity};
use rss_identity_core::{
    InstanceId,
    account::{LoginKey, Password, PasswordKdf},
};
use rss_identity_postgres::Authority;
use rss_mdm_authorization_service::{Receipt, User, canonical_uuid};
use rss_request_context::{Deadline, TenantId};
use std::{path::PathBuf, sync::Arc, time::Duration};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Initialize {
    pub profile: rss_mdm_install_support::StorageProfile,
    pub database: config::Database,
    pub audit: config::AuditConfig,
    pub identity_database: config::Database,
    pub installation: crate::migration::Installation,
    pub expected_epoch: i64,
    pub login: String,
    pub password_file: PathBuf,
    pub operation_id: uuid::Uuid,
    pub user: User,
}
impl Initialize {
    fn validate(&self) -> Result<(), Error> {
        if self.database.user
            != match self.profile {
                rss_mdm_install_support::StorageProfile::Mdm => "mdm_access",
                rss_mdm_install_support::StorageProfile::Da => "da_access",
            }
        {
            return Err(Error::Configuration(ConfigIssue::AccessDatabase));
        }
        if self.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        canonical_uuid(&self.user.instance_id)?;
        canonical_uuid(&self.user.tenant_id)?;
        self.user
            .validate(&self.user.tenant_id, &self.user.instance_id)?;
        let invalid = || Error::Configuration(ConfigIssue::IdentityConfiguration);
        if self.identity_database.user != "mdm_identity_runtime"
            || self.identity_database.host != self.database.host
            || self.identity_database.port != self.database.port
            || self.identity_database.name != self.database.name
            || self.installation.instance_id != self.user.instance_id
        {
            return Err(invalid());
        }
        self.installation.validate().map_err(|_| invalid())?;
        Ok(())
    }
}

/// Explicit operator command. The target must authenticate against this installed Identity.
/// No caller-selected UUID can permanently seed a rule for an absent or foreign account.
pub async fn initialize(config: Initialize) -> Result<Receipt, Error> {
    let clock = crate::lifecycle::RuntimeTimer;
    let deadline =
        Deadline::from_timeout(&clock, Duration::from_secs(30)).expect("bounded command budget");
    let audit = RequestAudit::new(
        config.profile,
        config.user.tenant_id.clone(),
        "authorization_initialize",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.operation(
        config.operation_id,
        "authorization_initialize",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let mut owned = Resources {
        runtime: None,
        source_runtime: None,
        access: None,
        kdf: Arc::new(PasswordKdf::new()),
    };
    // One total deadline, reserving five seconds for resources owned by this command.
    let mut result = bounded(
        &audit,
        deadline.capped(&clock, Duration::from_secs(25)),
        initialize_owned(config, &mut owned, &audit),
    )
    .await;
    owned.kdf.close();
    let cleanup = async {
        tokio::join!(
            owned.kdf.wait_closed(),
            async {
                if let Some(runtime) = &owned.runtime {
                    runtime.close().await;
                }
            },
            async {
                if let Some(runtime) = &owned.source_runtime {
                    runtime.close().await;
                }
                if let Some(access) = &owned.access {
                    access.close().await;
                }
            }
        );
    };
    if tokio::time::timeout_at(deadline.instant().into(), cleanup)
        .await
        .is_err()
    {
        eprintln!(
            "{}",
            serde_json::json!({"event":"mdm_authorization_shutdown_failure","operation_id":audit.snapshot().operation_id,"write_outcome":audit.snapshot().write_outcome})
        );
        if result.is_ok() {
            result = Err(crate::error_projection::audit_deadline(
                audit.snapshot().write_outcome,
            ));
        }
    }
    audit.finalize(result.as_ref().err().map(|_| FailureReason::Transaction));
    result
}
struct Resources {
    source_runtime: Option<Arc<rss_transactional_messaging_postgres::PgRuntime>>,
    runtime: Option<Arc<rss_transactional_messaging_postgres::PgRuntime>>,
    kdf: Arc<PasswordKdf>,
    access: Option<sqlx::PgPool>,
}
pub(crate) async fn bounded<T, E: Into<Error>>(
    audit: &RequestAudit,
    deadline: Deadline,
    work: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, Error> {
    tokio::time::timeout_at(deadline.instant().into(), work)
        .await
        .map_err(|_| crate::error_projection::audit_deadline(audit.snapshot().write_outcome))?
        .map_err(Into::into)
}
async fn initialize_owned(
    config: Initialize,
    owned: &mut Resources,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    config.validate()?;
    let invalid = || Error::Configuration(ConfigIssue::IdentityConfiguration);
    let tenant = TenantId::parse(&config.user.tenant_id).map_err(|_| invalid())?;
    let instance = InstanceId::parse(&config.user.instance_id).map_err(|_| invalid())?;
    let login = LoginKey::parse(&config.login).map_err(|_| invalid())?;
    let password =
        Password::new(config::secret(&config.password_file)?.to_string()).map_err(|_| invalid())?;
    crate::administration::tenants::claim_database_use(
        &config.identity_database,
        &config.installation,
        &config.user.tenant_id,
        config.expected_epoch,
    )
    .await?;
    owned.runtime = Some(
        identity::open_runtime(
            &config.identity_database,
            &config.installation.target,
            &config.installation.lineage,
            &[(tenant, config.expected_epoch)],
            crate::background::IDENTITY_CONNECTIONS,
        )
        .await?,
    );
    let runtime = owned
        .runtime
        .as_ref()
        .ok_or(Error::Unavailable(Failure::Runtime))?;
    let authority = async {
        let policy = Arc::new(
            crate::authorization::identity_management::IdentityManagementPolicy::new(
                config.profile,
                &config.user.instance_id,
            )?,
        );
        let authority = Authority::connect_runtime(
            runtime.clone(),
            owned.kdf.clone(),
            identity::authority_config(instance, vec![tenant], config.audit.integrity()?)?,
            policy,
            identity::deadline(),
        )
        .await
        .map_err(identity::failure)?;
        Ok::<_, Error>(authority)
    }
    .await?;
    owned.access = Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(2))
            .connect_with(config.database.options()?)
            .await
            .map_err(crate::database::db)?,
    );
    let database = owned
        .access
        .as_ref()
        .ok_or(Error::Unavailable(Failure::Database))?;
    admit(database, &config).await?;
    let source_runtime = identity::open_runtime(
        &config.database,
        &config.installation.target,
        &config.installation.lineage,
        &[(tenant, config.expected_epoch)],
        crate::background::IDENTITY_CONNECTIONS,
    )
    .await?;
    owned.source_runtime = Some(source_runtime.clone());
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let store = rss_mdm_audit_integration::AuditStore::new(
        database.clone(),
        config.audit.integrity()?,
        source_runtime,
        tenant,
        &budget.control(),
    )
    .await?;
    let pool = database.clone();
    let management: String =
        sqlx::query_scalar("SELECT management_tenant_id::text FROM public.mdm_installation")
            .fetch_one(&pool)
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
    let input = rss_mdm_authorization_service::initialization::Initialization {
        expected: config.user,
        login,
        password,
        operation_id: config.operation_id,
    };
    if config.profile == rss_mdm_install_support::StorageProfile::Da
        || input.expected.tenant_id == management
    {
        return rss_mdm_authorization_service::initialization::initialize(
            config.profile,
            &authority,
            &store,
            input,
            audit,
        )
        .await
        .map_err(Error::from);
    }
    let tenant = uuid::Uuid::parse_str(&input.expected.tenant_id).map_err(|_| Error::Malformed)?;
    let targets = crate::administration::baseline::manifest::build(tenant)?.targets();
    let (receipt, frozen) = rss_mdm_authorization_service::initialization::initialize_baseline(
        rss_mdm_install_support::StorageProfile::Mdm,
        &authority,
        &store,
        input,
        audit,
        targets,
    )
    .await?;
    crate::administration::baseline::reserve(&pool, &store, frozen).await?;
    Ok(receipt)
}

async fn admit(database: &sqlx::PgPool, config: &Initialize) -> Result<(), Error> {
    match config.profile {
        rss_mdm_install_support::StorageProfile::Mdm => {
            crate::database::admission(database, &config.audit).await?
        }
        rss_mdm_install_support::StorageProfile::Da => {
            let mut c = database.acquire().await.map_err(crate::database::db)?;
            crate::migration::device_access::verify_runtime(&mut c)
                .await
                .map_err(crate::database::db)?;
            crate::migration::device_access::verify_access(&mut c, &config.audit)
                .await
                .map_err(crate::database::db)?;
        }
    }
    Ok(())
}

use rss_mdm_audit_integration::{FailureReason, RequestAudit};

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn pending_initialization_projects_request_deadline() {
        let audit = super::RequestAudit::new(
            rss_mdm_audit_integration::StorageProfile::Mdm,
            uuid::Uuid::new_v4().to_string(),
            "authorization_initialize",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let deadline = rss_request_context::Deadline::from_timeout(
            &crate::lifecycle::RuntimeTimer,
            std::time::Duration::ZERO,
        )
        .unwrap();
        let result = super::bounded(
            &audit,
            deadline,
            std::future::pending::<Result<(), crate::Error>>(),
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::Error::Unavailable(crate::Failure::RequestDeadline))
        ));
        audit.finalize(Some(super::FailureReason::Transaction));
    }
}
