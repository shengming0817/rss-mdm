//! 只认证原账户；离线转交不能以重置密码替代未知结果恢复。
use crate::setup::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalAccount {
    pub principal_id: Uuid,
    pub login: String,
    pub password_file: PathBuf,
}
async fn verify_with(
    config: &crate::config::Config,
    tenant: &str,
    epoch: i64,
    account: &OriginalAccount,
    grant: Option<Uuid>,
    required: &[rss_mdm_authorization_service::Permission],
) -> Result<()> {
    use rss_identity_core::{
        InstanceId,
        account::{LoginKey, Password, PasswordKdf},
    };
    use rss_mdm_authorization_service::{Subject, User, initialization};
    let tenant_id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Input)?;
    let instance = InstanceId::parse(&config.identity.instance_id).map_err(|_| Error::Input)?;
    let login = LoginKey::parse(&account.login).map_err(|_| Error::Input)?;
    let password = Password::new(
        crate::config::secret(&account.password_file)
            .map_err(|_| Error::Input)?
            .to_string(),
    )
    .map_err(|_| Error::Input)?;
    let user = User {
        instance_id: config.identity.instance_id.clone(),
        tenant_id: tenant.into(),
        principal_id: account.principal_id.to_string(),
    };
    let runtime = crate::identity::open_runtime(
        &config.identity.database,
        &config.flow.storage.target,
        &config.flow.storage.lineage,
        &[(tenant_id, epoch)],
    )
    .await
    .map_err(|_| Error::Storage)?;
    let kdf = Arc::new(PasswordKdf::new());
    let result = async {
        let policy = Arc::new(
            crate::authorization::identity_management::IdentityManagementPolicy::new(
                &config.identity.instance_id,
            )
            .map_err(|_| Error::Input)?,
        );
        let authority = rss_identity_postgres::Authority::connect_runtime(
            runtime.clone(),
            kdf.clone(),
            crate::identity::authority_config(instance, vec![tenant_id])
                .map_err(|_| Error::Input)?,
            policy,
            crate::identity::deadline(),
        )
        .await
        .map_err(|_| Error::Storage)?;
        let verified = initialization::verify_local(&authority, user, login, password)
            .await
            .map_err(|_| Error::Conflict)?;
        let access = crate::Database::connect(config.access_options().map_err(|_| Error::Input)?)
            .await
            .map_err(|_| Error::Storage)?;
        let result = async {
            if let Some(operation) = grant {
                let audit = rss_mdm_audit_integration::RequestAudit::new(
                    tenant.into(),
                    "authorization_transfer",
                );
                let store = access
                    .audit_store(&config.audit)
                    .await
                    .map_err(|_| Error::Storage)?;
                let result = initialization::complete_verified_business_administrator(
                    &store, verified, operation, &audit,
                )
                .await
                .map_err(|_| Error::Conflict);
                audit.finalize(
                    result
                        .as_ref()
                        .err()
                        .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
                );
                result?;
            } else {
                let mut c = sqlx::PgConnection::connect_with(
                    &config.access_options().map_err(|_| Error::Input)?,
                )
                .await
                .map_err(|_| Error::Storage)?;
                use sqlx::Connection;
                let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                    .bind(tenant)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| Error::Storage)?;
                let rules = rss_mdm_authorization_service::snapshot_on(
                    &mut tx,
                    tenant,
                    &config.identity.instance_id,
                )
                .await
                .map_err(|_| Error::Storage)?;
                let allowed = required.iter().copied().all(|permission| {
                    rules
                        .rules
                        .iter()
                        .filter_map(|r| r.value.as_ref())
                        .any(|r| {
                            matches!(&r.subject,Subject::User{user} if user==verified.user())
                                && r.grants.iter().any(|g| g.covers(permission, None))
                        })
                });
                tx.rollback().await.map_err(|_| Error::Storage)?;
                c.close().await.map_err(|_| Error::Storage)?;
                if !allowed {
                    return Err(Error::Conflict);
                }
            }
            Ok(())
        }
        .await;
        access.close().await;
        result
    }
    .await;
    kdf.close();
    kdf.wait_closed().await;
    runtime.close().await;
    result
}

pub(super) async fn verify(
    config: &crate::config::Config,
    tenant: &str,
    epoch: i64,
    account: &OriginalAccount,
    grant: Option<Uuid>,
) -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    verify_with(
        config,
        tenant,
        epoch,
        account,
        grant,
        &[
            Permission::TenantCreate,
            Permission::TenantRead,
            Permission::AuthorizationWrite,
        ],
    )
    .await
}
pub(in crate::setup) async fn verify_restored(
    config: &crate::config::Config,
    tenant: &str,
    epoch: i64,
    account: &OriginalAccount,
    platform: bool,
) -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    let required = if platform {
        vec![
            Permission::TenantCreate,
            Permission::TenantRead,
            Permission::AuthorizationWrite,
        ]
    } else {
        vec![
            Permission::Credentials,
            Permission::RegistrationConfigurationWrite,
            Permission::AuthorizationWrite,
        ]
    };
    verify_with(config, tenant, epoch, account, None, &required).await
}
