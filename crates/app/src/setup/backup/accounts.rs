//! Restore authenticates original accounts and verifies their existing permission scope.
use super::OriginalAccount;
use crate::setup::{Error, Result};
use std::sync::Arc;
pub(super) async fn verify_restored(
    config: &crate::config::Config,
    tenant: &str,
    epoch: i64,
    account: &OriginalAccount,
    platform: bool,
) -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    let required = if platform {
        [
            Permission::TenantCreate,
            Permission::TenantRead,
            Permission::AuthorizationWrite,
        ]
    } else {
        [
            Permission::Credentials,
            Permission::RegistrationConfigurationWrite,
            Permission::AuthorizationWrite,
        ]
    };
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
        let mut c =
            sqlx::PgConnection::connect_with(&config.access_options().map_err(|_| Error::Input)?)
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
                        && r.grants.iter().any(|g| administrator_grant(g, permission))
                })
        });
        tx.rollback().await.map_err(|_| Error::Storage)?;
        c.close().await.map_err(|_| Error::Storage)?;
        if !allowed {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    .await;
    kdf.close();
    kdf.wait_closed().await;
    runtime.close().await;
    result
}

fn administrator_grant(
    grant: &rss_mdm_authorization_service::Grant,
    permission: rss_mdm_authorization_service::Permission,
) -> bool {
    use rss_mdm_authorization_service::Scope;
    grant.operation == permission
        && grant.scope
            == if permission.device() {
                Scope::AllDevices
            } else {
                Scope::Tenant
            }
}

#[cfg(test)]
mod tests {
    use super::administrator_grant;
    use rss_mdm_authorization_service::{Grant, Permission, Scope};
    #[test]
    fn restored_administrator_requires_the_complete_permission_scope() {
        let grant = |operation, scope| Grant { operation, scope };
        assert!(administrator_grant(
            &grant(Permission::Credentials, Scope::AllDevices),
            Permission::Credentials
        ));
        assert!(!administrator_grant(
            &grant(
                Permission::Credentials,
                Scope::Device {
                    id: uuid::Uuid::new_v4().to_string()
                }
            ),
            Permission::Credentials
        ));
        assert!(!administrator_grant(
            &grant(Permission::Credentials, Scope::Tenant),
            Permission::Credentials
        ));
        assert!(administrator_grant(
            &grant(Permission::AuthorizationWrite, Scope::Tenant),
            Permission::AuthorizationWrite
        ));
        assert!(!administrator_grant(
            &grant(Permission::DeviceWipe, Scope::AllDevices),
            Permission::Credentials
        ));
    }
}
