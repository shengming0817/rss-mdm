//! Restore authenticates original accounts and verifies their existing permission scope.
use super::OriginalAccount;
use crate::installation::{Error, Result};
use std::sync::Arc;
/// Read initialization facts from the restored archive using the admitted recovery administrator.
/// HTTP account/grant/child receipt commit together; the parent may still be pending.
/// CLI initialization owns a separate authorization receipt, including the management tenant.
pub(super) async fn initialized_tenants(
    c: &mut sqlx::PgConnection,
    instance: &str,
    archived: &[uuid::Uuid],
) -> Result<std::collections::BTreeSet<uuid::Uuid>> {
    let tenants: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT t.tenant_id FROM public.mdm_tenants t WHERE t.tenant_id=ANY($1) AND NOT t.deleted AND (
         EXISTS(SELECT FROM mdm_access.authorization_initializations a WHERE a.tenant_id=t.tenant_id AND a.instance=$2::uuid)
         OR EXISTS(SELECT FROM public.mdm_tenant_operations o WHERE o.tenant_id=t.tenant_id AND o.action='administrator_create' AND o.receipt->'result'->>'principalId' IS NOT NULL)) ORDER BY t.tenant_id"
    ).bind(archived).bind(instance).fetch_all(c).await.map_err(|_| Error::Storage)?;
    Ok(tenants.into_iter().collect())
}
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
        account::{LoginKey, Password},
    };
    use rss_mdm_authorization_service::{Subject, User, initialization};
    let tenant_id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Input)?;
    let instance = InstanceId::parse(&config.identity.instance_id).map_err(|_| Error::Input)?;
    let compiled = config
        .identity
        .runtime
        .compile(
            instance,
            config.audit.integrity().map_err(|_| Error::Input)?,
        )
        .map_err(|_| Error::Input)?;
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
    let cutoff = rss_request_context::Deadline::from_timeout(
        &crate::lifecycle::RuntimeTimer,
        compiled.maintenance,
    )
    .map_err(|_| Error::Input)?;
    let runtime = tokio::time::timeout_at(
        cutoff.instant().into(),
        crate::identity::open_runtime(
            &config.identity.database,
            &config.storage_binding.target,
            &config.storage_binding.lineage,
            crate::background::IDENTITY_CONNECTIONS,
        ),
    )
    .await
    .map_err(|_| Error::Storage)?
    .map_err(|_| Error::Storage)?;
    let kdf = compiled.kdf.clone();
    let binding = rss_transactional_messaging::fence::ExecutionBinding::new(
        config
            .storage_binding
            .identity()
            .map_err(|_| Error::Input)?,
        tenant_id,
        rss_transactional_messaging::fence::Epoch::new(epoch).map_err(|_| Error::Input)?,
    );
    let result = tokio::time::timeout_at(cutoff.instant().into(), async {
        let policy = Arc::new(
            crate::authorization::identity_management::IdentityManagementPolicy::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                &config.identity.instance_id,
            )
            .map_err(|_| Error::Input)?,
        );
        let authority = rss_identity_postgres::Authority::connect_runtime(
            runtime.clone(),
            kdf.clone(),
            compiled.authority,
            binding,
            policy,
            cutoff,
        )
        .await
        .map_err(|_| Error::Storage)?;
        let verified =
            initialization::verify_local(&authority, binding, user, login, password, cutoff)
                .await
                .map_err(|error| match error {
                    rss_mdm_authorization_service::Error::Unauthorized
                    | rss_mdm_authorization_service::Error::Forbidden => Error::Conflict,
                    _ => Error::Storage,
                })?;
        let mut c =
            sqlx::PgConnection::connect_with(&config.access_options().map_err(|_| Error::Input)?)
                .await
                .map_err(|_| Error::Storage)?;
        use sqlx::Connection;
        let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
        let remaining = cutoff.remaining(rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)).ok_or(Error::Storage)?;
        let milliseconds = remaining.as_millis().clamp(1, i32::MAX as u128).to_string();
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)")
            .bind(tenant)
            .bind(milliseconds)
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
        let rules = rss_mdm_authorization_service::snapshot_on(
            rss_mdm_install_support::StorageProfile::Mdm,
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
    })
    .await.unwrap_or(Err(Error::Storage));
    kdf.close();
    tokio::time::timeout(compiled.drain, async {
        tokio::join!(kdf.wait_closed(), runtime.close());
    })
    .await
    .map_err(|_| Error::Storage)?;
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
                    id: rss_mdm_agent_wire::DeviceId::new_v4()
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

#[cfg(test)]
mod t2 {
    #[tokio::test]
    #[ignore = "T2: restored-account authorization SQL shares the original deadline and releases blocked connections"]
    async fn blocked_authorization_read_expires_within_the_original_budget() -> anyhow::Result<()> {
        use crate::authority_t2_support::Context;
        use rss_mdm_authorization_service::Permission;
        use std::time::Duration;
        let c = Context::open("account_recovery", &[]).await?;
        let account = c
            .account(&[
                Permission::Credentials,
                Permission::RegistrationConfigurationWrite,
                Permission::AuthorizationWrite,
            ])
            .await?;
        let mut value: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/mdm-config.example.json"
        )))?;
        value["identity"]["database"] = serde_json::to_value(
            c.inputs
                .database("account_recovery", "mdm_identity_runtime"),
        )?;
        value["identity"]["instance_id"] = serde_json::json!(c.inputs.installation.instance_id);
        value["identity"]["runtime"]["maintenance_seconds"] = serde_json::json!(3);
        value["audit"] = serde_json::json!({"mode":"plain"});
        value["access_database"] =
            serde_json::to_value(c.inputs.database("account_recovery", "mdm_access"))?;
        value["storage_binding"] = serde_json::json!({"target":c.inputs.installation.target,"lineage":c.inputs.installation.lineage,"epoch":1});
        let config = serde_json::from_value(value)?;
        let password = tempfile::NamedTempFile::new_in(&c.inputs.directory)?;
        std::fs::write(password.path(), b"foundation-only-valid-password")?;
        let original = super::OriginalAccount {
            principal_id: account.user.principal_id.parse()?,
            login: format!("foundation-{}", account.user.principal_id),
            password_file: password.path().into(),
        };
        let mut lock = c.operator.begin().await?;
        sqlx::query("LOCK TABLE mdm_access.authorization_rules IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await?;
        let tenant = c.tenant.to_string();
        let verification = tokio::spawn(async move {
            super::verify_restored(&config, &tenant, 1, &original, false).await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='mdm_access' AND wait_event_type='Lock' AND query LIKE '%authorization_rules%')").fetch_one(&c.operator).await?;
                if blocked { return Ok::<_, anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        let result = tokio::time::timeout(Duration::from_secs(5), verification).await??;
        assert!(matches!(result, Err(crate::installation::Error::Storage)));
        lock.rollback().await?;
        c.close().await;
        Ok(())
    }
}
