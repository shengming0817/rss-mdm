//! Real embedded authority fixtures. Credentials and proofs come only from public APIs.
use crate::{config::Config, identity::Identity};
use anyhow::Result;
use rss_identity_core::{
    account::{LoginKey, Password},
    session::SessionSecret,
};
use rss_identity_postgres::AttemptSource;
use std::sync::Arc;
pub(crate) const INSTANCE: &str = "33333333-3333-4333-8333-333333333333";
pub(crate) const ADMIN: &str = "44444444-4444-4444-8444-444444444444";
pub(crate) const PASSWORD: &str = "Fixture-only-correct-horse-battery-2026!";
pub(crate) fn config(tenant: &str) -> Result<Config> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    value["identity"]["tenant_id"] = tenant.into();
    value["identity_management"] = serde_json::json!([{"tenant_id":tenant,"instance_id":INSTANCE,"principal_id":ADMIN,"permissions":["accounts","providers"]}]);
    Ok(serde_json::from_value(value)?)
}
pub(crate) async fn identity(tenant: &str) -> Result<Identity> {
    let config = config(tenant)?;
    let policy = Arc::new(
        crate::authorization::identity_management::IdentityManagementPolicy::new(
            tenant,
            INSTANCE,
            config.identity_management.clone(),
        )?,
    );
    Ok(Identity::connect(&config, policy, |_| {}).await?)
}
pub(crate) async fn login(identity: &Identity, login: &str) -> Result<SessionSecret> {
    let issued = identity
        .authority
        .login_local(
            identity.tenant,
            LoginKey::parse(login)?,
            Password::new(PASSWORD.into())?,
            AttemptSource::parse("owned-pg-fixture")?,
            None,
            crate::identity::deadline(),
        )
        .await?;
    Ok(SessionSecret::parse(issued.secret().expose().into())?)
}
pub(crate) fn credential(identity: &Identity, login: &str) -> Result<SessionSecret> {
    let config = std::path::PathBuf::from(std::env::var("MDM_TEST_CONFIG")?);
    let path = config
        .parent()
        .unwrap()
        .join(format!("credential-{}-{login}", identity.tenant));
    Ok(SessionSecret::parse(
        crate::config::secret(&path)?.to_string(),
    )?)
}
fn save(identity: &Identity, login: &str, secret: &SessionSecret) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let config = std::path::PathBuf::from(std::env::var("MDM_TEST_CONFIG")?);
    let path = config
        .parent()
        .unwrap()
        .join(format!("credential-{}-{login}", identity.tenant));
    std::fs::write(&path, secret.expose())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[tokio::test]
#[ignore = "make t2: seed through public account planning after operator initialization"]
async fn seed_accounts() -> Result<()> {
    for tenant in [
        "11111111-1111-4111-8111-111111111111",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    ] {
        let identity = identity(tenant)
            .await
            .map_err(|e| anyhow::anyhow!("identity seed admission: {e:?}"))?;
        let access = crate::Database::connect(config(tenant)?.access_database.options()?)
            .await
            .map_err(|e| anyhow::anyhow!("access seed admission: {e:?}"))?;
        crate::authorization::store::initialize_authorization(
            access.audit_store(&config(tenant)?.audit).await?.as_ref(),
            user(tenant, ADMIN),
            uuid::Uuid::new_v4(),
        )
        .await?;
        let secret = login(&identity, "admin").await?;
        save(&identity, "admin", &secret)?;
        let actor = identity
            .authority
            .authenticate_session(identity.tenant, secret, crate::identity::deadline())
            .await?;
        identity
            .authority
            .create_local_account(
                actor,
                LoginKey::parse("other")?,
                Password::new(PASSWORD.into())?,
                crate::identity::deadline(),
            )
            .await?;
        set_grants(
            tenant,
            ADMIN,
            device_grants(None, &["inventory_read", "enrollment", "credentials"])?,
        )
        .await?;
        // Each independently runnable module reuses its run-local real session.
        // Login behavior itself remains covered by identity.local.
        save(&identity, "other", &login(&identity, "other").await?)?;
    }
    Ok(())
}

pub(crate) fn user(tenant: &str, principal: &str) -> crate::authorization::User {
    crate::authorization::User {
        instance_id: INSTANCE.into(),
        tenant_id: tenant.into(),
        principal_id: principal.into(),
    }
}
pub(crate) fn device_grants(
    device: Option<&str>,
    permissions: &[&str],
) -> Result<Vec<crate::authorization::Grant>> {
    permissions
        .iter()
        .map(|p| {
            Ok(crate::authorization::Grant {
                operation: serde_json::from_value(serde_json::json!(p))?,
                scope: device.map_or(crate::authorization::Scope::AllDevices, |id| {
                    crate::authorization::Scope::Device { id: id.into() }
                }),
            })
        })
        .collect()
}
pub(crate) async fn set_grants(
    tenant: &str,
    subject: &str,
    grants: Vec<crate::authorization::Grant>,
) -> Result<()> {
    use crate::authorization::{Change, Permission, Rule, Subject};
    let identity = identity(tenant).await?;
    let access = crate::Database::connect(config(tenant)?.access_database.options()?).await?;
    let principal = crate::authorization::context::AuthorizedPrincipal::new(
        identity
            .authority
            .inspect_session(
                identity.tenant,
                credential(&identity, "admin")?,
                crate::identity::deadline(),
            )
            .await?,
    )?
    .load_authorization(&access)
    .await?;
    for record in &principal.authorization()?.rules {
        let Some(rule) = &record.value else { continue };
        if matches!(&rule.subject, Subject::User { user } if user.principal_id == subject)
            && !rule
                .grants
                .iter()
                .any(|g| g.operation == Permission::AuthorizationWrite)
        {
            let audit =
                rss_mdm_audit_integration::RequestAudit::new(tenant.into(), "authorization_write");
            principal.bind_audit(&audit)?;
            crate::authorization::store::change_rule(
                access.audit_store(&config(tenant)?.audit).await?.as_ref(),
                &principal,
                record.id,
                Change {
                    operation_id: uuid::Uuid::new_v4(),
                    expected_revision: record.revision,
                    value: None,
                },
                &audit,
            )
            .await?;
            audit.finalize(None);
        }
    }
    if !grants.is_empty() {
        let audit =
            rss_mdm_audit_integration::RequestAudit::new(tenant.into(), "authorization_write");
        principal.bind_audit(&audit)?;
        crate::authorization::store::change_rule(
            access.audit_store(&config(tenant)?.audit).await?.as_ref(),
            &principal,
            uuid::Uuid::new_v4(),
            Change {
                operation_id: uuid::Uuid::new_v4(),
                expected_revision: 0,
                value: Some(Rule {
                    subject: Subject::User {
                        user: user(tenant, subject),
                    },
                    grants,
                }),
            },
            &audit,
        )
        .await?;
        audit.finalize(None);
    }
    access.close().await;
    Ok(())
}

pub(crate) async fn audit_store(
    config: &crate::config::Config,
) -> anyhow::Result<std::sync::Arc<rss_mdm_audit_integration::AuditStore>> {
    Ok(crate::Database::connect(config.access_database.options()?)
        .await?
        .audit_store(&config.audit)
        .await?)
}
