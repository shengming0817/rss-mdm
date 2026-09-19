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
    value["bindings"] = serde_json::json!([{"tenant_id":tenant,"instance_id":INSTANCE,"principal_id":ADMIN,
        "roles":["mdm_admin"],"devices":["*"],"management":[],"identity_management":["accounts","providers"],
        "allow_wipe":false,"allow_enrollment":true,"allow_manage_credentials":true}]);
    Ok(serde_json::from_value(value)?)
}
pub(crate) async fn identity(tenant: &str) -> Result<Identity> {
    let config = config(tenant)?;
    let policy = Arc::new(crate::access::Policy::new(
        tenant,
        INSTANCE,
        config.bindings.clone(),
    )?);
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
#[ignore = "make t2: seed through public account management after operator initialization"]
async fn seed_accounts() -> Result<()> {
    for tenant in [
        "11111111-1111-4111-8111-111111111111",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    ] {
        let identity = identity(tenant).await?;
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
        // Protocol/store tests use this tenant's real credential. The HTTP tenant
        // performs its own logins so fixture setup does not consume its attempt budget.
        if tenant == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
            save(&identity, "other", &login(&identity, "other").await?)?;
        }
    }
    Ok(())
}
