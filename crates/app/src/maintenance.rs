//! Operator-only initialization and recovery through the component maintenance profile.
use crate::{ConfigIssue, Error, Failure, config};
use rss_identity_core::{
    InstanceId, PrincipalId,
    account::{AccountKey, LoginKey, Password, PasswordKdf},
};
use rss_identity_postgres::Authority;
use rss_request_context::TenantId;
use std::{path::PathBuf, sync::Arc, time::Duration};
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub database: config::Database,
    pub installation: crate::migration::Installation,
    pub tenant_id: String,
    pub principal_id: String,
    pub login: Option<String>,
    pub password_file: PathBuf,
}
pub async fn run(config: Config, initialize: bool) -> Result<(), Error> {
    let invalid = || Error::Configuration(ConfigIssue::IdentityConfiguration);
    if config.database.user != "mdm_identity_maintenance"
        || !config.installation.tenants.contains(&config.tenant_id)
    {
        return Err(invalid());
    }
    config.installation.validate().map_err(|_| invalid())?;
    let instance = InstanceId::parse(&config.installation.instance_id).map_err(|_| invalid())?;
    let tenant = TenantId::parse(&config.tenant_id).map_err(|_| invalid())?;
    let key = AccountKey {
        tenant,
        principal: PrincipalId::parse(&config.principal_id).map_err(|_| invalid())?,
    };
    let password =
        Password::new(config::secret(&config.password_file)?.to_string()).map_err(|_| invalid())?;
    let login = config
        .login
        .as_deref()
        .map(LoginKey::parse)
        .transpose()
        .map_err(|_| invalid())?;
    if initialize != login.is_some() {
        return Err(invalid());
    }
    let runtime = crate::identity::open_runtime(
        &config.database,
        &config.installation.target,
        &config.installation.lineage,
        config.installation.epoch,
        tenant,
    )
    .await?;
    let kdf = Arc::new(PasswordKdf::new());
    let result = async {
        let authority = Authority::connect_maintenance(
            runtime.clone(),
            kdf.clone(),
            crate::identity::authority_config(instance, tenant)?,
            crate::identity::deadline(),
        )
        .await
        .map_err(crate::identity::failure)?;
        if let Some(login) = login {
            authority
                .initialize(key, login, password, crate::identity::deadline())
                .await
        } else {
            authority
                .recover_local_password(key, password, crate::identity::deadline())
                .await
        }
        .map_err(crate::identity::failure)?;
        Ok(())
    }
    .await;
    kdf.close();
    let drained = tokio::time::timeout(Duration::from_secs(5), kdf.wait_closed())
        .await
        .is_ok();
    let closed = tokio::time::timeout(Duration::from_secs(5), runtime.close())
        .await
        .is_ok();
    match result {
        Err(error) => Err(error),
        Ok(()) if drained && closed => Ok(()),
        Ok(()) => Err(Error::Unavailable(Failure::Runtime)),
    }
}
