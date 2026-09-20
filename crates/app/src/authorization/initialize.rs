use super::{Receipt, User, canonical_uuid};
use crate::{AccessStore, ConfigIssue, Error, config, identity};
use rss_identity_core::{
    InstanceId,
    account::{LoginKey, Password, PasswordKdf},
    session::SessionSecret,
};
use rss_identity_postgres::{AttemptSource, Authority};
use rss_request_context::TenantId;
use std::{path::PathBuf, sync::Arc};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Initialize {
    pub database: config::Database,
    pub identity_database: config::Database,
    pub installation: crate::migration::Installation,
    pub login: String,
    pub password_file: PathBuf,
    pub operation_id: uuid::Uuid,
    pub user: User,
}
/// Explicit operator command. The target must authenticate against this installed Identity.
/// No caller-selected UUID can permanently seed a rule for an absent or foreign account.
pub async fn initialize(config: Initialize) -> Result<Receipt, Error> {
    if config.database.user != "mdm_access" {
        return Err(Error::Configuration(ConfigIssue::AccessDatabase));
    }
    if config.operation_id.is_nil() {
        return Err(Error::Malformed);
    }
    canonical_uuid(&config.user.instance_id)?;
    canonical_uuid(&config.user.tenant_id)?;
    config
        .user
        .validate(&config.user.tenant_id, &config.user.instance_id)?;
    let invalid = || Error::Configuration(ConfigIssue::IdentityConfiguration);
    if config.identity_database.user != "mdm_identity_runtime"
        || config.identity_database.host != config.database.host
        || config.identity_database.port != config.database.port
        || config.identity_database.name != config.database.name
        || config.installation.instance_id != config.user.instance_id
        || !config.installation.tenants.contains(&config.user.tenant_id)
    {
        return Err(invalid());
    }
    config.installation.validate().map_err(|_| invalid())?;
    let tenant = TenantId::parse(&config.user.tenant_id).map_err(|_| invalid())?;
    let instance = InstanceId::parse(&config.user.instance_id).map_err(|_| invalid())?;
    let login = LoginKey::parse(&config.login).map_err(|_| invalid())?;
    let password =
        Password::new(config::secret(&config.password_file)?.to_string()).map_err(|_| invalid())?;
    let runtime = identity::open_runtime(
        &config.identity_database,
        &config.installation.target,
        &config.installation.lineage,
        config.installation.epoch,
        tenant,
    )
    .await?;
    let kdf = Arc::new(PasswordKdf::new());
    let verified = async {
        let policy = Arc::new(crate::access::IdentityManagementPolicy::new(
            &config.user.tenant_id,
            &config.user.instance_id,
            vec![],
        )?);
        let authority = Authority::connect_runtime(
            runtime.clone(),
            kdf.clone(),
            identity::authority_config(instance, tenant)?,
            policy,
            identity::deadline(),
        )
        .await
        .map_err(identity::failure)?;
        let issued = authority
            .login_local(
                tenant,
                login,
                password,
                AttemptSource::parse("authorization-initialization").map_err(|_| invalid())?,
                None,
                identity::deadline(),
            )
            .await
            .map_err(identity::failure)?;
        let session = authority
            .inspect_session(
                tenant,
                SessionSecret::parse(issued.secret().expose().into()).map_err(|_| invalid())?,
                identity::deadline(),
            )
            .await
            .map_err(identity::failure)?;
        let user = User {
            instance_id: session.instance().to_string(),
            tenant_id: session.account().tenant.to_string(),
            principal_id: session.account().principal.as_uuid().to_string(),
        };
        // Bootstrap never leaves a transferable login credential behind.
        authority
            .revoke_current_session(session, identity::deadline())
            .await
            .map_err(identity::failure)?;
        if user != config.user {
            return Err(Error::Forbidden);
        }
        Ok(user)
    }
    .await;
    let user = crate::maintenance::settle(runtime, kdf, verified).await?;
    let store = AccessStore::connect(config.database.options()?).await?;
    let result = store
        .initialize_authorization(user, config.operation_id)
        .await;
    store.close().await;
    result
}
