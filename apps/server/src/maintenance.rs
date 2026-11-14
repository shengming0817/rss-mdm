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
    pub runtime: crate::identity::policy::RuntimePolicy,
    pub database: config::Database,
    pub audit: config::AuditConfig,
    pub installation: crate::migration::Installation,
    pub tenant_id: String,
    pub expected_epoch: i64,
    pub principal_id: String,
    pub login: Option<String>,
    pub password_file: PathBuf,
}
pub async fn run(config: Config, initialize: bool) -> Result<(), Error> {
    let cutoff = rss_request_context::Deadline::from_timeout(
        &crate::lifecycle::RuntimeTimer,
        crate::identity::policy::seconds(config.runtime.maintenance_seconds)?,
    )
    .map_err(|_| Error::Configuration(ConfigIssue::Budget))?;
    let deadline = || {
        rss_transactional_messaging::policy::OperationDeadline::from_cutoff(
            cutoff,
            &crate::lifecycle::RuntimeTimer,
        )
    };
    let invalid = || Error::Configuration(ConfigIssue::IdentityConfiguration);
    if config.database.user != "mdm_identity_maintenance" {
        return Err(invalid());
    }
    config.installation.validate().map_err(|_| invalid())?;
    if config.audit.mode() != config.installation.audit_mode {
        return Err(invalid());
    }
    let instance = InstanceId::parse(&config.installation.instance_id).map_err(|_| invalid())?;
    let compiled = config
        .runtime
        .compile(instance, config.audit.integrity()?)?;
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
        crate::background::IDENTITY_CONNECTIONS,
    )
    .await?;
    let kdf = compiled.kdf.clone();
    let result = async {
        let execution = config
            .installation
            .execution(tenant, config.expected_epoch)
            .map_err(|_| invalid())?;
        let claimed = runtime
            .local_tx_with_context(
                execution,
                deadline(),
                &config.installation,
                |installation, tx| {
                    Box::pin(async move {
                        tx.with_connection_context(installation, move |installation, c| {
                            Box::pin(async move {
                                sqlx::query_scalar::<_, bool>(
                                    "SELECT public.claim_tenant_use($1::uuid,$2,$3::uuid,$4,$5,$6)",
                                )
                                .bind(execution.tenant().to_string())
                                .bind(execution.epoch().get())
                                .bind(&installation.instance_id)
                                .bind(&installation.target[..])
                                .bind(&installation.lineage[..])
                                .bind(installation.audit_mode.as_str())
                                .fetch_one(c)
                                .await
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |_| Err(invalid()),
                |_| Err(invalid()),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(invalid()),
            )?;
        if !claimed {
            return Err(invalid());
        }
        let authority = Authority::connect_maintenance(
            runtime.clone(),
            kdf.clone(),
            compiled.authority,
            config
                .installation
                .execution(tenant, config.expected_epoch)
                .map_err(|_| invalid())?,
            deadline(),
        )
        .await
        .map_err(crate::identity::failure)?;
        if let Some(login) = login {
            authority
                .initialize(
                    config
                        .installation
                        .execution(tenant, config.expected_epoch)
                        .map_err(|_| invalid())?,
                    key,
                    login,
                    password,
                    deadline(),
                )
                .await
        } else {
            authority
                .recover_local_password(
                    config
                        .installation
                        .execution(tenant, config.expected_epoch)
                        .map_err(|_| invalid())?,
                    key,
                    password,
                    deadline(),
                )
                .await
        }
        .map_err(crate::identity::failure)?;
        Ok(())
    }
    .await;
    settle(runtime, kdf, compiled.drain, result).await
}
/// Operator execution own the same bounded KDF/runtime cleanup, including failed authentication.
pub(crate) async fn settle<T>(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    kdf: Arc<PasswordKdf>,
    drain: Duration,
    result: Result<T, Error>,
) -> Result<T, Error> {
    kdf.close();
    let (drained, closed) = tokio::join!(
        tokio::time::timeout(drain, kdf.wait_closed()),
        tokio::time::timeout(drain, runtime.close()),
    );
    let drained = drained.is_ok();
    let closed = closed.is_ok();
    if !drained || !closed {
        eprintln!(
            "{}",
            serde_json::json!({"event":"mdm_maintenance_shutdown_failure", "kdf_closed":drained, "runtime_closed":closed})
        );
    }
    match result {
        Err(error) => Err(error),
        Ok(value) if drained && closed => Ok(value),
        Ok(_) => Err(Error::Unavailable(Failure::Runtime)),
    }
}
