//! Explicit operator account initialization and recovery through the Identity SDK.
use crate::{
    Error, Result,
    config::{self, Config, Database},
    host,
};

use rss_identity_core::{
    PrincipalId,
    account::{AccountKey, LoginKey, Password, PasswordKdf},
};

use rss_identity_postgres::Authority;

use rss_mdm_install_support::{StorageProfile, files::secret};

use rss_runtime::{DynManagedResource, LifecycleScope, ScopeExit, TotalDrainBudget};

use std::{path::PathBuf, sync::Arc, time::Duration};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub runtime_file: PathBuf,
    pub maintenance_database: Database,
    pub tenant: uuid::Uuid,
    pub principal: uuid::Uuid,
    pub login: String,
    pub password_file: PathBuf,
    pub operation_id: uuid::Uuid,
}
pub enum AccountOperation {
    Initialize,
    Recover,
    Authorize,
}
pub async fn account(input: Account, mode: AccountOperation) -> Result<()> {
    let config: Config = config::load(&input.runtime_file)?;

    config.validate()?;

    if input.maintenance_database.user != "da_identity_maintenance"
        || !input.maintenance_database.same_database(&config.database)
        || !config
            .installation
            .tenants()?
            .iter()
            .any(|(t, _)| t.to_string() == input.tenant.to_string())
        || input.operation_id.is_nil()
    {
        return Err(Error::Configuration);
    }
    let mut scope = LifecycleScope::<(), Error, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(30)).map_err(|_| Error::Lifecycle)?,
        Arc::new(host::Timer),
    )
    .map_err(|_| Error::Lifecycle)?;

    let outcome=scope.drive(|mut startup| {Box::pin(async move {
  let runtime=host::runtime(&input.maintenance_database,&config.installation).await?;
startup.stage_resource(DynManagedResource::new_box(host::RuntimeResource(runtime.clone())));

  let kdf=Arc::new(PasswordKdf::new());
startup.stage_resource(DynManagedResource::new_box(host::Kdf(kdf.clone())));

  let authority=Authority::connect_maintenance(runtime,kdf.clone(),host::authority_config(&config.installation,config.audit.integrity()?)?,host::deadline()).await.map_err(|_|Error::Identity)?;

  let tenant=rss_request_context::TenantId::parse(&input.tenant.to_string()).map_err(|_|Error::Configuration)?;

  let key=AccountKey{tenant,principal:PrincipalId::parse(&input.principal.to_string()).map_err(|_|Error::Configuration)?};

  let password=||Password::new(secret(&input.password_file).map_err(|_|Error::Configuration)?.to_string()).map_err(|_|Error::Configuration);

  if matches!(mode,AccountOperation::Initialize) {authority.initialize(key,LoginKey::parse(&input.login).map_err(|_|Error::Configuration)?,password()?,host::deadline()).await.map_err(|_|Error::Identity)?;
} else if matches!(mode,AccountOperation::Recover) {authority.recover_local_password(key,password()?,host::deadline()).await.map_err(|_|Error::Identity)?;
startup.commit().finish();
return Ok(())}
  let identity=host::runtime(&config.identity_database,&config.installation).await?;
startup.stage_resource(DynManagedResource::new_box(host::RuntimeResource(identity.clone())));

  let authority=Authority::connect_runtime(identity,kdf,host::authority_config(&config.installation,config.audit.integrity()?)?,Arc::new(rss_mdm_authorization_service::identity_management::IdentityManagementPolicy::new(StorageProfile::Da,&config.installation.instance.to_string()).map_err(|_|Error::Configuration)?),host::deadline()).await.map_err(|_|Error::Identity)?;

  let pool=sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(config.database.options()?).await.map_err(|_|Error::Storage)?;
startup.stage_resource(DynManagedResource::new_box(host::Pool(pool.clone())));

  let transactions=host::runtime(&config.database,&config.installation).await?;
startup.stage_resource(DynManagedResource::new_box(host::RuntimeResource(transactions.clone())));

  let budget=rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(10));

  let store=rss_mdm_audit_integration::AuditStore::new(pool,config.audit.integrity()?,transactions,tenant,&budget.control()).await.map_err(|_| Error::AdmissionAt("account Audit"))?;

  let audit=rss_mdm_audit_integration::RequestAudit::new(rss_mdm_audit_integration::Origin::Background, StorageProfile::Da,tenant.to_string(),"da_initialize",rss_mdm_audit_integration::AuditIntent::Management);

  let result=rss_mdm_authorization_service::initialization::initialize(StorageProfile::Da,&authority,&store,rss_mdm_authorization_service::initialization::Initialization{expected:rss_mdm_authorization_service::User{tenant_id:tenant.to_string(),instance_id:config.installation.instance.to_string(),principal_id:input.principal.to_string()},login:LoginKey::parse(&input.login).map_err(|_|Error::Configuration)?,password:password()?,operation_id:input.operation_id},&audit).await;

  audit.finalize(result.as_ref().err().map(|_|rss_mdm_audit_integration::FailureReason::Transaction));

  result.map_err(|_| Error::AdmissionAt("authorization initialization"))?;
startup.commit().finish();
Ok(())
 })},std::future::pending()).await.map_err(|_|Error::Lifecycle)?;

    match outcome.exit() {
        ScopeExit::Completed(Err(e)) => Err(e.clone()),
        ScopeExit::Completed(Ok(())) if outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean()) => {
            Ok(())
        }
        _ => Err(Error::Lifecycle),
    }
}
/// Assemble without binding network listeners;
// teardown uses the same resource owner as serving.
pub async fn diagnose(config: Config) -> Result<()> {
    host::validate_tls(&config)?;
    let mut scope = LifecycleScope::<(), Error, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(30)).map_err(|_| Error::Lifecycle)?,
        Arc::new(host::Timer),
    )
    .map_err(|_| Error::Lifecycle)?;

    let outcome = scope
        .drive(
            |mut startup| {
                Box::pin(async move {
                    host::assemble(&config, |r| startup.stage_resource(r)).await?;

                    startup.commit().finish();

                    Ok(())
                })
            },
            std::future::pending(),
        )
        .await
        .map_err(|_| Error::Lifecycle)?;

    match outcome.exit() {
        ScopeExit::Completed(Err(e)) => Err(e.clone()),
        ScopeExit::Completed(Ok(())) if outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean()) => {
            Ok(())
        }
        _ => Err(Error::Lifecycle),
    }
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalAccount {
    pub tenant: uuid::Uuid,
    pub principal: uuid::Uuid,
    pub login: String,
    pub password_file: PathBuf,
}
/// Verify an existing account and its exact installed authorization;
// never initialize or recover it.
pub async fn verify_account(config: &Config, input: &OriginalAccount) -> Result<()> {
    let identity_database = config.identity_database.clone();

    let database = config.database.clone();

    let installation = config.installation.clone();

    let integrity = config.audit.integrity()?;

    let input = input.clone();

    let mut scope = LifecycleScope::<(), Error, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(30)).map_err(|_| Error::Lifecycle)?,
        Arc::new(host::Timer),
    )
    .map_err(|_| Error::Lifecycle)?;

    let outcome=scope.drive(|mut startup| {Box::pin(async move {
 let runtime=host::runtime(&identity_database,&installation).await?;

 startup.stage_resource(DynManagedResource::new_box(host::RuntimeResource(runtime.clone())));

 let kdf=Arc::new(PasswordKdf::new());

 startup.stage_resource(DynManagedResource::new_box(host::Kdf(kdf.clone())));

 let result=async {
  let authority=Authority::connect_runtime(runtime.clone(),kdf.clone(),host::authority_config(&installation,integrity.clone())?,Arc::new(rss_mdm_authorization_service::identity_management::IdentityManagementPolicy::new(StorageProfile::Da,&installation.instance.to_string()).map_err(|_|Error::Configuration)?),host::deadline()).await.map_err(|_|Error::Identity)?;

  let user=rss_mdm_authorization_service::User{instance_id:installation.instance.to_string(),tenant_id:input.tenant.to_string(),principal_id:input.principal.to_string()};

  let verified=rss_mdm_authorization_service::initialization::verify_local(&authority,user,LoginKey::parse(&input.login).map_err(|_|Error::Configuration)?,Password::new(secret(&input.password_file).map_err(|_|Error::Configuration)?.to_string()).map_err(|_|Error::Configuration)?).await.map_err(|_| Error::AdmissionAt("original account authentication"))?;

  use sqlx::Connection;

  let mut c=sqlx::PgConnection::connect_with(&database.options()?).await.map_err(|_|Error::Storage)?;

  let result=async {
   let mut tx=c.begin().await.map_err(|_|Error::Storage)?;

   sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(input.tenant.to_string()).execute(&mut *tx).await.map_err(|_|Error::Storage)?;

   let rules=rss_mdm_authorization_service::snapshot_on(StorageProfile::Da,&mut tx,&input.tenant.to_string(),&installation.instance.to_string()).await.map_err(|_| Error::AdmissionAt("original authorization"))?;

   let allowed=rules.rules.iter().filter_map(|r|r.value.as_ref()).any(|r|matches!(&r.subject,rss_mdm_authorization_service::Subject::User{user} if user==verified.user())&&r.grants.iter().any(|g|g.operation==rss_mdm_authorization_service::Permission::AuthorizationWrite&&g.scope==rss_mdm_authorization_service::Scope::Tenant));

   tx.rollback().await.map_err(|_|Error::Storage)?;
if allowed{Ok(())}else{Err(Error::Admission)}
  }.await;

  let close=c.close().await.map_err(|_|Error::Storage);
result.and(close)
 }.await;

 result?;
startup.commit().finish();
Ok(())
 })},std::future::pending()).await.map_err(|_|Error::Lifecycle)?;

    match outcome.exit() {
        ScopeExit::Completed(Err(e)) => Err(e.clone()),
        ScopeExit::Completed(Ok(())) if outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean()) => {
            Ok(())
        }
        _ => Err(Error::Lifecycle),
    }
}
