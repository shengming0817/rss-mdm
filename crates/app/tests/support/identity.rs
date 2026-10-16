//! Real embedded authority fixtures. Credentials and proofs come only from public APIs.
//! ref: rss-identity crates/identity-postgres/src/provisioning.rs@ad44649c8a6cbd8ab2c2e01e2858241ad7f18a37.
use crate::{config::Config, identity::Identity};
use anyhow::{Context, Result};
use rss_identity_core::{
    account::{LoginKey, Password},
    session::SessionSecret,
};
use rss_identity_postgres::AttemptSource;
use std::sync::Arc;
pub(crate) const INSTANCE: &str = "33333333-3333-4333-8333-333333333333";
const BOOTSTRAP: &str = "44444444-4444-4444-8444-444444444444";
pub(crate) const PASSWORD: &str = "Fixture-only-correct-horse-battery-2026!";
pub(crate) fn config(tenant: &str) -> Result<Config> {
    configured(tenant)
}
fn configured(tenant: &str) -> Result<Config> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    value["identity"]["tenant_id"] = tenant.into();
    Ok(serde_json::from_value(value)?)
}
pub(crate) async fn identity(tenant: &str) -> Result<Identity> {
    identity_with(config(tenant)?).await
}
async fn identity_with(config: Config) -> Result<Identity> {
    let policy = Arc::new(
        crate::authorization::identity_management::IdentityManagementPolicy::new(INSTANCE)?,
    );
    Ok(Identity::connect(&config, policy, |_| {}).await?)
}
pub(crate) async fn login(identity: &Identity, login: &str) -> Result<SessionSecret> {
    login_named(identity, super::case::login(login)).await
}
async fn login_named(identity: &Identity, login: &str) -> Result<SessionSecret> {
    let issued = identity
        .authority
        .login_local(
            identity.tenant,
            LoginKey::parse(login)?,
            Password::new(PASSWORD.into())?,
            AttemptSource::parse(&format!("t2-{}-{login}", identity.tenant))?,
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
pub(crate) fn age_prepared_admin_session() -> Result<()> {
    // Model a case waiting in the run queue beyond Recent(300s), only for its own actor.
    super::pg(&format!(
        "UPDATE identity_authority.sessions SET auth_time=auth_time-301,absolute_expires_at=absolute_expires_at-301 WHERE tenant_id='{}' AND principal_id='{}'",
        super::case::tenant(),
        super::case::admin()
    ))?;
    Ok(())
}
fn write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
fn save(root: &std::path::Path, tenant: &str, login: &str, secret: &SessionSecret) -> Result<()> {
    write(
        &root.join(format!("credential-{tenant}-{login}")),
        secret.expose().as_bytes(),
    )
}
#[derive(serde::Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
enum Setup {
    Environment,
    AgentTrust,
    Refresh,
    Accounts {
        cases: Vec<std::path::PathBuf>,
        management: String,
        source_secret: std::path::PathBuf,
        provisioning_database: crate::config::Database,
    },
    Sessions {
        cases: Vec<std::path::PathBuf>,
    },
}

#[tokio::test]
#[ignore = "make t2: prepare only admitted case actors through the public authority"]
async fn prepare_identity() -> Result<()> {
    let manifest: Setup =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_IDENTITY_SETUP")?)?)?;
    let config_path = std::path::PathBuf::from(std::env::var("MDM_TEST_CONFIG")?);
    let root = config_path.parent().unwrap();
    let costs = match manifest {
        Setup::Environment => {
            prepare_environment(root).await?;
            Vec::new()
        }
        Setup::AgentTrust => {
            let config: Config = serde_json::from_slice(&std::fs::read(&config_path)?)?;
            let tenant = rss_request_context::TenantId::parse(&config.identity.tenant_id)?;
            let access = crate::Database::connect(config.access_database.options()?).await?;
            let audit = access.audit_store(&config.audit).await?;
            let providers = crate::device_pki::providers(&config.device_pki)?;
            let pki = config
                .agent_pki
                .load(
                    audit.clone(),
                    Arc::new(crate::clock::SystemClock),
                    providers.clone(),
                )?
                .ok_or_else(|| anyhow::anyhow!("agent fixture trust missing"))?;
            use crate::clock::Clock;
            let result = rss_mdm_pki_service::registry::Registry::new(
                access.archive_pool(),
                audit,
                vec![pki.issuer.trust().trust.clone()],
                providers,
            )
            .admit(tenant, crate::clock::SystemClock.unix_seconds()?)
            .await;
            access.close().await;
            result?;
            Vec::new()
        }
        Setup::Refresh => {
            refresh_management(root).await?;
            Vec::new()
        }
        Setup::Accounts {
            cases,
            management,
            source_secret,
            provisioning_database,
        } => prepare_accounts(&cases, &management, &source_secret, &provisioning_database).await?,
        Setup::Sessions { cases } => prepare_sessions(&cases).await?,
    };
    write(
        &root.join("identity-costs.json"),
        &serde_json::to_vec(&costs)?,
    )
}

async fn prepare_environment(root: &std::path::Path) -> Result<()> {
    use base64::Engine;
    use ring::signature::KeyPair;
    use serde_json::json;
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("fixture signing key generation"))?;
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow::anyhow!("fixture signing key"))?;
    let keyfile = root.join("task-signing.pk8");
    write(&keyfile, pkcs8.as_ref())?;
    write(
        &root.join("task-signing.json"),
        &serde_json::to_vec(&json!({
            "private_key_file":keyfile,"key_id":"t2","trusted_keys":{"t2":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key().as_ref())}
        }))?,
    )?;
    let content = root.join("content");
    std::fs::create_dir(&content)?;
    write(
        &root.join("content.json"),
        &serde_json::to_vec(&json!({
            "storage":{"kind":"volume","directory":content},"imports":{},"max_artifact_bytes":33554432,"max_temporary_bytes":67108864,"max_uploads":4,"transfer_seconds":60,"retention_seconds":3600,"max_bundle_bytes":33554432,"max_bundle_entries":100,"max_expansion_ratio":100
        }))?,
    )?;
    let value: Config = serde_json::from_slice(&std::fs::read(root.join("runtime.json"))?)?;
    let access = crate::Database::connect(value.access_database.options()?).await?;
    let audit = access.audit_store(&value.audit).await?;
    let result = crate::authorization::store::initialize_authorization(
        &audit,
        user(&value.identity.tenant_id, BOOTSTRAP),
        uuid::Uuid::new_v4(),
    )
    .await;
    access.close().await;
    result?;
    refresh_management(root).await
}

async fn refresh_management(root: &std::path::Path) -> Result<()> {
    let value: Config = serde_json::from_slice(&std::fs::read(root.join("runtime.json"))?)?;
    let authority = identity_with(value).await?;
    let secret = login_named(&authority, "bootstrap").await?;
    write(&root.join("source-session"), secret.expose().as_bytes())
}

async fn prepare_accounts(
    paths: &[std::path::PathBuf],
    management: &str,
    source_secret: &std::path::Path,
    database: &crate::config::Database,
) -> Result<Vec<serde_json::Value>> {
    use super::case::{CaseContext, Phase};
    use rss_identity_core::{InstanceId, account::PasswordKdf};
    use rss_identity_postgres::AccountProvisioner;
    use rss_request_context::TenantId;
    use rss_transactional_messaging_postgres::PgError;
    use std::collections::{BTreeMap, BTreeSet};
    let mut cases = Vec::new();
    let mut seen = BTreeSet::new();
    let mut members: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
    for path in paths {
        anyhow::ensure!(seen.insert(path.canonicalize()?), "duplicate case path");
        let context = CaseContext::read(path, Phase::Preparing)?;
        for (actor, value) in context.actors().iter().enumerate() {
            members
                .entry(value.tenant.clone())
                .or_default()
                .push((cases.len(), actor));
        }
        cases.push(context);
    }
    let source = TenantId::parse(management)?;
    let mut tenants = vec![(source, 1)];
    for tenant in members.keys() {
        let tenant = TenantId::parse(tenant)?;
        anyhow::ensure!(tenant != source, "case actor cannot use management tenant");
        tenants.push((tenant, 1));
    }
    let config = configured(management)?;
    let source_identity = identity_with(configured(management)?).await?;
    let actor = Arc::new(
        source_identity
            .authority
            .inspect_session(
                source,
                SessionSecret::parse(crate::config::secret(source_secret)?.to_string())?,
                crate::identity::deadline(),
            )
            .await?,
    );
    let runtime = crate::identity::open_runtime(
        database,
        &config.flow.storage.target,
        &config.flow.storage.lineage,
        &tenants,
    )
    .await?;
    let kdf = Arc::new(PasswordKdf::new());
    let result = async {
        let provisioner = AccountProvisioner::connect(runtime.clone(), kdf.clone(),
            crate::identity::authority_config(InstanceId::parse(INSTANCE)?, tenants.iter().map(|(t, _)| *t).collect())?,
            source, Arc::new(crate::authorization::identity_management::IdentityManagementPolicy::new(INSTANCE)?),
            crate::identity::deadline()).await?;
        let mut costs = vec![serde_json::json!({"phase":"case-reads","count":paths.len()})];
        for (tenant, coordinates) in members {
            let timer = super::monotonic();
            let started = timer.now();
            let mut prepared = Vec::new();
            for &(case, index) in &coordinates {
                let account = &cases[case].actors()[index];
                prepared.push((account.role.clone(), provisioner.prepare_local_account(
                    LoginKey::parse(&account.login)?, Password::new(PASSWORD.into())?,
                    crate::identity::deadline()).await?));
            }
            let target = TenantId::parse(&tenant)?;
            let outcome = runtime.local_tx_with_context(target, crate::identity::deadline(),
                (&provisioner, actor.clone(), Some(prepared)), |(provisioner, actor, prepared), tx| Box::pin(async move {
                    let mut principals = Vec::new();
                    for (role, prepared) in prepared.take().ok_or_else(|| PgError::from(sqlx::Error::Protocol("fixture accounts consumed".into())))? {
                        let account = provisioner.create_local_account_in(tx, actor.clone(), prepared).await
                            .map_err(|e| PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                        let principal = account.key().principal.as_uuid().to_string();
                        if role == "admin" {
                            let rule = fixture_rule(&target.to_string(), &principal)
                                .map_err(|e| PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                            tx.with_connection(move |connection| Box::pin(async move {
                                sqlx::query("INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3,1,$4)")
                                    .bind(target.to_string()).bind(INSTANCE).bind(uuid::Uuid::new_v4()).bind(rule)
                                    .execute(connection).await?;
                                Ok(())
                            })).await?;
                        }
                        principals.push(principal);
                    }
                    Ok(principals)
                })).await;
            let principals = outcome.fold(Ok, |e| Err(anyhow::anyhow!(e)), |e| Err(anyhow::anyhow!(e)),
                |_| Err(anyhow::anyhow!("fixture rollback failed")), |_| Err(anyhow::anyhow!("fixture commit unknown")),
                |e| Err(anyhow::anyhow!(e)))?;
            for ((case, index), principal) in coordinates.iter().copied().zip(principals) {
                cases[case].actors_mut()[index].principal = Some(principal);
            }
            costs.push(serde_json::json!({"phase":"identity-accounts","count":coordinates.len(),"tenant":tenant,"seconds":timer.now().checked_duration_since(started).context("fixture clock moved backwards")?.as_secs_f64()}));
        }
        for (path, context) in paths.iter().zip(cases) {
            write(path, &serde_json::to_vec(&context)?)?;
        }
        costs.push(serde_json::json!({"phase":"case-writes","count":paths.len()}));
        Ok::<_, anyhow::Error>(costs)
    }.await;
    kdf.close();
    let cleanup = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        kdf.wait_closed().await;
        runtime.close().await;
    })
    .await;
    let costs = result?;
    cleanup.context("fixture identity cleanup deadline")?;
    Ok(costs)
}

fn fixture_rule(tenant: &str, principal: &str) -> Result<serde_json::Value> {
    use crate::authorization::{Grant, Permission, Rule, Scope, Subject};
    let mut grants: Vec<_> = [
        Permission::AuthorizationRead,
        Permission::AuthorizationWrite,
        Permission::UserGroupRead,
        Permission::UserGroupWrite,
        Permission::DepartmentRead,
        Permission::IdentityAccountsManage,
        Permission::IdentityProvidersManage,
    ]
    .into_iter()
    .map(|operation| Grant {
        operation,
        scope: Scope::Tenant,
    })
    .collect();
    grants.extend(device_grants(
        None,
        &["inventory_read", "enrollment", "credentials"],
    )?);
    let rule = Rule {
        subject: Subject::User {
            user: user(tenant, principal),
        },
        grants,
    };
    rule.validate(tenant, INSTANCE)?;
    Ok(serde_json::to_value(rule)?)
}

async fn prepare_sessions(paths: &[std::path::PathBuf]) -> Result<Vec<serde_json::Value>> {
    use super::case::{CaseContext, Phase};
    use std::collections::BTreeMap;
    let mut costs = Vec::new();
    for path in paths {
        let context = CaseContext::read(path, Phase::Ready)?;
        let mut authorities = BTreeMap::new();
        for actor in context.actors() {
            if !authorities.contains_key(&actor.tenant) {
                authorities.insert(
                    actor.tenant.clone(),
                    identity_with(configured(&actor.tenant)?).await?,
                );
            }
            let timer = super::monotonic();
            let started = timer.now();
            let secret = login_named(&authorities[&actor.tenant], &actor.login)
                .await
                .with_context(|| {
                    preparation_coordinate(
                        &actor.tenant,
                        context.invocation_id(),
                        &actor.role,
                        "login-account",
                    )
                })?;
            save(path.parent().unwrap(), &actor.tenant, &actor.role, &secret)?;
            costs.push(serde_json::json!({"phase":"identity-sessions","count":1,"tenant":actor.tenant,"invocationId":context.invocation_id(),"seconds":timer.now().checked_duration_since(started).context("fixture clock moved backwards")?.as_secs_f64()}));
        }
    }
    Ok(costs)
}

fn preparation_coordinate(tenant: &str, invocation: &str, kind: &str, phase: &str) -> String {
    format!(
        "identity preparation tenant={tenant} invocationId={invocation} kind={kind} phase={phase}"
    )
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
    set_grants_in(tenant, subject, grants, false).await
}
pub(crate) async fn independent_source_read(
    tenant: &str,
    subject: &str,
    grants: Vec<crate::authorization::Grant>,
) -> Result<()> {
    set_grants(tenant, subject, device_grants(None, &["inventory_read"])?).await?;
    set_management_grants(tenant, subject, grants).await
}
pub(crate) async fn set_management_grants(
    tenant: &str,
    subject: &str,
    grants: Vec<crate::authorization::Grant>,
) -> Result<()> {
    set_grants_in(tenant, subject, grants, true).await
}
async fn set_grants_in(
    tenant: &str,
    subject: &str,
    grants: Vec<crate::authorization::Grant>,
    preserve_read: bool,
) -> Result<()> {
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
    .load_authorization(access.authorization())
    .await?;
    grant(
        access.audit_store(&config(tenant)?.audit).await?.as_ref(),
        &principal,
        tenant,
        subject,
        grants,
        preserve_read,
    )
    .await?;
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

async fn grant(
    audit_store: &rss_mdm_audit_integration::AuditStore,
    principal: &crate::authorization::context::AuthorizedPrincipal,
    tenant: &str,
    subject: &str,
    grants: Vec<crate::authorization::Grant>,
    preserve_read: bool,
) -> Result<()> {
    use crate::authorization::{Change, Permission, Rule, Subject};
    for record in &principal.authorization()?.rules {
        let Some(rule) = &record.value else { continue };
        if preserve_read
            && rule
                .grants
                .iter()
                .all(|g| g.operation == Permission::InventoryRead)
        {
            continue;
        }
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
                audit_store,
                principal,
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
            audit_store,
            principal,
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
    Ok(())
}

pub(crate) async fn session_authority(
    config: &Config,
) -> Result<std::sync::Arc<rss_mdm_authorization_service::session::SessionAuthority>> {
    let policy = Arc::new(
        crate::authorization::identity_management::IdentityManagementPolicy::new(
            &config.identity.instance_id,
        )?,
    );
    let identity = Identity::connect(config, policy, |_| {}).await?;
    Ok(std::sync::Arc::new(
        rss_mdm_authorization_service::session::SessionAuthority::new(
            identity.authority,
            identity.tenant,
        ),
    ))
}
