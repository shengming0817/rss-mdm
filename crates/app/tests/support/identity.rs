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
pub(crate) async fn identity(tenant: &str) -> Result<(Identity, super::runtime::Resources)> {
    let config = config(tenant)?;
    let (resources, identity) = super::runtime::Resources::build(move |resources| {
        Box::pin(identity_with(config, resources))
    })
    .await?;
    Ok((identity, resources))
}
async fn identity_with(
    config: Config,
    resources: &mut super::runtime::Resources,
) -> Result<Identity> {
    let policy = Arc::new(
        crate::authorization::identity_management::IdentityManagementPolicy::new(INSTANCE)?,
    );
    Ok(Identity::connect(&config, policy, |resource| resources.acquire(resource)).await?)
}
pub(crate) async fn login(identity: &Identity, login: &str) -> Result<SessionSecret> {
    login_named(identity, super::case::login(login)).await
}
async fn login_named(identity: &Identity, login: &str) -> Result<SessionSecret> {
    let issued = issue_named(identity, login).await?;
    Ok(SessionSecret::parse(issued.secret().expose().into())?)
}
async fn issue_named(
    identity: &Identity,
    login: &str,
) -> Result<rss_identity_postgres::IssuedSession> {
    Ok(identity
        .authority
        .login_local(
            identity.tenant,
            LoginKey::parse(login)?,
            Password::new(PASSWORD.into())?,
            AttemptSource::parse(&format!("t2-{}-{login}", identity.tenant))?,
            None,
            crate::identity::deadline(),
        )
        .await?)
}
pub(crate) fn credential(identity: &Identity, login: &str) -> Result<SessionSecret> {
    credential_for(&identity.tenant.to_string(), login)
}
pub(crate) fn credential_for(tenant: &str, login: &str) -> Result<SessionSecret> {
    let config = std::path::PathBuf::from(std::env::var("MDM_TEST_CONFIG")?);
    let path = config
        .parent()
        .unwrap()
        .join(format!("credential-{tenant}-{login}"));
    Ok(SessionSecret::parse(
        crate::config::secret(&path)
            .with_context(|| format!("prepared identity credential unavailable for role {login}"))?
            .to_string(),
    )?)
}
pub(crate) fn age_prepared_admin_session() -> Result<()> {
    // Model a case waiting in the run queue beyond Recent(300s), only for its own actor.
    super::process::pg(&format!(
        "UPDATE identity_authority.sessions SET local_authenticated_at=local_authenticated_at-301 WHERE tenant_id='{}' AND principal_id='{}'",
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
    Refresh,
    Actors {
        cases: Vec<std::path::PathBuf>,
        management: String,
        source_secret: std::path::PathBuf,
        provisioning_database: crate::config::Database,
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
        Setup::Refresh => {
            refresh_management(root).await?;
            Vec::new()
        }
        Setup::Actors {
            cases,
            management,
            source_secret,
            provisioning_database,
        } => {
            let mut costs =
                prepare_accounts(&cases, &management, &source_secret, &provisioning_database)
                    .await?;
            costs.extend(prepare_sessions(&cases).await?);
            costs
        }
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
    let access = crate::Database::connect(value.access_options()?).await?;
    let tenant = rss_request_context::TenantId::parse(&value.identity.tenant_id)?;
    let source_runtime = crate::identity::open_runtime(
        &value.access_database,
        &value.flow.storage.target,
        &value.flow.storage.lineage,
        &[(tenant, value.flow.storage.epoch)],
    )
    .await?;
    let audit = access
        .audit_store(
            &value.audit,
            source_runtime.clone(),
            tenant,
            Default::default(),
        )
        .await?;
    let result = crate::authorization::store::initialize_authorization(
        &audit,
        user(&value.identity.tenant_id, BOOTSTRAP),
        uuid::Uuid::new_v4(),
    )
    .await;
    source_runtime.close().await;
    access.close().await;
    result?;
    refresh_management(root).await
}

async fn refresh_management(root: &std::path::Path) -> Result<()> {
    let root = root.to_path_buf();
    let (resources, ()) = super::runtime::Resources::build(move |resources| {
        Box::pin(async move {
            let value: Config = serde_json::from_slice(&std::fs::read(root.join("runtime.json"))?)?;
            let authority = identity_with(value, resources).await?;

            let secret = login_named(&authority, "bootstrap").await?;
            write(&root.join("source-session"), secret.expose().as_bytes())
        })
    })
    .await?;
    resources.finish(async { Ok(()) }).await
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
            if value.principal.is_some() {
                continue;
            }
            members
                .entry(value.tenant.clone())
                .or_default()
                .push((cases.len(), actor));
        }
        cases.push(context);
    }
    if members.is_empty() {
        return Ok(Vec::new());
    }
    let source = TenantId::parse(management)?;
    let mut tenants = vec![(source, 1)];
    for tenant in members.keys() {
        let tenant = TenantId::parse(tenant)?;
        anyhow::ensure!(tenant != source, "case actor cannot use management tenant");
        tenants.push((tenant, 1));
    }
    let config = configured(management)?;
    let (source_identity, identity_resources) = identity(management).await?;
    let actor = identity_resources
        .finish(async {
            Ok(Arc::new(
                source_identity
                    .authority
                    .inspect_session(
                        source,
                        SessionSecret::parse(crate::config::secret(source_secret)?.to_string())?,
                        crate::identity::deadline(),
                    )
                    .await?,
            ))
        })
        .await?;
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
            super::task_signing::seed(&tenant,&config).await?;
            let timer = super::runtime::monotonic();
            let started = timer.now();
            let mut prepared = Vec::new();
            let mut logins = BTreeSet::new();
            for &(case, index) in &coordinates {
                let account = &cases[case].actors()[index];
                if !logins.insert(account.login.clone()) { continue; }
                prepared.push((account.login.clone(), account.role.clone(), provisioner.prepare_local_account(
                    LoginKey::parse(&account.login)?, Password::new(PASSWORD.into())?,
                    crate::identity::deadline()).await?));
            }
            let target = TenantId::parse(&tenant)?;
            let outcome = runtime.local_tx_with_context(target, crate::identity::deadline(),
                (&provisioner, actor.clone(), Some(prepared)), |(provisioner, actor, prepared), tx| Box::pin(async move {
                    let mut principals = Vec::new();
                    for (login, role, prepared) in prepared.take().ok_or_else(|| PgError::from(sqlx::Error::Protocol("fixture accounts consumed".into())))? {
                        let account = provisioner.create_local_account_in(tx, actor.clone(), prepared).await
                            .map_err(|e| PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                        let principal = account.key().principal.as_uuid().to_string();
                        if role == "admin" {
                            let rules = fixture_rules(&target.to_string(), &principal)
                                .map_err(|e| PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                            tx.with_connection(move |connection| Box::pin(async move {
                                for rule in rules {
                                    sqlx::query("INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3,1,$4)")
                                        .bind(target.to_string()).bind(INSTANCE).bind(uuid::Uuid::new_v4()).bind(rule)
                                        .execute(&mut *connection).await?;
                                }
                                Ok(())
                            })).await?;
                        }
                        principals.push((login, principal));
                    }
                    Ok(principals)
                })).await;
            let principals = outcome.fold(Ok, |e| Err(anyhow::anyhow!(e)), |e| Err(anyhow::anyhow!(e)),
                |_| Err(anyhow::anyhow!("fixture rollback failed")), |_| Err(anyhow::anyhow!("fixture commit unknown")),
                |e| Err(anyhow::anyhow!(e)))?;
            let principals: BTreeMap<_, _> = principals.into_iter().collect();
            for &(case, index) in &coordinates {
                cases[case].actors_mut()[index].principal = Some(principals[&cases[case].actors()[index].login].clone());
            }
            costs.push(serde_json::json!({"phase":"identity-accounts","count":principals.len(),"tenant":tenant,"seconds":timer.now().checked_duration_since(started).context("fixture clock moved backwards")?.as_secs_f64()}));
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

const MANAGEMENT_PERMISSIONS: [crate::authorization::Permission; 13] = {
    use crate::authorization::Permission::*;
    [
        RegistrationConfigurationRead,
        RegistrationConfigurationWrite,
        AuditRead,
        AuthorizationRead,
        AuthorizationWrite,
        UserGroupRead,
        UserGroupWrite,
        DepartmentRead,
        IdentityAccountsManage,
        IdentityProvidersManage,
        UserAttributeDefinitionsRead,
        UserAttributeDefinitionsWrite,
        UserProfilesRead,
    ]
};

fn fixture_rules(tenant: &str, principal: &str) -> Result<Vec<serde_json::Value>> {
    use crate::authorization::{Grant, Rule, Scope, Subject};
    // Independent rules let business tests replace device grants without revoking
    // the authority needed to administer the next change. Keep read-only grants
    // separate for consumers that explicitly preserve only InventoryRead.
    let groups = [
        MANAGEMENT_PERMISSIONS
            .into_iter()
            .map(|operation| Grant {
                operation,
                scope: Scope::Tenant,
            })
            .collect(),
        device_grants(None, &["inventory_read"])?,
        device_grants(None, &["enrollment", "credentials"])?,
    ];
    groups
        .into_iter()
        .map(|grants| {
            let rule = Rule {
                subject: Subject::User {
                    user: user(tenant, principal),
                },
                grants,
            };
            rule.validate(tenant, INSTANCE)?;
            Ok(serde_json::to_value(rule)?)
        })
        .collect()
}

fn protected_management_rule(rule: &crate::authorization::Rule) -> bool {
    use crate::authorization::{Permission, Scope};
    rule.grants
        .iter()
        .any(|g| g.operation == Permission::AuthorizationWrite)
        && rule
            .grants
            .iter()
            .all(|g| MANAGEMENT_PERMISSIONS.contains(&g.operation) && g.scope == Scope::Tenant)
}

#[test]
fn baseline_management_does_not_protect_device_grants() -> Result<()> {
    use crate::authorization::{Permission, Rule};
    let rules = fixture_rules("11111111-1111-4111-8111-111111111111", BOOTSTRAP)?
        .into_iter()
        .map(serde_json::from_value::<Rule>)
        .collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(rules.len() == 3);
    anyhow::ensure!(protected_management_rule(&rules[0]));
    anyhow::ensure!(!protected_management_rule(&rules[1]) && !protected_management_rule(&rules[2]));
    anyhow::ensure!(
        rules[1]
            .grants
            .iter()
            .all(|g| g.operation == Permission::InventoryRead)
    );
    let mut mixed = rules[0].clone();
    mixed.grants.extend(rules[1].grants.clone());
    anyhow::ensure!(!protected_management_rule(&mixed));
    Ok(())
}

async fn prepare_sessions(paths: &[std::path::PathBuf]) -> Result<Vec<serde_json::Value>> {
    use super::case::{CaseContext, Phase};
    use std::collections::BTreeMap;
    let paths = paths.to_vec();
    let (resources, costs) = super::runtime::Resources::build(move |resources| Box::pin(async move {    let mut costs = Vec::new();
    let mut authorities = BTreeMap::new();
    let mut sessions = BTreeMap::new();
    for path in &paths {
        let context = CaseContext::read(path, Phase::Ready)?;
        for actor in context.actors() {
            let root = path.parent().unwrap();
            if root
                .join(format!("credential-{}-{}", actor.tenant, actor.role))
                .exists()
            {
                continue;
            }
            let key = (actor.tenant.clone(), actor.login.clone());
            if let std::collections::btree_map::Entry::Vacant(entry) = sessions.entry(key.clone()) {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    authorities.entry(actor.tenant.clone())
                {
                    entry.insert(identity_with(configured(&actor.tenant)?, resources).await?);
                }
                let timer = super::runtime::monotonic();
                let started = timer.now();
                let issued = issue_named(&authorities[&actor.tenant], &actor.login)
                    .await
                    .with_context(|| {
                        preparation_coordinate(
                            &actor.tenant,
                            context.invocation_id(),
                            &actor.role,
                            "login-account",
                        )
                    })?;
                let view = issued.view();
                let authenticated = authorities[&actor.tenant].authority.inspect_session(
                    rss_request_context::TenantId::parse(&actor.tenant)?, SessionSecret::parse(issued.secret().expose().into())?, crate::identity::deadline()).await?;
                let until = (authenticated.assurance()?.auth_time().context("local authentication time missing")? + 300)
                    .min(view.idle_expires_at)
                    .min(view.absolute_expires_at);
                entry.insert((
                    SessionSecret::parse(issued.secret().expose().into())?,
                    until,
                ));
                costs.push(serde_json::json!({"phase":"identity-sessions","count":1,"tenant":actor.tenant,"seconds":timer.now().checked_duration_since(started).context("fixture clock moved backwards")?.as_secs_f64()}));
            }
            let (secret, until) = &sessions[&key];
            save(root, &actor.tenant, &actor.role, secret)?;
            write(
                &root.join(format!("credential-meta-{}-{}", actor.tenant, actor.role)),
                &serde_json::to_vec(until)?,
            )?;
        }
    }
    Ok(costs)

    })).await?;
    resources.finish(async { Ok(costs) }).await
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
    let (identity, identity_resources) = identity(tenant).await?;
    identity_resources
        .finish(async {
            let access = crate::Database::connect(config(tenant)?.access_options()?).await?;
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
                access
                    .audit_store_fixture(&config(tenant)?.audit)
                    .await?
                    .as_ref(),
                &principal,
                tenant,
                subject,
                grants,
                preserve_read,
            )
            .await?;
            access.close().await;
            Ok(())
        })
        .await
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
            && !protected_management_rule(rule)
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
