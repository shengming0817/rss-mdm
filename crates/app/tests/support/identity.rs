//! Real embedded authority fixtures. Credentials and proofs come only from public APIs.
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
    configured(tenant, super::case::context().admin_for(tenant))
}
fn configured(tenant: &str, principal: &str) -> Result<Config> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    value["identity"]["tenant_id"] = tenant.into();
    value["identity_management"] = serde_json::json!([{"tenant_id":tenant,"instance_id":INSTANCE,"principal_id":principal,"permissions":["accounts","providers"]}]);
    Ok(serde_json::from_value(value)?)
}
pub(crate) async fn identity(tenant: &str) -> Result<Identity> {
    identity_with(config(tenant)?).await
}
async fn identity_with(config: Config) -> Result<Identity> {
    let tenant = &config.identity.tenant_id;
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
#[tokio::test]
#[ignore = "make t2: prepare real case accounts once per compatible environment"]
async fn seed_accounts() -> Result<()> {
    use super::case::{CaseContext, Phase};
    use base64::Engine;
    use ring::signature::KeyPair;
    use serde_json::json;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Setup {
        tenants: Vec<String>,
        cases: Vec<std::path::PathBuf>,
    }
    let manifest: Setup =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_IDENTITY_SETUP")?)?)?;
    let config_path = std::path::PathBuf::from(std::env::var("MDM_TEST_CONFIG")?);
    let root = config_path.parent().unwrap();
    let pkcs8 =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
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
        &serde_json::to_vec(
            &json!({"directory":content,"imports":{},"max_artifact_bytes":33554432,"max_temporary_bytes":67108864,"max_uploads":4,"transfer_seconds":60,"retention_seconds":3600,"max_bundle_bytes":67108864,"max_bundle_entries":100,"max_expansion_ratio":100}),
        )?,
    )?;
    let mut costs = Vec::new();
    for tenant in &manifest.tenants {
        let mut phase = "configuration";
        let prepared: Result<_> = async {
            let config = configured(tenant, BOOTSTRAP)?;
            phase = "access-connect";
            let access = crate::Database::connect(config.access_database.options()?).await?;
            phase = "audit-connect";
            let audit = access.audit_store(&config.audit).await?;
            phase = "identity-connect";
            let identity = identity_with(config).await?;
            phase = "authorization-initialize";
            crate::authorization::store::initialize_authorization(
                &audit,
                user(tenant, BOOTSTRAP),
                uuid::Uuid::new_v4(),
            )
            .await?;
            phase = "bootstrap-login";
            let bootstrap = login_named(&identity, "bootstrap").await?;
            Ok((access, audit, identity, bootstrap))
        }
        .await;
        let (access, audit, identity, bootstrap) = prepared
            .with_context(|| preparation_coordinate(tenant, "environment", "bootstrap", phase))?;
        for path in &manifest.cases {
            let mut context = CaseContext::read(path, Phase::Preparing)
                .context("identity preparation phase=case-context")?;
            if !context
                .identity_tenants()
                .iter()
                .any(|value| value == tenant)
            {
                continue;
            }
            for kind in ["admin", "other"] {
                let name = context.account_login(kind).to_owned();
                let mut phase = "authenticate-bootstrap";
                let prepared: Result<_> = async {
                let started = rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer);
                let actor = identity
                    .authority
                    .authenticate_session(
                        identity.tenant,
                        SessionSecret::parse(bootstrap.expose().into())?,
                        crate::identity::deadline(),
                    )
                    .await?;
                phase = "create-account";
                let account = identity
                    .authority
                    .create_local_account(
                        actor,
                        LoginKey::parse(&name)?,
                        Password::new(PASSWORD.into())?,
                        crate::identity::deadline(),
                    )
                    .await?;
                let subject = account.key().principal.as_uuid().to_string();
                if kind == "admin" {
                    phase = "inspect-bootstrap";
                    let principal = crate::authorization::context::AuthorizedPrincipal::new(
                        identity
                            .authority
                            .inspect_session(
                                identity.tenant,
                                SessionSecret::parse(bootstrap.expose().into())?,
                                crate::identity::deadline(),
                            )
                            .await?,
                    )?
                    .load_authorization(&access)
                    .await?;
                    phase = "load-foundational-grants";
                    let foundational = principal.authorization()?.rules.iter()
                        .filter_map(|record| record.value.as_ref())
                        .find(|rule| matches!(&rule.subject,
                            crate::authorization::Subject::User { user } if user.principal_id == BOOTSTRAP))
                        .context("bootstrap authorization missing")?
                        .grants.clone();
                    phase = "grant-foundational";
                    grant(&audit, &principal, tenant, &subject, foundational).await?;
                    phase = "grant-devices";
                    grant(
                        &audit,
                        &principal,
                        tenant,
                        &subject,
                        device_grants(None, &["inventory_read", "enrollment", "credentials"])?,
                    )
                    .await?;
                }
                costs.push(json!({"phase":"identity-accounts","count":1,"tenant":tenant,"invocationId":context.invocation_id(),"seconds":rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer).saturating_duration_since(started).as_secs_f64()}));
                let started = rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer);
                phase = "login-account";
                let secret = login_named(&identity, &name).await?;
                phase = "save-session";
                save(path.parent().unwrap(), tenant, kind, &secret)?;
                costs.push(json!({"phase":"identity-sessions","count":1,"tenant":tenant,"invocationId":context.invocation_id(),"seconds":rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer).saturating_duration_since(started).as_secs_f64()}));
                Ok(subject)
                }.await;
                let subject = prepared.with_context(|| {
                    preparation_coordinate(tenant, context.invocation_id(), kind, phase)
                })?;
                if kind == "admin" {
                    context.record_admin(tenant, subject).with_context(|| {
                        preparation_coordinate(
                            tenant,
                            context.invocation_id(),
                            kind,
                            "record-admin",
                        )
                    })?;
                }
            }
            write(path, &serde_json::to_vec(&context)?).with_context(|| {
                preparation_coordinate(tenant, context.invocation_id(), "accounts", "write-context")
            })?;
        }
        access.close().await;
    }
    write(
        &root.join("identity-costs.json"),
        &serde_json::to_vec(&costs)?,
    )?;
    Ok(())
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
    grant(
        access.audit_store(&config(tenant)?.audit).await?.as_ref(),
        &principal,
        tenant,
        subject,
        grants,
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
) -> Result<()> {
    use crate::authorization::{Change, Permission, Rule, Subject};
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
