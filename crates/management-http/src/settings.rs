//! Permission-filtered settings directory. Domain services remain the only write/state owners.
use crate::{Error, authorization::context::RequestAuth};
use axum::{Extension, Json};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::Serialize;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Deployment,
    Platform,
    Tenant,
    Device,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Custody {
    DeploymentOperator,
    Identity,
    DomainService,
    CertificateAuthority,
    StorageProvider,
    Device,
}
/// Applicable lifecycle, not a claim that any external qualification has been observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    DeploymentMaintenance,
    FixedInstallationIdentity,
    FixedLedgerKey,
    AccountCredential,
    ProtectionKey,
    SigningTrust,
    ExternalCertificate,
    ProviderCredential,
    BusinessConfiguration,
    SignedPackage,
    DeviceGenerated,
}
#[derive(Clone, Copy, Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: &'static str,
    pub scope: Scope,
    pub owner: &'static str,
    pub custody: Custody,
    pub lifecycle: Lifecycle,
    #[serde(skip)]
    #[schemars(skip)]
    permission: Permission,
}
macro_rules! item {
    ($id:literal,$scope:ident,$owner:literal,$custody:ident,$lifecycle:ident,$permission:ident) => {
        Item {
            id: $id,
            scope: Scope::$scope,
            owner: $owner,
            custody: Custody::$custody,
            lifecycle: Lifecycle::$lifecycle,
            permission: Permission::$permission,
        }
    };
}
/// The accepted 43-entry catalog. No material bytes, filesystem locations or deployment credentials.
pub const CATALOG: &[Item] = &[
    item!(
        "entry",
        Deployment,
        "deployment",
        DeploymentOperator,
        DeploymentMaintenance,
        TenantRead
    ),
    item!(
        "tls",
        Deployment,
        "deployment",
        DeploymentOperator,
        ExternalCertificate,
        TenantRead
    ),
    item!(
        "postgres",
        Deployment,
        "deployment",
        DeploymentOperator,
        DeploymentMaintenance,
        TenantRead
    ),
    item!(
        "dbpassword",
        Deployment,
        "deployment",
        DeploymentOperator,
        AccountCredential,
        TenantRead
    ),
    item!(
        "instance",
        Deployment,
        "installation",
        DeploymentOperator,
        FixedInstallationIdentity,
        TenantRead
    ),
    item!(
        "audit",
        Deployment,
        "installation",
        DeploymentOperator,
        FixedInstallationIdentity,
        TenantRead
    ),
    item!(
        "native",
        Deployment,
        "native-protection",
        DeploymentOperator,
        ProtectionKey,
        TenantRead
    ),
    item!(
        "ledger",
        Deployment,
        "audit",
        DeploymentOperator,
        FixedLedgerKey,
        TenantRead
    ),
    item!(
        "operation",
        Deployment,
        "installation",
        DeploymentOperator,
        FixedInstallationIdentity,
        TenantRead
    ),
    item!(
        "organization",
        Platform,
        "tenant-administration",
        DomainService,
        BusinessConfiguration,
        TenantRead
    ),
    item!(
        "password",
        Tenant,
        "identity",
        Identity,
        AccountCredential,
        IdentityAccountsManage
    ),
    item!(
        "recovery",
        Platform,
        "identity",
        Identity,
        AccountCredential,
        IdentityAccountsManage
    ),
    item!(
        "windows-key",
        Tenant,
        "windows-channel",
        DomainService,
        ProtectionKey,
        RegistrationConfigurationRead
    ),
    item!(
        "task-key",
        Tenant,
        "execution-service",
        DomainService,
        SigningTrust,
        RegistrationConfigurationRead
    ),
    item!(
        "oidc-state",
        Deployment,
        "identity-host",
        DeploymentOperator,
        ProtectionKey,
        TenantRead
    ),
    item!(
        "recovery-key",
        Tenant,
        "recovery-credentials",
        DomainService,
        ProtectionKey,
        Credentials
    ),
    item!(
        "recovery-rsa",
        Tenant,
        "recovery-credentials",
        DomainService,
        ExternalCertificate,
        Credentials
    ),
    item!(
        "apns-key",
        Tenant,
        "apple-channel",
        DomainService,
        ExternalCertificate,
        RegistrationConfigurationRead
    ),
    item!(
        "apns-cert",
        Tenant,
        "apple-channel",
        DomainService,
        ExternalCertificate,
        RegistrationConfigurationRead
    ),
    item!(
        "profile-key",
        Tenant,
        "apple-channel",
        DomainService,
        ExternalCertificate,
        RegistrationConfigurationRead
    ),
    item!(
        "profile-cert",
        Tenant,
        "apple-channel",
        DomainService,
        ExternalCertificate,
        RegistrationConfigurationRead
    ),
    item!(
        "ade-key",
        Tenant,
        "apple-channel",
        DomainService,
        SigningTrust,
        RegistrationConfigurationRead
    ),
    item!(
        "ade-token",
        Tenant,
        "apple-channel",
        DomainService,
        ProviderCredential,
        RegistrationConfigurationRead
    ),
    item!(
        "managed-key",
        Tenant,
        "apple-channel",
        DomainService,
        SigningTrust,
        RegistrationConfigurationRead
    ),
    item!(
        "apple-account",
        Tenant,
        "apple-channel",
        DomainService,
        BusinessConfiguration,
        RegistrationConfigurationRead
    ),
    item!(
        "ca-root",
        Deployment,
        "pki-provider",
        CertificateAuthority,
        ExternalCertificate,
        TenantRead
    ),
    item!(
        "ca-pass",
        Deployment,
        "pki-provider",
        CertificateAuthority,
        AccountCredential,
        TenantRead
    ),
    item!(
        "provisioner",
        Deployment,
        "pki-provider",
        CertificateAuthority,
        SigningTrust,
        TenantRead
    ),
    item!(
        "scep-decrypter",
        Deployment,
        "pki-provider",
        CertificateAuthority,
        ExternalCertificate,
        TenantRead
    ),
    item!(
        "ca-webhook",
        Deployment,
        "pki-provider",
        CertificateAuthority,
        ProviderCredential,
        TenantRead
    ),
    item!(
        "trust",
        Tenant,
        "pki-service",
        DomainService,
        SigningTrust,
        Credentials
    ),
    item!(
        "crl",
        Tenant,
        "pki-service",
        CertificateAuthority,
        ExternalCertificate,
        Credentials
    ),
    item!(
        "s3-key",
        Tenant,
        "content-service",
        DomainService,
        ProviderCredential,
        StorageConfigurationRead
    ),
    item!(
        "storage",
        Tenant,
        "content-service",
        DomainService,
        ProviderCredential,
        StorageConfigurationRead
    ),
    item!(
        "prefix",
        Platform,
        "tenant-administration",
        StorageProvider,
        BusinessConfiguration,
        TenantRead
    ),
    item!(
        "oidc",
        Tenant,
        "identity",
        Identity,
        ProviderCredential,
        IdentityProvidersManage
    ),
    item!(
        "wns",
        Tenant,
        "windows-channel",
        DomainService,
        ProviderCredential,
        RegistrationConfigurationRead
    ),
    item!(
        "smtp",
        Tenant,
        "mail-service",
        DomainService,
        ProviderCredential,
        RegistrationConfigurationRead
    ),
    item!(
        "webhook-own",
        Tenant,
        "webhook-service",
        DomainService,
        SigningTrust,
        WebhookRead
    ),
    item!(
        "agent-package",
        Tenant,
        "software-service",
        DomainService,
        SignedPackage,
        AgentEnrollmentRead
    ),
    item!(
        "device-key",
        Device,
        "registration-service",
        Device,
        DeviceGenerated,
        Credentials
    ),
    item!(
        "host-config",
        Platform,
        "tenant-administration",
        DeploymentOperator,
        BusinessConfiguration,
        TenantRead
    ),
    item!(
        "registration",
        Tenant,
        "registration-service",
        DomainService,
        BusinessConfiguration,
        AgentEnrollmentRead
    ),
];
fn catalog(proof: &AuthorizedPrincipal, platform: bool) -> Result<Vec<Item>, Error> {
    proof.check_live()?;
    let items = CATALOG
        .iter()
        .filter(|item| {
            let installation = matches!(item.scope, Scope::Deployment | Scope::Platform);
            installation == platform
                && if item.permission.device() {
                    proof.require_all_devices(item.permission).is_ok()
                } else {
                    proof.require(item.permission, None).is_ok()
                }
        })
        .copied()
        .collect();
    proof.check_live()?;
    Ok(items)
}
#[derive(Clone, Copy, Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Unknown,
    Unconfigured,
    Configured,
    Loaded,
    Pending,
    Unavailable,
}
#[derive(Clone, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Projection {
    pub status: Status,
    pub revision: Option<i64>,
    pub desired_revision: Option<i64>,
    pub applied_revision: Option<i64>,
    pub configured_count: Option<usize>,
    pub reason: Option<&'static str>,
    pub actions: Vec<Action>,
}
#[derive(Clone, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Action {
    pub name: &'static str,
    pub href: String,
}
impl Projection {
    pub fn unknown(href: Option<&'static str>) -> Self {
        Self {
            status: Status::Unknown,
            revision: None,
            desired_revision: None,
            applied_revision: None,
            configured_count: None,
            reason: Some("owner_observation_required"),
            actions: href
                .map(|href| {
                    vec![Action {
                        name: "inspect",
                        href: href.into(),
                    }]
                })
                .unwrap_or_default(),
        }
    }
}
#[derive(Serialize, schemars::JsonSchema)]
pub struct Entry {
    #[serde(flatten)]
    pub item: Item,
    #[serde(flatten)]
    pub projection: Projection,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub items: Vec<Entry>,
    pub domains: Vec<Domain>,
}
/// Navigation to existing domain owners; no shadow configuration or lifecycle state.
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Domain {
    pub id: &'static str,
    pub href: String,
}
fn domains(proof: &AuthorizedPrincipal, platform: bool) -> Vec<Domain> {
    let mut result = Vec::new();
    let entries = if platform {
        vec![
            (
                "tenants",
                "/api/v1/tenant-administration/tenants",
                Permission::TenantRead,
            ),
            (
                "provisionings",
                "/api/v1/tenant-administration/provisionings",
                Permission::TenantRead,
            ),
        ]
    } else {
        vec![
            ("groups", "/api/v1/groups", Permission::GroupRead),
            ("scopes", "/api/v1/scopes", Permission::ScopeRead),
            ("policies", "/api/v1/policies", Permission::PolicyRead),
            ("software", "/api/v1/resources", Permission::ResourceRead),
            (
                "apple-organizations",
                "/api/v1/apple/organizations",
                Permission::RegistrationConfigurationRead,
            ),
            (
                "registration",
                "/api/v1/agent-enrollment-settings",
                Permission::AgentEnrollmentRead,
            ),
        ]
    };
    for (id, href, permission) in entries {
        if proof.require(permission, None).is_ok() {
            result.push(Domain {
                id,
                href: href.into(),
            });
        }
    }
    if proof
        .require(Permission::IdentityAccountsManage, None)
        .is_ok()
    {
        result.push(Domain {
            id: "accounts",
            href: format!("/api/v1/identity/tenants/{}/accounts", proof.tenant_id()),
        });
    }
    result
}
pub trait Source: Send + Sync {
    fn project<'a>(
        &'a self,
        proof: Arc<AuthorizedPrincipal>,
        audit: RequestAudit,
        continuation: crate::http_operation::RequestContinuation,
        items: Vec<Item>,
    ) -> futures::future::BoxFuture<'a, Result<Vec<Entry>, Error>>;
}
async fn directory(
    source: Arc<dyn Source>,
    auth: RequestAuth,
    audit: RequestAudit,
    continuation: crate::http_operation::RequestContinuation,
    platform: bool,
) -> Result<Json<Catalog>, Error> {
    let items = catalog(&auth.proof, platform)?;
    let expected = items.iter().map(|i| i.id).collect::<Vec<_>>();
    let entries = source
        .project(auth.proof.clone(), audit, continuation, items)
        .await?;
    if entries.iter().map(|e| e.item.id).collect::<Vec<_>>() != expected {
        return Err(Error::Conflict);
    }
    auth.proof.check_live()?;
    Ok(Json(Catalog {
        items: entries,
        domains: domains(&auth.proof, platform),
    }))
}
pub(crate) async fn tenant(
    Extension(source): Extension<Arc<dyn Source>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(continuation): Extension<crate::http_operation::RequestContinuation>,
) -> Result<Json<Catalog>, Error> {
    directory(source, auth, audit, continuation, false).await
}
pub(crate) async fn platform(
    Extension(source): Extension<Arc<dyn Source>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(continuation): Extension<crate::http_operation::RequestContinuation>,
) -> Result<Json<Catalog>, Error> {
    directory(source, auth, audit, continuation, true).await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_catalog_schema_matches_runtime_dto() {
        let actual = serde_json::to_value(schemars::schema_for!(Catalog)).unwrap();
        let published: serde_json::Value =
            serde_json::from_str(include_str!("../schema/SettingsCatalog.json")).unwrap();
        assert_eq!(actual, published);
    }
    #[test]
    fn catalog_keeps_fixed_ledger_and_device_custody_distinct() {
        assert_eq!(CATALOG.len(), 43);
        let ids = CATALOG
            .iter()
            .map(|v| v.id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids.len(), 43);
        let ledger = CATALOG.iter().find(|v| v.id == "ledger").unwrap();
        assert_eq!(ledger.lifecycle, Lifecycle::FixedLedgerKey);
        let device = CATALOG.iter().find(|v| v.id == "device-key").unwrap();
        assert_eq!(device.custody, Custody::Device);
        for item in CATALOG
            .iter()
            .filter(|v| matches!(v.scope, Scope::Deployment | Scope::Platform))
        {
            assert!(!item.permission.device());
        }
    }
}
