//! Permission-filtered settings directory. Domain services remain the only write/state owners.
use crate::{Error, authorization::context::RequestAuth};
use axum::{Extension, Json};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Deployment,
    Platform,
    Tenant,
    Device,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
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
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: &'static str,
    pub scope: Scope,
    pub owner: &'static str,
    pub custody: Custody,
    pub lifecycle: Lifecycle,
    #[serde(skip)]
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
        AgentEnrollmentRead
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
        Deployment,
        "content-s3",
        StorageProvider,
        ProviderCredential,
        TenantRead
    ),
    item!(
        "storage",
        Deployment,
        "content-service",
        DeploymentOperator,
        DeploymentMaintenance,
        TenantRead
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
        "integrations",
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
        "registration-service",
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
        RegistrationConfigurationRead
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
pub(crate) async fn tenant(
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<serde_json::Value>, Error> {
    Ok(Json(
        serde_json::json!({"items":catalog(&auth.proof,false)?}),
    ))
}
pub(crate) async fn platform(
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<serde_json::Value>, Error> {
    Ok(Json(
        serde_json::json!({"items":catalog(&auth.proof,true)?}),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
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
