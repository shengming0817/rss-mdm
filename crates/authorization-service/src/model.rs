use super::error::AuthorizationError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    CertificateArchiveRead,
    CertificateArchiveWrite,
    CertificateArchiveUnlock,
    CertificateArchiveExport,
    RuntimeDiagnosticsRead,
    InventoryRead,
    InventorySensitiveRead,
    InventoryFieldsWrite,
    ComplianceRead,
    ComplianceRuleRead,
    ComplianceWrite,
    ComplianceRecompute,
    InventoryCollect,
    InventoryAssign,
    Enrollment,
    Credentials,
    DeviceWipe,
    ConfigurationWrite,
    DeviceControl,
    DeviceUpdate,
    AccountWrite,
    SecurityOperate,
    DeviceDiagnostics,
    ScriptExecute,
    SoftwareDeploy,
    OperationRead,
    OperationCancel,
    AuthorizationRead,
    AuthorizationWrite,
    UserGroupRead,
    UserGroupWrite,
    DepartmentRead,

    GroupRead,
    GroupWrite,
    GroupRecompute,
    ScopeRead,
    ScopeWrite,
    PolicyRead,
    PolicyWrite,
    ResourceRead,
    ResourceWrite,
    SoftwareRead,
    SoftwareWrite,
    SoftwareApprove,
    SoftwareWithdraw,
    ReleaseRead,
    ReleaseWrite,
    ReleaseValidate,
    ReleaseApprove,
    ReleasePublish,
    ReleaseWithdraw,
    ReleaseRecover,
}
impl Permission {
    fn device(self) -> bool {
        match self {
            Self::InventoryRead
            | Self::ComplianceRead
            | Self::InventoryCollect
            | Self::InventoryAssign
            | Self::Enrollment
            | Self::Credentials
            | Self::DeviceWipe
            | Self::DeviceControl
            | Self::DeviceUpdate
            | Self::AccountWrite
            | Self::SecurityOperate
            | Self::DeviceDiagnostics
            | Self::ConfigurationWrite
            | Self::ScriptExecute
            | Self::SoftwareDeploy
            | Self::OperationRead
            | Self::OperationCancel => true,
            Self::CertificateArchiveRead
            | Self::CertificateArchiveWrite
            | Self::CertificateArchiveUnlock
            | Self::CertificateArchiveExport
            | Self::InventorySensitiveRead
            | Self::InventoryFieldsWrite
            | Self::RuntimeDiagnosticsRead
            | Self::AuthorizationRead
            | Self::ComplianceRuleRead
            | Self::ComplianceWrite
            | Self::ComplianceRecompute
            | Self::AuthorizationWrite
            | Self::UserGroupRead
            | Self::UserGroupWrite
            | Self::DepartmentRead
            | Self::GroupRead
            | Self::GroupWrite
            | Self::GroupRecompute
            | Self::ScopeRead
            | Self::ScopeWrite
            | Self::PolicyRead
            | Self::PolicyWrite
            | Self::ResourceRead
            | Self::ResourceWrite
            | Self::SoftwareRead
            | Self::SoftwareWrite
            | Self::SoftwareApprove
            | Self::SoftwareWithdraw
            | Self::ReleaseRead
            | Self::ReleaseWrite
            | Self::ReleaseValidate
            | Self::ReleaseApprove
            | Self::ReleasePublish
            | Self::ReleaseWithdraw
            | Self::ReleaseRecover => false,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    Tenant,
    AllDevices,
    Device { id: String },
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    pub operation: Permission,
    pub scope: Scope,
}
impl Grant {
    pub fn validate(&self) -> Result<(), AuthorizationError> {
        if self.operation.device() == matches!(self.scope, Scope::Tenant) {
            return Err(AuthorizationError::Malformed);
        }
        if let Scope::Device { id } = &self.scope {
            rss_observation::Id::new(id).map_err(|_| AuthorizationError::Malformed)?;
        }
        Ok(())
    }
    pub fn covers(&self, operation: Permission, device: Option<&str>) -> bool {
        self.operation == operation
            && match (&self.scope, device) {
                (Scope::Tenant, None) | (Scope::AllDevices, Some(_)) => true,
                (Scope::Device { id }, Some(target)) => id == target,
                _ => false,
            }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct User {
    pub instance_id: String,
    pub tenant_id: String,
    pub principal_id: String,
}
impl User {
    pub fn validate(&self, tenant: &str, instance: &str) -> Result<(), AuthorizationError> {
        if self.tenant_id != tenant || self.instance_id != instance {
            return Err(AuthorizationError::Malformed);
        }
        canonical_uuid(&self.principal_id)?;
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Source {
    pub provider_id: Uuid,
    pub issuer: String,
    pub configuration_version: i64,
}
impl Source {
    fn validate(&self) -> Result<(), AuthorizationError> {
        if self.provider_id.is_nil() || self.configuration_version < 1 {
            return Err(AuthorizationError::Malformed);
        }
        let url = url::Url::parse(&self.issuer).map_err(|_| AuthorizationError::Malformed)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(AuthorizationError::Malformed);
        }
        if self.issuer.len() > 2048 {
            return Err(AuthorizationError::Malformed);
        }
        Ok(())
    }
    pub fn matches(&self, provider: Uuid, issuer: &str, version: i64) -> bool {
        self.provider_id == provider
            && self.issuer == issuer
            && self.configuration_version == version
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DepartmentMatch {
    Exact,
    Subtree,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Subject {
    User {
        user: User,
    },
    IdpGroup {
        source: Source,
        id: String,
    },
    Department {
        source: Source,
        id: String,
        matching: DepartmentMatch,
    },
    UserGroup {
        id: Uuid,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rule {
    pub subject: Subject,
    pub grants: Vec<Grant>,
}
impl Rule {
    pub fn validate(&self, tenant: &str, instance: &str) -> Result<(), AuthorizationError> {
        match &self.subject {
            Subject::User { user } => user.validate(tenant, instance)?,
            Subject::IdpGroup { source, id } | Subject::Department { source, id, .. } => {
                source.validate()?;
                exact_id(id)?;
            }
            Subject::UserGroup { id } if id.is_nil() => return Err(AuthorizationError::Malformed),
            Subject::UserGroup { .. } => {}
        }
        if self.grants.is_empty() || self.grants.len() > 256 {
            return Err(AuthorizationError::Malformed);
        }
        for (index, grant) in self.grants.iter().enumerate() {
            grant.validate()?;
            if self.grants[..index].contains(grant) {
                return Err(AuthorizationError::Malformed);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserGroup {
    pub name: String,
    pub enabled: bool,
    pub members: Vec<User>,
}
impl UserGroup {
    pub fn validate(&self, tenant: &str, instance: &str) -> Result<(), AuthorizationError> {
        exact_id(&self.name)?;
        if self.members.len() > 10000 {
            return Err(AuthorizationError::Malformed);
        }
        let mut unique = std::collections::BTreeSet::new();
        for member in &self.members {
            member.validate(tenant, instance)?;
            if !unique.insert(member) {
                return Err(AuthorizationError::Malformed);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct Revision<T> {
    pub id: Uuid,
    pub revision: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub value: Option<T>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct Change<T> {
    pub operation_id: Uuid,
    pub expected_revision: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub value: Option<T>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub id: Uuid,
    pub revision: u64,
    pub deleted: bool,
}
pub fn exact_id(value: &str) -> Result<(), AuthorizationError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AuthorizationError::Malformed);
    }
    Ok(())
}
pub fn canonical_uuid(value: &str) -> Result<(), AuthorizationError> {
    let id = Uuid::parse_str(value).map_err(|_| AuthorizationError::Malformed)?;
    if id.is_nil() || id.to_string() != value {
        return Err(AuthorizationError::Malformed);
    }
    Ok(())
}
