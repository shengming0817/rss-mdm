use crate::Error;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    InventoryRead,
    Enrollment,
    Credentials,
    DeviceWipe,
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
    PlanPreview,
    PlanSave,
    ResourceRead,
    ResourceWrite,
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
        matches!(
            self,
            Self::InventoryRead | Self::Enrollment | Self::Credentials | Self::DeviceWipe
        )
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
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.operation.device() == matches!(self.scope, Scope::Tenant) {
            return Err(Error::Malformed);
        }
        if let Scope::Device { id } = &self.scope {
            rss_observation::Id::new(id).map_err(|_| Error::Malformed)?;
        }
        Ok(())
    }
    pub(crate) fn covers(&self, operation: Permission, device: Option<&str>) -> bool {
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
    pub(crate) fn validate(&self, tenant: &str, instance: &str) -> Result<(), Error> {
        if self.tenant_id != tenant || self.instance_id != instance {
            return Err(Error::Malformed);
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
    fn validate(&self) -> Result<(), Error> {
        if self.provider_id.is_nil() || self.configuration_version < 1 {
            return Err(Error::Malformed);
        }
        crate::config::https_url(&self.issuer).map_err(|_| Error::Malformed)?;
        if self.issuer.len() > 2048 {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub(crate) fn matches(&self, provider: Uuid, issuer: &str, version: i64) -> bool {
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
    pub(crate) fn validate(&self, tenant: &str, instance: &str) -> Result<(), Error> {
        match &self.subject {
            Subject::User { user } => user.validate(tenant, instance)?,
            Subject::IdpGroup { source, id } | Subject::Department { source, id, .. } => {
                source.validate()?;
                exact_id(id)?;
            }
            Subject::UserGroup { id } if id.is_nil() => return Err(Error::Malformed),
            Subject::UserGroup { .. } => {}
        }
        if self.grants.is_empty() || self.grants.len() > 256 {
            return Err(Error::Malformed);
        }
        for (index, grant) in self.grants.iter().enumerate() {
            grant.validate()?;
            if self.grants[..index].contains(grant) {
                return Err(Error::Malformed);
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
    pub(crate) fn validate(&self, tenant: &str, instance: &str) -> Result<(), Error> {
        exact_id(&self.name)?;
        if self.members.len() > 10000 {
            return Err(Error::Malformed);
        }
        let mut unique = std::collections::BTreeSet::new();
        for member in &self.members {
            member.validate(tenant, instance)?;
            if !unique.insert(member) {
                return Err(Error::Malformed);
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
pub(crate) fn exact_id(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(Error::Malformed);
    }
    Ok(())
}
pub(crate) fn canonical_uuid(value: &str) -> Result<(), Error> {
    let id = Uuid::parse_str(value).map_err(|_| Error::Malformed)?;
    if id.is_nil() || id.to_string() != value {
        return Err(Error::Malformed);
    }
    Ok(())
}
