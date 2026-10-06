use crate::Error;
use crate::context::AuthorizedPrincipal;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityManagementGrant {
    pub tenant_id: String,
    pub instance_id: String,
    pub principal_id: String,
    pub permissions: BTreeSet<IdentityPermission>,
}
pub struct IdentityManagementPolicy {
    instance: String,
    grants: BTreeMap<(String, String), IdentityManagementGrant>,
}
impl IdentityManagementPolicy {
    pub fn new(instance: &str, grants: Vec<IdentityManagementGrant>) -> Result<Self, Error> {
        let invalid = || Error::Configuration;
        crate::canonical_uuid(instance).map_err(|_| invalid())?;
        if grants.len() > 10000 {
            return Err(invalid());
        }
        let mut entries = BTreeMap::new();
        for grant in grants {
            crate::canonical_uuid(&grant.tenant_id).map_err(|_| invalid())?;
            crate::canonical_uuid(&grant.principal_id).map_err(|_| invalid())?;
            if grant.instance_id != instance
                || grant.permissions.is_empty()
                || entries
                    .insert((grant.tenant_id.clone(), grant.principal_id.clone()), grant)
                    .is_some()
            {
                return Err(invalid());
            }
        }
        Ok(Self {
            instance: instance.into(),
            grants: entries,
        })
    }
    /// Runtime accepts exactly the business and installation management tenant.
    pub fn validate_admission(&self, business: &str, management: &str) -> Result<(), Error> {
        if business == management
            || self.grants.values().any(|grant| {
                (grant.tenant_id != business && grant.tenant_id != management)
                    || (grant.tenant_id == management
                        && grant.permissions.contains(&IdentityPermission::Providers))
            })
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    pub fn identity_navigation(
        &self,
        proof: &AuthorizedPrincipal,
    ) -> Result<IdentityNavigation, Error> {
        proof.check_live()?;
        if proof.instance_id() != self.instance {
            return Err(Error::Unauthorized);
        }
        let grant = self
            .grants
            .get(&(proof.tenant_id().into(), proof.principal_id().into()));
        Ok(IdentityNavigation {
            manage_accounts: grant
                .is_some_and(|g| g.permissions.contains(&IdentityPermission::Accounts)),
            manage_providers: grant
                .is_some_and(|g| g.permissions.contains(&IdentityPermission::Providers)),
        })
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityNavigation {
    pub manage_accounts: bool,
    pub manage_providers: bool,
}
/// Product-owned grants for the embedded account and provider planning interfaces.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum IdentityPermission {
    Accounts,
    Providers,
}
impl rss_identity_postgres::ManagementPolicy for IdentityManagementPolicy {
    fn authorize(
        &self,
        context: &rss_identity_postgres::ManagementContext<'_>,
    ) -> Result<
        rss_identity_postgres::ReauthenticationRequirement,
        rss_identity_postgres::ManagementDenied,
    > {
        use rss_identity_postgres::{
            ManagementDenied, ManagementOperation as Op, ReauthenticationRequirement as Auth,
        };
        if context.instance().to_string() != self.instance
            || context
                .target()
                .is_some_and(|target| target.tenant != context.actor().tenant)
        {
            return Err(ManagementDenied);
        }
        if context.operation() == Op::ChangeOwnPassword {
            return if context.target() == Some(context.actor()) {
                Ok(Auth::Recent(std::time::Duration::from_secs(300)))
            } else {
                Err(ManagementDenied)
            };
        }
        let actor = self
            .grants
            .get(&(
                context.actor().tenant.to_string(),
                context.actor().principal.as_uuid().to_string(),
            ))
            .ok_or(ManagementDenied)?;
        let permission = match context.operation() {
            Op::ListProviders
            | Op::CreateProvider
            | Op::UpdateProvider(_)
            | Op::SetProviderEnabled(_, _)
            | Op::TestProvider(_) => IdentityPermission::Providers,
            _ => IdentityPermission::Accounts,
        };
        if !actor.permissions.contains(&permission) {
            return Err(ManagementDenied);
        }
        // Protect every restart-owned account manager from disabling/removing membership.
        if matches!(
            context.operation(),
            Op::SetAccountEnabled(false) | Op::SetMembership(false)
        ) && context.target().is_some_and(|key| {
            self.grants
                .get(&(key.tenant.to_string(), key.principal.as_uuid().to_string()))
                .is_some_and(|binding| binding.permissions.contains(&IdentityPermission::Accounts))
        }) {
            return Err(ManagementDenied);
        }
        Ok(match context.operation() {
            Op::ListAccounts | Op::ListProviders => Auth::None,
            _ => Auth::Recent(std::time::Duration::from_secs(300)),
        })
    }
}
