//! Durable initialization evidence, restricted to one tenant's fixed baseline objects.
//! No browser credential or new grant is created; every use checks the original rule revision.
use crate::{
    Error, Grant, Permission, Receipt, Scope, Subject, User, context::AuthorizedPrincipal,
};
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};

/// Stored only by the product initialization owner, never accepted from management input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    profile: rss_mdm_install_support::StorageProfile,
    user: User,
    rule: Receipt,
    targets: BTreeSet<String>,
    storage_target: [u8; 16],
    storage_lineage: [u8; 16],
    expected_epoch: i64,
}
const PERMISSIONS: &[Permission] = &[
    Permission::GroupRead,
    Permission::GroupWrite,
    Permission::GroupRecompute,
    Permission::PolicyRead,
    Permission::PolicyWrite,
    Permission::ResourceRead,
    Permission::ResourceWrite,
    Permission::InventoryRead,
    // Native publication retains full raw query evidence, including unmapped properties.
    Permission::InventorySensitiveRead,
    Permission::InventoryCollect,
    Permission::InventoryFieldsWrite,
];
impl Authority {
    pub(crate) fn new(
        binding: ExecutionBinding,
        profile: rss_mdm_install_support::StorageProfile,
        user: User,
        rule: Receipt,
        targets: BTreeSet<String>,
    ) -> Result<Self, Error> {
        user.validate(&user.tenant_id, &user.instance_id)?;
        if user.tenant_id != binding.tenant().to_string() {
            return Err(Error::Forbidden);
        }
        if rule.deleted
            || rule.id.is_nil()
            || rule.revision == 0
            || targets.is_empty()
            || targets.len() > 512
            || targets.iter().any(|s| s.is_empty() || s.len() > 256)
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            storage_target: binding.storage().target(),
            storage_lineage: binding.storage().lineage(),
            expected_epoch: binding.epoch().get(),
            profile,
            user,
            rule,
            targets,
        })
    }
    /// Stable owner of the original authenticated initialization, not a transferable credential.
    pub(crate) fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn user(&self) -> &User {
        &self.user
    }
    pub fn binding(&self) -> Result<ExecutionBinding, Error> {
        Ok(ExecutionBinding::new(
            StorageIdentity::new(self.storage_target, self.storage_lineage)
                .map_err(|_| Error::Corrupt)?,
            rss_request_context::TenantId::parse(&self.user.tenant_id)
                .map_err(|_| Error::Corrupt)?,
            Epoch::new(self.expected_epoch).map_err(|_| Error::Corrupt)?,
        ))
    }
    pub(crate) fn allows_target(&self, target: &str) -> bool {
        self.targets.contains(target)
    }
    pub(crate) fn grants(&self, snapshot: &crate::Snapshot) -> Result<Vec<Grant>, Error> {
        let record = snapshot
            .rules
            .iter()
            .find(|r| r.id == self.rule.id && r.revision == self.rule.revision)
            .ok_or(Error::Forbidden)?;
        let rule = record.value.as_ref().ok_or(Error::Forbidden)?;
        if !matches!(&rule.subject,Subject::User {user} if user==&self.user) {
            return Err(Error::Forbidden);
        }
        let grants = rule
            .grants
            .iter()
            .filter(|g| PERMISSIONS.contains(&g.operation))
            .cloned()
            .collect::<Vec<_>>();
        for permission in PERMISSIONS {
            let scope = if permission.device() {
                Scope::AllDevices
            } else {
                Scope::Tenant
            };
            if !grants
                .iter()
                .any(|g| g.operation == *permission && g.scope == scope)
            {
                return Err(Error::Forbidden);
            }
        }
        Ok(grants)
    }
    pub(crate) fn effective(
        &self,
        snapshot: &crate::Snapshot,
    ) -> Result<Vec<crate::evaluate::EffectiveGrant>, Error> {
        Ok(self
            .grants(snapshot)?
            .into_iter()
            .map(|grant| crate::evaluate::EffectiveGrant {
                rule_id: self.rule.id,
                rule_revision: self.rule.revision,
                subject: Subject::User {
                    user: self.user.clone(),
                },
                grant,
                observation: None,
            })
            .collect())
    }
    /// Rehydrate a bounded attempt from trusted product state and current authorization facts.
    pub async fn principal(&self, store: &crate::Store) -> Result<AuthorizedPrincipal, Error> {
        if self.profile != store.profile() || self.profile != store.authority_profile() {
            return Err(Error::Forbidden);
        }
        let principal =
            AuthorizedPrincipal::from_initialization(Arc::new(self.clone()), store.clock.clone())?
                .load_authorization(store)
                .await?;
        self.grants(principal.authorization()?)?;
        Ok(principal)
    }
}
/// Called only inside the already-authenticated target account/grant creation transaction.
/// The caller must commit the returned evidence with that same provisioning operation.
pub async fn grant_administrator_on(
    binding: ExecutionBinding,
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    user: User,
    id: uuid::Uuid,
    targets: BTreeSet<String>,
) -> Result<(Receipt, Authority), Error> {
    let receipt = crate::store::grant_tenant_administrator_on(profile, c, user.clone(), id).await?;
    let authority = Authority::new(binding, profile, user, receipt.clone(), targets)?;
    Ok((receipt, authority))
}

/// Fence a baseline mutation in its owner's original transaction, before business locks.
pub async fn check_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    proof: &AuthorizedPrincipal,
    permission: Permission,
    target: &str,
) -> Result<(), Error> {
    let profile = proof.profile();

    if proof.initialization_authority().is_none() {
        return Err(Error::Forbidden);
    }
    if tx.tenant_id().to_string() != proof.tenant_id() {
        return Err(Error::Forbidden);
    }
    proof.require_initialization_target(target)?;
    let authority = if permission.device() {
        crate::OperationAuthority::all_devices(proof.authorization()?, proof, permission)?
    } else {
        crate::OperationAuthority::tenant(proof.authorization()?, proof, permission)?
    };
    let valid = tx
        .with_connection(move |c| {
            Box::pin(async move {
                let now: i64 =
                    sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::bigint")
                        .fetch_one(&mut *c)
                        .await?;
                Ok(authority.valid(profile, c, permission, now).await)
            })
        })
        .await
        .map_err(|_| Error::Storage)??;
    if !valid {
        return Err(Error::Forbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    #[test]
    fn evidence_limits_permissions_targets_and_original_rule_revision() {
        let user = User {
            tenant_id: Uuid::from_u128(1).to_string(),
            instance_id: Uuid::from_u128(2).to_string(),
            principal_id: Uuid::from_u128(3).to_string(),
        };
        let id = Uuid::from_u128(4);
        let authority = Authority::new(
            ExecutionBinding::new(
                StorageIdentity::new([1; 16], [2; 16]).unwrap(),
                rss_request_context::TenantId::parse(&user.tenant_id).unwrap(),
                Epoch::new(1).unwrap(),
            ),
            rss_mdm_install_support::StorageProfile::Mdm,
            user.clone(),
            Receipt {
                id,
                revision: 1,
                deleted: false,
            },
            ["fixed-resource".into()].into(),
        )
        .unwrap();
        let mut snapshot = crate::Snapshot {
            rules: vec![crate::Revision {
                id,
                revision: 1,
                value: Some(crate::tenant_administrator_rule(user)),
            }],
            groups: vec![],
            keys: vec![],
            installation: None,
        };
        let grants = authority.grants(&snapshot).unwrap();
        assert!(
            grants
                .iter()
                .any(|g| g.operation == Permission::GroupRead && g.scope == crate::Scope::Tenant)
        );
        assert!(grants.iter().any(
            |g| g.operation == Permission::InventoryRead && g.scope == crate::Scope::AllDevices
        ));
        assert!(
            !grants
                .iter()
                .any(|g| g.operation == Permission::AuthorizationWrite
                    || g.operation == Permission::ScriptExecute)
        );
        assert!(authority.allows_target("fixed-resource"));
        assert!(!authority.allows_target("another-resource"));
        snapshot.rules[0].revision = 2;
        assert!(authority.grants(&snapshot).is_err());
        snapshot.rules[0].revision = 1;
        snapshot.rules[0].value = None;
        assert!(authority.grants(&snapshot).is_err());
    }
}
