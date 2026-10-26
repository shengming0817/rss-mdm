use super::error::AuthorizationError;
use super::*;
use crate::context::AuthorizedPrincipal;
use rss_identity_postgres::{
    DepartmentAccessError, GroupAccessError, VerifiedDepartmentSnapshot, VerifiedGroups,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One database statement observes rules and explicit members together. Never cached across proofs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub rules: Vec<Revision<Rule>>,
    pub groups: Vec<Revision<UserGroup>>,
    pub(crate) keys: Vec<crate::api_key::KeyRecord>,
    #[serde(skip)]
    pub(crate) installation: Option<crate::tenancy::InstallationTenants>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveGrant {
    pub(super) rule_id: Uuid,
    pub(super) rule_revision: u64,
    pub(crate) subject: Subject,
    #[serde(flatten)]
    pub(super) grant: Grant,
    pub(super) observation: Option<Observation>,
}
#[derive(schemars::JsonSchema, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Observation {
    snapshot_id: Uuid,
    observed_at: i64,
    pub(super) expires_at: i64,
    source_revision: Option<String>,
}
impl Snapshot {
    pub fn key_record(&self, id: Uuid) -> Option<&crate::api_key::KeyRecord> {
        self.keys.iter().find(|key| key.id == id)
    }
    pub(crate) fn key(
        &self,
        proof: &AuthorizedPrincipal,
    ) -> Result<Option<&crate::api_key::KeyRecord>, AuthorizationError> {
        proof
            .check_live()
            .map_err(|_| AuthorizationError::Unauthorized)?;
        let Some(credential) = proof.key_proof() else {
            return Ok(None);
        };
        let key = self
            .keys
            .iter()
            .find(|key| key.id == credential.id)
            .ok_or(AuthorizationError::Unauthorized)?;
        // The authenticated proof bounds expiry in its injected monotonic clock.
        // Any grant, expiry or enabled-state change invalidates that proof.
        if key.credential_revision != credential.credential_revision
            || key.authority_revision != credential.authority_revision
            || key.revoked
            || !key.metadata.enabled
        {
            return Err(AuthorizationError::Unauthorized);
        }
        Ok(Some(key))
    }
    /// Deterministic query binding for a live principal and its effective authority.
    pub fn query_binding(&self, proof: &AuthorizedPrincipal) -> Result<String, Error> {
        use sha2::{Digest, Sha256};
        if let Some(key) = self.key(proof)? {
            return Ok(format!(
                "{:x}",
                Sha256::digest(
                    serde_json::to_vec(&(
                        proof.actor(),
                        key.authority_revision,
                        &key.metadata.grants
                    ))
                    .map_err(|_| Error::Malformed)?
                )
            ));
        }
        let mut grants = self
            .effective(proof)?
            .into_iter()
            .map(|grant| serde_json::to_string(&grant).map_err(|_| Error::Malformed))
            .collect::<Result<Vec<_>, _>>()?;
        grants.sort();
        Ok(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(proof.actor(), grants)).map_err(|_| Error::Malformed)?
            )
        ))
    }

    pub fn validate(&self, tenant: &str, instance: &str) -> Result<(), AuthorizationError> {
        let invalid = || AuthorizationError::Corrupt;
        if self.rules.len() > 10000 || self.groups.len() > 10000 || self.keys.len() > 1000 {
            return Err(invalid());
        }
        for key in &self.keys {
            if key.id.is_nil()
                || key.revision == 0
                || key.authority_revision == 0
                || key.credential_revision == 0
            {
                return Err(invalid());
            }
            key.metadata.validate().map_err(|_| invalid())?;
            key.created_by
                .validate(tenant, instance)
                .map_err(|_| invalid())?;
        }
        for r in &self.rules {
            if r.id.is_nil() || r.revision == 0 {
                return Err(invalid());
            }
            if let Some(rule) = &r.value {
                rule.validate(tenant, instance).map_err(|_| invalid())?;
            }
        }
        for g in &self.groups {
            if g.id.is_nil() || g.revision == 0 {
                return Err(invalid());
            }
            if let Some(group) = &g.value {
                group.validate(tenant, instance).map_err(|_| invalid())?;
            }
        }
        Ok(())
    }
    pub fn effective(
        &self,
        proof: &AuthorizedPrincipal,
    ) -> Result<Vec<EffectiveGrant>, AuthorizationError> {
        proof
            .check_live()
            .map_err(|_| AuthorizationError::Unauthorized)?;
        if let Some(authority) = proof.initialization_authority() {
            return authority
                .effective(self)
                .map_err(|_| AuthorizationError::Forbidden);
        }
        proof.session().map_err(|_| AuthorizationError::Forbidden)?;
        let mut grants = Vec::new();
        for record in &self.rules {
            let Some(rule) = &record.value else { continue };
            let Some(observation) = self.matches(proof, &rule.subject)? else {
                continue;
            };
            grants.extend(rule.grants.iter().cloned().map(|grant| EffectiveGrant {
                rule_id: record.id,
                rule_revision: record.revision,
                subject: rule.subject.clone(),
                grant,
                observation: observation.clone(),
            }));
        }
        proof
            .check_live()
            .map_err(|_| AuthorizationError::Unauthorized)?;
        Ok(grants)
    }
    pub fn require(
        &self,
        proof: &AuthorizedPrincipal,
        operation: Permission,
        device: Option<&str>,
    ) -> Result<(), AuthorizationError> {
        self.installation
            .as_ref()
            .ok_or(AuthorizationError::Corrupt)?
            .require(proof, operation)
            .map_err(|_| AuthorizationError::Forbidden)?;
        proof
            .check_live()
            .map_err(|_| AuthorizationError::Unauthorized)?;
        if let Some(device) = device {
            rss_observation::Id::new(device).map_err(|_| AuthorizationError::Malformed)?;
        }
        if let Some(key) = self.key(proof)? {
            return if key
                .metadata
                .grants
                .iter()
                .any(|g| g.covers(operation, device))
            {
                Ok(())
            } else {
                Err(AuthorizationError::Forbidden)
            };
        }
        if proof.initialization_authority().is_some() {
            return if self
                .effective(proof)?
                .iter()
                .any(|g| g.grant.covers(operation, device))
            {
                Ok(())
            } else {
                Err(AuthorizationError::Forbidden)
            };
        }
        for record in &self.rules {
            let Some(rule) = &record.value else { continue };
            if rule.grants.iter().any(|g| g.covers(operation, device))
                && self.matches(proof, &rule.subject)?.is_some()
            {
                return proof
                    .check_live()
                    .map_err(|_| AuthorizationError::Unauthorized);
            }
        }
        Err(AuthorizationError::Forbidden)
    }
    pub(crate) fn require_management(
        &self,
        context: &rss_identity_postgres::ManagementContext<'_>,
        operation: Permission,
    ) -> Result<(), AuthorizationError> {
        let facts = SubjectFacts::Management(context);
        facts.check_live()?;
        let user = facts.user();
        self.installation
            .as_ref()
            .ok_or(AuthorizationError::Corrupt)?
            .require_identity(&user.instance_id, &user.tenant_id, operation)
            .map_err(|_| AuthorizationError::Forbidden)?;
        for rule in self.rules.iter().filter_map(|r| r.value.as_ref()) {
            if rule.grants.iter().any(|g| g.covers(operation, None))
                && self.matches_facts(&facts, &rule.subject)?.is_some()
            {
                return facts.check_live();
            }
        }
        Err(AuthorizationError::Forbidden)
    }
    pub fn inventory_devices(
        &self,
        proof: &AuthorizedPrincipal,
    ) -> Result<Option<std::collections::BTreeSet<String>>, AuthorizationError> {
        self.devices_for(proof, Permission::InventoryRead)
    }
    /// Project the current device grants for an existing device-scoped operation.
    /// `None` means all devices; an absent grant remains a denial, never an empty authority.
    pub fn devices_for(
        &self,
        proof: &AuthorizedPrincipal,
        permission: Permission,
    ) -> Result<Option<std::collections::BTreeSet<String>>, AuthorizationError> {
        proof
            .check_live()
            .map_err(|_| AuthorizationError::Unauthorized)?;
        if let Some(key) = self.key(proof)? {
            let grants: Vec<_> = key
                .metadata
                .grants
                .iter()
                .filter(|g| g.operation == permission)
                .collect();
            if grants.iter().any(|g| g.scope == Scope::AllDevices) {
                return Ok(None);
            }
            let devices: std::collections::BTreeSet<_> = grants
                .into_iter()
                .filter_map(|g| {
                    if let Scope::Device { id } = &g.scope {
                        Some(id.clone())
                    } else {
                        None
                    }
                })
                .collect();
            return if devices.is_empty() {
                Err(AuthorizationError::Forbidden)
            } else {
                Ok(Some(devices))
            };
        }
        if proof.initialization_authority().is_some() {
            return if self
                .effective(proof)?
                .iter()
                .any(|g| g.grant.operation == permission && g.grant.scope == Scope::AllDevices)
            {
                Ok(None)
            } else {
                Err(AuthorizationError::Forbidden)
            };
        }
        let mut devices = std::collections::BTreeSet::new();
        let mut all = false;
        for record in &self.rules {
            let Some(rule) = &record.value else { continue };
            if self.matches(proof, &rule.subject)?.is_none() {
                continue;
            }
            for grant in &rule.grants {
                if grant.operation != permission {
                    continue;
                }
                match &grant.scope {
                    Scope::AllDevices => all = true,
                    Scope::Device { id } => {
                        devices.insert(id.clone());
                    }
                    Scope::Tenant => return Err(AuthorizationError::Forbidden),
                }
            }
        }
        proof
            .check_live()
            .map_err(|_| AuthorizationError::Unauthorized)?;
        if all {
            Ok(None)
        } else if devices.is_empty() {
            Err(AuthorizationError::Forbidden)
        } else {
            Ok(Some(devices))
        }
    }

    /// Match trusted identity facts without granting a management permission.
    pub fn matches_subjects(
        &self,
        facts: SubjectFacts<'_>,
        subjects: &[Subject],
    ) -> Result<bool, AuthorizationError> {
        facts.check_live()?;
        let mut matched = false;
        for subject in subjects {
            if self.matches_facts(&facts, subject)?.is_some() {
                matched = true;
                break;
            }
        }
        facts.check_live()?;
        Ok(matched)
    }
    fn matches(
        &self,
        proof: &AuthorizedPrincipal,
        subject: &Subject,
    ) -> Result<Option<Option<Observation>>, AuthorizationError> {
        self.matches_facts(
            &SubjectFacts::Authenticated(
                proof.session().map_err(|_| AuthorizationError::Forbidden)?,
            ),
            subject,
        )
    }
    fn matches_facts(
        &self,
        proof: &SubjectFacts<'_>,
        subject: &Subject,
    ) -> Result<Option<Option<Observation>>, AuthorizationError> {
        match subject {
            Subject::User { user } => Ok((user == &proof.user()).then_some(None)),
            Subject::UserGroup { id } => Ok(self
                .groups
                .iter()
                .any(|g| {
                    g.id == *id
                        && g.value
                            .as_ref()
                            .is_some_and(|g| g.enabled && g.members.contains(&proof.user()))
                })
                .then_some(None)),
            Subject::IdpGroup { source, id } => {
                let VerifiedGroups::Available(groups) = proof
                    .groups()
                    .map_err(|_| AuthorizationError::Unauthorized)?
                else {
                    return Ok(None);
                };
                if !source.matches(
                    groups.source().provider_id(),
                    groups.source().issuer(),
                    groups.provider_config_version(),
                ) {
                    return Ok(None);
                }
                let values = match groups.values() {
                    Ok(values) => values,
                    Err(GroupAccessError::SnapshotExpired) => return Ok(None),
                    Err(GroupAccessError::ProofExpired) => {
                        return Err(AuthorizationError::Unauthorized);
                    }
                };
                Ok(values.contains(id).then(|| {
                    Some(Observation {
                        snapshot_id: groups.snapshot_id(),
                        observed_at: groups.observed_at(),
                        expires_at: groups.expires_at(),
                        source_revision: None,
                    })
                }))
            }
            Subject::Department {
                source,
                id,
                matching,
            } => {
                let VerifiedDepartmentSnapshot::Available(department) = proof
                    .department_snapshot()
                    .map_err(|_| AuthorizationError::Unauthorized)?
                else {
                    return Ok(None);
                };
                if !source.matches(
                    department.provider_id(),
                    department.issuer(),
                    department.provider_config_version(),
                ) {
                    return Ok(None);
                }
                let snapshot = match department.snapshot() {
                    Ok(value) => value,
                    Err(DepartmentAccessError::SnapshotExpired) => return Ok(None),
                    Err(DepartmentAccessError::ProofExpired) => {
                        return Err(AuthorizationError::Unauthorized);
                    }
                };
                Ok(department_matches(snapshot, id, *matching).then(|| {
                    Some(Observation {
                        snapshot_id: department.snapshot_id(),
                        observed_at: department.observed_at(),
                        expires_at: department.expires_at(),
                        source_revision: Some(snapshot.source_revision().into()),
                    })
                }))
            }
        }
    }
}
pub fn department_matches(
    snapshot: &rss_identity_core::department::DepartmentSnapshot,
    id: &str,
    matching: DepartmentMatch,
) -> bool {
    snapshot.memberships().iter().any(|member| {
        let mut current = Some(member.as_str());
        while let Some(value) = current {
            if value == id {
                return true;
            }
            if matching == DepartmentMatch::Exact {
                return false;
            }
            current = snapshot
                .nodes()
                .iter()
                .find(|node| node.id().as_str() == value)
                .and_then(|node| node.parent_id().map(|v| v.as_str()));
        }
        false
    })
}

impl Snapshot {
    pub fn require_all_devices(
        &self,
        proof: &crate::context::AuthorizedPrincipal,
        permission: Permission,
    ) -> Result<(), crate::Error> {
        if let Some(key) = self.key(proof)? {
            return if key
                .metadata
                .grants
                .iter()
                .any(|g| g.operation == permission && g.scope == Scope::AllDevices)
            {
                Ok(())
            } else {
                Err(Error::Forbidden)
            };
        }
        if self
            .effective(proof)
            .map_err(crate::Error::from)?
            .iter()
            .any(|g| g.grant.operation == permission && matches!(g.grant.scope, Scope::AllDevices))
        {
            proof.check_live()
        } else {
            Err(crate::Error::Forbidden)
        }
    }
}

/// A borrowed component proof. Neither form is a caller-supplied identity assertion.
pub enum SubjectFacts<'a> {
    Authenticated(&'a rss_identity_postgres::AuthenticatedSession),
    Revalidated(&'a rss_identity_postgres::RevalidatedSession),
    Management(&'a rss_identity_postgres::ManagementContext<'a>),
}
impl SubjectFacts<'_> {
    fn check_live(&self) -> Result<(), AuthorizationError> {
        match self {
            Self::Authenticated(proof) => proof
                .assurance()
                .map(|_| ())
                .map_err(|_| AuthorizationError::Unauthorized),
            Self::Revalidated(proof) => proof
                .check_live()
                .map_err(|_| AuthorizationError::Unauthorized),
            Self::Management(proof) => proof
                .check_live()
                .map_err(|_| AuthorizationError::Unauthorized),
        }
    }
    pub fn user(&self) -> User {
        let (instance, account) = match self {
            Self::Authenticated(proof) => (proof.instance(), proof.account()),
            Self::Revalidated(proof) => (proof.instance(), proof.account()),
            Self::Management(proof) => (proof.instance(), proof.actor()),
        };
        User {
            instance_id: instance.to_string(),
            tenant_id: account.tenant.to_string(),
            principal_id: account.principal.as_uuid().to_string(),
        }
    }
    fn groups(&self) -> Result<VerifiedGroups<'_>, GroupAccessError> {
        match self {
            Self::Authenticated(proof) => proof.groups(),
            Self::Revalidated(proof) => proof.groups(),
            Self::Management(proof) => proof.groups(),
        }
    }
    fn department_snapshot(&self) -> Result<VerifiedDepartmentSnapshot<'_>, DepartmentAccessError> {
        match self {
            Self::Authenticated(proof) => proof.department_snapshot(),
            Self::Revalidated(proof) => proof.department_snapshot(),
            Self::Management(proof) => proof.department_snapshot(),
        }
    }
}
