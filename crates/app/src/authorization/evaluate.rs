use super::*;
use crate::{Error, Failure, identity::Principal};
use rss_identity_postgres::{
    DepartmentAccessError, GroupAccessError, VerifiedDepartmentSnapshot, VerifiedGroups,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One database statement observes rules and explicit members together. Never cached across proofs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub(crate) rules: Vec<Revision<Rule>>,
    pub(crate) groups: Vec<Revision<UserGroup>>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EffectiveGrant {
    rule_id: Uuid,
    rule_revision: u64,
    subject: Subject,
    #[serde(flatten)]
    grant: Grant,
    observation: Option<Observation>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Observation {
    snapshot_id: Uuid,
    observed_at: i64,
    expires_at: i64,
    source_revision: Option<String>,
}
impl Snapshot {
    pub(crate) fn validate(&self, tenant: &str, instance: &str) -> Result<(), Error> {
        let invalid = || Error::Unavailable(Failure::AccessStore);
        if self.rules.len() > 10000 || self.groups.len() > 10000 {
            return Err(invalid());
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
    pub(crate) fn effective(&self, proof: &Principal) -> Result<Vec<EffectiveGrant>, Error> {
        proof.check_live()?;
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
        proof.check_live()?;
        Ok(grants)
    }
    pub(crate) fn require(
        &self,
        proof: &Principal,
        operation: Permission,
        device: Option<&str>,
    ) -> Result<(), Error> {
        proof.check_live()?;
        if let Some(device) = device {
            rss_observation::Id::new(device).map_err(|_| Error::Malformed)?;
        }
        for record in &self.rules {
            let Some(rule) = &record.value else { continue };
            if rule.grants.iter().any(|g| g.covers(operation, device))
                && self.matches(proof, &rule.subject)?.is_some()
            {
                return proof.check_live();
            }
        }
        Err(Error::Forbidden)
    }
    pub(crate) fn inventory_devices(
        &self,
        proof: &Principal,
    ) -> Result<Option<std::collections::BTreeSet<String>>, Error> {
        proof.check_live()?;
        let mut devices = std::collections::BTreeSet::new();
        let mut all = false;
        for record in &self.rules {
            let Some(rule) = &record.value else { continue };
            if self.matches(proof, &rule.subject)?.is_none() {
                continue;
            }
            for grant in &rule.grants {
                if grant.operation != Permission::InventoryRead {
                    continue;
                }
                match &grant.scope {
                    Scope::AllDevices => all = true,
                    Scope::Device { id } => {
                        devices.insert(id.clone());
                    }
                    Scope::Tenant => return Err(Error::Forbidden),
                }
            }
        }
        proof.check_live()?;
        if all {
            Ok(None)
        } else if devices.is_empty() {
            Err(Error::Forbidden)
        } else {
            Ok(Some(devices))
        }
    }
    pub(crate) fn publisher(&self, user: &User) -> Result<(), Error> {
        if self.rules.iter().filter_map(|r| r.value.as_ref()).any(|r| {
            matches!(&r.subject, Subject::User { user: candidate } if candidate == user)
                && r.grants
                    .iter()
                    .any(|g| g.covers(Permission::ReleasePublish, None))
        }) {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }
    fn matches(
        &self,
        proof: &Principal,
        subject: &Subject,
    ) -> Result<Option<Option<Observation>>, Error> {
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
                let VerifiedGroups::Available(groups) =
                    proof.session().groups().map_err(|_| Error::Unauthorized)?
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
                    Err(GroupAccessError::ProofExpired) => return Err(Error::Unauthorized),
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
                    .session()
                    .department_snapshot()
                    .map_err(|_| Error::Unauthorized)?
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
                    Err(DepartmentAccessError::ProofExpired) => return Err(Error::Unauthorized),
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
pub(crate) fn department_matches(
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
