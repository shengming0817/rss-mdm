use crate::{PolicyError, PolicyId, Version};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Draft,
    Active,
    Paused,
    Archived,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transition {
    Activate(Version),
    Pause,
    Resume,
    Archive,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionKind {
    Activate,
    Pause,
    Resume,
    Archive,
}
impl Transition {
    pub fn kind(&self) -> TransitionKind {
        match self {
            Self::Activate(_) => TransitionKind::Activate,
            Self::Pause => TransitionKind::Pause,
            Self::Resume => TransitionKind::Resume,
            Self::Archive => TransitionKind::Archive,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    key: PolicyId,
    revision: u64,
    status: Status,
    version: Option<Version>,
}
impl Policy {
    pub fn draft(key: PolicyId) -> Self {
        Self {
            key,
            revision: 0,
            status: Status::Draft,
            version: None,
        }
    }
    /// Rehydrate a caller-owned snapshot; does not prove database authenticity or CAS.
    pub fn restore(
        key: PolicyId,
        revision: u64,
        status: Status,
        version: Option<Version>,
    ) -> Result<Self, PolicyError> {
        let valid = match status {
            Status::Draft => revision == 0 && version.is_none(),
            _ => revision > 0 && version.is_some(),
        };
        if !valid {
            return Err(PolicyError::InvalidSnapshot { status, revision });
        }
        if let Some(v) = &version {
            check_policy(&key, v)?;
        }
        Ok(Self {
            key,
            revision,
            status,
            version,
        })
    }
    pub fn key(&self) -> &PolicyId {
        &self.key
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn status(&self) -> Status {
        self.status
    }
    pub fn version(&self) -> Option<&Version> {
        self.version.as_ref()
    }
    /// Returns a new snapshot. The persistence owner must CAS the input revision.
    pub fn transition(
        &self,
        expected_revision: u64,
        transition: Transition,
    ) -> Result<Self, PolicyError> {
        if expected_revision != self.revision {
            return Err(PolicyError::RevisionConflict {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        let operation = transition.kind();
        let (status, version) = match transition {
            Transition::Activate(v) if self.status != Status::Archived => {
                self.check_activation(&v)?;
                (Status::Active, Some(v))
            }
            Transition::Pause if self.status == Status::Active => {
                (Status::Paused, self.version.clone())
            }
            Transition::Resume if self.status == Status::Paused => {
                (Status::Active, self.version.clone())
            }
            Transition::Archive if matches!(self.status, Status::Active | Status::Paused) => {
                (Status::Archived, self.version.clone())
            }
            _ => {
                return Err(PolicyError::InvalidTransition {
                    status: self.status,
                    operation,
                });
            }
        };
        Ok(Self {
            key: self.key.clone(),
            revision: self
                .revision
                .checked_add(1)
                .ok_or(PolicyError::RevisionOverflow)?,
            status,
            version,
        })
    }
    fn check_activation(&self, new: &Version) -> Result<(), PolicyError> {
        check_policy(&self.key, new)?;
        if let Some(old) = &self.version {
            if old.number() == new.number() && old != new {
                return Err(PolicyError::VersionConflict {
                    version: new.number(),
                });
            }
            if new.number() <= old.number() {
                return Err(PolicyError::StaleVersion {
                    requested: new.number(),
                    latest: old.number(),
                });
            }
            check_payload(old, new)?;
        }
        Ok(())
    }
}
pub(crate) fn check_policy(key: &PolicyId, v: &Version) -> Result<(), PolicyError> {
    if key.tenant() != v.policy().tenant() {
        return Err(PolicyError::TenantMismatch);
    }
    if key != v.policy() {
        return Err(PolicyError::PolicyMismatch);
    }
    Ok(())
}
pub(crate) fn check_payload(a: &Version, b: &Version) -> Result<(), PolicyError> {
    let (a, b) = (a.payload(), b.payload());
    if a.object() == b.object() && a.revision() == b.revision() && a.digest() != b.digest() {
        return Err(PolicyError::PayloadConflict {
            object: b.object().clone(),
            revision: b.revision(),
        });
    }
    Ok(())
}
