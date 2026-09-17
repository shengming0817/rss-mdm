use crate::{PolicyError, PolicyId, Version};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Policy lifecycle controlling new scheduling; does not describe actual device state.
pub enum Status {
    /// Revision zero without a version; no scheduling.
    Draft,
    /// Current version may produce new Apply intents.
    Active,
    /// New/progressing Apply scheduling is closed; cancellation intents remain possible.
    Paused,
    /// Permanently closed; outstanding executions may receive cancellation intents.
    Archived,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Requested in-memory lifecycle change, checked by [`Policy::transition`].
pub enum Transition {
    /// Activate a same-policy, strictly newer version from any non-archived state.
    Activate(Version),
    /// Pause an active policy, retaining its version.
    Pause,
    /// Resume a paused policy with the same version.
    Resume,
    /// Archive an active or paused policy without undoing device effects.
    Archive,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Payload-free lifecycle operation label used in diagnostics.
pub enum TransitionKind {
    /// Activation of a version.
    Activate,
    /// Pause of scheduling.
    Pause,
    /// Resume of scheduling.
    Resume,
    /// Permanent archival.
    Archive,
}
impl Transition {
    /// Return the operation label without exposing its version payload.
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
/// In-memory policy aggregate; the adapter owns authorization and durable revision CAS.
pub struct Policy {
    key: PolicyId,
    revision: u64,
    status: Status,
    version: Option<Version>,
}
impl Policy {
    /// Create revision zero in Draft state with no version and no I/O.
    pub fn draft(key: PolicyId) -> Self {
        Self {
            key,
            revision: 0,
            status: Status::Draft,
            version: None,
        }
    }
    /// Rehydrate a caller-owned snapshot; does not prove database authenticity or CAS.
    /// Draft requires revision zero and no version; all other states require positive
    /// revision and a version. Violations return [`PolicyError::InvalidSnapshot`].
    /// The version must have the same tenant and policy identity. Historical transition
    /// validity and persisted evidence remain the storage owner's responsibility.
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
    /// Borrow the owning policy identity.
    pub fn key(&self) -> &PolicyId {
        &self.key
    }
    /// Return the aggregate revision used for storage CAS, distinct from version number.
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Return the lifecycle state controlling planning.
    pub fn status(&self) -> Status {
        self.status
    }
    /// Borrow the latest version, absent only in Draft state.
    pub fn version(&self) -> Option<&Version> {
        self.version.as_ref()
    }
    /// Return a new snapshot with revision incremented exactly once, without mutating self.
    /// Checks expected revision, lifecycle admissibility and overflow. Activation requires
    /// a strictly newer same-policy version and rejects conflicting immutable version or
    /// payload content. Failures return the corresponding [`PolicyError`].
    /// The persistence owner must authorize and CAS the input revision; this method
    /// performs no writes, dispatch, retries or rollback of device effects.
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
