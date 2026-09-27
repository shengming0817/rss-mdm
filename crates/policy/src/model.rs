use crate::{Definition, Error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
/// Execution platform selected by the product resource resolver.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// Windows execution.
    Windows,
    /// macOS execution.
    Macos,
}
/// Machine architecture required by a resource variant.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    /// 64-bit x86.
    X86_64,
    /// 64-bit ARM.
    Aarch64,
}
/// Closed configuration mutations. Execution progress cannot mutate this CAS.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Change {
    /// Create or replace the complete definition at an expected CAS.
    Put {
        /// Replacement definition.
        definition: Definition,
        /// Requested enabled state.
        enabled: bool,
    },
    /// Enable the existing definition without changing execution content.
    Enable,
    /// Disable the existing definition without changing execution content.
    Disable,
}
/// The one persistent Policy aggregate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Policy {
    /// Stable Policy identity within its owning tenant.
    pub id: Uuid,
    /// Configuration CAS, independent of device execution progress.
    pub revision: i64,
    /// Current immutable execution/configuration version identity.
    pub version: Uuid,
    /// Monotonic semantic version number.
    pub number: i64,
    /// Whether the persistent assignment is enabled.
    pub enabled: bool,
    /// Complete authored definition.
    pub definition: Definition,
}
/// A checked configuration change and whether immutable execution content changed.
pub struct Changed {
    /// Resulting aggregate.
    pub policy: Policy,
    /// Whether a new immutable version must be persisted.
    pub semantic_changed: bool,
    /// Digest of resource and behavior, excluding Scope membership and enablement.
    pub semantic: [u8; 32],
}
impl Policy {
    /// Apply exactly one configuration CAS using a caller-provided new version identity.
    pub fn apply(
        id: Uuid,
        old: Option<&Self>,
        expected: u64,
        input: &Change,
        next_version: Uuid,
    ) -> Result<Changed, Error> {
        if id.is_nil() || next_version.is_nil() {
            return Err(Error::Malformed);
        }
        if let Some(p) = old {
            if p.id.is_nil()
                || p.version.is_nil()
                || p.revision < 1
                || p.number < 1
                || p.number > p.revision
            {
                return Err(Error::Malformed);
            }
            p.definition.validate()?;
        }
        if old.is_some_and(|p| p.id != id) || old.map_or(0, |p| p.revision as u64) != expected {
            return Err(Error::Conflict);
        }
        let revision = expected
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(Error::Conflict)? as i64;
        let (definition, enabled) = match input {
            Change::Put {
                definition,
                enabled,
            } => (definition.clone(), *enabled),
            Change::Enable => (old.ok_or(Error::NotFound)?.definition.clone(), true),
            Change::Disable => (old.ok_or(Error::NotFound)?.definition.clone(), false),
        };
        definition.validate()?;
        let semantic = definition.semantic()?;
        let changed = old.map(|p| p.definition.semantic()).transpose()?.as_ref() != Some(&semantic);
        if changed && old.is_some_and(|p| p.version == next_version) {
            return Err(Error::Malformed);
        }
        let number = if changed {
            old.map_or(Some(1), |p| p.number.checked_add(1))
                .ok_or(Error::Conflict)?
        } else {
            old.ok_or(Error::NotFound)?.number
        };
        let version = if changed {
            next_version
        } else {
            old.ok_or(Error::NotFound)?.version
        };
        Ok(Changed {
            policy: Policy {
                id,
                revision,
                version,
                number,
                enabled,
                definition,
            },
            semantic_changed: changed,
            semantic,
        })
    }
}
impl Definition {
    /// Resource/execution semantics, excluding Scope and the enabled flag.
    pub fn semantic(&self) -> Result<[u8; 32], Error> {
        Ok(Sha256::digest(
            serde_json::to_vec(&(&self.resource, &self.behavior)).map_err(|_| Error::Malformed)?,
        )
        .into())
    }
}
