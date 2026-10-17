use crate::{Definition, Error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
/// Execution platform selected by the product resource resolver.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// Windows execution.
    Windows,
    /// macOS execution.
    Macos,
}
/// Machine architecture required by a resource variant.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    /// 64-bit x86.
    X86_64,
    /// 64-bit ARM.
    Aarch64,
}
/// Closed configuration mutations. Execution progress cannot mutate this CAS.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
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
        definition: Box<Definition>,
        /// Requested enabled state.
        enabled: bool,
    },
    /// Enable the existing definition without changing execution content.
    Enable,
    /// Disable the existing definition without changing execution content.
    Disable,
    /// Permanently close an already disabled policy, preserving immutable history.
    #[serde(skip_deserializing)]
    #[schemars(skip)]
    Archive,
}
/// The one persistent Policy aggregate.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
pub struct Policy {
    /// Stable Policy identity within its owning tenant.
    pub id: Uuid,
    /// Configuration CAS, independent of device execution progress.
    pub revision: i64,
    /// Current immutable execution/configuration version identity.
    pub version: Uuid,
    /// Monotonic semantic version number.
    pub number: i64,
    /// Persistent assignment lifecycle.
    pub state: State,
    /// Complete authored definition.
    pub definition: Definition,
    /// Backend-resolved software lifecycle, never authored by an administrator.
    pub execution_binding: Option<[u8; 32]>,
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
        execution_binding: Option<[u8; 32]>,
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
        if old.is_some_and(|p| p.state == State::Archived) {
            return Err(Error::Conflict);
        }
        let revision = expected
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(Error::Conflict)? as i64;
        let (mut definition, state) = match input {
            Change::Put {
                definition,
                enabled,
            } => (
                (**definition).clone(),
                if *enabled {
                    State::Enabled
                } else {
                    State::Disabled
                },
            ),
            Change::Enable => (
                old.ok_or(Error::NotFound)?.definition.clone(),
                State::Enabled,
            ),
            Change::Disable => (
                old.ok_or(Error::NotFound)?.definition.clone(),
                State::Disabled,
            ),
            Change::Archive => {
                let previous = old.ok_or(Error::NotFound)?;
                if previous.state != State::Disabled {
                    return Err(Error::Conflict);
                }
                (previous.definition.clone(), State::Archived)
            }
        };
        if let Some(config) = &mut definition.self_service {
            config.normalize(old.and_then(|p| p.definition.self_service.as_ref()));
        }
        definition.validate()?;
        let execution_binding = if matches!(input, Change::Put { .. }) {
            execution_binding
        } else {
            old.and_then(|p| p.execution_binding)
        };
        if matches!(
            definition.action,
            crate::Action::Software { .. } | crate::Action::EnsureAgentInstalled { .. }
        ) != execution_binding.is_some()
        {
            return Err(Error::Malformed);
        }
        let semantic = bound_semantic(&definition, execution_binding)?;
        let changed = old
            .map(|p| bound_semantic(&p.definition, p.execution_binding))
            .transpose()?
            .as_ref()
            != Some(&semantic);
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
                state,
                definition,
                execution_binding,
            },
            semantic_changed: changed,
            semantic,
        })
    }
}
impl Definition {
    /// Resource/execution semantics, excluding Scope and the enabled flag.
    pub fn semantic(&self) -> Result<[u8; 32], Error> {
        Ok(Sha256::digest(self.action.semantic_bytes()?).into())
    }
}
impl crate::Action {
    pub(crate) fn semantic_bytes(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Software {
                resource,
                delivery,
                intent,
                schedule,
                run_lifetime_seconds,
                ..
            } => serde_json::to_vec(&(
                Some(resource),
                delivery,
                intent,
                schedule,
                run_lifetime_seconds,
            )),
            _ => serde_json::to_vec(self),
        }
        .map_err(|_| Error::Malformed)
    }
}
/// Public management projection; the display version and immutable version ID are distinct.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct View {
    /// Stable Policy identity.
    pub id: Uuid,
    /// Configuration CAS.
    pub revision: i64,
    /// Display execution version number.
    pub version: i64,
    /// Immutable execution version identity.
    pub version_id: Uuid,
    /// Automatic and self-service assignment lifecycle.
    pub state: State,
    /// Complete authored definition, with normalized stored self-service defaults.
    pub definition: Definition,
}
impl From<&Policy> for View {
    fn from(policy: &Policy) -> Self {
        Self {
            id: policy.id,
            revision: policy.revision,
            version: policy.number,
            version_id: policy.version,
            state: policy.state,
            definition: policy.definition.clone(),
        }
    }
}

fn bound_semantic(definition: &Definition, binding: Option<[u8; 32]>) -> Result<[u8; 32], Error> {
    let semantic = definition.semantic()?;
    let Some(binding) = binding else {
        return Ok(semantic);
    };
    let mut hash = Sha256::new();
    hash.update(b"software-policy-lifecycle/v1");
    hash.update(semantic);
    hash.update(binding);
    Ok(hash.finalize().into())
}

/// The one Policy lifecycle; archived policies cannot be edited or enabled.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Open to current assignment admission.
    Enabled,
    /// Explicitly stopped; existing execution recovery remains active.
    Disabled,
    /// Permanently closed while all history remains referenced.
    Archived,
}
impl State {
    /// Whether new business admission is allowed by the authored lifecycle.
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
    /// Canonical persistence discriminator.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Archived => "archived",
        }
    }
}
