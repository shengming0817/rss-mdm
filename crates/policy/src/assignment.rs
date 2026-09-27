//! Persistent authored assignment. A scope reference is never a frozen device list.
use crate::Error;
use crate::schedule::{Schedule, Trigger};
use crate::{Architecture, Platform};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Opaque immutable resource selection, resolved by the product composition.
pub struct ResourceBinding {
    /// Opaque resource identity.
    pub id: String,
    /// Immutable resource version identity.
    pub version: String,
    /// Requested resource platform.
    pub platform: Platform,
    /// Requested machine architecture.
    pub architecture: Architecture,
    /// Exact resource variant key.
    pub variant: String,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Execution-history rule evaluated when a device checks in.
pub enum Frequency {
    #[default]
    /// At most once for each immutable execution version and registration.
    OncePerVersion,
    /// At most once for each membership entry and registration.
    OncePerEntry,
    /// Each distinct due trigger, subject to outstanding execution safety.
    EveryTrigger,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Supported configuration behavior when the last assignment exits.
pub enum Exit {
    #[default]
    /// Retain effects when the assignment no longer applies.
    Retain,
    /// Remove only effects that the selected resource supports removing.
    Remove,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
/// Execution and configuration have disjoint authoring contracts.
pub enum Behavior {
    /// A side-effecting or collection action admitted on Agent check-in.
    Execution {
        /// Literal parameters validated against the selected script.
        parameters: Value,
        #[serde(default = "default_schedule")]
        /// Calendar and event conditions; defaults to check-in without an end.
        schedule: Schedule,
        #[serde(default)]
        /// History deduplication rule; defaults to once per version.
        frequency: Frequency,
        /// Maximum lifetime of each admitted run, from 60 seconds through seven days.
        run_lifetime_seconds: u32,
    },
    /// A persistent native configuration without a script schedule.
    Configuration {
        #[serde(default)]
        /// What to do when this configuration no longer has an owner.
        exit: Exit,
    },
}
fn default_schedule() -> Schedule {
    Schedule {
        trigger: Trigger::CheckIn {
            minimum_seconds: 60,
        },
        misfire: Default::default(),
        not_before: 0,
        until: None,
        jitter_seconds: 0,
        window: None,
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Complete authored Policy definition, without execution progress.
pub struct Definition {
    /// Immutable resource selection.
    pub resource: ResourceBinding,
    /// Opaque Scope identity; Scope alone owns membership and entry coordinates.
    pub scope: Uuid,
    /// Closed action or configuration semantics.
    pub behavior: Behavior,
}
impl Definition {
    /// Validate closed shape, bounded identities, calendar conditions and run lifetime.
    pub fn validate(&self) -> Result<(), Error> {
        if serde_json::to_vec(self)
            .map_err(|_| Error::Malformed)?
            .len()
            > 4_194_304
        {
            return Err(Error::Malformed);
        }
        self.resource.validate()?;
        if self.scope.is_nil() {
            return Err(Error::Malformed);
        }
        self.behavior.validate()?;
        Ok(())
    }
}

impl ResourceBinding {
    /// Validate opaque immutable resource coordinates.
    pub fn validate(&self) -> Result<(), Error> {
        for id in [&self.id, &self.version, &self.variant] {
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
                || id.split('/').any(|s| s.is_empty() || s == "." || s == "..")
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
}
impl Behavior {
    /// Validate calendar and lifetime semantics without owning any targets.
    pub fn validate(&self) -> Result<(), Error> {
        if let Behavior::Execution {
            schedule,
            run_lifetime_seconds,
            ..
        } = self
        {
            schedule.validate()?;
            if !(60..=604800).contains(run_lifetime_seconds) {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn configuration() -> serde_json::Value {
        json!({"resource":{"id":"firewall","version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"scope":"11111111-1111-1111-1111-111111111111","behavior":{"kind":"configuration","exit":"retain"}})
    }
    #[test]
    fn configuration_cannot_accept_execution_fields() {
        let v = configuration();
        let d: Definition = serde_json::from_value(v.clone()).unwrap();
        d.validate().unwrap();
        for field in ["schedule", "frequency", "parameters", "runLifetimeSeconds"] {
            let mut invalid = v.clone();
            invalid["behavior"][field] = json!(null);
            assert!(
                serde_json::from_value::<Definition>(invalid).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn execution_defaults_to_checkin_once_per_version_without_an_end() {
        let mut v = configuration();
        v["behavior"] = json!({"kind":"execution","parameters":{},"runLifetimeSeconds":300});
        let d: Definition = serde_json::from_value(v).unwrap();
        d.validate().unwrap();
        let Behavior::Execution {
            schedule,
            frequency,
            ..
        } = d.behavior
        else {
            panic!()
        };
        assert!(schedule.until.is_none());
        assert!(matches!(frequency, Frequency::OncePerVersion));
    }
    #[test]
    fn policy_cannot_embed_a_device_membership_list() {
        let mut v = configuration();
        v["targets"] = json!({"kind":"devices","devices":["device"]});
        assert!(serde_json::from_value::<Definition>(v).is_err());
    }
}
