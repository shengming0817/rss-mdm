//! Immutable collection prerequisites; unknown evidence never satisfies a declared constraint.
use crate::Error;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
/// Additional prerequisites within the Resource variant's exact OS and architecture.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Applicability {
    /// Inclusive minimum numeric OS version.
    pub minimum_os_version: Option<String>,
    /// Inclusive minimum OS build.
    pub minimum_build: Option<u32>,
    /// Exact admitted edition identifiers; empty means unconstrained.
    pub editions: BTreeSet<String>,
    /// Exact enrollment modes; empty means unconstrained.
    pub enrollments: BTreeSet<String>,
    /// Required minimum tool versions, e.g. osquery 5.23.1.
    pub tools: BTreeMap<String, String>,
    /// Required current executor capabilities.
    pub capabilities: BTreeSet<String>,
}
/// Authenticated, current endpoint evidence, separate from administrator-authored requirements.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectionEnvironment {
    /// Numeric OS version, absent when not observed.
    pub os_version: Option<String>,
    /// Numeric OS build, absent when not observed.
    pub build: Option<u32>,
    /// Exact edition, absent when not observed.
    pub edition: Option<String>,
    /// Installed controlled tool versions.
    pub tools: BTreeMap<String, String>,
}
fn numeric(value: &str) -> Option<[u32; 4]> {
    let mut out = [0; 4];
    if value.is_empty() || value.len() > 64 || value.split('.').count() > 4 {
        return None;
    }
    for (i, part) in value.split('.').enumerate() {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out[i] = part.parse().ok()?;
    }
    Some(out)
}
fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
impl CollectionEnvironment {
    /// Validate bounded current evidence before persisting it.
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .os_version
            .as_ref()
            .is_some_and(|v| numeric(v).is_none())
            || self.edition.as_ref().is_some_and(|v| !token(v))
            || self.tools.len() > 16
            || self
                .tools
                .iter()
                .any(|(k, v)| !token(k) || numeric(v).is_none())
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
impl Applicability {
    /// Validate closed budgets and version syntax before freezing a Resource version.
    pub fn validate(&self) -> Result<(), Error> {
        CollectionEnvironment {
            os_version: self.minimum_os_version.clone(),
            build: self.minimum_build,
            edition: None,
            tools: self.tools.clone(),
        }
        .validate()?;
        for set in [&self.editions, &self.enrollments, &self.capabilities] {
            if set.len() > 32 || set.iter().any(|v| !token(v)) {
                return Err(Error::InvalidInput);
            }
        }
        Ok(())
    }
    /// Missing OS/edition/tool evidence fails a declared requirement without inventing a default.
    pub fn allows(
        &self,
        facts: &CollectionEnvironment,
        enrollment: &str,
        capabilities: &BTreeSet<String>,
    ) -> bool {
        self.validate().is_ok()
            && facts.validate().is_ok()
            && self.minimum_os_version.as_ref().is_none_or(|v| {
                facts
                    .os_version
                    .as_ref()
                    .is_some_and(|f| numeric(f) >= numeric(v))
            })
            && self
                .minimum_build
                .is_none_or(|v| facts.build.is_some_and(|f| f >= v))
            && (self.editions.is_empty()
                || facts
                    .edition
                    .as_ref()
                    .is_some_and(|f| self.editions.contains(f)))
            && (self.enrollments.is_empty() || self.enrollments.contains(enrollment))
            && self.tools.iter().all(|(tool, v)| {
                facts
                    .tools
                    .get(tool)
                    .is_some_and(|f| numeric(f) >= numeric(v))
            })
            && self.capabilities.is_subset(capabilities)
    }
}
