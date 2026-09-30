//! Source-owned channel facts. Connectivity and elapsed time never imply absence.
use crate::{Invalid, Result};
use serde::{Deserialize, Serialize};
/// Native MDM evidence about the product's fixed Agent identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentInstallation {
    /// A complete native application query proved absence.
    Absent,
    /// The product Agent is present; this does not prove Agent registration.
    Installed,
    /// No decisive evidence is available.
    Unknown,
}
impl AgentInstallation {
    /// Only explicit native absence admits an installation.
    pub const fn requires_install(self) -> bool {
        matches!(self, Self::Absent)
    }
    /// Canonical dictionary value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Installed => "installed",
            Self::Unknown => "unknown",
        }
    }
    /// Parse the closed dictionary value.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "absent" => Ok(Self::Absent),
            "installed" => Ok(Self::Installed),
            "unknown" => Ok(Self::Unknown),
            _ => Err(Invalid::Value),
        }
    }
}
/// Agent evidence about local MDM enrollment, relative to its authenticated organization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MdmEnrollment {
    /// The local OS positively reports no MDM enrollment.
    Unenrolled,
    /// The local enrollment belongs to this organization.
    ThisOrganization,
    /// A different organization owns the local enrollment.
    OtherOrganization,
    /// No decisive evidence is available.
    Unknown,
}
impl MdmEnrollment {
    /// Other organizations, missing reports and uncertainty never authorize enrollment.
    pub const fn requires_enrollment(self) -> bool {
        matches!(self, Self::Unenrolled)
    }
    /// Canonical dictionary value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unenrolled => "unenrolled",
            Self::ThisOrganization => "this_organization",
            Self::OtherOrganization => "other_organization",
            Self::Unknown => "unknown",
        }
    }
    /// Parse the closed dictionary value.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "unenrolled" => Ok(Self::Unenrolled),
            "this_organization" => Ok(Self::ThisOrganization),
            "other_organization" => Ok(Self::OtherOrganization),
            "unknown" => Ok(Self::Unknown),
            _ => Err(Invalid::Value),
        }
    }
}
