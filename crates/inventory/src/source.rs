//! Closed trusted producer vocabulary shared by collection, storage and asset consumers.
use crate::{Invalid, Result};
use serde::{Deserialize, Serialize};
/// Device communication channel; source binding is defined by [`ReportSource::channel`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// Built-in agent transport.
    Agent,
    /// MDM transport.
    Mdm,
}
impl Channel {
    /// Canonical storage identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Mdm => "mdm",
        }
    }
}
/// Only sources allowed to produce device reports. Manual cannot enter collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportSource {
    /// Existing Windows MDM collector.
    #[serde(rename = "mdm.windows")]
    MdmWindows,
    /// Existing built-in agent source.
    #[serde(rename = "agent.builtin")]
    AgentBuiltin,
}
impl ReportSource {
    /// Parse the canonical source without accepting Manual or unknown producers.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "mdm.windows" => Ok(Self::MdmWindows),
            "agent.builtin" => Ok(Self::AgentBuiltin),
            _ => Err(Invalid::UnknownSource),
        }
    }
    /// Canonical storage identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MdmWindows => "mdm.windows",
            Self::AgentBuiltin => "agent.builtin",
        }
    }
    /// The sole source-to-channel binding.
    pub const fn channel(self) -> Channel {
        match self {
            Self::MdmWindows => Channel::Mdm,
            Self::AgentBuiltin => Channel::Agent,
        }
    }
}
/// All allowed asset sources. Serialized as their canonical stable identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Source {
    /// Built-in agent evidence.
    #[serde(rename = "agent.builtin")]
    AgentBuiltin,
    /// Administrator assignment.
    #[serde(rename = "manual")]
    Manual,
    /// Windows MDM evidence.
    #[serde(rename = "mdm.windows")]
    MdmWindows,
}
impl Source {
    /// Canonical evidence identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::MdmWindows => ReportSource::MdmWindows.as_str(),
            Self::AgentBuiltin => ReportSource::AgentBuiltin.as_str(),
        }
    }
    /// Parse stored evidence through the same report vocabulary.
    pub fn parse(s: &str) -> Result<Self> {
        if s == "manual" {
            Ok(Self::Manual)
        } else {
            ReportSource::parse(s).map(Into::into)
        }
    }
}
impl From<ReportSource> for Source {
    fn from(source: ReportSource) -> Self {
        match source {
            ReportSource::MdmWindows => Self::MdmWindows,
            ReportSource::AgentBuiltin => Self::AgentBuiltin,
        }
    }
}
