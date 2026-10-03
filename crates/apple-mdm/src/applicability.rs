//! macOS applicability is independent of product authorization and effect evidence.
//! ref: apple/device-management docs/schema.md (09f249a06e7e3289930bf6d05f38fb562f748ebf).
use serde::{Deserialize, Serialize};

/// Numeric macOS version; missing minor and patch components are zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Version([u32; 3]);
impl Version {
    pub(crate) fn components(self) -> [u32; 3] {
        self.0
    }
    pub fn parse(value: &str) -> Result<Self, Rejection> {
        let parts = value.split('.').collect::<Vec<_>>();
        if parts.is_empty() || parts.len() > 3 {
            return Err(Rejection::MalformedVersion);
        }
        let mut version = [0; 3];
        for (index, part) in parts.into_iter().enumerate() {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Rejection::MalformedVersion);
            }
            version[index] = part.parse().map_err(|_| Rejection::MalformedVersion)?;
        }
        if version[0] == 0 {
            return Err(Rejection::MalformedVersion);
        }
        Ok(Self(version))
    }
}
impl TryFrom<String> for Version {
    type Error = Rejection;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}
impl From<Version> for String {
    fn from(value: Version) -> Self {
        format!("{}.{}.{}", value.0[0], value.0[1], value.0[2])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Device,
    User,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enrollment {
    Device,
    User,
}

/// Facts supplied by the registration/platform owner, not a grant to execute.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub version: Option<Version>,
    pub channel: Channel,
    pub enrollment: Enrollment,
    pub supervised: Option<bool>,
    pub automated_enrollment: Option<bool>,
    pub user_approved: Option<bool>,
    /// Authenticated DeviceInformation evidence; absence is not Intel or Apple silicon.
    pub apple_silicon: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentRule {
    Any,
    DeviceOnly,
    UserOnly,
}

/// A fully inherited schema condition; a field may further restrict its object.
#[derive(Clone, Debug)]
pub struct Support {
    pub introduced: Version,
    pub removed: Option<Version>,
    pub beta: bool,
    pub device_channel: bool,
    pub user_channel: bool,
    pub supervised: bool,
    pub automated_enrollment: bool,
    pub user_approved: bool,
    pub enrollment: EnrollmentRule,
}
impl Support {
    /// Unspecified conditions do not manufacture required facts or authorization.
    pub fn since(version: &str) -> Result<Self, Rejection> {
        Ok(Self {
            introduced: Version::parse(version)?,
            removed: None,
            beta: false,
            device_channel: true,
            user_channel: true,
            supervised: false,
            automated_enrollment: false,
            user_approved: false,
            enrollment: EnrollmentRule::Any,
        })
    }
    pub fn check(&self, context: &Context) -> Result<(), Rejection> {
        if self.beta {
            return Err(Rejection::Unsupported(Condition::Beta));
        }
        let version = context
            .version
            .ok_or(Rejection::MissingEvidence(Condition::Version))?;
        if version < self.introduced || self.removed.is_some_and(|v| version >= v) {
            return Err(Rejection::Unsupported(Condition::Version));
        }
        if !match context.channel {
            Channel::Device => self.device_channel,
            Channel::User => self.user_channel,
        } {
            return Err(Rejection::Unsupported(Condition::Channel));
        }
        if matches!(
            (self.enrollment, context.enrollment),
            (EnrollmentRule::DeviceOnly, Enrollment::User)
                | (EnrollmentRule::UserOnly, Enrollment::Device)
        ) {
            return Err(Rejection::Unsupported(Condition::Enrollment));
        }
        for (required, actual, condition) in [
            (self.supervised, context.supervised, Condition::Supervision),
            (
                self.automated_enrollment,
                context.automated_enrollment,
                Condition::AutomatedEnrollment,
            ),
            (
                self.user_approved,
                context.user_approved,
                Condition::UserApproval,
            ),
        ] {
            if required {
                match actual {
                    Some(true) => {}
                    Some(false) => return Err(Rejection::Unsupported(condition)),
                    None => return Err(Rejection::MissingEvidence(condition)),
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Condition {
    Version,
    Beta,
    Channel,
    Enrollment,
    Supervision,
    AutomatedEnrollment,
    UserApproval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Rejection {
    #[error("malformed macOS version")]
    MalformedVersion,
    #[error("native prerequisite is not satisfied: {0:?}")]
    Unsupported(Condition),
    #[error("native prerequisite evidence is missing: {0:?}")]
    MissingEvidence(Condition),
}

#[cfg(test)]
#[path = "../tests/applicability.rs"]
mod tests;

impl Context {
    /// Native prerequisite facts; absent facts remain unknown, never a grant or default hardware.
    pub fn from_reports(
        device: &plist::Dictionary,
        security: Option<&plist::Dictionary>,
        channel: Channel,
    ) -> Result<Self, crate::Error> {
        use plist::{Dictionary, Value};
        let facts = device
            .get("QueryResponses")
            .and_then(Value::as_dictionary)
            .ok_or(crate::Error::Malformed)?;
        if facts
            .keys()
            .any(|key| !["OSVersion", "IsSupervised", "IsAppleSilicon"].contains(&key.as_str()))
        {
            return Err(crate::Error::Malformed);
        }
        let version = Version::parse(crate::protocol::text(facts, "OSVersion")?)
            .map_err(|_| crate::Error::Malformed)?;
        let security = security
            .map(|body| {
                body.get("SecurityInfo")
                    .and_then(Value::as_dictionary)
                    .ok_or(crate::Error::Malformed)
            })
            .transpose()?;
        let management = security
            .and_then(|body| body.get("ManagementStatus"))
            .map(|value| value.as_dictionary().ok_or(crate::Error::Malformed))
            .transpose()?;
        let boolean = |body: Option<&Dictionary>, key: &str| {
            body.and_then(|body| body.get(key))
                .map(|value| value.as_boolean().ok_or(crate::Error::Malformed))
                .transpose()
        };
        Ok(Self {
            version: Some(version),
            channel,
            enrollment: if boolean(management, "IsUserEnrollment")? == Some(true) {
                Enrollment::User
            } else {
                Enrollment::Device
            },
            supervised: boolean(Some(facts), "IsSupervised")?,
            automated_enrollment: boolean(management, "EnrolledViaDEP")?,
            user_approved: boolean(management, "UserApprovedEnrollment")?,
            apple_silicon: boolean(Some(facts), "IsAppleSilicon")?,
        })
    }
}
