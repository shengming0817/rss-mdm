//! Explicit DMClient schedules, in minutes. No configuration is inferred from absent fields.
//! ref: https://learn.microsoft.com/en-us/windows/client-management/mdm/dmclient-csp#deviceproviderprovideridpoll
use crate::{CodecError, Result};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// The three native schedules and two native login triggers.
pub struct Poll {
    /// Initial retry interval; zero disables this tier.
    pub interval_for_first_set_of_retries: u32,
    /// Initial retry count; zero repeats an enabled tier forever.
    pub number_of_first_retries: u32,
    /// Second retry interval; zero disables this tier.
    pub interval_for_second_set_of_retries: u32,
    /// Second retry count; zero repeats an enabled tier forever.
    pub number_of_second_retries: u32,
    /// Long-running retry interval; zero disables this tier.
    pub interval_for_remaining_scheduled_retries: u32,
    /// Long-running retry count; zero repeats an enabled tier forever.
    pub number_of_remaining_scheduled_retries: u32,
    /// Start a session on each login, independently of WNS.
    pub poll_on_login: bool,
    /// Start a session on each operating-system user’s first login.
    pub all_users_poll_on_first_login: bool,
}
impl Poll {
    /// Validate bounded native integers, enabled tiers and a reachable infinite schedule.
    pub fn validate(&self) -> Result<()> {
        let schedules = [
            (
                self.interval_for_first_set_of_retries,
                self.number_of_first_retries,
            ),
            (
                self.interval_for_second_set_of_retries,
                self.number_of_second_retries,
            ),
            (
                self.interval_for_remaining_scheduled_retries,
                self.number_of_remaining_scheduled_retries,
            ),
        ];
        let mut infinite = false;
        for (interval, count) in schedules {
            if interval > i32::MAX as u32
                || count > i32::MAX as u32
                || (interval == 0 && count != 0)
                || (infinite && interval != 0)
            {
                return Err(CodecError::InvalidValue);
            }
            infinite |= interval != 0 && count == 0;
        }
        // Windows restores an invalid finite-only configuration to a daily schedule.
        // Require the actual long-running schedule to be explicit instead.
        if !infinite
            || (self.interval_for_second_set_of_retries != 0
                && self.interval_for_second_set_of_retries
                    <= self.interval_for_first_set_of_retries)
        {
            return Err(CodecError::InvalidValue);
        }
        Ok(())
    }
    /// Return the exact native provisioning parameter names, values and datatypes.
    pub fn parameters(&self) -> [(&'static str, String, &'static str); 8] {
        [
            (
                "IntervalForFirstSetOfRetries",
                self.interval_for_first_set_of_retries.to_string(),
                "integer",
            ),
            (
                "NumberOfFirstRetries",
                self.number_of_first_retries.to_string(),
                "integer",
            ),
            (
                "IntervalForSecondSetOfRetries",
                self.interval_for_second_set_of_retries.to_string(),
                "integer",
            ),
            (
                "NumberOfSecondRetries",
                self.number_of_second_retries.to_string(),
                "integer",
            ),
            (
                "IntervalForRemainingScheduledRetries",
                self.interval_for_remaining_scheduled_retries.to_string(),
                "integer",
            ),
            (
                "NumberOfRemainingScheduledRetries",
                self.number_of_remaining_scheduled_retries.to_string(),
                "integer",
            ),
            ("PollOnLogin", self.poll_on_login.to_string(), "boolean"),
            (
                "AllUsersPollOnFirstLogin",
                self.all_users_poll_on_first_login.to_string(),
                "boolean",
            ),
        ]
    }
}
