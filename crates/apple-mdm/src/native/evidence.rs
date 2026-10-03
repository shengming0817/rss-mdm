//! Typed native facts; execution owns eligibility, authorization and command transitions.
//! ref: apple/device-management mdm/execution and mdm/commands/profile.list.yaml.
use super::outcome::Outcome;
use crate::protocol::Status;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    ResolveDevice,
    ResolveSecurity,
    Execute,
    Observe,
}
impl Phase {
    pub fn prerequisite(self) -> bool {
        matches!(self, Self::ResolveDevice | Self::ResolveSecurity)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    Pending,
    Sent,
    NotNow,
    Acknowledged,
    Error,
    Superseded,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settlement {
    Waiting,
    Received,
    Reported,
    Rejected,
    Profile,
}
/// Interpret native receipt semantics without granting execution eligibility.
pub fn settlement(
    phase: Phase,
    status: Status,
    outcome: Option<Outcome>,
    profile: bool,
    query: bool,
) -> Settlement {
    use Settlement as S;
    match (phase, status) {
        (_, Status::NotNow | Status::Idle) => S::Waiting,
        (Phase::ResolveDevice | Phase::ResolveSecurity, Status::Acknowledged) => S::Waiting,
        (Phase::Observe, Status::Error) => S::Waiting,
        (_, Status::Error) if profile => S::Waiting,
        (_, Status::Error) => S::Rejected,
        (Phase::Execute, Status::Acknowledged)
            if outcome == Some(Outcome::Rejected) && !profile =>
        {
            S::Rejected
        }
        (Phase::Execute, Status::Acknowledged)
            if query || outcome.is_some_and(Outcome::completes_query) =>
        {
            S::Reported
        }
        (Phase::Execute, Status::Acknowledged) => S::Received,
        (Phase::Observe, Status::Acknowledged) if profile => S::Profile,
        (Phase::Observe, Status::Acknowledged) => S::Waiting,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_and_effect_are_distinct() {
        assert_eq!(
            settlement(
                Phase::Execute,
                Status::Acknowledged,
                Some(Outcome::Rejected),
                false,
                false
            ),
            Settlement::Rejected
        );
        assert_eq!(
            settlement(Phase::Execute, Status::Acknowledged, None, true, false),
            Settlement::Received
        );
        assert_eq!(
            settlement(Phase::Observe, Status::Error, None, true, false),
            Settlement::Waiting
        );
        assert_eq!(
            settlement(Phase::Execute, Status::Error, None, true, false),
            Settlement::Waiting
        );
        assert_eq!(
            settlement(Phase::Execute, Status::Acknowledged, None, false, true),
            Settlement::Reported
        );
        assert_eq!(
            settlement(Phase::Observe, Status::Acknowledged, None, false, false),
            Settlement::Waiting
        );
    }
}
