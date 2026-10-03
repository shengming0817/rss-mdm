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

pub struct Observation {
    pub phase: crate::native::evidence::Phase,
    pub state: crate::native::evidence::ReceiptState,
    pub fields: Option<crate::native::input::Fields>,
    pub error: Option<crate::native::input::Fields>,
    pub profile: Option<crate::native::profiles::Verification>,
    pub application: Option<crate::software::Presence>,
    pub received_at: Option<i64>,
    pub accepted: bool,
    pub native_outcome: Option<crate::native::outcome::Outcome>,
}

/// Native read facts, independent of the execution reducer and HTTP representation.
pub enum ReadEvidence {
    Command {
        receipts: Vec<Receipt>,
        outcome: Option<Outcome>,
        fields: Option<super::input::Fields>,
        error: Option<super::input::Fields>,
    },
    Profile {
        receipts: Vec<Receipt>,
        progress: MutationProgress,
        verification: Option<super::profiles::Verification>,
        status: Option<Status>,
        received_at: Option<i64>,
    },
}
pub struct Receipt {
    pub phase: Phase,
    pub state: ReceiptState,
    pub received_at: Option<i64>,
    pub accepted: bool,
    pub outcome: Option<Outcome>,
    pub fields: Option<super::input::Fields>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationProgress {
    Succeeded,
    Failed,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationState {
    Published,
    Withdrawn,
}
pub struct DeclarationEvidence {
    pub input_version: String,
    pub expected: serde_json::Value,
    pub publication: PublicationState,
    pub received_at: Option<i64>,
    pub status: super::ddm::StatusProjection,
}
/// Rows are ordered by the channel's original attempt ordinal and phase.
pub fn summarize(rows: Vec<Observation>, profile: bool) -> ReadEvidence {
    if profile {
        let progress = rows
            .iter()
            .rev()
            .find(|r| r.phase == Phase::Execute && r.accepted)
            .map_or(MutationProgress::Unknown, |r| match r.state {
                ReceiptState::Acknowledged => MutationProgress::Succeeded,
                ReceiptState::Error => MutationProgress::Failed,
                _ => MutationProgress::Unknown,
            });
        let latest = rows.iter().rev().find(|r| r.phase == Phase::Observe);
        let verification = latest.and_then(|r| r.profile);
        let status = latest.and_then(|r| match r.state {
            ReceiptState::Acknowledged => Some(Status::Acknowledged),
            ReceiptState::Error => Some(Status::Error),
            ReceiptState::NotNow => Some(Status::NotNow),
            _ => None,
        });
        let received_at = latest.and_then(|r| r.received_at);
        ReadEvidence::Profile {
            receipts: receipts(rows),
            progress,
            verification,
            status,
            received_at,
        }
    } else {
        let latest = rows
            .iter()
            .rev()
            .find(|r| r.accepted && r.native_outcome.is_some() && !r.phase.prerequisite());
        let outcome = latest.and_then(|r| r.native_outcome);
        let fields = latest.and_then(|r| r.fields.clone());
        let error = latest
            .filter(|r| r.state == ReceiptState::Error)
            .and_then(|r| r.error.clone());
        ReadEvidence::Command {
            receipts: receipts(rows),
            outcome,
            fields,
            error,
        }
    }
}
fn receipts(rows: Vec<Observation>) -> Vec<Receipt> {
    rows.into_iter()
        .map(|r| Receipt {
            phase: r.phase,
            state: r.state,
            received_at: r.received_at,
            accepted: r.accepted,
            outcome: r.native_outcome,
            fields: r.fields,
        })
        .collect()
}

#[cfg(test)]
mod read_tests {
    use super::*;
    fn row(
        phase: Phase,
        state: ReceiptState,
        accepted: bool,
        outcome: Option<Outcome>,
    ) -> Observation {
        Observation {
            phase,
            state,
            accepted,
            native_outcome: outcome,
            fields: None,
            error: None,
            profile: None,
            application: None,
            received_at: Some(1),
        }
    }
    #[test]
    fn rejected_and_prerequisite_receipts_cannot_replace_command_evidence() {
        let mut error = row(
            Phase::Execute,
            ReceiptState::Error,
            true,
            Some(Outcome::Rejected),
        );
        error.error = Some(super::super::input::Fields::default());
        let facts = summarize(
            vec![
                error,
                row(
                    Phase::Execute,
                    ReceiptState::Acknowledged,
                    false,
                    Some(Outcome::QueryResult),
                ),
                row(
                    Phase::ResolveSecurity,
                    ReceiptState::Acknowledged,
                    true,
                    Some(Outcome::QueryResult),
                ),
            ],
            false,
        );
        let ReadEvidence::Command {
            outcome,
            error,
            receipts,
            ..
        } = facts
        else {
            panic!("command evidence")
        };
        assert_eq!(outcome, Some(Outcome::Rejected));
        assert!(error.is_some());
        assert_eq!(receipts.len(), 3);
    }
    #[test]
    fn incomplete_latest_observation_keeps_profile_unknown_after_native_ack() {
        let mut old = row(Phase::Observe, ReceiptState::Acknowledged, true, None);
        old.profile = Some(super::super::profiles::Verification::Matched);
        let latest = row(Phase::Observe, ReceiptState::Sent, false, None);
        let facts = summarize(
            vec![
                row(Phase::Execute, ReceiptState::Acknowledged, true, None),
                old,
                latest,
            ],
            true,
        );
        let ReadEvidence::Profile {
            progress,
            verification,
            status,
            ..
        } = facts
        else {
            panic!("profile evidence")
        };
        assert_eq!(progress, MutationProgress::Succeeded);
        assert_eq!(verification, None);
        assert_eq!(status, None);
    }
    #[test]
    fn failed_reverse_evidence_is_distinct_from_success_and_unknown() {
        let mut observed = row(Phase::Observe, ReceiptState::Acknowledged, true, None);
        observed.profile = Some(super::super::profiles::Verification::Failed);
        let facts = summarize(
            vec![
                row(Phase::Execute, ReceiptState::Error, true, None),
                observed,
            ],
            true,
        );
        let ReadEvidence::Profile {
            progress,
            verification,
            status,
            ..
        } = facts
        else {
            panic!("profile evidence")
        };
        assert_eq!(progress, MutationProgress::Failed);
        assert_eq!(
            verification,
            Some(super::super::profiles::Verification::Failed)
        );
        assert_eq!(status, Some(Status::Acknowledged));
    }
}
