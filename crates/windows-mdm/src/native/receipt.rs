//! Windows-native receipt decisions; storage and common execution eligibility stay with callers.
//! ref: OMA SyncML Representation 1.2.2 §10; rustls rustls/src/verify.rs@v/0.23.32.
use super::Error;
use crate::syncml::{rejected_status, successful_status, terminal_status};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Purpose of one native attempt; independent of the common command state.
pub enum ReceiptRole {
    /// Prerequisite evidence before native execution.
    Prepare,
    /// Receipt of the requested native operation.
    Execute,
    /// Independent readback of the requested native effect.
    Observe,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Closed set of supported native attempt item commands.
pub enum CommandKind {
    /// Create a native object.
    Add,
    /// Replace a native value.
    Replace,
    /// Delete a native object.
    Delete,
    /// Read a native value.
    Get,
    /// Execute a native operation.
    Exec,
    /// Native atomic group receipt.
    Atomic,
    /// Native ordered group receipt.
    Sequence,
}
impl CommandKind {
    /// Restore a stored native kind, rejecting unknown identities.
    pub fn parse(value: &str) -> Result<Self, Error> {
        Ok(match value {
            "add" => Self::Add,
            "replace" => Self::Replace,
            "delete" => Self::Delete,
            "get" => Self::Get,
            "exec" => Self::Exec,
            "atomic" => Self::Atomic,
            "sequence" => Self::Sequence,
            _ => return Err(Error::Value),
        })
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Replace => "replace",
            Self::Delete => "delete",
            Self::Get => "get",
            Self::Exec => "exec",
            Self::Atomic => "atomic",
            Self::Sequence => "sequence",
        }
    }
}
/// Allow provisional completion and atomic rollback while preserving terminal facts and values.
pub fn compatible_receipt(
    kind: CommandKind,
    atomic: bool,
    old: Option<i32>,
    new: Option<i32>,
    old_value: Option<&str>,
    new_value: Option<&str>,
) -> bool {
    !old.is_some_and(|old| {
        terminal_status(old)
            && new.is_some_and(|new| {
                old != new
                    && !(atomic
                        && matches!(new, 216 | 516)
                        && successful_status(kind.as_str(), old))
            })
    }) && old_value.is_none_or(|old| new_value.is_none_or(|new| old == new))
}

/// Provisional frame receipts may progress; a terminal receipt cannot be replaced.
pub fn compatible_frame(old: Option<i32>, new: i32) -> bool {
    old.is_none_or(|old| !terminal_status(old) || old == new)
}

/// Assess a terminal frame as logical item evidence; provisional receipts return no settlement.
pub fn frame_receipt(code: i32, admitted: bool, end: usize, total: usize) -> Option<bool> {
    terminal_status(code).then_some(admitted && (rejected_status(code) || end == total))
}

/// Native fragment progress; the caller still owns current eligibility and dispatch.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameContinuation {
    /// Await a buffer receipt or the complete object's logical receipt.
    Wait,
    /// The peer accepted the current buffer and may receive the next range.
    Continue,
    /// An early terminal receipt or an unadmitted buffer forbids continuing.
    Abort,
}

/// Only an admitted 213 buffer receipt may advance an incomplete native object.
pub fn frame_continuation(
    status: Option<i32>,
    admitted: bool,
    end: usize,
    total: usize,
) -> FrameContinuation {
    if status.is_some_and(terminal_status) && end < total {
        FrameContinuation::Abort
    } else if end == total || status != Some(213) {
        FrameContinuation::Wait
    } else if admitted {
        FrameContinuation::Continue
    } else {
        FrameContinuation::Abort
    }
}

/// Native item evidence after caller-owned current eligibility checks.
pub struct ItemEvidence {
    /// Attempt purpose.
    pub phase: ReceiptRole,
    /// Native operation kind.
    pub kind: CommandKind,
    /// Native receipt code, absent before receipt.
    pub status: Option<i32>,
    /// Whether the caller admitted this receipt.
    pub receipt_accepted: bool,
    /// Whether an independently returned value is retained.
    pub has_value: bool,
    /// Whether the caller admitted the returned value.
    pub result_accepted: bool,
}
impl ItemEvidence {
    /// A completed observation may report failure; it cannot substitute a missing Get value.
    pub fn complete(&self) -> bool {
        self.receipt_accepted
            && self.status.is_some_and(terminal_status)
            && (self.kind != CommandKind::Get
                || !matches!(self.status, Some(200 | 214))
                || (self.has_value && self.result_accepted))
    }
    /// An accepted success must include any expected query value.
    pub fn successful(&self) -> bool {
        self.receipt_accepted
            && self
                .status
                .is_some_and(|code| successful_status(self.kind.as_str(), code))
            && (self.kind != CommandKind::Get
                || self.status == Some(204)
                || (self.has_value && self.result_accepted))
    }
    /// Outstanding transport work is independent of whether its evidence was authorized.
    pub fn pending(&self) -> bool {
        !self.status.is_some_and(terminal_status)
            || (self.kind == CommandKind::Get
                && matches!(self.status, Some(200 | 214))
                && !self.has_value)
    }
}
#[derive(Debug, PartialEq, Eq)]
/// Native receipt assessment; the caller maps this to its common reducer.
pub enum Settlement {
    /// Native receipt or package evidence remains incomplete.
    Wait,
    /// An accepted native execution or prerequisite receipt explicitly rejected the operation.
    Reject,
    /// The requested native execution has been received.
    Receive {
        /// Whether an entirely read-only execution has complete values.
        query_complete: bool,
        /// Whether every execution Get has its required returned value.
        values_complete: bool,
    },
}
/// Assess native receipts without advancing common execution state.
pub fn settle(items: &[ItemEvidence], package_complete: bool) -> Settlement {
    if items.iter().any(|i| {
        i.phase != ReceiptRole::Observe
            && i.receipt_accepted
            && i.status.is_some_and(rejected_status)
    }) {
        return Settlement::Reject;
    }
    let execution: Vec<_> = items
        .iter()
        .filter(|i| i.phase == ReceiptRole::Execute)
        .collect();
    if !package_complete
        || execution.is_empty()
        || !execution.iter().all(|i| {
            i.receipt_accepted
                && i.status
                    .is_some_and(|code| successful_status(i.kind.as_str(), code))
        })
    {
        return Settlement::Wait;
    }
    let values_complete = execution
        .iter()
        .filter(|i| i.kind == CommandKind::Get)
        .all(|i| i.status == Some(204) || (i.has_value && i.result_accepted));
    let query_complete = values_complete
        && execution.iter().any(|i| i.kind == CommandKind::Get)
        && execution.iter().all(|i| {
            matches!(
                i.kind,
                CommandKind::Get | CommandKind::Atomic | CommandKind::Sequence
            )
        });
    Settlement::Receive {
        query_complete,
        values_complete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn get() -> ItemEvidence {
        ItemEvidence {
            phase: ReceiptRole::Execute,
            kind: CommandKind::Get,
            status: Some(200),
            receipt_accepted: true,
            has_value: true,
            result_accepted: true,
        }
    }
    #[test]
    fn incomplete_packages_and_unaccepted_values_never_report_success() {
        assert_eq!(settle(&[get()], false), Settlement::Wait);
        let mut item = get();
        item.result_accepted = false;
        assert_eq!(
            settle(&[item], true),
            Settlement::Receive {
                query_complete: false,
                values_complete: false
            }
        );
        assert_eq!(
            settle(&[get()], true),
            Settlement::Receive {
                query_complete: true,
                values_complete: true
            }
        );
    }
    #[test]
    fn prepare_success_is_not_execution_and_rejection_requires_authority() {
        let mut item = get();
        item.phase = ReceiptRole::Prepare;
        assert_eq!(settle(&[item], true), Settlement::Wait);
        let mut item = get();
        item.status = Some(500);
        item.receipt_accepted = false;
        assert_eq!(settle(&[item], true), Settlement::Wait);
        let mut item = get();
        item.status = Some(500);
        assert_eq!(settle(&[item], false), Settlement::Reject);
    }
    #[test]
    fn effect_observation_does_not_block_or_reject_an_execution_receipt() {
        for status in [None, Some(200), Some(500)] {
            let mut execution = get();
            execution.kind = CommandKind::Replace;
            execution.has_value = false;
            execution.result_accepted = false;
            let mut observation = get();
            observation.phase = ReceiptRole::Observe;
            observation.status = status;
            assert_eq!(
                settle(&[execution, observation], true),
                Settlement::Receive {
                    query_complete: false,
                    values_complete: true,
                }
            );
        }
    }
    #[test]
    fn early_frame_success_cannot_become_success_after_later_frames_are_sent() {
        assert_eq!(frame_receipt(200, true, 4, 8), Some(false));
        assert_eq!(frame_receipt(200, true, 8, 8), Some(true));
        assert_eq!(frame_receipt(500, true, 4, 8), Some(true));
        assert_eq!(frame_receipt(213, true, 8, 8), None);
        assert_eq!(frame_receipt(200, false, 8, 8), Some(false));
    }
    #[test]
    fn frame_replays_preserve_terminal_receipts() {
        assert!(compatible_frame(None, 213));
        assert!(compatible_frame(Some(213), 200));
        assert!(compatible_frame(Some(200), 200));
        assert!(!compatible_frame(Some(200), 500));
        assert!(!compatible_frame(Some(500), 200));
    }
    #[test]
    fn fragments_continue_only_after_admitted_buffer_receipts() {
        use FrameContinuation::*;
        assert_eq!(frame_continuation(None, true, 4, 8), Wait);
        assert_eq!(frame_continuation(Some(101), true, 4, 8), Wait);
        assert_eq!(frame_continuation(Some(213), true, 4, 8), Continue);
        assert_eq!(frame_continuation(Some(213), false, 4, 8), Abort);
        assert_eq!(frame_continuation(Some(200), true, 4, 8), Abort);
        assert_eq!(frame_continuation(Some(500), true, 4, 8), Abort);
        assert_eq!(frame_continuation(Some(213), true, 8, 8), Wait);
        assert_eq!(frame_continuation(Some(200), true, 8, 8), Wait);
    }
    #[test]
    fn query_receipts_keep_completeness_separate_from_success_and_authority() {
        let mut item = get();
        for code in [200, 214] {
            item.status = Some(code);
            item.has_value = false;
            assert!(!item.complete());
            assert!(item.pending());
            assert!(!item.successful());
        }
        item.status = Some(204);
        assert!(item.complete());
        assert!(!item.pending());
        assert!(item.successful());
        item.status = Some(500);
        assert!(item.complete());
        assert!(!item.successful());
        item.receipt_accepted = false;
        assert!(!item.complete());
        for code in [101, 202, 206, 213] {
            item.status = Some(code);
            assert!(item.pending());
        }
    }
    #[test]
    fn rollback_is_allowed_only_with_atomic_ancestry_and_values_are_immutable() {
        assert!(compatible_receipt(
            CommandKind::Replace,
            true,
            Some(200),
            Some(216),
            None,
            None
        ));
        assert!(!compatible_receipt(
            CommandKind::Replace,
            false,
            Some(200),
            Some(216),
            None,
            None
        ));
        assert!(!compatible_receipt(
            CommandKind::Get,
            true,
            Some(200),
            Some(200),
            Some("a"),
            Some("b")
        ));
        assert!(compatible_receipt(
            CommandKind::Get,
            false,
            Some(213),
            Some(200),
            None,
            Some("a")
        ));
    }
}
