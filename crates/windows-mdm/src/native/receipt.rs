//! Windows-native receipt decisions; storage and common execution eligibility stay with callers.
//! ref: OMA SyncML Representation 1.2.2 §10; rustls rustls/src/verify.rs@v/0.23.32.
use super::Error;
use crate::syncml::{rejected_status, successful_status, terminal_status};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptRole { Prepare, Execute, Observe }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandKind { Add, Replace, Delete, Get, Exec, Atomic, Sequence }
impl CommandKind {
    pub fn parse(value: &str) -> Result<Self, Error> {
        Ok(match value {
            "add"=>Self::Add,"replace"=>Self::Replace,"delete"=>Self::Delete,"get"=>Self::Get,
            "exec"=>Self::Exec,"atomic"=>Self::Atomic,"sequence"=>Self::Sequence,
            _=>return Err(Error::Value),
        })
    }
    fn as_str(self) -> &'static str {
        match self { Self::Add=>"add",Self::Replace=>"replace",Self::Delete=>"delete",Self::Get=>"get",Self::Exec=>"exec",Self::Atomic=>"atomic",Self::Sequence=>"sequence" }
    }
}
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
                old != new && !(atomic && matches!(new, 216 | 516) && successful_status(kind.as_str(), old))
            })
    }) && old_value.is_none_or(|old| new_value.is_none_or(|new| old == new))
}

pub fn accepts_frame(code: i32, accepted: bool, end: i32, total: i32) -> bool {
    accepted && terminal_status(code) && (rejected_status(code) || end == total)
}

pub struct ItemEvidence {
    pub phase: ReceiptRole,
    pub kind: CommandKind,
    pub status: Option<i32>,
    pub receipt_accepted: bool,
    pub has_value: bool,
    pub result_accepted: bool,
}
impl ItemEvidence {
    /// A completed observation may report failure; it cannot substitute a missing Get value.
    pub fn complete(&self) -> bool {
        self.receipt_accepted && self.status.is_some_and(terminal_status)
            && (self.kind != CommandKind::Get || !matches!(self.status, Some(200 | 214))
                || (self.has_value && self.result_accepted))
    }
    /// An accepted success must include any expected query value.
    pub fn successful(&self) -> bool {
        self.receipt_accepted && self.status.is_some_and(|code| successful_status(self.kind.as_str(),code))
            && (self.kind != CommandKind::Get || self.status == Some(204) || (self.has_value && self.result_accepted))
    }
    /// Outstanding transport work is independent of whether its evidence was authorized.
    pub fn pending(&self) -> bool {
        !self.status.is_some_and(terminal_status)
            || (self.kind == CommandKind::Get && matches!(self.status,Some(200 | 214)) && !self.has_value)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Settlement {
    Wait,
    Reject,
    Receive {
        query_complete: bool,
        values_complete: bool,
    },
}
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
        && execution
            .iter()
            .all(|i| matches!(i.kind, CommandKind::Get | CommandKind::Atomic | CommandKind::Sequence));
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
        assert!(!accepts_frame(200, true, 4, 8));
        assert!(accepts_frame(200, true, 8, 8));
        assert!(accepts_frame(500, true, 4, 8));
        assert!(!accepts_frame(213, true, 8, 8));
        assert!(!accepts_frame(200, false, 8, 8));
    }
    #[test]
    fn query_receipts_keep_completeness_separate_from_success_and_authority() {
        let mut item = get();
        for code in [200,214] {
            item.status = Some(code); item.has_value = false;
            assert!(!item.complete()); assert!(item.pending()); assert!(!item.successful());
        }
        item.status = Some(204);
        assert!(item.complete()); assert!(!item.pending()); assert!(item.successful());
        item.status = Some(500);
        assert!(item.complete()); assert!(!item.successful());
        item.receipt_accepted = false;
        assert!(!item.complete());
        for code in [101,202,206,213] { item.status = Some(code); assert!(item.pending()); }
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
