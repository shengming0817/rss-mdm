//! Decisions over native evidence; storage and current authority are adapter inputs.
use rss_mdm_windows_mdm::syncml::{rejected_status, successful_status, terminal_status};

pub(crate) struct Eligibility {
    pub latest: bool,
    pub within_deadline: bool,
    pub active: bool,
    pub authority_valid: bool,
}
impl Eligibility {
    pub fn allows(&self) -> bool {
        self.latest && self.within_deadline && self.active && self.authority_valid
    }
}

pub(crate) fn compatible_receipt(
    kind: &str,
    atomic: bool,
    old: Option<i32>,
    new: Option<i32>,
    old_value: Option<&str>,
    new_value: Option<&str>,
) -> bool {
    !old.is_some_and(|old| {
        terminal_status(old)
            && new.is_some_and(|new| {
                old != new && !(atomic && matches!(new, 216 | 516) && successful_status(kind, old))
            })
    }) && !old_value.is_some_and(|old| new_value.is_some_and(|new| old != new))
}

pub(crate) fn accepts_frame(code: i32, accepted: bool, end: i32, total: i32) -> bool {
    accepted && terminal_status(code) && (rejected_status(code) || end == total)
}

pub(crate) struct ItemEvidence {
    pub prepare: bool,
    pub kind: String,
    pub status: Option<i32>,
    pub receipt_accepted: bool,
    pub has_value: bool,
    pub result_accepted: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Settlement {
    Wait,
    Reject,
    Receive {
        query_complete: bool,
        values_complete: bool,
    },
}
pub(crate) fn settle(items: &[ItemEvidence], package_complete: bool) -> Settlement {
    if items
        .iter()
        .any(|i| i.receipt_accepted && i.status.is_some_and(rejected_status))
    {
        return Settlement::Reject;
    }
    let execution: Vec<_> = items.iter().filter(|i| !i.prepare).collect();
    if !package_complete
        || execution.is_empty()
        || !execution.iter().all(|i| {
            i.receipt_accepted
                && i.status
                    .is_some_and(|code| successful_status(&i.kind, code))
        })
    {
        return Settlement::Wait;
    }
    let values_complete = execution
        .iter()
        .filter(|i| i.kind == "get")
        .all(|i| i.status == Some(204) || (i.has_value && i.result_accepted));
    let query_complete = values_complete
        && execution.iter().any(|i| i.kind == "get")
        && execution
            .iter()
            .all(|i| matches!(i.kind.as_str(), "get" | "atomic" | "sequence"));
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
            prepare: false,
            kind: "get".into(),
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
        item.prepare = true;
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
    fn early_frame_success_cannot_become_success_after_later_frames_are_sent() {
        assert!(!accepts_frame(200, true, 4, 8));
        assert!(accepts_frame(200, true, 8, 8));
        assert!(accepts_frame(500, true, 4, 8));
        assert!(!accepts_frame(213, true, 8, 8));
        assert!(!accepts_frame(200, false, 8, 8));
    }
    #[test]
    fn rollback_is_allowed_only_with_atomic_ancestry_and_values_are_immutable() {
        assert!(compatible_receipt(
            "replace",
            true,
            Some(200),
            Some(216),
            None,
            None
        ));
        assert!(!compatible_receipt(
            "replace",
            false,
            Some(200),
            Some(216),
            None,
            None
        ));
        assert!(!compatible_receipt(
            "get",
            true,
            Some(200),
            Some(200),
            Some("a"),
            Some("b")
        ));
        assert!(compatible_receipt(
            "get",
            false,
            Some(213),
            Some(200),
            None,
            Some("a")
        ));
    }
    #[test]
    fn every_live_authority_guard_is_required() {
        for missing in 0..4 {
            let e = Eligibility {
                latest: missing != 0,
                within_deadline: missing != 1,
                active: missing != 2,
                authority_valid: missing != 3,
            };
            assert!(!e.allows());
        }
    }
}
