//! Native command receipt classification from OMA SyncML Representation 1.2.2 §10.
/// OMA SyncML Representation 1.2.2 §10: provisional receipts allow later completion.
/// Unknown codes remain evidence, without inventing a successful business outcome.
pub fn terminal_status(status: i32) -> bool {
    status >= 200 && !matches!(status, 202 | 206 | 213)
}
/// Whether this status explicitly completes the named SyncML command successfully.
pub fn successful_status(kind: &str, status: i32) -> bool {
    match status {
        200 | 214 => matches!(
            kind,
            "add" | "replace" | "delete" | "get" | "exec" | "atomic" | "sequence"
        ),
        201 => kind == "add",
        204 => kind == "get",
        210 | 211 => kind == "delete",
        _ => false,
    }
}
/// Whether this status explicitly rejects the command; rollback failure remains unknown.
pub fn rejected_status(status: i32) -> bool {
    matches!(status, 215 | 216) || ((400..600).contains(&status) && status != 516)
}
#[cfg(test)]
mod status_tests {
    #[test]
    fn only_explicit_command_outcomes_are_successful() {
        for kind in [
            "add", "replace", "delete", "get", "exec", "atomic", "sequence",
        ] {
            assert!(super::successful_status(kind, 200));
            for code in [
                101, 202, 203, 205, 206, 207, 208, 209, 212, 213, 215, 216, 217, 218, 507, 516,
            ] {
                assert!(!super::successful_status(kind, code), "{kind} {code}");
            }
        }
        assert!(super::successful_status("get", 204));
        assert!(!super::successful_status("exec", 204));
        assert!(super::successful_status("add", 201));
        assert!(!super::successful_status("get", 201));
        assert!(super::successful_status("delete", 211));
        assert!(super::rejected_status(215));
        assert!(super::rejected_status(216));
        assert!(!super::rejected_status(516));
    }
    #[test]
    fn partial_completion_can_receive_a_later_terminal_receipt() {
        for code in [101, 202, 206, 213] {
            assert!(!super::terminal_status(code), "provisional status {code}");
        }
        assert!(super::terminal_status(200));
    }
}
