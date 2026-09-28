use super::*;
#[test]
fn expired_delivery_can_retry_but_unknown_side_effect_cannot() {
    let mut run = RunState::new(300, 0).unwrap();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    run.claim(first, 0).unwrap();
    assert!(run.start(first, 1).is_err());
    assert!(run.claim(second, 59).is_err());
    run.claim(second, 60).unwrap();
    assert!(run.received(first, 61).is_err());
    run.received(second, 61).unwrap();
    run.start(second, 62).unwrap();
    run.expire(122, 60);
    assert_eq!(run.execution, Execution::Unknown);
    assert!(run.claim(Uuid::new_v4(), 123).is_err());
    run.result(second, true).unwrap();
    assert_eq!(run.execution, Execution::Succeeded);
}
#[test]
fn late_or_cancelled_evidence_cannot_become_trusted_facts() {
    let mut run = RunState::new(100, 0).unwrap();
    let attempt = Uuid::new_v4();
    run.claim(attempt, 0).unwrap();
    run.received(attempt, 1).unwrap();
    run.start(attempt, 2).unwrap();
    assert!(run.trusts_result(61, 60));
    assert!(!run.trusts_result(62, 60));
    assert!(!run.trusts_result(100, 3600));
    run.cancel();
    assert!(!run.trusts_result(3, 60));
    run.cancelled(attempt).unwrap();
    assert!(!run.trusts_result(4, 60));
    run.result(attempt, true).unwrap();
    assert_eq!(run.execution, Execution::Succeeded);
    assert!(!run.trusts_result(5, 60));
}
#[test]
fn cancellation_is_separate_from_effect_and_late_execution_evidence() {
    let mut run = RunState::new(300, 0).unwrap();
    let attempt = Uuid::new_v4();
    run.claim(attempt, 0).unwrap();
    run.received(attempt, 1).unwrap();
    run.start(attempt, 2).unwrap();
    run.cancel();
    run.cancelled(attempt).unwrap();
    assert_eq!(run.execution, Execution::Unknown);
    assert_eq!(run.cancellation, Cancellation::Confirmed);
    assert!(run.start(attempt, 3).is_err());
    run.result(attempt, false).unwrap();
    assert_eq!(run.execution, Execution::Failed);
    assert_eq!(run.cancellation, Cancellation::Confirmed);
}
