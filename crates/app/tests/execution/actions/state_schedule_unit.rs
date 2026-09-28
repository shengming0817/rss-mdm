use rss_mdm_policy::schedule::*;
#[test]
fn native_schedule_window_is_also_a_run_admission_boundary() {
    let schedule:Schedule=serde_json::from_value(serde_json::json!({"trigger":{"kind":"once","at":3600},"notBefore":0,"jitterSeconds":0,"window":{"zone":"UTC","weekdays":[4],"startMinute":120,"endMinute":180}})).unwrap();
    let slot = schedule.occurrence(3600, b"device").unwrap().unwrap();
    assert_eq!(slot.available_at, 7200);
    assert_eq!(slot.window_end, Some(10800));
    let mut run = crate::execution::actions::state::RunState::new(
        slot.window_end.unwrap(),
        slot.available_at,
    )
    .unwrap();
    assert!(run.claim(uuid::Uuid::new_v4(), 10800).is_err());
}
