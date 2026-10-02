use super::*;
#[test]
fn phase_storage_roundtrip_rejects_unknown() {
    for phase in [AttemptPhase::Execute, AttemptPhase::Observe] {
        assert_eq!(AttemptPhase::parse(phase.as_str()).unwrap(), phase);
    }
    assert!(AttemptPhase::parse("retry").is_err());
}
