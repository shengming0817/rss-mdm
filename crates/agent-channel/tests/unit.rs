use super::*;

#[test]
fn wire_discriminators_distinguish_absent_from_unsupported() {
    let error =
        parse_report(br#"{"reportId":"00000000-0000-0000-0000-000000000001"}"#).unwrap_err();
    assert!(matches!(
        error,
        AgentError::Wire(wire::ErrorCode::MalformedRequest)
    ));
    let error = parse_report(br#"{"wireVersion":1}"#).unwrap_err();
    assert!(matches!(
        error,
        AgentError::Wire(wire::ErrorCode::MalformedRequest)
    ));
    let error = parse_report(br#"{"wireVersion":6}"#).unwrap_err();
    assert!(matches!(
        error,
        AgentError::Wire(wire::ErrorCode::UnsupportedWire)
    ));
}
