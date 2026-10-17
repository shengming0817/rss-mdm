use super::*;
#[test]
fn subject_preserves_two_complete_ids_within_common_name_limit() {
    let enrollment = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let encoded = subject(enrollment, attempt);
    assert_eq!(encoded.len(), 64);
    let name = format!("CN={encoded}").parse().unwrap();
    assert_eq!(parse_subject(&name).unwrap(), (enrollment, attempt));
    assert!(parse_subject(&format!("CN={enrollment}:{attempt}").parse().unwrap()).is_err());
    assert!(parse_subject(&format!("CN={encoded},O=extra").parse().unwrap()).is_err());
    assert!(
        parse_subject(
            &format!("CN={}", subject(Uuid::nil(), attempt))
                .parse()
                .unwrap()
        )
        .is_err()
    );
}
