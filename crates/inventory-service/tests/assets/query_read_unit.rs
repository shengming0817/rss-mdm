use super::*;

#[test]
fn largest_result_identity_and_facet_fit_the_signed_cursor_budget() {
    let codec = CursorCodec::new(&[3; 32]).unwrap();
    let binding = "f".repeat(64);
    // Even worst-case JSON escaping of all 256 stored bytes stays bounded.
    for position in [
        Position::Items {
            device: "\0".repeat(256),
        },
        Position::Facet {
            facet: Facet::OsVersions,
            label: "\0".repeat(256),
        },
    ] {
        let token = codec.encode(&binding, &position).unwrap();
        assert!(token.as_str().len() <= 4096);
        let decoded: Position = codec.decode(&token, &binding).unwrap();
        assert_eq!(
            serde_json::to_value(position).unwrap(),
            serde_json::to_value(decoded).unwrap()
        );
    }
    assert!(
        serde_json::from_value::<Position>(
            serde_json::json!({"kind":"items","device":"x","key":[1,2]})
        )
        .is_err()
    );
}
