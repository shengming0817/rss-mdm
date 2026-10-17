use super::*;
#[test]
fn package_identities_are_format_specific() {
    assert!(
        Identity::WindowsMsi {
            product: Uuid::nil(),
            publisher: "RSS".into()
        }
        .validate()
        .is_err()
    );
    assert!(
        Identity::Macos {
            receipt: "com.rss.agent.pkg".into(),
            bundle: "com.rss.agent".into(),
            team: "RSS1234567".into()
        }
        .validate()
        .is_ok()
    );
    assert!(
        serde_json::from_value::<Identity>(
            serde_json::json!({"platform":"windows","product":Uuid::new_v4(),"publisher":"RSS"})
        )
        .is_err()
    );
}
