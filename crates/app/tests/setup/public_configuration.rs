use super::*;
const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const MANAGEMENT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

#[test]
fn public_inputs_only_contain_distinct_registered_entry_coordinates() {
    let inputs = project("https://mdm.example.test", true, TENANT, MANAGEMENT).unwrap();
    assert_eq!(
        serde_json::to_value(inputs).unwrap(),
        serde_json::json!({
            "ui.json": {"canonicalOrigin":"https://mdm.example.test", "oidcEnabled":true},
            "mdm.json": {"canonicalOrigin":"https://mdm.example.test", "tenant":TENANT, "managementTenant":MANAGEMENT}
        })
    );
    assert!(project("https://mdm.example.test", false, TENANT, TENANT).is_err());
    assert!(
        project(
            "https://mdm.example.test",
            false,
            TENANT,
            &Uuid::nil().to_string()
        )
        .is_err()
    );
    assert!(
        project(
            "https://mdm.example.test",
            false,
            TENANT,
            &MANAGEMENT.to_uppercase()
        )
        .is_err()
    );
}

#[test]
fn host_configuration_rejects_noncanonical_or_untrusted_origins() {
    for origin in [
        "http://mdm.example.test",
        "https://mdm.example.test/",
        "https://user@mdm.example.test",
        "https://mdm.example.test?next=elsewhere",
    ] {
        assert!(project(origin, false, TENANT, MANAGEMENT).is_err());
    }
}
