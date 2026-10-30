pub(crate) mod identity_context;
pub(crate) mod runtime_diagnostics;

#[test]
fn http_contract_authentication_survives_final_listener_assembly() {
    let document = crate::api::http_contract_document().unwrap();
    let endpoints = document["endpoints"].as_array().unwrap();
    for resource in ["wns", "ade_configuration", "devices"] {
        let selected = endpoints
            .iter()
            .filter(|e| e["resource"]["id"] == resource)
            .collect::<Vec<_>>();
        assert!(!selected.is_empty(), "missing {resource}");
        for endpoint in selected {
            assert_eq!(
                endpoint["authentication"]["alternatives"]
                    .as_array()
                    .unwrap()
                    .len(),
                3,
                "{endpoint}"
            );
        }
    }
    let health = endpoints
        .iter()
        .find(|e| e["resource"]["id"] == "health")
        .unwrap();
    assert!(health["authentication"].is_null());
}

#[test]
fn offline_contract_contains_each_native_listener_and_shared_protocol_endpoint() {
    let document = crate::api::http_contract_document().unwrap();
    let external = document["external"].as_array().unwrap();
    for (listener, method, path) in [
        (
            "windows-enrollment",
            "POST",
            "/EnrollmentServer/Discovery.svc",
        ),
        (
            "windows-enrollment",
            "POST",
            "/EnrollmentServer/Enrollment.svc",
        ),
        (
            "windows-management",
            "POST",
            "/EnrollmentServer/Discovery.svc",
        ),
        ("windows-management", "POST", "/ManagementServer/MDM.svc"),
        ("apple", "PUT", "/checkin"),
        ("apple", "PUT", "/mdm"),
        (
            "apple",
            "GET",
            "/native/apple/ddm/assets/{operation}/{identifier}",
        ),
    ] {
        assert_eq!(
            external
                .iter()
                .filter(|e| e["listener"] == listener && e["method"] == method && e["path"] == path)
                .count(),
            1,
            "{listener} {method} {path}"
        );
    }
}
