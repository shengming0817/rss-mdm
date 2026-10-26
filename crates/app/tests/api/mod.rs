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
