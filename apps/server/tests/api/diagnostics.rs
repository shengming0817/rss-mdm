use crate::http_contract_document;
use serde_json::json;
#[test]
fn application_administration_routes_keep_original_authentication_boundaries() {
    let document = http_contract_document().expect("complete application route contract");
    let endpoints = document["endpoints"]
        .as_array()
        .expect("endpoint descriptions");
    for (method, path, alternatives) in [
        ("GET", "/api/v1/user-attribute-definitions", 3),
        ("GET", "/api/v1/settings/catalog", 3),
        ("PUT", "/api/v1/settings/first-use", 3),
        ("GET", "/api/v1/tenant-administration/settings/catalog", 1),
    ] {
        let matches = endpoints
            .iter()
            .filter(|endpoint| endpoint["method"] == method && endpoint["path"] == path)
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "each application endpoint has exactly one canonical registration: {method} {path}"
        );
        assert_eq!(
            matches[0]["authentication"]["alternatives"]
                .as_array()
                .expect("protected endpoint")
                .len(),
            alternatives,
            "{path}"
        );
        if method == "PUT" {
            assert_eq!(
                matches[0]["authentication"]["alternatives"][0]["required_headers"],
                json!(["cookie", "origin", "x-identity-request", "x-csrf-token"])
            );
        }
    }
}
