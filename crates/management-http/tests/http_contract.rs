use crate::{Mounts, contract_routes};

#[test]
fn offline_management_contract_is_complete_without_runtime_services() {
    let routes = contract_routes(Mounts {
        agent_enrollment: true,
        filevault: true,
        recovery_credentials: true,
    });
    let document =
        rss_mdm_http_contract::artifact::document([("browser", routes.into_endpoints())]);
    if let Err(errors) = document {
        panic!("{}", errors.join("\n"));
    }
}

#[test]
fn disabled_conditions_remove_only_their_actual_mounts() {
    let routes = contract_routes(Mounts {
        agent_enrollment: false,
        filevault: false,
        recovery_credentials: false,
    });
    let endpoints = routes.endpoints();
    assert!(
        !endpoints
            .iter()
            .any(|e| e.path.starts_with("/api/v1/device-access/broker"))
    );
    assert!(
        !endpoints
            .iter()
            .any(|e| e.path.contains("/recovery-credentials/filevault/"))
    );
    // These intentionally remain registered and report unavailable at runtime.
    for path in [
        "/api/v1/agent-connections",
        "/api/v1/windows/entra-policy",
        "/api/v1/telemetry/history",
    ] {
        assert!(
            endpoints.iter().any(|e| e.path == path),
            "missing unavailable-service endpoint {path}"
        );
    }
}

#[test]
fn authentication_owner_resolves_final_paths_and_cookie_activity() {
    let routes = contract_routes(Mounts {
        agent_enrollment: true,
        filevault: true,
        recovery_credentials: true,
    });
    let doc =
        rss_mdm_http_contract::artifact::document([("browser", routes.into_endpoints())]).unwrap();
    let endpoint = |method: &str, path: &str| {
        doc["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["method"] == method && e["path"] == path)
            .unwrap()
            .clone()
    };
    let devices = endpoint("GET", "/api/v1/devices");
    let auth = &devices["authentication"];
    assert_eq!(auth["alternatives"].as_array().unwrap().len(), 3);
    assert_eq!(
        auth["alternatives"][0]["required_headers"],
        serde_json::json!(["cookie"])
    );
    assert_eq!(auth["conditional_response_headers"][0]["value"], "Bearer");
    assert_eq!(
        auth["conditional_response_headers"][1]["request_headers_absent"],
        serde_json::json!(["authorization"])
    );
    let quota = endpoint("GET", "/api/v1/registration-quotas/me");
    assert_eq!(
        quota["authentication"]["alternatives"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Every protected write requires active Cookie proof, without imposing it on API credentials.
    let writes = doc["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["method"] == "POST" && e["authentication"].is_object())
        .collect::<Vec<_>>();
    assert!(!writes.is_empty());
    for write in writes {
        assert_eq!(
            write["authentication"]["alternatives"][0]["required_headers"],
            serde_json::json!(["cookie", "origin", "x-identity-request", "x-csrf-token"])
        );
    }
    let management = crate::tenant_administration::contract_routes(
        crate::router::workspace_routes().bind_with(None::<&()>, |_| ()),
    );
    // This subtree's configured static route is validated with its capture sibling by App.
    assert!(!management.endpoints().is_empty());
    for endpoint in management.endpoints() {
        let describe = endpoint
            .authentication
            .expect("management authentication owner");
        assert_eq!(
            describe(endpoint.method, &endpoint.path).alternatives.len(),
            1
        );
    }
}

#[test]
#[should_panic(expected = "contract descriptions cannot serve HTTP")]
fn offline_authentication_mount_cannot_serve_without_runtime_owner() {
    let _ = crate::authorization::http::mount_protection(
        crate::router::workspace_routes().bind_with(None::<&()>, |_| ()),
        None,
        false,
    )
    .into_axum();
}

#[test]
fn each_presence_switch_changes_only_its_declared_module() {
    for (agent, filevault, recovery) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
        (false, true, true),
        (true, true, true),
    ] {
        let routes = contract_routes(Mounts {
            agent_enrollment: agent,
            filevault,
            recovery_credentials: recovery,
        });
        let has = |path: &str| routes.endpoints().iter().any(|e| e.path == path);
        assert_eq!(has("/api/v1/device-access/broker"), agent);
        assert_eq!(
            has("/api/v1/devices/{device}/recovery-credentials/filevault/configuration"),
            filevault
        );
        assert_eq!(
            has("/api/v1/devices/{device}/recovery-credentials"),
            recovery
        );
        assert!(
            has("/api/v1/agent-connections")
                && has("/api/v1/windows/entra-policy")
                && has("/api/v1/telemetry/history")
        );
    }
}
