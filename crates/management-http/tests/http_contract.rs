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
