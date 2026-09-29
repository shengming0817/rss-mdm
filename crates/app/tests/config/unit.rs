use super::*;
fn independent_secrets(value: &mut serde_json::Value) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("worker-config-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    for role in ["database", "audit_worker"] {
        let path = root.join(role);
        std::fs::write(&path, role).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        value["identity"][role]["password_file"] = serde_json::json!(path);
    }
    root
}
#[test]
fn worker_rejects_shared_password_path_and_contents() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("worker-secrets-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let runtime = root.join("runtime");
    let worker = root.join("worker");
    for path in [&runtime, &worker] {
        std::fs::write(
            path,
            if path == &runtime {
                "same-secret\n"
            } else {
                "same-secret"
            },
        )
        .unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    value["identity"]["database"]["password_file"] = serde_json::json!(runtime);
    for path in [&runtime, &worker] {
        value["identity"]["audit_worker"]["password_file"] = serde_json::json!(path);
        assert!(matches!(
            serde_json::from_value::<Config>(value.clone())
                .unwrap()
                .compile(),
            Err(Error::Configuration(ConfigIssue::IdentityAuditDatabase))
        ));
    }
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn identity_worker_requires_its_own_same_database_credentials() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    value["identity"]["audit_worker"] = value["identity"]["database"].clone();
    assert!(
        serde_json::from_value::<Config>(value.clone())
            .and_then(|c| c.compile().map_err(serde::de::Error::custom))
            .is_err()
    );
    value["identity"]["audit_worker"]["user"] = "mdm_identity_audit".into();
    let root = independent_secrets(&mut value);
    assert!(
        serde_json::from_value::<Config>(value.clone())
            .unwrap()
            .compile()
            .is_ok()
    );
    value["identity"]["audit_worker"]["name"] = "other".into();
    assert!(
        serde_json::from_value::<Config>(value.clone())
            .unwrap()
            .compile()
            .is_err()
    );
    value["identity"]
        .as_object_mut()
        .unwrap()
        .remove("audit_worker");
    assert!(serde_json::from_value::<Config>(value).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn static_business_permissions_are_rejected() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    let root = independent_secrets(&mut value);
    value["bindings"] = serde_json::json!([]);
    assert!(serde_json::from_value::<Config>(value.clone()).is_err());
    value.as_object_mut().unwrap().remove("bindings");
    value["identity_management"] = serde_json::json!([]);
    assert!(
        serde_json::from_value::<Config>(value.clone())
            .unwrap()
            .compile()
            .is_ok()
    );
    value.as_object_mut().unwrap().remove("access_database");
    assert!(serde_json::from_value::<Config>(value).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn startup_configuration_diagnostics_identify_safe_fields() {
    for (pointer, value, field) in [
        ("/listen", serde_json::json!("0.0.0.0:8080"), "Listen"),
        (
            "/execution/database/user",
            serde_json::json!("mdm_access"),
            "Execution",
        ),
        (
            "/execution/database/host",
            serde_json::json!("other-host"),
            "Execution",
        ),
        (
            "/execution/database/port",
            serde_json::json!(5433),
            "Execution",
        ),
        (
            "/execution/database/name",
            serde_json::json!("other-db"),
            "Execution",
        ),
        (
            "/access_database/user",
            serde_json::json!("postgres"),
            "AccessDatabase",
        ),
        (
            "/product_origin",
            serde_json::json!("https://synthetic-secret@example.test"),
            "ProductOrigin",
        ),
        (
            "/identity/instance_id",
            serde_json::json!("synthetic-secret"),
            "Instance",
        ),
        (
            "/identity/database/user",
            serde_json::json!("postgres"),
            "IdentityDatabase",
        ),
        (
            "/identity/tenant_id",
            serde_json::json!("synthetic-secret"),
            "Tenant",
        ),
        (
            "/native_protocols/windows/enrollment/origin",
            serde_json::json!("http://synthetic-secret.example.test"),
            "WindowsListeners",
        ),
        (
            "/native_protocols/windows/management/origin",
            serde_json::json!("http://synthetic-secret.example.test"),
            "WindowsListeners",
        ),
    ] {
        let mut value_config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))
                .unwrap();
        *value_config.pointer_mut(pointer).unwrap() = value;
        let config: Config = serde_json::from_value(value_config).unwrap();
        let error = match config.compile() {
            Err(error) => error,
            Ok(_) => panic!("invalid configuration accepted"),
        };
        let diagnostic = crate::ProcessError::at("startup.configuration", error).to_string();
        assert!(diagnostic.contains(field));
        assert!(!diagnostic.contains("synthetic-secret"));
    }
}
#[test]
fn native_protocols_are_explicit_closed_and_do_not_require_windows() {
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    let windows = config["native_protocols"]["windows"].clone();
    config["native_protocols"] = serde_json::json!({});
    let decoded: Config = serde_json::from_value(config.clone()).unwrap();
    assert!(decoded.native_protocols.windows.is_none() && decoded.native_protocols.apple.is_none());
    for protocols in [
        serde_json::json!({"windows":null}),
        serde_json::json!({"apple":null}),
        serde_json::json!({"unknown":{}}),
    ] {
        config["native_protocols"] = protocols;
        assert!(serde_json::from_value::<Config>(config.clone()).is_err());
    }
    config.as_object_mut().unwrap().remove("native_protocols");
    assert!(serde_json::from_value::<Config>(config.clone()).is_err());
    config["windows"] = windows;
    assert!(serde_json::from_value::<Config>(config).is_err());
}
#[test]
fn ca_inputs_reject_symlinks_directories_and_oversize() {
    let root = std::env::temp_dir().join(format!("mdm-ca-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let ca = root.join("ca");
    std::fs::write(&ca, b"public certificate").unwrap();
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&ca, &alias).unwrap();
    use std::os::unix::fs::PermissionsExt;
    let password = root.join("password");
    std::fs::write(&password, "fixture").unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut database = Database {
        host: "localhost".into(),
        port: 5432,
        name: "mdm".into(),
        user: "mdm_api".into(),
        password_file: password,
        ca_file: alias,
    };
    assert!(database.options().is_err());
    database.ca_file = root.clone();
    assert!(database.options().is_err());
    database.ca_file = ca.clone();
    std::fs::write(&ca, vec![0; 1024 * 1024 + 1]).unwrap();
    assert!(database.options().is_err());
    std::fs::write(&ca, b"public certificate").unwrap();
    assert!(database.options().is_ok());
    std::fs::remove_dir_all(root).unwrap();
}
