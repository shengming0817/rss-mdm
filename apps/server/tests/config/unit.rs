use super::*;
#[test]
fn content_budget_reserves_all_three_physical_pools() {
    let mut config: Config =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    config.content = None;
    let base = (1..256)
        .find(|budget| {
            config.background.database_connection_budget = *budget;
            config.background.compile(&config).is_ok()
        })
        .unwrap();
    config.content = Some(rss_mdm_content_service::Config {
        storage: rss_mdm_content_service::Storage::Volume {
            directory: "/unused-budget-proof".into(),
        },
        imports: Default::default(),
        max_artifact_bytes: 1,
        max_temporary_bytes: 1,
        max_uploads: 1,
        transfer_seconds: 1,
        retention_seconds: 1,
        max_bundle_entries: 1,
        max_expansion_ratio: 1,
    });
    config.background.database_connection_budget = base + crate::background::CONTENT_CONNECTIONS;
    assert!(config.background.compile(&config).is_err());
    config.background.database_connection_budget += rss_mdm_content_service::ADMISSION_CONNECTIONS;
    assert!(config.background.compile(&config).is_err());
    config.background.database_connection_budget += 2;
    assert!(config.background.compile(&config).is_ok());
}

#[test]
fn background_budget_includes_each_tenant_host_and_rejects_overflow() {
    let mut config: Config =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    assert!(config.background.compile(&config).is_ok());
    config.background.database_host_instances = 2;
    assert!(config.background.compile(&config).is_err());
    config.background.database_connection_budget = 256;
    assert!(config.background.compile(&config).is_ok());
    config.background.database_host_instances = u32::MAX;
    assert!(config.background.compile(&config).is_err());
    config.background.database_host_instances = 0;
    assert!(config.background.compile(&config).is_err());
    config.background.database_host_instances = 1;
    for concurrency in [0, usize::MAX] {
        config.background.device_concurrency = concurrency;
        assert!(config.background.compile(&config).is_err());
    }
}

fn independent_secrets(value: &mut serde_json::Value) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("identity-config-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    {
        let role = "database";
        let path = root.join(role);
        std::fs::write(&path, role).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        value["identity"][role]["password_file"] = serde_json::json!(path);
    }
    for pointer in [
        "/access_database",
        "/runtime_database",
        "/command_database",
        "/business_databases/inventory",
        "/business_databases/scope",
        "/business_databases/policy",
        "/business_databases/resource",
        "/business_databases/software",
        "/business_databases/content",
        "/business_databases/telemetry",
        "/business_databases/scheduler",
        "/publication/database",
        "/tenant_administration/registry_database",
        "/tenant_administration/provisioning_database",
    ] {
        if let Some(database) = value.pointer_mut(pointer).filter(|v| v.is_object()) {
            let name = pointer.replace('/', "-");
            let path = root.join(&name);
            std::fs::write(&path, &name).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            database["password_file"] = serde_json::json!(path);
        }
    }
    for (index, pointer) in [
        "/native_protection/active_file",
        "/native_protection/fingerprint_file",
    ]
    .into_iter()
    .enumerate()
    {
        let path = root.join(format!("key-{index}"));
        std::fs::write(&path, [index as u8 + 1; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        *value.pointer_mut(pointer).unwrap() = serde_json::json!(path);
    }
    root
}
#[test]
fn static_business_permissions_are_rejected() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    let root = independent_secrets(&mut value);
    value["bindings"] = serde_json::json!([]);
    assert!(serde_json::from_value::<Config>(value.clone()).is_err());
    value.as_object_mut().unwrap().remove("bindings");
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
            "/command_database/user",
            serde_json::json!("mdm_access"),
            "CommandStorage",
        ),
        (
            "/command_database/host",
            serde_json::json!("other-host"),
            "CommandStorage",
        ),
        (
            "/command_database/port",
            serde_json::json!(5433),
            "CommandStorage",
        ),
        (
            "/command_database/name",
            serde_json::json!("other-db"),
            "CommandStorage",
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
        let root = independent_secrets(&mut value_config);
        *value_config.pointer_mut(pointer).unwrap() = value;
        let config: Config = serde_json::from_value(value_config).unwrap();
        let error = match config.compile() {
            Err(error) => error,
            Ok(_) => panic!("invalid configuration accepted"),
        };
        let diagnostic = crate::ProcessError::at("startup.configuration", error).to_string();
        assert!(diagnostic.contains(field), "{pointer}: {diagnostic}");
        assert!(!diagnostic.contains("synthetic-secret"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
#[test]
fn native_protocols_are_explicit_closed_and_do_not_require_windows() {
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
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
    database.password_file = root.join("missing-password");
    assert!(matches!(
        database.options(),
        Err(Error::Configuration(ConfigIssue::DatabasePassword))
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_pki_configuration_is_explicit_and_closed() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    assert!(serde_json::from_value::<Config>(value.clone()).is_ok());
    for invalid in [
        serde_json::Value::Null,
        serde_json::json!({}),
        serde_json::json!({"mode":"local_ca"}),
        serde_json::json!({"mode":"disabled","kid":"secret"}),
    ] {
        value["agent_pki"] = invalid;
        assert!(
            serde_json::from_value::<Config>(value.clone()).is_err(),
            "{}",
            value["agent_pki"]
        );
    }
    value.as_object_mut().unwrap().remove("agent_pki");
    assert!(serde_json::from_value::<Config>(value).is_err());
}

#[test]
fn standard_agent_lifetime_rejects_extra_fields() {
    assert!(
        serde_json::from_value::<crate::agent_pki::Lifetime>(
            serde_json::json!({"mode":"standard","days":3650})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<crate::agent_pki::Lifetime>(
            serde_json::json!({"mode":"standard"})
        )
        .is_ok()
    );
}

#[test]
fn optional_signing_is_admitted_by_consumers_not_core_configuration() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    let root = independent_secrets(&mut value);
    let endpoint = serde_json::json!({"origin":"https://agent.example.test"});
    for enabled in [false, true] {
        for signed in [false, true] {
            value["agent_pki"] = if enabled {
                serde_json::json!({"mode":"step_ca","endpoint":endpoint,"trust_file":"unused.json"})
            } else {
                serde_json::json!({"mode":"disabled"})
            };
            value["task_signing"] = if signed {
                serde_json::json!({"revision":1})
            } else {
                serde_json::Value::Null
            };
            let result = serde_json::from_value::<Config>(value.clone())
                .unwrap()
                .compile();
            assert!(result.is_ok(), "enabled={enabled}, signed={signed}");
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn configured_worker_capacity_and_pool_arithmetic_are_checked_together() {
    let mut config: Config =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    config.background.device_concurrency = 128;
    config.background.database_connection_budget = 4096;
    config.background.scheduling.device.claim_batch_size = 1024;
    config.background.scheduling.device.scan_budget = 4096;
    let compiled = config.background.compile(&config).unwrap();
    assert_eq!(compiled.device.concurrency(), 128);
    assert_eq!(compiled.device.claim_batch_size(), 1024);
    assert_eq!(compiled.device.scan_budget(), 4096);
    assert_eq!(compiled.access_connections, 136);
    config.background.device_concurrency = u32::MAX as usize;
    assert!(config.background.compile(&config).is_err());
    config.background.device_concurrency = 128;
    for claim in [0, 1025] {
        config.background.scheduling.device.claim_batch_size = claim;
        assert!(config.background.compile(&config).is_err());
    }
    config.background.scheduling.device.claim_batch_size = 1024;
    config.background.scheduling.device.attempt_ms = 0;
    assert!(config.background.compile(&config).is_err());
}
