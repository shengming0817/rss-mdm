use super::*;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

fn runtime(root: &std::path::Path) -> Value {
    let mut value: Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    let key = root.join("protection.key");
    std::fs::write(&key, [7; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    value["native_protection"] =
        json!({"active_file":key,"historical_files":[],"fingerprint_file":key});
    value["native_protocols"] = json!({});
    value["device_pki"] = json!([]);
    value
}

fn input(root: &std::path::Path) -> Input {
    serde_json::from_value(json!({
        "directory":root.join("installation"),
        "deployment":{"directory":root.join("primary"),"gateway_directory":root.join("gateway"),
            "certificate_file":root.join("tls.crt"),"private_key_file":root.join("tls.key"),"trust_file":root.join("ca.crt")},
        "database":{"name":"mdm","administrator":{"host":"postgres","port":5432,"name":"postgres","user":"postgres",
            "password_file":root.join("password"),"ca_file":root.join("ca.crt")}},
        "organization_name":"Capacity test","platform_login":"platform","administrator_login":"administrator",
        "origin":"https://primary.example.test","listen":"127.0.0.1:8081","trusted_gateway":"127.0.0.1"
    })).unwrap()
}

fn slot(root: &std::path::Path, name: &str, port: u16) -> Slot {
    Slot {
        origin: format!("https://{name}.example.test"),
        listen: format!("127.0.0.1:{port}").parse().unwrap(),
        deployment: runtime_files::Config {
            directory: root.join(name),
            ..input(root).deployment
        },
    }
}

#[test]
fn capacity_checks_each_hosts_physical_pools_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let mut value = runtime(&root);
    let minimum = (1..512)
        .find(|budget| {
            Capacity::new(1, *budget)
                .unwrap()
                .project(&mut value.clone())
                .is_ok()
        })
        .unwrap();
    let capacity = Capacity::new(1, minimum).unwrap();
    capacity.project(&mut value).unwrap();
    let mut content = value.clone();
    content["content"] = json!({"storage":{"kind":"volume","directory":root.join("content")},"imports":{},
        "max_artifact_bytes":1024,"max_temporary_bytes":2048,"max_uploads":1,"transfer_seconds":60,
        "retention_seconds":86400,"max_bundle_entries":8,"max_expansion_ratio":10});
    assert!(capacity.project(&mut content).is_err());
    assert!(
        Capacity::new(1, minimum - 1)
            .unwrap()
            .project(&mut value.clone())
            .is_err()
    );
    assert!(Capacity::new(1024, u32::MAX).is_err());
    let mut deferred = value.clone();
    deferred["content"] = Value::Null;
    assert!(
        capacity
            .preflight(&deferred, &super::super::install::ContentStorage::Volume)
            .is_ok()
    );
    assert!(
        capacity
            .preflight(&deferred, &super::super::install::ContentStorage::S3)
            .is_err()
    );
    assert!(deferred["content"].is_null());
    deferred["content"] = super::super::application::s3_content(7);
    assert!(capacity.project(&mut deferred).is_err());
}

#[test]
fn declarations_are_append_only_even_after_partial_slot_publication() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let mut input = input(&root);
    let journal = Journal::open(&input.directory).unwrap();
    input.additional_hosts.push(slot(&root, "second", 8082));
    save_slots(&input, &journal).unwrap();
    assert!(validate_declaration(&input, &journal, 1).is_ok());
    input.additional_hosts.push(slot(&root, "third", 8083));
    assert!(validate_declaration(&input, &journal, 2).is_ok());
    input.additional_hosts.swap(0, 1);
    assert!(matches!(
        validate_declaration(&input, &journal, 2),
        Err(Error::Conflict)
    ));
    input.additional_hosts.clear();
    assert!(matches!(
        validate_declaration(&input, &journal, 1),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        validate_declaration(&input, &journal, 2),
        Err(Error::Conflict)
    ));
}

#[test]
fn pending_runtime_keeps_identity_materials_and_stable_capacity_request() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let input = input(&root);
    let mut cached = runtime(&root);
    cached["task_signing"] = json!({"revision":7});
    let host: Uuid = serde_json::from_value(cached["runtime_binding"]["host_id"].clone()).unwrap();
    let owner = Journal::open(&input.directory.join(format!("rss-mdm-{}", host.simple()))).unwrap();
    let before = super::super::application::fingerprint(&cached).unwrap();
    let old_binding = cached["runtime_binding"].clone();
    let capacity = Capacity::new(1, 512).unwrap();
    capacity.project(&mut cached).unwrap();
    super::super::application::bind_change(&mut cached, &before).unwrap();
    assert_eq!(
        cached["runtime_binding"]["revision"].as_u64().unwrap(),
        old_binding["revision"].as_u64().unwrap() + 1
    );
    assert_eq!(cached["runtime_binding"]["host_id"], old_binding["host_id"]);
    owner.save("requested-runtime.json", &cached).unwrap();
    let mut resumed: Value = owner.load("requested-runtime.json").unwrap().unwrap();
    let before = super::super::application::fingerprint(&resumed).unwrap();
    capacity.project(&mut resumed).unwrap();
    super::super::application::bind_change(&mut resumed, &before).unwrap();
    assert_eq!(resumed, cached);
    assert_eq!(resumed["task_signing"]["revision"], 7);
    assert!(
        Capacity::new(0, 512)
            .unwrap()
            .require_current(&resumed)
            .is_err()
    );
    assert!(capacity.require_current(&resumed).is_ok());
}
