use super::*;

#[test]
fn additional_host_content_and_cold_snapshot_follow_its_own_deployment() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let primary = runtime_files::Config {
        directory: root.join("primary-runtime"),
        content_volume: Some(root.join("primary-content")),
        probe_address: None,
        certificate_file: root.join("server.crt"),
        private_key_file: root.join("server.key"),
        trust_file: root.join("ca.crt"),
    };
    let mut runtime: Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    runtime["content"] =
        serde_json::json!({"storage":primary.prepare_content_storage().unwrap(),"max_uploads":8});
    std::fs::write(primary.content_directory().join("artifact"), b"primary").unwrap();
    let progress = super::super::model::Provisioning {
        operation_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        administrator_id: Some(Uuid::new_v4()),
        host_id: Uuid::new_v4(),
        revision: 1,
        phase: Phase::HostPending,
        blocked: None,
        origin: None,
        application: None,
    };
    for explicit in [true, false] {
        let slot = Slot {
            origin: "https://secondary.example.test".into(),
            listen: "127.0.0.1:8082".parse().unwrap(),
            deployment: runtime_files::Config {
                directory: root.join(if explicit {
                    "explicit-runtime"
                } else {
                    "default-runtime"
                }),
                content_volume: explicit.then(|| root.join("secondary-content")),
                ..primary.clone()
            },
        };
        let candidate = additional_runtime(&runtime, &slot, &progress).unwrap();
        let volume = slot
            .deployment
            .content_snapshot(&candidate)
            .unwrap()
            .unwrap();
        assert_ne!(volume, primary.content_directory());
        assert_eq!(candidate["content"]["max_uploads"], 8);
        assert!(matches!(
            slot.deployment.content_snapshot(&runtime),
            Err(Error::Conflict)
        ));
        std::fs::write(volume.join("artifact"), b"secondary").unwrap();
        let journal = Journal::open(&root.join(if explicit {
            "explicit-backup"
        } else {
            "default-backup"
        }))
        .unwrap();
        super::super::snapshot_tree::capture(&journal, "volume", &volume).unwrap();
        std::fs::remove_dir_all(&volume).unwrap();
        super::super::snapshot_tree::restore(&journal, "volume").unwrap();
        assert_eq!(
            std::fs::read(volume.join("artifact")).unwrap(),
            b"secondary"
        );
        assert_eq!(
            std::fs::read(primary.content_directory().join("artifact")).unwrap(),
            b"primary"
        );
        let mut shared = slot;
        shared.deployment.content_volume = primary.content_volume.clone();
        assert_eq!(
            shared.deployment.content_snapshot(&runtime).unwrap(),
            primary.content_snapshot(&runtime).unwrap()
        );
    }
}
