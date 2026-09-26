use super::*;
use uuid::Uuid;
fn config(directory: PathBuf) -> Config {
    Config {
        directory,
        imports: std::collections::BTreeMap::new(),
        max_artifact_bytes: 32 * 1024 * 1024,
        max_temporary_bytes: 64 * 1024 * 1024,
        max_uploads: 4,
        transfer_seconds: 60,
        retention_seconds: 3600,
        max_bundle_bytes: 64 * 1024 * 1024,
        max_bundle_entries: 100,
        max_expansion_ratio: 100,
    }
}
fn binding(bytes: &[u8]) -> Binding {
    Binding {
        resource: "app".into(),
        version: "1".into(),
        variant: "default".into(),
        platform: rss_mdm_resource::Platform::Windows,
        architecture: rss_mdm_resource::Architecture::X86_64,
        resource_digest: [1; 32],
        source: None,
        origin: None,
        reference: "package".into(),
        length: bytes.len() as u64,
        sha256: rss_mdm_resource::Digest::of(bytes).bytes(),
        actor: "user".into(),
    }
}
#[tokio::test]
async fn large_upload_resumes_after_restart_and_publishes_only_complete_hash() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path().to_owned());
    let tenant = "10000000-0000-0000-0000-000000000001";
    let store = Store::open(&config, tenant, Arc::new(crate::lifecycle::RuntimeTimer)).unwrap();
    let bytes = vec![9u8; 16_777_217];
    let binding = binding(&bytes);
    let artifact = binding.artifact().unwrap();
    let id = Uuid::new_v4();
    store.begin(id, binding.clone(), 100).await.unwrap();
    store.append(id, 0, 100, &bytes[..1_000_000]).await.unwrap();
    assert!(!store.path(&artifact).exists());
    drop(store);
    let store = Store::open(&config, tenant, Arc::new(crate::lifecycle::RuntimeTimer)).unwrap();
    assert_eq!(store.status(id, 101).await.unwrap().offset, 1_000_000);
    assert!(matches!(
        store.append(id, 0, 101, &bytes[..1]).await,
        Err(Error::Conflict)
    ));
    store
        .append(id, 1_000_000, 101, &bytes[1_000_000..])
        .await
        .unwrap();
    store.finish(id, 101).await.unwrap();
    store.finish(id, 101).await.unwrap();
    let verified = store.verify(&artifact).await.unwrap();
    assert!(verified.matches(&artifact));
    drop(verified);
    assert!(
        Store::open(
            &config,
            "20000000-0000-0000-0000-000000000001",
            Arc::new(crate::lifecycle::RuntimeTimer)
        )
        .unwrap()
        .verify(&artifact)
        .await
        .is_err()
    );
}
#[tokio::test]
async fn wrong_bytes_and_interrupted_tail_never_publish() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(
        &config(dir.path().to_owned()),
        "10000000-0000-0000-0000-000000000001",
        Arc::new(crate::lifecycle::RuntimeTimer),
    )
    .unwrap();
    let expected = binding(b"abc");
    let id = Uuid::new_v4();
    store.begin(id, expected.clone(), 1).await.unwrap();
    assert!(store.append(id, 0, 1, &b"abcd"[..]).await.is_err());
    assert_eq!(store.status(id, 1).await.unwrap().offset, 0);
    store.append(id, 0, 1, &b"xyz"[..]).await.unwrap();
    assert!(store.finish(id, 1).await.is_err());
    assert!(!store.path(&expected.artifact().unwrap()).exists());
}

#[test]
fn bundle_checks_closed_manifest_paths_and_member_bytes() {
    use rss_mdm_resource::{BundleEntry, BundleManifest, SoftwareDefinition};
    use std::io::Write;
    let entries = std::collections::BTreeMap::from([
        (
            "install.ps1".into(),
            BundleEntry {
                length: 4,
                sha256: rss_mdm_resource::Digest::of(b"exit").bytes(),
            },
        ),
        (
            "payload.bin".into(),
            BundleEntry {
                length: 3,
                sha256: rss_mdm_resource::Digest::of(b"abc").bytes(),
            },
        ),
    ]);
    let manifest = BundleManifest {
        schema: 1,
        platform: rss_mdm_resource::Platform::Windows,
        architecture: rss_mdm_resource::Architecture::X86_64,
        entries,
    };
    for malicious in [
        None,
        Some("../escape"),
        Some("PAYLOAD.BIN"),
        Some("wrong-bytes"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.zip");
        let mut writer = zip::ZipWriter::new(File::create(&path).unwrap());
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("manifest.json", options).unwrap();
        writer
            .write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        writer.start_file("install.ps1", options).unwrap();
        writer.write_all(b"exit").unwrap();
        writer.start_file("payload.bin", options).unwrap();
        writer
            .write_all(if malicious == Some("wrong-bytes") {
                b"bad"
            } else {
                b"abc"
            })
            .unwrap();
        if let Some(name) = malicious.filter(|v| *v != "wrong-bytes") {
            writer.start_file(name, options).unwrap();
            writer.write_all(b"bad").unwrap();
        }
        writer.finish().unwrap();
        let definition:SoftwareDefinition=serde_json::from_value(serde_json::json!({"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"App","version":"1","format":"bundle","primary":"zip","artifacts":{"zip":{"reference":"zip","length":std::fs::metadata(&path).unwrap().len(),"sha256":vec![2;32]}},"install":{"executor":"power_shell7","entry":"install.ps1","runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},"uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"bundle":manifest})).unwrap();
        let result = super::bundle::validate(
            &mut File::open(path).unwrap(),
            &definition,
            &config(dir.path().to_owned()),
            &crate::lifecycle::RuntimeTimer,
            rss_request_context::Deadline::from_timeout(
                &crate::lifecycle::RuntimeTimer,
                std::time::Duration::from_secs(60),
            )
            .unwrap(),
        );
        assert_eq!(result.is_ok(), malicious.is_none(), "{malicious:?}");
    }
}
#[tokio::test]
async fn garbage_never_removes_a_pinned_stream_or_live_upload() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path().to_owned());
    let store = Store::open(
        &config,
        "10000000-0000-0000-0000-000000000001",
        Arc::new(crate::lifecycle::RuntimeTimer),
    )
    .unwrap();
    let binding = binding(b"abc");
    let id = Uuid::new_v4();
    store.begin(id, binding.clone(), 1).await.unwrap();
    store.append(id, 0, 1, &b"abc"[..]).await.unwrap();
    store.finish(id, 1).await.unwrap();
    let artifact = binding.artifact().unwrap();
    let verified = store.verify(&artifact).await.unwrap();
    assert!(store.garbage(i64::MAX / 2).await.unwrap().is_empty());
    drop(verified);
    let garbage = store.garbage(i64::MAX / 2).await.unwrap();
    assert_eq!(garbage.len(), 1);
    assert!(matches!(
        store.verify(&artifact).await,
        Err(Error::Conflict)
    ));
    garbage.into_iter().next().unwrap().remove().await.unwrap();
    assert!(!store.path(&artifact).exists());
}

#[tokio::test]
async fn concurrent_equal_uploads_share_one_blob_and_release_temporary_space() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(
        &config(directory.path().to_owned()),
        "10000000-0000-0000-0000-000000000001",
        Arc::new(crate::lifecycle::RuntimeTimer),
    )
    .unwrap();
    let bytes = vec![4; 1024 * 1024];
    let binding = binding(&bytes);
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    for id in [first, second] {
        store.begin(id, binding.clone(), 1).await.unwrap();
    }
    let (a, b) = tokio::join!(
        store.append(first, 0, 1, bytes.as_slice()),
        store.append(second, 0, 1, bytes.as_slice())
    );
    a.unwrap();
    b.unwrap();
    let (a, b) = tokio::join!(store.finish(first, 1), store.finish(second, 1));
    for (id, result) in [(first, a), (second, b)] {
        match result {
            Ok(_) => (),
            Err(Error::Conflict) => {
                store.finish(id, 1).await.unwrap();
            }
            Err(e) => panic!("unexpected upload error: {e:?}"),
        }
    }
    assert!(store.path(&binding.artifact().unwrap()).is_file());
    assert_eq!(
        std::fs::read_dir(&store.directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
            .count(),
        0
    );
}
