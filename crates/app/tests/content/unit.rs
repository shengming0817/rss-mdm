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
    garbage.into_iter().next().unwrap().remove().unwrap();
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

#[test]
fn startup_rejects_corrupt_upload_metadata_and_busy_recovery_lock() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().to_owned());
    let tenant = "10000000-0000-0000-0000-000000000001";
    let store = Store::open(&config, tenant, Arc::new(crate::lifecycle::RuntimeTimer)).unwrap();
    let guard = lock(&store.directory.join(".upload.lock")).unwrap();
    assert!(Store::open(&config, tenant, Arc::new(crate::lifecycle::RuntimeTimer)).is_err());
    drop(guard);
    fs::write(
        store.upload_path(Uuid::new_v4(), "json"),
        b"broken metadata",
    )
    .unwrap();
    let error = Store::open(&config, tenant, Arc::new(crate::lifecycle::RuntimeTimer))
        .err()
        .expect("corrupt metadata must reject startup");
    let diagnostic = serde_json::to_string(&error).unwrap();
    assert!(diagnostic.contains("content_metadata"));
    assert!(!diagnostic.contains("broken metadata"));
    assert!(!diagnostic.contains(directory.path().to_str().unwrap()));
}

#[tokio::test]
async fn startup_reclaims_completed_tails_and_preserves_resumable_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().to_owned());
    let tenant = "10000000-0000-0000-0000-000000000001";
    let store = Store::open(&config, tenant, Arc::new(crate::lifecycle::RuntimeTimer)).unwrap();
    let completed = Uuid::new_v4();
    store.begin(completed, binding(b"abc"), 100).await.unwrap();
    store.append(completed, 0, 100, &b"abc"[..]).await.unwrap();
    store.finish(completed, 100).await.unwrap();
    // Simulate a crash after durable completion metadata but before removing the tail.
    fs::hard_link(
        store.path(&binding(b"abc").artifact().unwrap()),
        store.upload_path(completed, "part"),
    )
    .unwrap();
    let partial = Uuid::new_v4();
    store.begin(partial, binding(b"abcdef"), 100).await.unwrap();
    store.append(partial, 0, 100, &b"abc"[..]).await.unwrap();
    // begin already performs recovery; leave the completed tail for startup specifically.
    fs::hard_link(
        store.path(&binding(b"abc").artifact().unwrap()),
        store.upload_path(completed, "part"),
    )
    .unwrap();
    drop(store);
    let reopened = Store::open(&config, tenant, Arc::new(crate::lifecycle::RuntimeTimer)).unwrap();
    assert!(!reopened.upload_path(completed, "part").exists());
    assert_eq!(reopened.status(partial, 101).await.unwrap().offset, 3);
    reopened.append(partial, 3, 101, &b"def"[..]).await.unwrap();
    reopened.finish(partial, 101).await.unwrap();
}

#[test]
fn content_lock_files_remain_bounded_across_unique_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(
        &config(directory.path().to_owned()),
        "10000000-0000-0000-0000-000000000001",
        Arc::new(crate::lifecycle::RuntimeTimer),
    )
    .unwrap();
    for sequence in 0u32..1024 {
        let digest = rss_mdm_resource::Digest::of(&sequence.to_le_bytes()).bytes();
        drop(lock(&store.blob_lock(digest)).unwrap());
    }
    let files = fs::read_dir(&store.directory).unwrap().count();
    assert!(
        files <= 257,
        "persistent lock files grew with artifact history: {files}"
    );
}

#[test]
fn bundle_rejects_unsafe_zip_structure_and_small_budget_overruns() {
    use rss_mdm_resource::{BundleEntry, BundleManifest, SoftwareDefinition};
    use std::io::Write;
    let manifest = BundleManifest {
        schema: 1,
        platform: rss_mdm_resource::Platform::Windows,
        architecture: rss_mdm_resource::Architecture::X86_64,
        entries: std::collections::BTreeMap::from([
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
        ]),
    };
    let make = |compression| {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default().compression_method(compression);
        for (name, data) in [
            ("manifest.json", serde_json::to_vec(&manifest).unwrap()),
            ("install.ps1", b"exit".to_vec()),
            ("payload.bin", b"abc".to_vec()),
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(&data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    };
    let stored = make(zip::CompressionMethod::Stored);
    let deflated = make(zip::CompressionMethod::Deflated);
    let directory = tempfile::tempdir().unwrap();
    let cfg = config(directory.path().to_owned());
    let valid = |bytes: &[u8], cfg: &Config| {
        let path = directory.path().join("boundary.zip");
        fs::write(&path, bytes).unwrap();
        let definition: SoftwareDefinition=serde_json::from_value(serde_json::json!({"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"App","version":"1","format":"bundle","primary":"zip","artifacts":{"zip":{"reference":"zip","length":bytes.len(),"sha256":vec![2;32]}},"install":{"executor":"power_shell7","entry":"install.ps1","runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},"uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"bundle":manifest})).unwrap();
        super::bundle::validate(
            &mut File::open(path).unwrap(),
            &definition,
            cfg,
            &crate::lifecycle::RuntimeTimer,
            rss_request_context::Deadline::from_timeout(
                &crate::lifecycle::RuntimeTimer,
                std::time::Duration::from_secs(60),
            )
            .unwrap(),
        )
        .is_ok()
    };
    assert!(valid(&stored, &cfg));
    assert!(valid(&deflated, &cfg));
    let central: Vec<_> = stored
        .windows(4)
        .enumerate()
        .filter_map(|(i, b)| (b == b"PK\x01\x02").then_some(i))
        .collect();
    let local: Vec<_> = stored
        .windows(4)
        .enumerate()
        .filter_map(|(i, b)| (b == b"PK\x03\x04").then_some(i))
        .collect();
    let end = stored.len() - 22;
    let mut record = vec![0u8; 56];
    record[..4].copy_from_slice(b"PK\x06\x06");
    record[4..12].copy_from_slice(&44u64.to_le_bytes());
    record[12..14].copy_from_slice(&45u16.to_le_bytes());
    record[14..16].copy_from_slice(&45u16.to_le_bytes());
    record[24..32].copy_from_slice(&3u64.to_le_bytes());
    record[32..40].copy_from_slice(&3u64.to_le_bytes());
    let size = u32::from_le_bytes(stored[end + 12..end + 16].try_into().unwrap()) as u64;
    let offset = u32::from_le_bytes(stored[end + 16..end + 20].try_into().unwrap()) as u64;
    record[40..48].copy_from_slice(&size.to_le_bytes());
    record[48..56].copy_from_slice(&offset.to_le_bytes());
    let mut locator = vec![0u8; 20];
    locator[..4].copy_from_slice(b"PK\x06\x07");
    locator[8..16].copy_from_slice(&(end as u64).to_le_bytes());
    locator[16..20].copy_from_slice(&1u32.to_le_bytes());
    let mut footer = stored[end..].to_vec();
    footer[8..20].fill(255);
    let mut zip64 = stored[..end].to_vec();
    zip64.extend(record);
    zip64.extend(locator);
    zip64.extend(footer);
    assert!(valid(&zip64, &cfg), "valid small ZIP64 footer");
    let mut cases = Vec::new();
    let mut encrypted = stored.clone();
    encrypted[local[0] + 6] |= 1;
    encrypted[central[0] + 8] |= 1;
    cases.push(("encrypted", encrypted, cfg.clone()));
    let mut method = stored.clone();
    method[local[0] + 8..local[0] + 10].copy_from_slice(&12u16.to_le_bytes());
    method[central[0] + 10..central[0] + 12].copy_from_slice(&12u16.to_le_bytes());
    cases.push(("compression", method, cfg.clone()));
    let mut overlap = stored.clone();
    let first = overlap[central[0] + 42..central[0] + 46].to_vec();
    overlap[central[1] + 42..central[1] + 46].copy_from_slice(&first);
    cases.push(("overlap", overlap, cfg.clone()));
    let mut multi = stored.clone();
    multi[end + 4] = 1;
    cases.push(("multi-disk", multi, cfg.clone()));
    let mut directory_budget = stored.clone();
    directory_budget[end + 12..end + 16].copy_from_slice(&(33 * 1024 * 1024u32).to_le_bytes());
    cases.push(("directory-budget", directory_budget, cfg.clone()));
    let mut invalid64 = zip64;
    invalid64[end + 4..end + 12].copy_from_slice(&43u64.to_le_bytes());
    cases.push(("zip64-record", invalid64, cfg.clone()));
    let mut entries = cfg.clone();
    entries.max_bundle_entries = 1;
    cases.push(("entry-budget", stored.clone(), entries));
    let mut expanded = cfg.clone();
    expanded.max_bundle_bytes = 1;
    cases.push(("expanded-budget", stored, expanded));
    let mut ratio = cfg;
    ratio.max_expansion_ratio = 1;
    cases.push(("ratio", deflated, ratio));
    for (name, bytes, cfg) in cases {
        assert!(!valid(&bytes, &cfg), "accepted {name}");
    }
}

#[tokio::test]
async fn expired_partial_cleanup_tolerates_entries_removed_earlier_in_the_scan() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(
        &config(directory.path().to_owned()),
        "10000000-0000-0000-0000-000000000001",
        Arc::new(crate::lifecycle::RuntimeTimer),
    )
    .unwrap();
    for _ in 0..4 {
        let id = Uuid::new_v4();
        store.begin(id, binding(b"abc"), 100).await.unwrap();
        store.append(id, 0, 100, &b"a"[..]).await.unwrap();
    }
    assert!(store.garbage(i64::MAX / 2).await.unwrap().is_empty());
    assert!(store.garbage(i64::MAX / 2).await.unwrap().is_empty());
    assert!(!fs::read_dir(&store.directory).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".upload-")
    }));
}
