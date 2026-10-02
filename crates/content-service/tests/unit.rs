use super::*;
use uuid::Uuid;
fn protection() -> Arc<rss_mdm_native_protection::Protector> {
    Arc::new(rss_mdm_native_protection::Protector::new(&[39; 32]).unwrap())
}
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

#[test]
fn msix_content_identity_must_match_the_approved_definition() {
    use rss_mdm_resource::{SoftwareBehavior, SoftwareDefinition};
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    let cfg = config(directory.path().to_owned());
    let declaration = serde_json::json!({"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"Acme.App","version":"1.0.0.0","provenance":{"kind":"private"},"artifacts":{"installer":{"reference":"installer","length":3,"sha256":vec![1;32]}},"behavior":{"kind":"msix","container":{"kind":"package","installer":"installer"},"identity":{"name":"Acme.App","publisher":"CN=Acme","version":[1,0,0,0],"architecture":"x86_64","resourceId":""},"dependencies":[],"deployment":{"kind":"device_provisioning"},"minimumOs":[10,0,19041,0],"requireSideload":true,"allowUnsigned":false,"uninstall":true,"invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place"},"signatures":[],"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"export":{"kind":"disabled"}});
    let definition: SoftwareDefinition = serde_json::from_value(declaration).unwrap();
    let SoftwareBehavior::Msix(msix) = &definition.spec().behavior else {
        panic!("msix fixture");
    };
    for publisher in ["CN=Acme", "CN=Other"] {
        let path = directory.path().join("app.msix");
        let mut writer = zip::ZipWriter::new(File::create(&path).unwrap());
        writer
            .start_file("AppxManifest.xml", zip::write::SimpleFileOptions::default())
            .unwrap();
        write!(writer,"<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\"><Identity Name=\"Acme.App\" Publisher=\"{publisher}\" Version=\"1.0.0.0\" ProcessorArchitecture=\"x64\"/><Dependencies><TargetDeviceFamily Name=\"Windows.Desktop\" MinVersion=\"10.0.19041.0\" MaxVersionTested=\"10.0.19041.0\"/></Dependencies></Package>").unwrap();
        writer.finish().unwrap();
        let deadline = rss_request_context::Deadline::from_timeout(
            &RuntimeTimer,
            std::time::Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(
            super::native::msix(
                &mut File::open(path).unwrap(),
                msix,
                &cfg,
                &RuntimeTimer,
                deadline
            )
            .is_ok(),
            publisher == "CN=Acme"
        );
    }
}
fn binding(bytes: &[u8]) -> Binding {
    Binding {
        storage_class: StorageClass::Artifact,
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
    let store = Store::open(protection(), &config, tenant, Arc::new(RuntimeTimer)).unwrap();
    let bytes = vec![9u8; 16_777_217];
    let binding = binding(&bytes);
    let artifact = binding.artifact().unwrap();
    let id = Uuid::new_v4();
    store.begin(id, binding.clone(), 100).await.unwrap();
    store
        .append("user", id, 0, 100, &bytes[..1_000_000])
        .await
        .unwrap();
    assert!(!store.path(&artifact).exists());
    drop(store);
    let store = Store::open(protection(), &config, tenant, Arc::new(RuntimeTimer)).unwrap();
    assert_eq!(
        store.status("user", id, 101).await.unwrap().offset,
        1_000_000
    );
    assert!(matches!(
        store.append("user", id, 0, 101, &bytes[..1]).await,
        Err(Error::Conflict)
    ));
    store
        .append("user", id, 1_000_000, 101, &bytes[1_000_000..])
        .await
        .unwrap();
    store.finish("user", id, 101).await.unwrap();
    store.finish("user", id, 101).await.unwrap();
    let verified = store.verify(&artifact).await.unwrap();
    assert!(verified.matches(&artifact));
    drop(verified);
    assert!(
        Store::open(
            protection(),
            &config,
            "20000000-0000-0000-0000-000000000001",
            Arc::new(RuntimeTimer)
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
        protection(),
        &config(dir.path().to_owned()),
        "10000000-0000-0000-0000-000000000001",
        Arc::new(RuntimeTimer),
    )
    .unwrap();
    let expected = binding(b"abc");
    let id = Uuid::new_v4();
    store.begin(id, expected.clone(), 1).await.unwrap();
    assert!(store.append("user", id, 0, 1, &b"abcd"[..]).await.is_err());
    assert_eq!(store.status("user", id, 1).await.unwrap().offset, 0);
    store.append("user", id, 0, 1, &b"xyz"[..]).await.unwrap();
    assert!(store.finish("user", id, 1).await.is_err());
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
        let definition:SoftwareDefinition=serde_json::from_value(serde_json::json!({"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"App","version":"1","artifacts":{"zip":{"reference":"zip","length":std::fs::metadata(&path).unwrap().len(),"sha256":vec![2;32]}},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"behavior":{"kind":"bundle","archive":"zip","manifest":manifest,"install":{"interpreter":"power_shell7","entry":"install.ps1","invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}})).unwrap();
        let result = super::bundle::validate(
            &mut File::open(path).unwrap(),
            &definition,
            &config(dir.path().to_owned()),
            &RuntimeTimer,
            rss_request_context::Deadline::from_timeout(
                &RuntimeTimer,
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
        protection(),
        &config,
        "10000000-0000-0000-0000-000000000001",
        Arc::new(RuntimeTimer),
    )
    .unwrap();
    let binding = binding(b"abc");
    let id = Uuid::new_v4();
    store.begin(id, binding.clone(), 1).await.unwrap();
    store.append("user", id, 0, 1, &b"abc"[..]).await.unwrap();
    store.finish("user", id, 1).await.unwrap();
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
        protection(),
        &config(directory.path().to_owned()),
        "10000000-0000-0000-0000-000000000001",
        Arc::new(RuntimeTimer),
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
        store.append("user", first, 0, 1, bytes.as_slice()),
        store.append("user", second, 0, 1, bytes.as_slice())
    );
    a.unwrap();
    b.unwrap();
    let (a, b) = tokio::join!(
        store.finish("user", first, 1),
        store.finish("user", second, 1)
    );
    for (id, result) in [(first, a), (second, b)] {
        match result {
            Ok(_) => (),
            Err(Error::Conflict) => {
                store.finish("user", id, 1).await.unwrap();
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
    let store = Store::open(protection(), &config, tenant, Arc::new(RuntimeTimer)).unwrap();
    let guard = lock(&store.directory.join(".upload.lock")).unwrap();
    assert!(Store::open(protection(), &config, tenant, Arc::new(RuntimeTimer)).is_err());
    drop(guard);
    fs::write(
        store.upload_path(Uuid::new_v4(), "json"),
        b"broken metadata",
    )
    .unwrap();
    let error = Store::open(protection(), &config, tenant, Arc::new(RuntimeTimer))
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
    let store = Store::open(protection(), &config, tenant, Arc::new(RuntimeTimer)).unwrap();
    let completed = Uuid::new_v4();
    store.begin(completed, binding(b"abc"), 100).await.unwrap();
    store
        .append("user", completed, 0, 100, &b"abc"[..])
        .await
        .unwrap();
    store.finish("user", completed, 100).await.unwrap();
    // Simulate a crash after durable completion metadata but before removing the tail.
    fs::hard_link(
        store.path(&binding(b"abc").artifact().unwrap()),
        store.upload_path(upload::storage_key("user", completed), "part"),
    )
    .unwrap();
    let partial = Uuid::new_v4();
    store.begin(partial, binding(b"abcdef"), 100).await.unwrap();
    store
        .append("user", partial, 0, 100, &b"abc"[..])
        .await
        .unwrap();
    // begin already performs recovery; leave the completed tail for startup specifically.
    fs::hard_link(
        store.path(&binding(b"abc").artifact().unwrap()),
        store.upload_path(upload::storage_key("user", completed), "part"),
    )
    .unwrap();
    drop(store);
    let reopened = Store::open(protection(), &config, tenant, Arc::new(RuntimeTimer)).unwrap();
    assert!(
        !reopened
            .upload_path(upload::storage_key("user", completed), "part")
            .exists()
    );
    assert_eq!(
        reopened.status("user", partial, 101).await.unwrap().offset,
        3
    );
    reopened
        .append("user", partial, 3, 101, &b"def"[..])
        .await
        .unwrap();
    reopened.finish("user", partial, 101).await.unwrap();
}

#[test]
fn content_lock_files_remain_bounded_across_unique_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(
        protection(),
        &config(directory.path().to_owned()),
        "10000000-0000-0000-0000-000000000001",
        Arc::new(RuntimeTimer),
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
        let definition: SoftwareDefinition=serde_json::from_value(serde_json::json!({"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"App","version":"1","artifacts":{"zip":{"reference":"zip","length":bytes.len(),"sha256":vec![2;32]}},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"behavior":{"kind":"bundle","archive":"zip","manifest":manifest,"install":{"interpreter":"power_shell7","entry":"install.ps1","invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}})).unwrap();
        super::bundle::validate(
            &mut File::open(path).unwrap(),
            &definition,
            cfg,
            &RuntimeTimer,
            rss_request_context::Deadline::from_timeout(
                &RuntimeTimer,
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
        protection(),
        &config(directory.path().to_owned()),
        "10000000-0000-0000-0000-000000000001",
        Arc::new(RuntimeTimer),
    )
    .unwrap();
    for _ in 0..4 {
        let id = Uuid::new_v4();
        store.begin(id, binding(b"abc"), 100).await.unwrap();
        store.append("user", id, 0, 100, &b"a"[..]).await.unwrap();
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

struct RuntimeTimer;
impl rss_request_context::Clock for RuntimeTimer {
    #[allow(clippy::disallowed_methods, reason = "test clock uses Tokio time")]
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}

#[tokio::test]
async fn upload_operation_is_scoped_to_actor() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(
        protection(),
        &config(dir.path().to_owned()),
        "10000000-0000-0000-0000-000000000001",
        Arc::new(RuntimeTimer),
    )
    .unwrap();
    let id = Uuid::new_v4();
    let a = binding(b"abc");
    let mut b = a.clone();
    b.actor = "another-user".into();
    store.begin(id, a.clone(), 100).await.unwrap();
    store.begin(id, b.clone(), 100).await.unwrap();
    store.append("user", id, 0, 100, &b"a"[..]).await.unwrap();
    assert_eq!(
        store.status("another-user", id, 100).await.unwrap().offset,
        0
    );
    assert_eq!(store.status("user", id, 100).await.unwrap().offset, 1);
    let mut changed = a.clone();
    changed.reference = "different".into();
    assert!(matches!(
        store.begin(id, changed, 100).await,
        Err(Error::Conflict)
    ));
}

#[tokio::test]
async fn msix_nested_material_shares_the_pending_upload_disk_budget() {
    use rss_mdm_resource as r;
    use rss_mdm_software_service::catalog::ContentPort;
    use std::io::{Cursor, Write};
    fn archive(files: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (path, bytes) in files {
            zip.start_file(
                path,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
            zip.write_all(&bytes).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }
    let package=archive(vec![("AppxManifest.xml",br#"<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Acme.App" Publisher="CN=Acme" Version="1.0.0.0" ProcessorArchitecture="x64"/><Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0"/></Dependencies></Package>"#.to_vec())]);
    let bundle_xml = format!(
        r#"<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Identity Name="Acme.App" Publisher="CN=Acme" Version="1.0.0.0"/><Packages><Package FileName="Acme.msix" Type="application" Architecture="x64" Version="1.0.0.0" Size="{}"/></Packages></Bundle>"#,
        package.len()
    );
    let bytes = archive(vec![
        (
            "AppxMetadata/AppxBundleManifest.xml",
            bundle_xml.into_bytes(),
        ),
        ("Acme.msix", package.clone()),
    ]);
    let identity = serde_json::json!({"name":"Acme.App","publisher":"CN=Acme","version":[1,0,0,0],"architecture":"x86_64","resourceId":""});
    let definition:r::SoftwareDefinition=serde_json::from_value(serde_json::json!({"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"Acme.App","version":"1.0.0.0","provenance":{"kind":"private"},"artifacts":{"installer":{"reference":"installer","length":bytes.len(),"sha256":r::Digest::of(&bytes).bytes()}},"behavior":{"kind":"msix","container":{"kind":"bundle","installer":"installer","members":[{"path":"Acme.msix","identity":identity,"length":package.len(),"sha256":r::Digest::of(&package).bytes()}]},"identity":identity,"dependencies":[],"deployment":{"kind":"device_provisioning"},"minimumOs":[10,0,19041,0],"requireSideload":true,"allowUnsigned":false,"uninstall":true,"invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place"},"signatures":[],"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"export":{"kind":"disabled"}})).unwrap();
    let r::SoftwareBehavior::Msix(expected) = &definition.spec().behavior else {
        panic!("msix");
    };
    for kind in ["application", "resource"] {
        let xml = format!(
            r#"<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Identity Name="Acme.App" Publisher="CN=Acme" Version="1.0.0.0"/><Packages><Package FileName="Acme.msix" Type="application" Architecture="x64" Version="1.0.0.0" Size="{}"/><Package FileName="Extra.msix" Type="{kind}" Architecture="x64" Version="1.0.0.0" Size="{}"/></Packages></Bundle>"#,
            package.len(),
            package.len()
        );
        let extra = archive(vec![
            ("AppxMetadata/AppxBundleManifest.xml", xml.into_bytes()),
            ("Acme.msix", package.clone()),
            ("Extra.msix", package.clone()),
        ]);
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&extra).unwrap();
        file.rewind().unwrap();
        let deadline =
            Deadline::from_timeout(&RuntimeTimer, std::time::Duration::from_secs(60)).unwrap();
        assert!(
            super::native::msix(
                &mut file,
                expected,
                &config(PathBuf::new()),
                &RuntimeTimer,
                deadline
            )
            .is_err(),
            "accepted undeclared {kind}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path().to_owned());
    cfg.max_artifact_bytes = 1024 * 1024;
    cfg.max_temporary_bytes = 1024 * 1024;
    let tenant =
        rss_request_context::TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap();
    let store = Store::open(
        protection(),
        &cfg,
        &tenant.to_string(),
        Arc::new(RuntimeTimer),
    )
    .unwrap();
    let id = Uuid::new_v4();
    store.begin(id, binding(&bytes), 100).await.unwrap();
    store
        .append("user", id, 0, 100, Cursor::new(bytes))
        .await
        .unwrap();
    store.finish("user", id, 100).await.unwrap();
    let version = r::Version::new(
        tenant,
        r::Id::new("app").unwrap(),
        r::Id::new("1").unwrap(),
        r::Kind::Software,
        vec![r::Variant::new(
            r::Platform::Windows,
            r::Architecture::X86_64,
            r::Id::new("default").unwrap(),
            r::Declaration::Software { definition },
        )],
    )
    .unwrap();
    assert!(ContentPort::verify(store.as_ref(), &version).await.is_ok());
    let pending = vec![8; 1024 * 1024 - 1];
    let id = Uuid::new_v4();
    store.begin(id, binding(&pending), 100).await.unwrap();
    assert!(
        ContentPort::verify(store.as_ref(), &version).await.is_err(),
        "nested spool escaped the shared disk reservation"
    );
}

#[test]
fn xml_reads_bound_actual_output_even_when_zip_length_is_forged() {
    use std::io::{Cursor, Write};
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "AppxManifest.xml",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
    writer.write_all(&vec![b' '; 2 * 1_048_576]).unwrap();
    let mut bytes = writer.finish().unwrap().into_inner();
    let central = bytes.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    bytes[central + 24..central + 28].copy_from_slice(&1u32.to_le_bytes());
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&bytes).unwrap();
    file.rewind().unwrap();
    let mut archive = zip::ZipArchive::new(&mut file).unwrap();
    let deadline =
        Deadline::from_timeout(&RuntimeTimer, std::time::Duration::from_secs(60)).unwrap();
    let mut entry = archive.by_name("AppxManifest.xml").unwrap();
    let length = entry.size();
    assert!(matches!(
        super::native::read_xml_bytes(&mut entry, length, &RuntimeTimer, deadline, &mut Vec::new()),
        Err(Error::Malformed)
    ));
    // The bounded reader is independently checked so post-read XML rejection cannot mask over-allocation.
    let mut reader = Cursor::new(vec![b' '; 2 * 1_048_576]);
    assert!(
        super::native::read_xml_bytes(&mut reader, 1, &RuntimeTimer, deadline, &mut Vec::new())
            .is_err()
    );
    assert!(reader.position() <= 8192);
}

#[tokio::test]
async fn native_configuration_keeps_acknowledged_tail_encrypted_and_ranges_plaintext() {
    use futures::TryStreamExt;
    let root = tempfile::tempdir().unwrap();
    let cfg = config(root.path().to_owned());
    let tenant = "10000000-0000-0000-0000-000000000001";
    let key = protection();
    let store = Store::open(key.clone(), &cfg, tenant, Arc::new(RuntimeTimer)).unwrap();
    let bytes = b"native-secret-canary-0123456789".repeat(6000);
    let mut input = binding(&bytes);
    input.storage_class = StorageClass::NativeConfiguration;
    let artifact = input.artifact().unwrap();
    let id = Uuid::new_v4();
    store.begin(id, input.clone(), 100).await.unwrap();
    let mut offset = 0;
    for count in [1, 63 * 1024, 2049, 65536] {
        let end = (offset + count).min(bytes.len());
        store
            .append("user", id, offset as u64, 100, &bytes[offset..end])
            .await
            .unwrap();
        offset = end;
    }
    let stage = store.upload_path(upload::storage_key("user", id), "part");
    // Unacknowledged ciphertext bytes cannot displace the sealed tail in the checkpoint.
    use std::io::Write;
    options()
        .append(true)
        .open(&stage)
        .unwrap()
        .write_all(b"unacknowledged-tail")
        .unwrap();
    drop(store);
    let store = Store::open(key.clone(), &cfg, tenant, Arc::new(RuntimeTimer)).unwrap();
    assert_eq!(
        store.status("user", id, 101).await.unwrap().offset,
        offset as u64
    );
    store
        .append("user", id, offset as u64, 101, &bytes[offset..])
        .await
        .unwrap();
    for entry in fs::read_dir(&store.directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let data = fs::read(path).unwrap();
            assert!(
                !data
                    .windows(b"native-secret-canary".len())
                    .any(|v| v == b"native-secret-canary")
            );
        }
    }
    store.finish("user", id, 102).await.unwrap();
    store.finish("user", id, 102).await.unwrap();
    let checkpoint_path = store.upload_path(upload::storage_key("user", id), "json");
    let checkpoint: serde_json::Value =
        serde_json::from_slice(&fs::read(&checkpoint_path).unwrap()).unwrap();
    assert!(
        checkpoint["native"]["tail"].is_null(),
        "completed upload retained its large sealed tail"
    );
    assert!(
        store
            .native_temporary_space(cfg.max_temporary_bytes)
            .is_err(),
        "completed native checkpoints bypassed the disk budget"
    );
    assert!(
        store.verify(&artifact).await.is_err(),
        "protected content fell back to the plain class"
    );
    let verified = store
        .verify_class(&artifact, StorageClass::NativeConfiguration)
        .await
        .unwrap();
    assert_eq!(&*verified.read_plaintext(bytes.len()).unwrap(), &bytes);
    let mut stream = verified.stream(65_530, 131_080).await.unwrap();
    let mut range = Vec::new();
    while let Some(chunk) = stream.try_next().await.unwrap() {
        range.extend_from_slice(&chunk);
    }
    assert_eq!(range, bytes[65_530..131_080]);
    drop(stream);
    let public = Uuid::new_v4();
    store.begin(public, binding(&bytes), 103).await.unwrap();
    store
        .append("user", public, 0, 103, bytes.as_slice())
        .await
        .unwrap();
    store.finish("user", public, 103).await.unwrap();
    assert!(store.verify(&artifact).await.is_ok());
    let native_path = store.path_class(&artifact, StorageClass::NativeConfiguration);
    fs::remove_file(&native_path).unwrap();
    assert!(
        store
            .verify_class(&artifact, StorageClass::NativeConfiguration)
            .await
            .is_err(),
        "same-SHA public bytes satisfied a protected read"
    );
}

#[tokio::test]
async fn native_finish_recovers_a_published_hard_link_without_truncating_it() {
    let root = tempfile::tempdir().unwrap();
    let cfg = config(root.path().to_owned());
    let tenant = "10000000-0000-0000-0000-000000000001";
    let store = Store::open(protection(), &cfg, tenant, Arc::new(RuntimeTimer)).unwrap();
    let bytes = b"durable-native-content".repeat(5000);
    let mut input = binding(&bytes);
    input.storage_class = StorageClass::NativeConfiguration;
    let artifact = input.artifact().unwrap();
    let id = Uuid::new_v4();
    store.begin(id, input, 100).await.unwrap();
    store
        .append("user", id, 0, 100, bytes.as_slice())
        .await
        .unwrap();
    let key = upload::storage_key("user", id);
    let checkpoint = fs::read(store.upload_path(key, "json")).unwrap();
    store.finish("user", id, 101).await.unwrap();
    let blob = store.path_class(&artifact, StorageClass::NativeConfiguration);
    let persisted = fs::read(&blob).unwrap();
    // Reconstruct the actual crash point: linked and synced blob, old pre-finish checkpoint.
    fs::hard_link(&blob, store.upload_path(key, "part")).unwrap();
    fs::write(store.upload_path(key, "json"), checkpoint).unwrap();
    assert!(
        store
            .append("user", id, bytes.len() as u64, 102, &b"x"[..])
            .await
            .is_err()
    );
    assert_eq!(fs::read(&blob).unwrap(), persisted);
    drop(store);
    let store = Store::open(protection(), &cfg, tenant, Arc::new(RuntimeTimer)).unwrap();
    store.finish("user", id, 102).await.unwrap();
    assert_eq!(fs::read(&blob).unwrap(), persisted);
    let verified = store
        .verify_class(&artifact, StorageClass::NativeConfiguration)
        .await
        .unwrap();
    assert_eq!(&*verified.read_plaintext(bytes.len()).unwrap(), &bytes);
}

#[tokio::test]
async fn native_metadata_and_records_reject_tamper_and_budget_includes_encryption() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let mut cfg = config(root.path().to_owned());
    let tenant = "10000000-0000-0000-0000-000000000001";
    let bytes = vec![17; 70000];
    let mut input = binding(&bytes);
    input.storage_class = StorageClass::NativeConfiguration;
    let reserved = protected::reservation(&input).unwrap();
    cfg.max_artifact_bytes = bytes.len() as u64;
    cfg.max_temporary_bytes = reserved - 1;
    let store = Store::open(protection(), &cfg, tenant, Arc::new(RuntimeTimer)).unwrap();
    assert!(matches!(
        store.begin(Uuid::new_v4(), input.clone(), 100).await,
        Err(Error::Conflict)
    ));
    drop(store);
    cfg.max_temporary_bytes = reserved;
    let store = Store::open(protection(), &cfg, tenant, Arc::new(RuntimeTimer)).unwrap();
    let id = Uuid::new_v4();
    store.begin(id, input.clone(), 100).await.unwrap();
    store
        .append("user", id, 0, 100, bytes.as_slice())
        .await
        .unwrap();
    let key = upload::storage_key("user", id);
    let meta = store.upload_path(key, "json");
    let original = fs::read(&meta).unwrap();
    let mut tampered: serde_json::Value = serde_json::from_slice(&original).unwrap();
    tampered["upload"]["offset"] = serde_json::json!(1);
    fs::write(&meta, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(store.status("user", id, 100).await.is_err());
    fs::write(&meta, &original).unwrap();
    let wrong = Arc::new(rss_mdm_native_protection::Protector::new(&[40; 32]).unwrap());
    assert!(Store::open(wrong, &cfg, tenant, Arc::new(RuntimeTimer)).is_err());
    let part = store.upload_path(key, "part");
    let original = fs::read(&part).unwrap();
    let mut corrupt = original.clone();
    corrupt[80] ^= 1;
    options()
        .truncate(true)
        .open(&part)
        .unwrap()
        .write_all(&corrupt)
        .unwrap();
    assert!(store.finish("user", id, 101).await.is_err());
    fs::write(&part, &original).unwrap();
    store.finish("user", id, 101).await.unwrap();
    let artifact = input.artifact().unwrap();
    let path = store.path_class(&artifact, StorageClass::NativeConfiguration);
    let mut corrupt = fs::read(&path).unwrap();
    corrupt.pop();
    fs::write(&path, corrupt).unwrap();
    assert!(
        store
            .verify_class(&artifact, StorageClass::NativeConfiguration)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn native_failed_body_and_uncommitted_checkpoint_keep_the_acknowledged_frontier() {
    let root = tempfile::tempdir().unwrap();
    let cfg = config(root.path().to_owned());
    let tenant = "10000000-0000-0000-0000-000000000001";
    let mut store = Store::open(protection(), &cfg, tenant, Arc::new(RuntimeTimer)).unwrap();
    let bytes = b"checkpoint-native-canary".repeat(8000);
    let mut input = binding(&bytes);
    input.storage_class = StorageClass::NativeConfiguration;
    let artifact = input.artifact().unwrap();
    let id = Uuid::new_v4();
    store.begin(id, input.clone(), 100).await.unwrap();
    store.append("user", id, 0, 100, &bytes[..1]).await.unwrap();
    let interrupted = futures::stream::iter(vec![
        Ok(bytes::Bytes::copy_from_slice(&bytes[1..70000])),
        Err(std::io::Error::other("fixture interrupted body")),
    ]);
    assert!(
        store
            .append(
                "user",
                id,
                1,
                101,
                tokio_util::io::StreamReader::new(interrupted)
            )
            .await
            .is_err()
    );
    assert_eq!(store.status("user", id, 101).await.unwrap().offset, 1);
    let key = upload::storage_key("user", id);
    let old = fs::read(store.upload_path(key, "json")).unwrap();
    store
        .append("user", id, 1, 102, &bytes[1..70000])
        .await
        .unwrap();
    let pending = fs::read(store.upload_path(key, "json")).unwrap();
    fs::write(store.upload_path(key, "next"), pending).unwrap();
    fs::write(store.upload_path(key, "json"), old).unwrap();
    let occupied: u64 = fs::read_dir(&store.directory)
        .unwrap()
        .filter_map(|e| {
            let e = e.unwrap();
            e.file_name()
                .to_string_lossy()
                .starts_with(".upload-")
                .then(|| e.metadata().unwrap().len())
        })
        .sum();
    assert!(occupied <= protected::reservation(&input).unwrap());
    drop(store);
    store = Store::open(protection(), &cfg, tenant, Arc::new(RuntimeTimer)).unwrap();
    assert_eq!(store.status("user", id, 103).await.unwrap().offset, 1);
    store.append("user", id, 1, 103, &bytes[1..]).await.unwrap();
    store.finish("user", id, 104).await.unwrap();
    let verified = store
        .verify_class(&artifact, StorageClass::NativeConfiguration)
        .await
        .unwrap();
    assert_eq!(&*verified.read_plaintext(bytes.len()).unwrap(), &bytes);
    let other = Store::open(
        protection(),
        &cfg,
        "20000000-0000-0000-0000-000000000001",
        Arc::new(RuntimeTimer),
    )
    .unwrap();
    fs::copy(
        store.path_class(&artifact, StorageClass::NativeConfiguration),
        other.path_class(&artifact, StorageClass::NativeConfiguration),
    )
    .unwrap();
    assert!(
        other
            .verify_class(&artifact, StorageClass::NativeConfiguration)
            .await
            .is_err(),
        "native blob lost tenant binding"
    );
}
