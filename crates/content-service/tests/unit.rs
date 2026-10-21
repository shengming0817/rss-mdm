use super::*;
fn protection() -> Arc<rss_mdm_native_protection::Protector> {
    Arc::new(rss_mdm_native_protection::Protector::new(&[39; 32]).unwrap())
}
fn config(directory: PathBuf) -> Config {
    Config {
        storage: Storage::Volume { directory },
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
    let declaration = serde_json::json!({"material":{"format":"msix","installer":"installer"},"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"Acme.App","version":"1.0.0.0","provenance":{"kind":"private"},"artifacts":{"installer":{"reference":"installer","length":3,"sha256":vec![1;32]}},"behavior":{"kind":"msix","container":{"kind":"package","installer":"installer"},"identity":{"name":"Acme.App","publisher":"CN=Acme","version":[1,0,0,0],"architecture":"x86_64","resourceId":""},"dependencies":[],"deployment":{"kind":"device_provisioning"},"minimumOs":[10,0,19041,0],"requireSideload":true,"allowUnsigned":false,"uninstall":true,"invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place"},"signatures":[],"reboot":"report","downgrade":"deny","dependencies":[],"export":{"kind":"disabled"}});
    let definition: SoftwareDefinition = serde_json::from_value(declaration).unwrap();
    let Some(SoftwareBehavior::Msix(msix)) = &definition.spec().behavior else {
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
        purpose: crate::Purpose::Resource(crate::ResourceBinding {
            storage_class: StorageClass::Artifact,
            resource: "app".into(),
            version: "1".into(),
            variant: "default".into(),
            platform: rss_mdm_resource::Platform::Windows,
            architecture: rss_mdm_resource::Architecture::X86_64,
            resource_digest: [1; 32],
            source: None,
            origin: None,
        }),
        reference: "package".into(),
        length: bytes.len() as u64,
        sha256: rss_mdm_resource::Digest::of(bytes).bytes(),
        actor: "user".into(),
    }
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
        let definition:SoftwareDefinition=serde_json::from_value(serde_json::json!({"material":{"format":"bundle","installer":"zip"},"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"App","version":"1","artifacts":{"zip":{"reference":"zip","length":std::fs::metadata(&path).unwrap().len(),"sha256":vec![2;32]}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"bundle","archive":"zip","manifest":manifest,"install":{"interpreter":"power_shell7","entry":"install.ps1","invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}})).unwrap();
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
        let definition: SoftwareDefinition=serde_json::from_value(serde_json::json!({"material":{"format":"bundle","installer":"zip"},"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"App","version":"1","artifacts":{"zip":{"reference":"zip","length":bytes.len(),"sha256":vec![2;32]}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"bundle","archive":"zip","manifest":manifest,"install":{"interpreter":"power_shell7","entry":"install.ps1","invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}})).unwrap();
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

struct RuntimeTimer;
impl Clock for RuntimeTimer {
    #[allow(clippy::disallowed_methods, reason = "test clock provider")]
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}
fn test_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let tenant =
        rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let store = Store {
        cleanup_tasks: tokio_util::task::TaskTracker::new(),
        protection: protection(),
        tenant,
        config: config(dir.path().to_owned()),
        transfers: Arc::new(Semaphore::new(4)),
        timer: Arc::new(RuntimeTimer),
        backend: backend::Backend::Volume {
            directory: dir.path().to_owned(),
            scope: [8; 32],
            timer: Arc::new(RuntimeTimer),
        },
        pool: sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/test")
            .unwrap(),
    };
    (dir, store)
}
#[tokio::test]
async fn native_ciphertext_binds_class_tenant_digest_and_record_frontier() {
    let (_dir, mut store) = test_store();
    let bytes = vec![0x39; 65539];
    let a = binding(&bytes).artifact().unwrap();
    let c = StorageClass::NativeConfiguration;
    let sealed = store.seal(&bytes, &a, c).unwrap();
    assert!(!sealed.windows(100).any(|b| b == &bytes[..100]));
    assert_eq!(
        &*store.plaintext(&sealed, &a, c, bytes.len() as u64).unwrap(),
        &bytes
    );
    assert!(
        store
            .plaintext(&sealed, &a, StorageClass::Artifact, bytes.len() as u64)
            .is_err()
    );
    assert!(
        store
            .plaintext(&sealed, &a, c, bytes.len() as u64 - 1)
            .is_err()
    );
    let mut damaged = sealed.clone();
    damaged[4] ^= 1;
    assert!(
        store
            .plaintext(&damaged, &a, c, bytes.len() as u64)
            .is_err()
    );
    store.tenant =
        rss_request_context::TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap();
    assert!(store.plaintext(&sealed, &a, c, bytes.len() as u64).is_err());
}
#[tokio::test]
async fn volume_exact_coordinate_rejects_replacement_and_other_scope() {
    let (_dir, store) = test_store();
    let d = store.deadline().unwrap();
    let content = rss_mdm_content_s3::Content {
        length: 3,
        sha256: Sha256::digest(b"abc").into(),
    };
    let intent = store.backend.intent(uuid::Uuid::new_v4(), content).unwrap();
    let coordinate = store
        .backend
        .write(&intent, content, b"abc".to_vec(), d)
        .await
        .unwrap();
    assert_eq!(
        store
            .backend
            .read(&coordinate, content, 1, 3, d)
            .await
            .unwrap(),
        b"bc"
    );
    let backend::Coordinate::Volume { id, .. } = &coordinate else {
        panic!()
    };
    fs::write(
        store
            .config
            .storage
            .volume_directory()
            .unwrap()
            .join(id.to_string()),
        b"bad",
    )
    .unwrap();
    assert!(
        store
            .backend
            .read(&coordinate, content, 0, 3, d)
            .await
            .is_err()
    );
    let other = backend::Coordinate::Volume {
        id: *id,
        scope: [0; 32],
    };
    assert!(store.backend.delete(&other, d).await.is_err());
}
#[test]
fn piece_and_native_limits_are_arithmetic_boundaries() {
    assert_eq!(1_099_511_627_776u64.div_ceil(journal::CHUNK), 8192);
    let mut b = binding(b"abc");
    b.purpose = match b.purpose {
        Purpose::Software { .. } => panic!("resource fixture"),
        Purpose::Resource(mut r) => {
            r.storage_class = StorageClass::NativeConfiguration;
            Purpose::Resource(r)
        }
    };
    b.length = protected::NATIVE_LIMIT;
    assert!(protected::reservation(&b).unwrap() > b.length);
    b.length += 1;
    assert!(protected::reservation(&b).is_err());
}

#[tokio::test]
async fn volume_reclaims_interrupted_intents_and_fences_late_publication() {
    let (dir, store) = test_store();
    let deadline = store.deadline().unwrap();
    let content = rss_mdm_content_s3::Content {
        length: 3,
        sha256: Sha256::digest(b"abc").into(),
    };
    for interrupted in [false, true] {
        let id = uuid::Uuid::new_v4();
        let intent = store.backend.intent(id, content).unwrap();
        let temporary = dir.path().join(format!(".{id}.tmp"));
        if interrupted {
            fs::write(&temporary, b"a").unwrap();
        }
        let coordinate = store
            .backend
            .recover(&intent, content, deadline)
            .await
            .unwrap()
            .unwrap();
        assert!(store.backend.delete(&coordinate, deadline).await.unwrap());
        assert!(!temporary.exists());
        assert!(matches!(
            store
                .backend
                .write(&intent, content, b"abc".to_vec(), deadline)
                .await,
            Err(backend::WriteFailure::Unresolved(Error::Conflict))
        ));
        assert!(!dir.path().join(id.to_string()).exists());
        assert!(store.backend.delete(&coordinate, deadline).await.unwrap());
    }
}

#[tokio::test]
async fn volume_range_validates_consumed_bytes_during_replacement_and_in_place_write() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct MutationClock {
        path: PathBuf,
        replace: bool,
        armed: AtomicBool,
    }
    impl Clock for MutationClock {
        fn now(&self) -> std::time::Instant {
            if self.armed.swap(false, Ordering::SeqCst) {
                if self.replace {
                    let replacement = self.path.with_extension("replacement");
                    fs::write(&replacement, b"bad").unwrap();
                    fs::rename(replacement, &self.path).unwrap();
                } else {
                    fs::write(&self.path, b"bad").unwrap();
                }
            }
            RuntimeTimer.now()
        }
    }
    for replace in [true, false] {
        let (dir, store) = test_store();
        let deadline = store.deadline().unwrap();
        let id = uuid::Uuid::new_v4();
        let content = rss_mdm_content_s3::Content {
            length: 3,
            sha256: Sha256::digest(b"abc").into(),
        };
        let intent = store.backend.intent(id, content).unwrap();
        let coordinate = store
            .backend
            .write(&intent, content, b"abc".to_vec(), deadline)
            .await
            .unwrap();
        let timer = Arc::new(MutationClock {
            path: dir.path().join(id.to_string()),
            replace,
            armed: AtomicBool::new(true),
        });
        let backend = backend::Backend::Volume {
            directory: dir.path().to_owned(),
            scope: [8; 32],
            timer,
        };
        // Clock cutoff is checked after opening the exact file, before consuming it.
        let result = backend.read(&coordinate, content, 1, 3, deadline).await;
        if replace {
            assert_eq!(result.unwrap(), b"bc");
        } else {
            assert!(matches!(result, Err(Error::Invariant)));
        }
    }
}

#[test]
fn msix_bundle_rejects_undeclared_application_and_resource_members() {
    use rss_mdm_resource as r;
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
    let definition:r::SoftwareDefinition=serde_json::from_value(serde_json::json!({"material":{"format":"msix","installer":"installer"},"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"Acme.App","version":"1.0.0.0","provenance":{"kind":"private"},"artifacts":{"installer":{"reference":"installer","length":bytes.len(),"sha256":r::Digest::of(&bytes).bytes()}},"behavior":{"kind":"msix","container":{"kind":"bundle","installer":"installer","members":[{"path":"Acme.msix","identity":identity,"length":package.len(),"sha256":r::Digest::of(&package).bytes()}]},"identity":identity,"dependencies":[],"deployment":{"kind":"device_provisioning"},"minimumOs":[10,0,19041,0],"requireSideload":true,"allowUnsigned":false,"uninstall":true,"invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place"},"signatures":[],"reboot":"report","downgrade":"deny","dependencies":[],"export":{"kind":"disabled"}})).unwrap();
    let Some(r::SoftwareBehavior::Msix(expected)) = &definition.spec().behavior else {
        panic!("msix");
    };
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&bytes).unwrap();
    file.rewind().unwrap();
    let deadline =
        Deadline::from_timeout(&RuntimeTimer, std::time::Duration::from_secs(60)).unwrap();
    super::native::msix(
        &mut file,
        expected,
        &config(PathBuf::new()),
        &RuntimeTimer,
        deadline,
    )
    .unwrap();
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
}

#[path = "fixtures/installers.rs"]
mod installer_fixtures;
#[test]
fn unsigned_native_installers_are_observed_without_signature_evidence() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path().to_owned());
    let samples = [
        ("agent.exe", installer_fixtures::exe("1"), None),
        (
            "agent.msi",
            installer_fixtures::msi(Some("1.2.3"), true),
            Some("1.2.3"),
        ),
        (
            "agent.msix",
            installer_fixtures::msix("1.2.3.0", false),
            Some("1.2.3.0"),
        ),
        ("agent.pkg", installer_fixtures::pkg("1.2.3"), Some("1.2.3")),
    ];
    for (name, bytes, version) in samples {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        let deadline = rss_request_context::Deadline::from_timeout(
            &RuntimeTimer,
            std::time::Duration::from_secs(60),
        )
        .unwrap();
        let facts =
            super::installer::inspect(&mut file, name, &config, &RuntimeTimer, deadline).unwrap();
        assert_eq!(facts.version.as_deref(), version);
        file.set_len(2).unwrap();
        assert!(
            super::installer::inspect(&mut file, name, &config, &RuntimeTimer, deadline).is_err()
        );
    }
}
