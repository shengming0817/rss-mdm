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

        max_bundle_entries: 4096,
        max_expansion_ratio: 100,
    }
}

fn binding(bytes: &[u8]) -> Binding {
    Binding {
        purpose: crate::Purpose::Resource(crate::ResourceBinding {
            inspection: None,
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
fn test_backend() -> (tempfile::TempDir, backend::Backend) {
    let dir = tempfile::tempdir().unwrap();
    let backend = backend::Backend::Volume {
        directory: dir.path().to_owned(),
        scope: [8; 32],
        timer: Arc::new(RuntimeTimer),
    };
    (dir, backend)
}
#[test]
fn native_ciphertext_binds_class_tenant_digest_and_record_frontier() {
    let protection = protection();
    let mut tenant =
        rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let bytes = vec![0x39; 65539];
    let a = binding(&bytes).artifact().unwrap();
    let c = StorageClass::NativeConfiguration;
    let sealed = protected::seal(&protection, tenant, &bytes, &a, c).unwrap();
    assert!(!sealed.windows(100).any(|b| b == &bytes[..100]));
    assert_eq!(
        &*protected::plaintext(&protection, tenant, &sealed, &a, c, bytes.len() as u64).unwrap(),
        &bytes
    );
    assert!(
        protected::plaintext(
            &protection,
            tenant,
            &sealed,
            &a,
            StorageClass::Artifact,
            bytes.len() as u64
        )
        .is_err()
    );
    assert!(
        protected::plaintext(&protection, tenant, &sealed, &a, c, bytes.len() as u64 - 1).is_err()
    );
    let mut damaged = sealed.clone();
    damaged[4] ^= 1;
    assert!(
        protected::plaintext(&protection, tenant, &damaged, &a, c, bytes.len() as u64).is_err()
    );
    tenant = rss_request_context::TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap();
    assert!(protected::plaintext(&protection, tenant, &sealed, &a, c, bytes.len() as u64).is_err());
}
#[tokio::test]
async fn volume_exact_coordinate_rejects_replacement_and_other_scope() {
    let (dir, backend) = test_backend();
    let d = Deadline::from_timeout(&RuntimeTimer, std::time::Duration::from_secs(60)).unwrap();
    let content = rss_mdm_content_s3::Content {
        length: 3,
        sha256: Sha256::digest(b"abc").into(),
    };
    let intent = backend.intent(uuid::Uuid::new_v4(), content).unwrap();
    let coordinate = backend
        .write(&intent, content, b"abc".to_vec(), d, ())
        .await
        .unwrap();
    assert_eq!(
        backend
            .read(&coordinate, content, 1, 3, d, ())
            .await
            .unwrap(),
        b"bc"
    );
    let backend::Coordinate::Volume { id, .. } = &coordinate else {
        panic!()
    };
    fs::write(dir.path().join(id.to_string()), b"bad").unwrap();
    assert!(
        backend
            .read(&coordinate, content, 0, 3, d, ())
            .await
            .is_err()
    );
    let other = backend::Coordinate::Volume {
        id: *id,
        scope: [0; 32],
    };
    assert!(backend.delete(&other, d).await.is_err());
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
    let (dir, backend) = test_backend();
    let deadline =
        Deadline::from_timeout(&RuntimeTimer, std::time::Duration::from_secs(60)).unwrap();
    let content = rss_mdm_content_s3::Content {
        length: 3,
        sha256: Sha256::digest(b"abc").into(),
    };
    for interrupted in [false, true] {
        let id = uuid::Uuid::new_v4();
        let intent = backend.intent(id, content).unwrap();
        let temporary = dir.path().join(format!(".{id}.tmp"));
        if interrupted {
            fs::write(&temporary, b"a").unwrap();
        }
        let coordinate = backend
            .recover(&intent, content, deadline)
            .await
            .unwrap()
            .unwrap();
        assert!(backend.delete(&coordinate, deadline).await.unwrap());
        assert!(!temporary.exists());
        assert!(matches!(
            backend
                .write(&intent, content, b"abc".to_vec(), deadline, ())
                .await,
            Err(backend::WriteFailure::Unresolved(Error::Conflict))
        ));
        assert!(!dir.path().join(id.to_string()).exists());
        assert!(backend.delete(&coordinate, deadline).await.unwrap());
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
        let (dir, backend) = test_backend();
        let deadline =
            Deadline::from_timeout(&RuntimeTimer, std::time::Duration::from_secs(60)).unwrap();
        let id = uuid::Uuid::new_v4();
        let content = rss_mdm_content_s3::Content {
            length: 3,
            sha256: Sha256::digest(b"abc").into(),
        };
        let intent = backend.intent(id, content).unwrap();
        let coordinate = backend
            .write(&intent, content, b"abc".to_vec(), deadline, ())
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
        let result = backend.read(&coordinate, content, 1, 3, deadline, ()).await;
        if replace {
            assert_eq!(result.unwrap(), b"bc");
        } else {
            assert!(matches!(result, Err(Error::Invariant)));
        }
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
        (
            "pkgbuild.pkg",
            installer_fixtures::pkgbuild(),
            Some("1.2.3"),
        ),
        (
            "productbuild.pkg",
            installer_fixtures::productbuild(),
            Some("1.2.3"),
        ),
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
        if name.ends_with(".exe") {
            file.set_len(513).unwrap();
            assert!(
                super::installer::inspect(&mut file, name, &config, &RuntimeTimer, deadline)
                    .is_err()
            );
        }
        file.set_len(2).unwrap();
        assert!(
            super::installer::inspect(&mut file, name, &config, &RuntimeTimer, deadline).is_err()
        );
    }
}

#[test]
fn msi_rejects_oversized_string_claims_before_parser_allocation() {
    use std::io::Write;
    for summary in [false, true] {
        let bytes = installer_fixtures::msi(Some("1.2.3"), false);
        let mut compound = cfb::CompoundFile::open(std::io::Cursor::new(bytes)).unwrap();
        if summary {
            // A summary LPSTR with a four GiB length but no body.
            let mut header = vec![0u8; 68];
            header[44..48].copy_from_slice(&48u32.to_le_bytes());
            header[52..56].copy_from_slice(&1u32.to_le_bytes());
            header[60..64].copy_from_slice(&16u32.to_le_bytes());
            header[64..68].copy_from_slice(&30u32.to_le_bytes());
            header.extend(u32::MAX.to_le_bytes());
            let mut stream = compound.open_stream("\u{5}SummaryInformation").unwrap();
            stream.set_len(0).unwrap();
            stream.write_all(&header).unwrap();
        } else {
            let pool = "\u{4840}\u{3f3f}\u{4577}\u{446c}\u{3e6a}\u{44b2}\u{482f}";
            let mut stream = compound.open_stream(pool).unwrap();
            stream.set_len(0).unwrap();
            stream.write_all(&[0xe4, 4, 0, 0, 0, 0, 1, 0]).unwrap();
            stream.write_all(&u32::MAX.to_le_bytes()).unwrap();
        }
        let bytes = compound.into_inner().into_inner();
        let dir = tempfile::tempdir().unwrap();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        let deadline =
            Deadline::from_timeout(&RuntimeTimer, std::time::Duration::from_secs(60)).unwrap();
        assert!(
            super::installer::inspect(
                &mut file,
                "bad.msi",
                &config(dir.path().to_owned()),
                &RuntimeTimer,
                deadline
            )
            .is_err()
        );
    }
}

#[test]
fn malformed_msi_property_schema_is_rejected_without_panicking() {
    use std::io::{Cursor, Write};
    let mut package =
        msi::Package::create(msi::PackageType::Installer, Cursor::new(Vec::new())).unwrap();
    package
        .create_table(
            "Property",
            vec![
                msi::Column::build("MissingProperty")
                    .primary_key()
                    .string(72),
            ],
        )
        .unwrap();
    let bytes = package.into_inner().unwrap().into_inner();
    let dir = tempfile::tempdir().unwrap();
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&bytes).unwrap();
    let deadline =
        Deadline::from_timeout(&RuntimeTimer, std::time::Duration::from_secs(60)).unwrap();
    assert!(
        super::installer::inspect(
            &mut file,
            "bad.msi",
            &config(dir.path().to_owned()),
            &RuntimeTimer,
            deadline
        )
        .is_err()
    );
}

#[test]
fn automatic_inspection_has_a_one_gib_boundary() {
    use super::installer::{AUTO_LIMIT, Kind, automatic};
    assert!(automatic(Some(Kind::Pkg), AUTO_LIMIT - 1));
    assert!(automatic(Some(Kind::Pkg), AUTO_LIMIT));
    assert!(!automatic(Some(Kind::Pkg), AUTO_LIMIT + 1));
    assert!(!automatic(None, 1));
}
#[test]
fn bundle_observations_do_not_validate_payload_bytes() {
    use std::io::{Cursor, Write};
    for (count, link) in [
        (4096, None),
        (4097, None),
        (3, Some("manifest.json")),
        (3, Some("install.ps1")),
    ] {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        let digest = rss_mdm_resource::Digest::of(b"original").bytes();
        let manifest = serde_json::to_string(&serde_json::json!({"schema":1,"platform":"windows","architecture":"x86_64","entries":{"install.ps1":{"length":8,"sha256":digest},"payload.bin":{"length":8,"sha256":digest}}})).unwrap();
        if link == Some("manifest.json") {
            zip.add_symlink("manifest.json", manifest, options).unwrap();
        } else {
            zip.start_file("manifest.json", options).unwrap();
            zip.write_all(manifest.as_bytes()).unwrap();
        }
        if link == Some("install.ps1") {
            zip.add_symlink("install.ps1", "payload.bin", options)
                .unwrap();
        } else {
            zip.start_file("install.ps1", options).unwrap();
            zip.write_all(b"changed").unwrap();
        }
        zip.start_file("payload.bin", options).unwrap();
        zip.write_all(b"changed").unwrap();
        for index in 3..count {
            zip.start_file(format!("unused-{index}"), options).unwrap();
        }
        let bytes = zip.finish().unwrap().into_inner();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        let deadline =
            Deadline::from_timeout(&RuntimeTimer, std::time::Duration::from_secs(60)).unwrap();
        let result = super::installer::inspect(
            &mut file,
            "bundle.zip",
            &config(PathBuf::new()),
            &RuntimeTimer,
            deadline,
        );
        if count <= 4096 && link.is_none() {
            assert_eq!(
                result.unwrap().format,
                rss_mdm_resource::SoftwareFormat::Bundle
            );
        } else {
            assert!(result.is_err());
        }
    }
}
