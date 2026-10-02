#![allow(
    dead_code,
    reason = "shared software materials are consumed by separate capability test targets"
)]
pub mod ack;
pub mod pg;
pub const INSTANCE: &str = "33333333-3333-4333-8333-333333333333";
use pg::*;
use rss_mdm_resource as resource;
use rss_mdm_resource_postgres as resource_pg;
use rss_mdm_software_release as rel;
use rss_mdm_software_service::publication::*;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
#[derive(Default)]
pub struct State {
    pub source_documents: BTreeMap<String, Vec<u8>>,
    pub manifests: BTreeMap<String, serde_json::Value>,
    pub posts: usize,
    pub deletes: usize,
    pub drop_post_response: bool,
    pub drop_delete_response: bool,
    pub hidden_reads: usize,
    pub reject_information_once: bool,
    pub artifact_auth_leaked: bool,
    pub artifact_pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}
pub struct Server {
    pub state: Arc<Mutex<State>>,
    pub base: String,
    pub address: std::net::IpAddr,
    pub ca: Vec<u8>,
    pub logical: String,
    pub secret: PathBuf,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.secret);
    }
}
impl Server {
    pub async fn new() -> Self {
        Self::at_port(0).await
    }
    pub async fn at_port(port: u16) -> Self {
        let root = PathBuf::from(std::env::var("SOURCE_T2_TLS").unwrap());
        let address = std::env::var("SOURCE_T2_ADDRESS").unwrap().parse().unwrap();
        let bind_address = if port == 443 {
            "0.0.0.0".parse().unwrap()
        } else {
            address
        };
        let listener = TcpListener::bind((bind_address, port)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let certs =
            tokio_rustls::rustls::pki_types::CertificateDer::pem_file_iter(root.join("server.pem"))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
        let key =
            tokio_rustls::rustls::pki_types::PrivateKeyDer::from_pem_file(root.join("server.key"))
                .unwrap();
        let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[
            &tokio_rustls::rustls::version::TLS13,
            &tokio_rustls::rustls::version::TLS12,
        ])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let state = Arc::new(Mutex::new(State::default()));
        let logical = format!("source-{}", unique());
        let secret = root.join(format!("secret-{}", unique()));
        std::fs::write(&secret, "fixture-source-token").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let st = state.clone();
        let source = logical.clone();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {accepted=listener.accept()=>{let(socket,_)=accepted.unwrap();let tls=tls.clone();let state=st.clone();let source=source.clone();tasks.spawn(async move{let Ok(mut socket)=tls.accept(socket).await else{return};let _=tokio::time::timeout(Duration::from_secs(30),async{let mut head=Vec::new();while !head.ends_with(b"\r\n\r\n"){head.push(socket.read_u8().await?);assert!(head.len()<16384);}let header=String::from_utf8(head).unwrap();let line=header.lines().next().unwrap();let mut parts=line.split_whitespace();let method=parts.next().unwrap();let path=parts.next().unwrap();let length=header.lines().find_map(|s|s.to_ascii_lowercase().strip_prefix("content-length: ").map(|v|v.parse::<usize>().unwrap())).unwrap_or(0);assert!(length<=4*1024*1024);let mut bytes=vec![0;length];socket.read_exact(&mut bytes).await?;
                if path.ends_with("/timeout") {tokio::time::sleep(Duration::from_secs(1)).await;}
                let pause = if path.starts_with("/artifacts/") { state.lock().unwrap().artifact_pause.take() } else { None };
                let response=respond(&state,&source,method,path,&header,&bytes);if let Some((status,body))=response{let location=if status==302 {"Location: /test/information\r\n"} else {""};socket.write_all(format!("HTTP/1.1 {status} Fixture\r\n{location}Connection: close\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",body.len()).as_bytes()).await?;if let Some((started,resume))=pause { let split=usize::from(!body.is_empty());socket.write_all(&body[..split]).await?;socket.flush().await?;started.notify_one();resume.notified().await;socket.write_all(&body[split..]).await?; } else { socket.write_all(&body).await?; }}Ok::<(),std::io::Error>(())}).await;});},_=tasks.join_next(),if !tasks.is_empty()=>{}}
            }
        });
        Self {
            state,
            base: format!("https://source.invalid:{port}/"),
            address,
            ca: std::fs::read(root.join("ca.pem")).unwrap(),
            logical,
            secret,
            task,
        }
    }
    pub fn artifacts(&self) -> ArtifactReader {
        ArtifactReader::new(
            vec![ArtifactOrigin {
                base: format!("{}artifacts/", self.base),
                addresses: vec![self.address],
                private_ca: Some(self.ca.clone()),
            }],
            1024 * 1024,
            Duration::from_secs(10),
        )
        .unwrap()
    }
    pub fn winget(&self) -> RingSources {
        let [test, pilot, production] = ["test", "pilot", "production"].map(|ring| {
            SourceConfig::Winget(WingetConfig {
                base: format!("{}{ring}/", self.base),
                artifacts_base: format!("{}hosted/artifacts/", self.base),
            })
        });
        RingSources {
            test,
            pilot,
            production,
        }
    }
    pub async fn service(
        &self,
        runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
        config: RingSources,
    ) -> PublicationService {
        PublicationService::connect(
            host(runtime, audit_store().await),
            tenant(),
            self.logical.clone(),
            config,
            actors(),
            cutoff(),
        )
        .await
        .unwrap()
    }
    pub fn winget_document(&self) -> ExportDocument {
        let mut v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../crates/winget-source/tests/fixtures/msi.json"
        ))
        .unwrap();
        v["Data"]["Versions"][0]["PackageVersion"] = "1".into();
        v["Data"]["Versions"][0]["Installers"][0]["InstallerUrl"] =
            format!("{}artifacts/x64.msi", self.base).into();
        v["Data"]["Versions"][0]["Installers"][0]["InstallerSha256"] =
            hex(&rel::Digest::of(b"abc").bytes()).into();
        let mut arm = v["Data"]["Versions"][0]["Installers"][0].clone();
        arm["Architecture"] = "arm64".into();
        arm["InstallerUrl"] = format!("{}artifacts/arm64.msi", self.base).into();
        v["Data"]["Versions"][0]["Installers"]
            .as_array_mut()
            .unwrap()
            .push(arm);
        ExportDocument::Winget {
            manifest: v["Data"].clone(),
        }
    }
}
use tokio_rustls::rustls::pki_types::pem::PemObject;
fn respond(
    state: &Arc<Mutex<State>>,
    logical: &str,
    method: &str,
    path: &str,
    header: &str,
    bytes: &[u8],
) -> Option<(u16, Vec<u8>)> {
    let mut s = state.lock().unwrap();
    let lower = header.to_ascii_lowercase();
    if let Some(document) = s.source_documents.get(path) {
        assert!(
            !lower.contains("authorization:")
                && !lower.contains("cookie:")
                && !lower.contains("x-functions-key:")
        );
        return Some((200, document.clone()));
    }
    if path.starts_with("/artifacts/") {
        s.artifact_auth_leaked |= lower.contains("authorization:")
            || lower.contains("cookie:")
            || lower.contains("x-functions-key:");
        if path.ends_with("redirect") {
            return Some((302, vec![]));
        }
        return Some((200, b"abc".to_vec()));
    }
    assert!(lower.contains("x-functions-key: fixture-source-token\r\n"));
    let ring = path.split('/').nth(1).unwrap().to_owned();
    if path.ends_with("/information") {
        if s.reject_information_once {
            s.reject_information_once = false;
            return Some((401, vec![]));
        }
        return Some((200,serde_json::to_vec(&serde_json::json!({"Data":{"SourceIdentifier":logical,"ServerSupportedVersions":["1.0.0"]}})).unwrap()));
    }
    match method {
        "POST" => {
            s.posts += 1;
            let v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            assert_eq!(v["Versions"].as_array().unwrap().len(), 1);
            let key = format!(
                "{ring}/{}/{}",
                v["PackageIdentifier"].as_str().unwrap(),
                v["Versions"][0]["PackageVersion"].as_str().unwrap()
            );
            let code =
                if let std::collections::btree_map::Entry::Vacant(entry) = s.manifests.entry(key) {
                    entry.insert(v);
                    201
                } else {
                    409
                };
            if s.drop_post_response {
                s.drop_post_response = false;
                None
            } else {
                Some((code, b"{}".to_vec()))
            }
        }
        "DELETE" => {
            s.deletes += 1;
            let parts: Vec<_> = path.split('/').collect();
            let key = format!("{ring}/{}/{}", parts[3], parts[5]);
            let code = if s.manifests.remove(&key).is_some() {
                204
            } else {
                404
            };
            if s.drop_delete_response {
                s.drop_delete_response = false;
                None
            } else {
                Some((code, vec![]))
            }
        }
        "GET" => {
            if s.hidden_reads > 0 {
                s.hidden_reads -= 1;
                return Some((404, vec![]));
            }
            let (package, version) = path
                .split("packageManifests/")
                .nth(1)
                .unwrap()
                .split_once("?Version=")
                .unwrap();
            let key = format!("{ring}/{package}/{version}");
            Some(match s.manifests.get(&key) {
                Some(v) => (
                    200,
                    serde_json::to_vec(&serde_json::json!({"Data":v})).unwrap(),
                ),
                None => (404, vec![]),
            })
        }
        _ => panic!("unexpected source method"),
    }
}
pub fn actors() -> ServiceIdentity {
    let a = |s| rel::ActorId::new(tenant(), s).unwrap();
    ServiceIdentity {
        backend: a("backend"),
    }
}
pub fn id(s: &str) -> resource::Id {
    resource::Id::new(s).unwrap()
}
pub fn request(c: &rel::Candidate) -> ServiceRequest {
    ServiceRequest {
        actor: rel::ActorId::new(
            tenant(),
            if rel::Ring::ALL
                .iter()
                .any(|r| matches!(c.snapshot().ring_state(*r), rel::RingState::Validated(_)))
            {
                "approver"
            } else {
                "publisher"
            },
        )
        .unwrap(),
        id: rel::RequestId::new(tenant(), unique()).unwrap(),
        expected_revision: c.snapshot().revision,
        as_of: at(10),
    }
}
#[allow(
    clippy::cognitive_complexity,
    reason = "typed provider fixtures retain format-specific immutable material and admission setup"
)]
pub async fn seed(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    server: &Server,
    document: ExportDocument,
) -> CandidateInput {
    let store = resource_pg::ResourceStore::new(runtime, tenant(), deadline())
        .await
        .unwrap();
    let source_snapshot = admit_private_source(&server.logical).await;
    let key = id(&unique());
    let mut variants = Vec::new();
    let (package, package_version, platform, variant) = match &document {
        ExportDocument::Winget { manifest } => (
            manifest["PackageIdentifier"].as_str().unwrap(),
            manifest["Versions"][0]["PackageVersion"].as_str().unwrap(),
            resource::Platform::Windows,
            "msi.machine.no-id",
        ),
        ExportDocument::Brew { recipe } => (
            recipe.package.as_str(),
            recipe.version.as_str(),
            resource::Platform::MacOS,
            if matches!(recipe.payload, BrewPayload::Formula { .. }) {
                "bottle"
            } else {
                "cask"
            },
        ),
    };
    for (arch, keyname) in [
        (resource::Architecture::X86_64, "x64"),
        (resource::Architecture::Aarch64, "arm64"),
    ] {
        variants.push(resource::Variant::new(
            platform,
            arch,
            id(variant),
            resource::Declaration::Software {
                definition: {
                    let mut spec = software_definition(
                        &server.logical,
                        package,
                        package_version,
                        platform,
                        keyname,
                    )
                    .spec()
                    .clone();
                    spec.source = source_snapshot.clone();
                    match &document {
                        ExportDocument::Winget { manifest } => {
                            let version = &manifest["Versions"][0];
                            let metadata = &version["DefaultLocale"];
                            spec.export = resource::SoftwareExport::Winget {
                                locale: metadata["PackageLocale"].as_str().unwrap().into(),
                                name: metadata["PackageName"].as_str().unwrap().into(),
                                publisher: metadata["Publisher"].as_str().unwrap().into(),
                                description: metadata["ShortDescription"].as_str().unwrap().into(),
                                license: metadata["License"].as_str().unwrap().into(),
                            };
                            let installer = version["Installers"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .find(|i| {
                                    i["Architecture"]
                                        == if arch == resource::Architecture::X86_64 {
                                            "x64"
                                        } else {
                                            "arm64"
                                        }
                                })
                                .unwrap();
                            spec.artifacts.get_mut("package").unwrap().origin =
                                Some(installer["InstallerUrl"].as_str().unwrap().into());
                        }
                        ExportDocument::Brew { recipe } => {
                            let payload = match &recipe.payload {
                                BrewPayload::Cask { artifacts, install } => {
                                    let file = artifacts
                                        .iter()
                                        .find(|a| {
                                            a.architecture
                                                == if arch == resource::Architecture::X86_64 {
                                                    "x86_64"
                                                } else {
                                                    "aarch64"
                                                }
                                        })
                                        .unwrap();
                                    spec.artifacts.get_mut("package").unwrap().origin =
                                        Some(file.artifact.url.clone());
                                    let (path, receipts) = match install {
                                        CaskInstall::Pkg { path, receipts } => {
                                            (path.clone(), receipts.clone())
                                        }
                                        CaskInstall::App { path } => (path.clone(), vec![]),
                                    };
                                    if let resource::SoftwareBehavior::Brew(n) = &mut spec.behavior
                                    {
                                        n.scope = resource::SoftwareScope::System;
                                        n.install.run_as = resource::RunAs::System;
                                        n.upgrade_invocation.run_as = resource::RunAs::System;
                                        let native = n.clone();
                                        spec.behavior = resource::SoftwareBehavior::Pkg(native);
                                    }
                                    resource::BrewExport::Cask { path, receipts }
                                }
                                BrewPayload::Formula {
                                    source: _,
                                    executable,
                                    bottles,
                                    revision,
                                    rebuild,
                                    ..
                                } => {
                                    if let resource::SoftwareBehavior::Brew(n) = &mut spec.behavior
                                    {
                                        n.uninstall = Some(resource::NativeRemoval {
                                            installer: n.installer.clone(),
                                            invocation: n.install.clone(),
                                        });
                                    }

                                    let b = bottles
                                        .iter()
                                        .find(|b| {
                                            b.tag
                                                == if arch == resource::Architecture::X86_64 {
                                                    "sonoma"
                                                } else {
                                                    "arm64_sonoma"
                                                }
                                        })
                                        .unwrap();
                                    spec.artifacts.get_mut("package").unwrap().origin =
                                        Some(b.artifact.url.clone());
                                    resource::BrewExport::Bottle {
                                        artifact: "package".into(),
                                        source: "source".into(),
                                        tag: b.tag.clone(),
                                        cellar: b.cellar.clone(),
                                        revision: *revision,
                                        rebuild: *rebuild,
                                        executable: executable.clone(),
                                    }
                                }
                            };
                            spec.export = resource::SoftwareExport::Brew {
                                name: recipe.name.clone(),
                                description: recipe.description.clone(),
                                homepage: recipe.homepage.clone(),
                                payload,
                            };
                        }
                    }
                    if let ExportDocument::Brew { recipe } = &document
                        && let BrewPayload::Formula {
                            source,
                            dependencies,
                            ..
                        } = &recipe.payload
                    {
                        for a in std::iter::once(source)
                            .chain(dependencies.iter().flat_map(|d| d.artifacts.iter()))
                        {
                            spec.artifacts.insert(
                                a.key.clone(),
                                resource::SoftwareArtifact {
                                    reference: a.key.clone(),
                                    origin: Some(a.url.clone()),
                                    length: a.length,
                                    sha256: a.sha256,
                                },
                            );
                        }
                    }
                    resource::SoftwareDefinition::new(spec).unwrap()
                },
            },
        ));
    }
    let version = resource::Version::new(
        tenant(),
        key.clone(),
        id("one"),
        resource::Kind::Software,
        variants,
    )
    .unwrap();
    let content = stored_content();
    for v in version.variants() {
        let resource::Declaration::Software { definition } = v.declaration() else {
            unreachable!()
        };
        for artifact in definition.materials() {
            let upload = uuid::Uuid::new_v4();
            let actor = "publication-fixture";
            let binding = rss_mdm_content_service::Binding {
                storage_class: rss_mdm_content_service::StorageClass::Artifact,
                resource: key.as_str().into(),
                version: version.label().as_str().into(),
                variant: v.key().as_str().into(),
                platform: v.platform(),
                architecture: v.architecture(),
                resource_digest: version.digest().bytes(),
                source: Some(definition.spec().source.clone()),
                origin: artifact.origin.clone(),
                reference: artifact.reference.clone(),
                length: artifact.length,
                sha256: artifact.sha256,
                actor: actor.into(),
            };
            content.begin(upload, binding, 1700000000).await.unwrap();
            content
                .append(
                    actor,
                    upload,
                    0,
                    1700000000,
                    std::io::Cursor::new(b"abc".to_vec()),
                )
                .await
                .unwrap();
            content.finish(actor, upload, 1700000000).await.unwrap();
        }
    }
    for (revision, command) in [
        (0, resource_pg::Command::Create(resource::Kind::Software)),
        (1, resource_pg::Command::Insert(version.clone())),
    ] {
        store
            .execute(
                &resource_pg::Request {
                    id: id(&unique()),
                    resource: key.clone(),
                    expected_storage_revision: revision,
                    as_of: at(1),
                    command,
                },
                deadline(),
            )
            .await
            .unwrap();
    }
    admit_version(&version).await;
    CandidateInput {
        actor: rel::ActorId::new(tenant(), "publisher").unwrap(),
        candidate: rel::CandidateId::new(tenant(), unique()).unwrap(),
        request: rel::RequestId::new(tenant(), unique()).unwrap(),
        resource: key,
        version: id("one"),
        expected_resource_revision: 2,
        resource_digest: version.digest().bytes(),
        as_of: at(1),
    }
}
pub async fn authorize(
    service: &PublicationService,
    id: &rel::CandidateId,
    ring: rel::Ring,
) -> rel::Publication {
    let c = service.candidate(id, cutoff()).await.unwrap().unwrap();
    service
        .validate(id, ring, &request(&c), cutoff())
        .await
        .unwrap();
    let c = service.candidate(id, cutoff()).await.unwrap().unwrap();
    service
        .approve(
            id,
            ring,
            &rel::ActorId::new(tenant(), "publisher").unwrap(),
            &request(&c),
            cutoff(),
        )
        .await
        .unwrap();
    let c = service.candidate(id, cutoff()).await.unwrap().unwrap();
    let r = request(&c);
    let result = service.authorize(id, ring, &r, cutoff()).await.unwrap();
    assert!(matches!(
        service.authorize(id, ring, &r, cutoff()).await.unwrap(),
        rel::Transition::Replayed(_)
    ));
    let rel::Transition::Applied {
        decision: rel::Decision::Publish(p),
        ..
    } = result
    else {
        panic!()
    };
    *p
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

pub fn brew_config() -> (tempfile::TempDir, RingSources) {
    let root = tempfile::tempdir().unwrap();
    let config = ["test", "pilot", "production"].map(|ring| {
        let repository = root.path().join(format!("{ring}.git"));
        assert!(
            std::process::Command::new("/usr/bin/git")
                .args(["init", "--quiet", "--bare"])
                .arg(&repository)
                .status()
                .unwrap()
                .success()
        );
        SourceConfig::Brew(BrewConfig {
            base: format!("https://hosted.example.test/brew/{ring}/"),
            artifacts_base: "https://hosted.example.test/artifacts/".into(),
            credential_reference: "source-key".into(),
            tap: format!("acme/{ring}"),
            repository,
        })
    });
    let [test, pilot, production] = config;
    (
        root,
        RingSources {
            test,
            pilot,
            production,
        },
    )
}
pub fn cask(server: &Server, package: &str, version: &str) -> ExportDocument {
    ExportDocument::Brew {
        recipe: BrewRecipe {
            package: package.into(),
            version: version.into(),
            name: "Application".into(),
            description: "Controlled app".into(),
            homepage: "https://example.com/".into(),
            payload: BrewPayload::Cask {
                artifacts: [("x86_64", "x64"), ("aarch64", "arm64")]
                    .into_iter()
                    .map(|(arch, key)| BrewArtifact {
                        architecture: arch.into(),
                        artifact: PublicArtifact {
                            key: key.into(),
                            url: format!("{}artifacts/{key}.pkg", server.base),
                            length: 3,
                            sha256: rel::Digest::of(b"abc").bytes(),
                        },
                    })
                    .collect(),
                install: CaskInstall::Pkg {
                    path: "App.pkg".into(),
                    receipts: vec!["com.acme.app".into()],
                },
            },
        }
        .into(),
    }
}
pub fn formula(server: &Server) -> ExportDocument {
    ExportDocument::Brew {
        recipe: BrewRecipe {
            package: "tool".into(),
            version: "1".into(),
            name: "Tool".into(),
            description: "Controlled tool".into(),
            homepage: "https://example.com/".into(),
            payload: BrewPayload::Formula {
                revision: 0,
                rebuild: 0,
                source: PublicArtifact {
                    key: "source".into(),
                    url: format!("{}artifacts/source.tar.gz", server.base),
                    length: 3,
                    sha256: rel::Digest::of(b"abc").bytes(),
                },
                executable: "tool".into(),
                bottles: [("sonoma", "x64"), ("arm64_sonoma", "arm64")]
                    .into_iter()
                    .map(|(tag, key)| BottleInput {
                        cellar: "any_skip_relocation".into(),
                        tag: tag.into(),
                        root_url: format!("{}artifacts", server.base),
                        artifact: PublicArtifact {
                            key: key.into(),
                            url: format!("{}artifacts/tool-1.{tag}.bottle.tar.gz", server.base),
                            length: 3,
                            sha256: rel::Digest::of(b"abc").bytes(),
                        },
                    })
                    .collect(),
                dependencies: vec![],
            },
        }
        .into(),
    }
}
pub fn git(config: &RingSources, args: &[&str]) -> String {
    let SourceConfig::Brew(c) = &config.test else {
        panic!()
    };
    let out = std::process::Command::new("/usr/bin/git")
        .arg("--git-dir")
        .arg(&c.repository)
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

pub async fn request_for(service: &PublicationService, id: &rel::CandidateId) -> ServiceRequest {
    request(&service.candidate(id, cutoff()).await.unwrap().unwrap())
}

/// Complete immutable fixture shared with product HTTP tests.
pub fn software_definition(
    source: &str,
    package: &str,
    version: &str,
    platform: resource::Platform,
    key: &str,
) -> resource::SoftwareDefinition {
    let windows = platform == resource::Platform::Windows;
    serde_json::from_value(serde_json::json!({"source":{"id":source,"revision":"1","sha256":vec![1;32]},"package":package,"version":version,"artifacts":{"package":{"reference":key,"length":3,"sha256":resource::Digest::of(b"abc").bytes()}},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"behavior":{"kind":if windows {"winget"} else {"brew"},"installer":"package","scope":if (if windows {"system"}else{"logged_in_user"}) == "logged_in_user" {"user"} else {"system"},"install":{"runAs":if windows {"system"}else{"logged_in_user"},"arguments":[],"environment":{},"timeoutSeconds":600,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","uninstall":null,"detect":if windows {serde_json::json!({"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":version})}else{serde_json::json!({"kind":"pkg_receipt","receipt":"com.acme.app","version":version})},"upgradeInvocation":{"runAs":if windows {"system"}else{"logged_in_user"},"arguments":[],"environment":{},"timeoutSeconds":600,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}})).unwrap()
}

pub fn host(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
) -> rss_mdm_software_service::Host {
    rss_mdm_software_service::Host {
        runtime,
        audit: Arc::new(TestAudit(audit)),
        content: stored_content(),
        credentials: Arc::new(TestCredentials),
    }
}
struct TestAudit(Arc<rss_mdm_audit_integration::AuditStore>);
impl rss_mdm_software_service::AuditPort for TestAudit {
    fn lock_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    ) -> rss_mdm_software_service::AuditFuture<'a> {
        Box::pin(async move { self.0.lock_in(tx).await })
    }
    fn append_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        fact: &'a rss_mdm_audit_integration::Fact,
        replayed: bool,
    ) -> rss_mdm_software_service::AuditFuture<'a> {
        Box::pin(async move { self.0.append_in(tx, fact, replayed).await })
    }
    fn append_request_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        request: &'a rss_mdm_audit_integration::RequestAudit,
        status: u16,
        result: &'a str,
    ) -> rss_mdm_software_service::AuditFuture<'a> {
        Box::pin(async move { self.0.append_request_in(tx, request, status, result).await })
    }
}
struct TestCredentials;
impl rss_mdm_software_service::Credentials for TestCredentials {
    fn brew_read(
        &self,
        tenant: rss_request_context::TenantId,
        source: &str,
        _reference: &str,
    ) -> rss_mdm_software_service::publication::Result<rss_mdm_software_service::BrewReadAccess>
    {
        rss_mdm_software_service::BrewReadAccess::new(
            tenant,
            source,
            "fixture-read-only-token-2531-000000000",
        )
        .map_err(|_| rss_mdm_software_service::publication::Error::Identity)
    }
}

pub fn private_definition(source: serde_json::Value, bytes: &[u8]) -> serde_json::Value {
    let digest = rss_mdm_resource::Digest::of(bytes).bytes();
    serde_json::json!({"source":source,"package":"Acme.Private","version":"1+enterprise","artifacts":{"package":{"reference":"installer","length":bytes.len(),"sha256":digest}},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"behavior":{"kind":"msi","installer":"package","scope":"system","install":{"runAs":"system","arguments":["/qn"],"environment":{},"timeoutSeconds":600,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1+enterprise"},"upgradeInvocation":{"runAs":"system","arguments":["/qn"],"environment":{},"timeoutSeconds":600,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}})
}

struct ContentClock;
impl rss_request_context::Clock for ContentClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "real content fixture clock provider"
    )]
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}
pub fn stored_content() -> Arc<rss_mdm_content_service::Store> {
    static CONTENT: std::sync::OnceLock<(tempfile::TempDir, Arc<rss_mdm_content_service::Store>)> =
        std::sync::OnceLock::new();
    CONTENT
        .get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let store = rss_mdm_content_service::Store::open(
                Arc::new(rss_mdm_native_protection::Protector::new(&[82; 32]).unwrap()),
                &rss_mdm_content_service::Config {
                    directory: dir.path().to_owned(),
                    imports: Default::default(),
                    max_artifact_bytes: 16 * 1024 * 1024,
                    max_temporary_bytes: 64 * 1024 * 1024,
                    max_uploads: 64,
                    transfer_seconds: 30,
                    retention_seconds: 3600,
                    max_bundle_bytes: 16 * 1024 * 1024,
                    max_bundle_entries: 256,
                    max_expansion_ratio: 100,
                },
                &tenant().to_string(),
                Arc::new(ContentClock),
            )
            .unwrap();
            (dir, store)
        })
        .1
        .clone()
}

async fn admit_private_source(source: &str) -> resource::SoftwareSource {
    use rss_mdm_software_service::catalog as c;
    let runtime = pg::runtime_at(None, "mdm_flow_runtime").await;
    let audit = pg::audit_store_for("mdm_flow_runtime").await;
    let catalog = c::Catalog::new(runtime.clone(), tenant(), Arc::new(TestAudit(audit)));
    let definition = c::SourceDefinition {
        id: source.into(),
        revision: "1".into(),
        protocol: c::SourceProtocol::Private,
    };
    let snapshot = definition.snapshot().unwrap();
    for (expected_revision, input) in [
        (0, c::SourceChange::Register { definition }),
        (
            1,
            c::SourceChange::Approve {
                evidence: vec!["controlled fixture source".into()],
            },
        ),
    ] {
        let request = rss_mdm_audit_integration::RequestAudit::new(
            tenant().to_string(),
            "software_source_write",
        );
        request.set_principal("operator", INSTANCE);
        let op = c::Operation {
            operation_id: uuid::Uuid::new_v4(),
            expected_revision,
            input,
        };
        let result = runtime
            .local_tx_with_context(
                tenant(),
                deadline(),
                (&catalog, &request, &op, source),
                |(catalog, request, op, source), tx| {
                    Box::pin(async move {
                        if let Ok(value) = catalog.source_read_in(tx, source, "1").await
                            && value["admission"]["state"] == "approved"
                        {
                            return Ok(Ok(()));
                        }
                        catalog
                            .source_in(tx, request, source, "1", op)
                            .await
                            .map(|_| Ok(()))
                            .map_err(|_| {
                                sqlx::Error::Protocol("fixture source approval".into()).into()
                            })
                    })
                },
            )
            .await;
        result.fold(|r| r, Err, Err, Err, Err, Err).unwrap();
        request.finalize(None);
    }
    runtime.close().await;
    snapshot
}
async fn admit_version(version: &resource::Version) {
    use rss_mdm_software_service::catalog::{self as c, ContentPort};
    let runtime = pg::runtime_at(None, "mdm_flow_runtime").await;
    let audit = pg::audit_store_for("mdm_flow_runtime").await;
    let catalog = c::Catalog::new(runtime.clone(), tenant(), Arc::new(TestAudit(audit)));
    let content = stored_content().as_ref().verify(version).await.unwrap();
    let op = c::Operation {
        operation_id: uuid::Uuid::new_v4(),
        expected_revision: 0,
        input: c::VersionChange::Approve {
            evidence: vec!["complete fixture bytes and definition".into()],
        },
    };
    let request = rss_mdm_audit_integration::RequestAudit::new(
        tenant().to_string(),
        "software_version_write",
    );
    request.set_principal("operator", INSTANCE);
    runtime
        .local_tx_with_context(
            tenant(),
            deadline(),
            (&catalog, &request, &op, &content, version),
            |(catalog, request, op, content, version), tx| {
                Box::pin(async move {
                    catalog
                        .version_change_in(
                            tx,
                            request,
                            version.resource().as_str(),
                            version.label().as_str(),
                            op,
                            Some(content.as_ref()),
                        )
                        .await
                        .map(|_| Ok(()))
                        .map_err(|_| {
                            sqlx::Error::Protocol("fixture version approval".into()).into()
                        })
                })
            },
        )
        .await
        .fold(|r| r, Err, Err, Err, Err, Err)
        .unwrap();
    request.finalize(None);
    runtime.close().await;
}

/// Withdraw only the enterprise admission; an existing publication reference still fences archival.
pub async fn withdraw_version_admission(input: &CandidateInput) {
    use rss_mdm_software_service::catalog as c;
    let runtime = pg::runtime_at(None, "mdm_flow_runtime").await;
    let catalog = c::Catalog::new(
        runtime.clone(),
        tenant(),
        Arc::new(TestAudit(pg::audit_store_for("mdm_flow_runtime").await)),
    );
    let request =
        rss_mdm_audit_integration::RequestAudit::new(tenant().to_string(), "software_withdraw");
    request.set_principal("publisher", INSTANCE);
    let op = c::Operation {
        operation_id: uuid::Uuid::new_v4(),
        expected_revision: 1,
        input: c::VersionChange::Withdraw {
            evidence: vec!["fixture admission withdrawal".into()],
        },
    };
    runtime
        .local_tx_with_context(
            tenant(),
            pg::deadline(),
            (&catalog, &request, &op, input),
            |(catalog, request, op, input), tx| {
                Box::pin(async move {
                    catalog
                        .version_change_in(
                            tx,
                            request,
                            input.resource.as_str(),
                            input.version.as_str(),
                            op,
                            None,
                        )
                        .await
                        .map(|_| ())
                        .map_err(|_| {
                            sqlx::Error::Protocol("fixture admission withdrawal".into()).into()
                        })
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)
        .unwrap();
    request.finalize(None);
    runtime.close().await;
}
