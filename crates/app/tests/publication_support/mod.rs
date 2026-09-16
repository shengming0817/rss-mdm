pub mod ack;
pub mod pg;
use pg::*;
use rss_mdm_app::software_publication::*;
use rss_mdm_resource as resource;
use rss_mdm_resource_postgres as resource_pg;
use rss_mdm_software_release as rel;
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
    pub manifests: BTreeMap<String, serde_json::Value>,
    pub posts: usize,
    pub deletes: usize,
    pub drop_post_response: bool,
    pub drop_delete_response: bool,
    pub hidden_reads: usize,
    pub reject_information_once: bool,
    pub artifact_auth_leaked: bool,
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
        let root = PathBuf::from(std::env::var("SOURCE_T2_TLS").unwrap());
        let address = std::env::var("SOURCE_T2_ADDRESS").unwrap().parse().unwrap();
        let listener = TcpListener::bind((address, 0)).await.unwrap();
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
                let response=respond(&state,&source,method,path,&header,&bytes);if let Some((status,body))=response{let location=if status==302 {"Location: /test/information\r\n"} else {""};socket.write_all(format!("HTTP/1.1 {status} Fixture\r\n{location}Connection: close\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",body.len()).as_bytes()).await?;socket.write_all(&body).await?;}Ok::<(),std::io::Error>(())}).await;});},_=tasks.join_next(),if !tasks.is_empty()=>{}}
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
                addresses: vec![self.address],
                private_ca: Some(self.ca.clone()),
                credential_reference: "source-key".into(),
                credential_file: self.secret.clone(),
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
            runtime,
            tenant(),
            self.logical.clone(),
            config,
            self.artifacts(),
            actors(),
            cutoff(),
        )
        .await
        .unwrap()
    }
    pub fn winget_submission(&self) -> Submission {
        let mut v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../winget-source/tests/fixtures/msi.json"
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
        Submission::Winget {
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
pub async fn seed(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    server: &Server,
    submission: Submission,
) -> CandidateInput {
    let store = resource_pg::ResourceStore::new(runtime, tenant(), deadline())
        .await
        .unwrap();
    let key = id(&unique());
    let mut variants = Vec::new();
    let (package, package_version, platform, variant) = match &submission {
        Submission::Winget { .. } => (
            "Acme.App",
            "1",
            resource::Platform::Windows,
            "msi.machine.no-id",
        ),
        Submission::Brew { recipe } => (
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
                package: resource::Package::new(
                    id(&server.logical),
                    id(package),
                    id(package_version),
                ),
                artifact: resource::Artifact::new(id(keyname), 3, resource::Digest::of(b"abc"))
                    .unwrap(),
                install: id("install"),
                detect: id("detect"),
                uninstall: None,
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
    for (revision, command) in [
        (0, resource_pg::Command::Create(resource::Kind::Software)),
        (1, resource_pg::Command::Insert(version)),
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
    CandidateInput {
        actor: rel::ActorId::new(tenant(), "publisher").unwrap(),
        candidate: rel::CandidateId::new(tenant(), unique()).unwrap(),
        request: rel::RequestId::new(tenant(), unique()).unwrap(),
        resource: key,
        version: id("one"),
        expected_resource_revision: 2,
        submission,
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
pub fn cask(server: &Server, package: &str, version: &str) -> Submission {
    Submission::Brew {
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
pub fn formula(server: &Server) -> Submission {
    Submission::Brew {
        recipe: BrewRecipe {
            package: "tool".into(),
            version: "1".into(),
            name: "Tool".into(),
            description: "Controlled tool".into(),
            homepage: "https://example.com/".into(),
            payload: BrewPayload::Formula {
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
