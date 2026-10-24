use crate::publication_support as p;
use crate::test_support::*;
use rss_mdm_software_service::publication::SourceConfig;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=software.http; requires actual Homebrew CLI"]
async fn immutable_native_tap_is_consumed_by_git_and_homebrew_and_withdrawn() -> Result<()> {
    let peer = p::Server::new().await;
    let runtime = p::pg::runtime().await;
    let content = p::stored_content().await;
    let (audit, audit_pool) = p::pg::audit_store(runtime.clone()).await;
    let (root, mut config) = p::brew_config();
    let SourceConfig::Brew(source) = &mut config else {
        unreachable!()
    };
    source.base = format!(
        "https://mdm.example.test/api/v1/software/native/sources/{}/",
        peer.logical
    );
    source.artifacts_base = format!(
        "https://mdm.example.test/api/v1/software/native/sources/{}/artifacts/",
        peer.logical
    );
    let service = Arc::new(
        peer.service(runtime.clone(), audit.clone(), content.clone(), config)
            .await,
    );
    let input = p::seed(runtime.clone(), &content, &peer, p::formula(&peer)).await;
    let publication = p::submit_publication(&service, &input).await;
    service
        .publish(publication.id(), 1, p::pg::at(10), p::pg::cutoff())
        .await?;
    let frozen = service
        .published(publication.id().digest().bytes(), p::pg::cutoff())
        .await?;
    let snapshot = frozen.snapshot.unwrap();
    let directory = Arc::new(
        rss_mdm_software_service::management::publication::service::PublicationDirectory {
            cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                &[9; 32],
            )),
            services: std::collections::BTreeMap::from([(peer.logical.clone(), service.clone())]),
            tenant: p::pg::tenant(),
            runtime: runtime.clone(),
            audit_store: audit,
            clock: Arc::new(crate::clock::FlowClock(Arc::new(crate::clock::SystemClock))),
        },
    );
    let router = rss_mdm_management_http::software_native::routes().with_state(Arc::new(
        rss_mdm_management_http::software_native::StateData {
            directory,
            content: Some(content.clone()),
            requests: Arc::new(tokio::sync::Semaphore::new(8)),
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hosted = router.clone().into_axum();
    let server = crate::test_support::software::HttpServer::start(listener, hosted);
    let id = publication
        .id()
        .digest()
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let url = format!(
        "http://{address}/api/v1/software/native/sources/{}/exports/{id}.git",
        peer.logical
    );
    let client = Client::builder().no_proxy().build()?;
    ensure!(
        client
            .get(format!("{url}/info/refs?service=git-upload-pack"))
            .send()
            .await?
            .status()
            == StatusCode::UNAUTHORIZED
    );
    let token = "fixture-read-only-token-2531-000000000";
    let clone = root.path().join("consumer");
    let git = tokio::process::Command::new("/usr/bin/git")
        .args([
            "-c",
            "credential.helper=",
            "-c",
            &format!("http.extraHeader=Authorization: Bearer {token}"),
            "clone",
            "--quiet",
            "--no-tags",
            "--single-branch",
            "--branch",
            "main",
            &url,
        ])
        .arg(&clone)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .await?;
    ensure!(
        git.status.success(),
        "native upload-pack clone: {}",
        String::from_utf8_lossy(&git.stderr)
    );
    let head = tokio::process::Command::new("/usr/bin/git")
        .args(["-C", clone.to_str().unwrap(), "rev-parse", "HEAD"])
        .output()
        .await?;
    ensure!(String::from_utf8(head.stdout)?.trim() == snapshot);
    let formula = clone.join("Formula/tool.rb");
    ensure!(
        std::fs::read_to_string(&formula)?
            .contains("RSS bottle-only: source installation is unsupported")
    );
    // Use the installed CLI code with isolated Tap/cache directories, preserving the user's Homebrew installation.
    let prefix = tokio::process::Command::new("brew")
        .arg("--repository")
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .output()
        .await?;
    ensure!(prefix.status.success());
    let installed = std::path::PathBuf::from(String::from_utf8(prefix.stdout)?.trim());
    let isolated = root.path().join("homebrew");
    std::fs::create_dir_all(isolated.join("bin"))?;
    std::fs::create_dir_all(isolated.join("Library/Taps/rss"))?;
    std::fs::copy(installed.join("bin/brew"), isolated.join("bin/brew"))?;
    std::os::unix::fs::symlink(
        installed.join("Library/Homebrew"),
        isolated.join("Library/Homebrew"),
    )?;
    std::os::unix::fs::symlink(&clone, isolated.join("Library/Taps/rss/homebrew-frozen"))?;
    let brew = tokio::process::Command::new(isolated.join("bin/brew"))
        .args(["info", "--json=v2", "--formula", "rss/frozen/tool"])
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .env("HOMEBREW_NO_ANALYTICS", "1")
        .env("HOMEBREW_NO_INSTALL_FROM_API", "1")
        .env("HOMEBREW_NO_ENV_HINTS", "1")
        .env("HOMEBREW_CACHE", root.path().join("brew-cache"))
        .output()
        .await?;
    ensure!(
        brew.status.success(),
        "native Homebrew consumption: {}",
        String::from_utf8_lossy(&brew.stderr)
    );
    let metadata: Value = serde_json::from_slice(&brew.stdout)?;
    ensure!(
        metadata["formulae"][0]["versions"]["stable"] == "1",
        "metadata: {metadata}"
    );
    ensure!(
        metadata["formulae"][0]["bottle"]["stable"]["files"]["arm64_sonoma"]["sha256"]
            == rss_mdm_resource::Digest::of(b"abc")
                .bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
    );
    let digest = rss_mdm_resource::Digest::of(b"abc")
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let resource_digest = input
        .resource_digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let prefix = format!(
        "https://mdm.example.test/api/v1/software/native/sources/{}/artifacts/{}/{}/{resource_digest}/",
        peer.logical,
        input.resource.as_str(),
        input.version.as_str()
    );
    let expected: std::collections::BTreeSet<_> = [
        format!("{digest}.source.tar.gz"),
        "tool-1.arm64_sonoma.bottle.tar.gz".into(),
        "tool-1.sonoma.bottle.tar.gz".into(),
    ]
    .into_iter()
    .map(|file| (format!("content.{digest}"), format!("{prefix}{file}")))
    .collect();
    let actual: std::collections::BTreeSet<_> = frozen
        .artifacts
        .iter()
        .map(|a| (a.key.clone(), a.url.clone()))
        .collect();
    ensure!(
        actual == expected && actual.len() == frozen.artifacts.len(),
        "published artifacts differ: {actual:?}, expected {expected:?}"
    );
    ensure!(
        frozen
            .artifacts
            .iter()
            .all(|a| a.length == 3 && a.sha256 == rss_mdm_resource::Digest::of(b"abc").bytes())
    );
    let artifact_url = frozen.artifacts[0].url.clone();
    for artifact in frozen.artifacts {
        let path = url::Url::parse(&artifact.url)?.path().to_owned();
        let fetched = client
            .get(format!("http://{address}{path}"))
            .bearer_auth(token)
            .send()
            .await?;
        ensure!(fetched.status() == StatusCode::OK);
        ensure!(fetched.bytes().await? == b"abc".as_slice());
    }
    let request = p::request_for(&service, &input.record).await;
    service
        .withdraw(
            &input.record,
            &request,
            &p::TestPublishAccess,
            p::pg::cutoff(),
        )
        .await?;
    ensure!(
        client
            .get(format!("{url}/info/refs?service=git-upload-pack"))
            .bearer_auth(token)
            .send()
            .await?
            .status()
            == StatusCode::NOT_FOUND
    );
    let artifact_path = url::Url::parse(&artifact_url)?.path().to_owned();
    ensure!(
        client
            .get(format!("http://{address}{artifact_path}"))
            .bearer_auth(token)
            .send()
            .await?
            .status()
            == StatusCode::NOT_FOUND
    );
    // Withdrawal leaves bytes already cloned at the consumer; it revokes fresh hosted reads.
    ensure!(formula.exists());
    drop(server);
    content.close().await;
    audit_pool.close().await;
    runtime.close().await;
    Ok(())
}
