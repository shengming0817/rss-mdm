use rss_contract::Timepoint;
use rss_mdm_brew_source::*;
use rss_request_context::TenantId;
use std::{process::Command, time::Duration};
fn tenant() -> TenantId {
    TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap()
}
fn now() -> Timepoint {
    Timepoint::try_from_duration(Duration::from_secs(1700000000)).unwrap()
}
fn document(version: &str) -> Document {
    Cask::new(
        PackageKey::new(tenant(), "acme/private", "app").unwrap(),
        version,
        "App",
        "Internal app",
        "https://acme.example/",
        vec![(
            Architecture::Arm64,
            Artifact::new("https://files.example/app.pkg", [1; 32]).unwrap(),
        )],
        CaskArtifact::Pkg("App.pkg".into()),
    )
    .unwrap()
    .render()
    .unwrap()
}
async fn repository() -> (tempfile::TempDir, Repository) {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new("/usr/bin/git")
        .args(["init", "--bare", "--object-format=sha1"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let r = Repository::open(dir.path(), tenant(), "acme/private")
        .await
        .unwrap();
    (dir, r)
}
#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn git_commit_cas_replay_and_fixed_snapshot() {
    let (_dir, r) = repository().await;
    let doc = document("1");
    let p = r.prepare(None, doc.clone(), "first", now()).await.unwrap();
    assert!(r.head().await.unwrap().is_none());
    let same = r.prepare(None, doc.clone(), "first", now()).await.unwrap();
    assert_eq!(p.target(), same.target());
    assert_eq!(r.apply(&p).await.unwrap(), PublishResult::Applied);
    assert_eq!(r.apply(&same).await.unwrap(), PublishResult::AlreadyApplied);
    let snap = r.read(p.target(), &doc).await.unwrap();
    assert_eq!(snap.digest, doc.digest());
    let p2 = r
        .prepare(Some(p.target().clone()), document("2"), "second", now())
        .await
        .unwrap();
    let conflict = r
        .prepare(Some(p.target().clone()), document("3"), "third", now())
        .await
        .unwrap();
    r.apply(&p2).await.unwrap();
    assert_eq!(r.apply(&conflict).await, Err(Error::Conflict));
    assert_eq!(r.read(p.target(), &doc).await.unwrap().digest, doc.digest());
    assert_eq!(
        r.read(p2.target(), &doc).await.unwrap_err(),
        Error::DigestMismatch
    );
}
#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn response_loss_reconciles_original_commit_and_repository_binding() {
    let (dir, r) = repository().await;
    let p = r
        .prepare(None, document("1"), "first", now())
        .await
        .unwrap();
    // The update completed externally, but the caller lost its response before recording it.
    let status = Command::new("/usr/bin/git")
        .arg("--git-dir")
        .arg(dir.path())
        .args([
            "update-ref",
            "refs/heads/main",
            p.target().as_str(),
            "0000000000000000000000000000000000000000",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(r.apply(&p).await.unwrap(), PublishResult::AlreadyApplied);
    let (_other_dir, other) = repository().await;
    assert_eq!(other.apply(&p).await, Err(Error::IdentityMismatch));
    let other_tenant = TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap();
    let other = Repository::open(dir.path(), other_tenant, "acme/private")
        .await
        .unwrap();
    assert_eq!(other.apply(&p).await, Err(Error::TenantMismatch));
}

#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn symlink_tree_and_symbolic_ref_are_rejected() {
    let (dir, r) = repository().await;
    let p = r
        .prepare(None, document("1"), "first", now())
        .await
        .unwrap();
    r.apply(&p).await.unwrap();
    let git = |args: &[&str]| {
        let o = Command::new("/usr/bin/git")
            .arg("--git-dir")
            .arg(dir.path())
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success());
        String::from_utf8(o.stdout).unwrap().trim().to_owned()
    };
    git(&["update-ref", "refs/heads/other", p.target().as_str()]);
    git(&["symbolic-ref", "refs/heads/main", "refs/heads/other"]);
    assert_eq!(r.head().await, Err(Error::PathDenied));
    #[cfg(unix)]
    {
        let links = tempfile::tempdir().unwrap();
        let link = links.path().join("alias");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(matches!(
            Repository::open(&link, tenant(), "acme/private").await,
            Err(Error::PathDenied)
        ));
    }
}
