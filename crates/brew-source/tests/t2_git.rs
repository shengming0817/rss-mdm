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
        CaskArtifact::Pkg {
            path: "App.pkg".into(),
            receipts: vec!["com.acme.app".into()],
        },
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
    assert_eq!(snap.digest(), doc.digest());
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
    assert_eq!(
        r.read(p.target(), &doc).await.unwrap().digest(),
        doc.digest()
    );
    assert_eq!(
        r.read(p2.target(), &doc).await.unwrap_err(),
        Error::DigestMismatch
    );
}
#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn prepared_commit_is_bound_to_repository_and_tenant() {
    let (dir, r) = repository().await;
    let p = r
        .prepare(None, document("1"), "first", now())
        .await
        .unwrap();
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

#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn git_tree_modes_cannot_replace_a_directory_or_document() {
    use std::io::Write;
    use std::process::Stdio;
    let (dir, r) = repository().await;
    let git = |args: &[&str], input: &str| {
        let mut c = Command::new("/usr/bin/git")
            .arg("--git-dir")
            .arg(dir.path())
            .args(args)
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@invalid")
            .env("GIT_AUTHOR_DATE", "@1700000000 +0000")
            .env("GIT_COMMITTER_DATE", "@1700000000 +0000")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        let out = c.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    let blob = git(&["hash-object", "-w", "--stdin"], "outside");
    for root in [
        git(&["mktree"], &format!("120000 blob {blob}\tCasks\n")),
        git(&["mktree"], &format!("100644 blob {blob}\tCasks\n")),
        {
            let tree = git(&["mktree"], &format!("120000 blob {blob}\tapp.rb\n"));
            git(&["mktree"], &format!("040000 tree {tree}\tCasks\n"))
        },
        {
            let tree = git(&["mktree"], &format!("100755 blob {blob}\tapp.rb\n"));
            git(&["mktree"], &format!("040000 tree {tree}\tCasks\n"))
        },
    ] {
        let commit = CommitId::parse(&git(&["commit-tree", &root], "malicious tree\n")).unwrap();
        assert_eq!(
            r.prepare(Some(commit.clone()), document("1"), "first", now())
                .await
                .unwrap_err(),
            Error::PathDenied
        );
        assert_eq!(
            r.read(&commit, &document("1")).await.unwrap_err(),
            Error::PathDenied
        );
    }
}

#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn git_failure_reports_safe_stage_without_raw_diagnostics() {
    let (_dir, r) = repository().await;
    let missing = CommitId::parse("1111111111111111111111111111111111111111").unwrap();
    assert_eq!(
        r.prepare(Some(missing), document("1"), "first", now())
            .await
            .unwrap_err(),
        Error::NotFound
    );
    let invalid = tempfile::tempdir().unwrap();
    let error = match Repository::open(invalid.path(), tenant(), "acme/private").await {
        Err(error) => error,
        Ok(_) => panic!("non repository accepted"),
    };
    assert!(matches!(
        error,
        Error::GitFailure {
            stage: GitStage::Inspect,
            exit_code: Some(_)
        }
    ));
    assert!(!error.to_string().contains(invalid.path().to_str().unwrap()));
}

#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn conditional_removal_preserves_other_paths_and_old_commits() {
    let (_dir, r) = repository().await;
    let doc = document("1");
    let first = r
        .prepare(None, doc.clone(), "initial", now())
        .await
        .unwrap();
    r.apply(&first).await.unwrap();
    let other = Cask::new(
        PackageKey::new(tenant(), "acme/private", "other").unwrap(),
        "1",
        "Other",
        "Other app",
        "https://acme.example/",
        vec![(
            Architecture::Arm64,
            Artifact::new("https://files.example/other.dmg", [2; 32]).unwrap(),
        )],
        CaskArtifact::App("Other.app".into()),
    )
    .unwrap()
    .render()
    .unwrap();
    let next = r
        .prepare(Some(first.target().clone()), other.clone(), "other", now())
        .await
        .unwrap();
    r.apply(&next).await.unwrap();
    let remove = r
        .prepare_remove(next.target().clone(), doc.clone(), "remove", now())
        .await
        .unwrap();
    r.apply(&remove).await.unwrap();
    assert_eq!(
        r.presence(remove.target(), &doc).await.unwrap(),
        DocumentPresence::Absent
    );
    r.read(remove.target(), &other).await.unwrap();
    r.read(first.target(), &doc).await.unwrap();
    assert!(r.contains_commit(first.target()).await.unwrap());
    assert!(matches!(
        r.prepare_remove(remove.target().clone(), doc, "again", now())
            .await,
        Err(Error::NotFound)
    ));
    assert_eq!(r.head().await.unwrap().as_ref(), Some(remove.target()));
}

#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn immutable_snapshot_has_only_frozen_documents_and_replays_after_later_publish() {
    let (dir, repo) = repository().await;
    let old = Cask::new(
        PackageKey::new(tenant(), "acme/private", "retired").unwrap(),
        "1",
        "Retired",
        "Old app",
        "https://acme.example/",
        vec![(
            Architecture::Arm64,
            Artifact::new("https://files.example/old.pkg", [2; 32]).unwrap(),
        )],
        CaskArtifact::Pkg {
            path: "Old.pkg".into(),
            receipts: vec!["com.acme.old".into()],
        },
    )
    .unwrap()
    .render()
    .unwrap();
    let first = repo
        .prepare_snapshot(None, vec![document("1"), old.clone()], "first", now())
        .await
        .unwrap();
    repo.apply(&first).await.unwrap();
    let second = repo
        .prepare_snapshot(
            Some(first.target().clone()),
            vec![document("2")],
            "second",
            now(),
        )
        .await
        .unwrap();
    repo.apply(&second).await.unwrap();
    assert_eq!(
        repo.apply(&first).await.unwrap(),
        PublishResult::AlreadyApplied
    );
    let history = Command::new("/usr/bin/git")
        .arg("--git-dir")
        .arg(dir.path())
        .args(["rev-list", "--count", second.target().as_str()])
        .output()
        .unwrap();
    assert!(history.status.success());
    assert_eq!(history.stdout, b"1\n");
    let tree = Command::new("/usr/bin/git")
        .arg("--git-dir")
        .arg(dir.path())
        .args(["ls-tree", "-r", "--name-only", second.target().as_str()])
        .output()
        .unwrap();
    assert!(tree.status.success());
    assert_eq!(
        String::from_utf8(tree.stdout).unwrap(),
        format!("{}\n", document("2").path())
    );
    assert_eq!(
        repo.read(second.target(), &document("2"))
            .await
            .unwrap()
            .digest(),
        document("2").digest()
    );
    assert!(matches!(
        repo.read(second.target(), &old).await,
        Err(Error::NotFound)
    ));
    assert!(repo.snapshot_exists(first.target()).await.unwrap());
    repo.withdraw_snapshot(first.target()).await.unwrap();
    assert!(!repo.snapshot_exists(first.target()).await.unwrap());
    assert!(repo.snapshot_exists(second.target()).await.unwrap());
}

#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn readonly_upload_pack_advertises_only_the_selected_snapshot() {
    let (_dir, repo) = repository().await;
    let first = repo
        .prepare_snapshot(None, vec![document("1")], "first", now())
        .await
        .unwrap();
    repo.apply(&first).await.unwrap();
    let second = repo
        .prepare_snapshot(
            Some(first.target().clone()),
            vec![document("2")],
            "second",
            now(),
        )
        .await
        .unwrap();
    repo.apply(&second).await.unwrap();
    let advertised = repo
        .upload_pack(first.target(), true, false, &[])
        .await
        .unwrap();
    let text = String::from_utf8(advertised).unwrap();
    assert!(text.contains(first.target().as_str()));
    assert!(!text.contains(second.target().as_str()));
    assert!(text.contains("refs/heads/main"));
    repo.withdraw_snapshot(first.target()).await.unwrap();
    assert!(matches!(
        repo.upload_pack(first.target(), true, false, &[]).await,
        Err(Error::NotFound)
    ));
}
