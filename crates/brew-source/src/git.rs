use crate::*;
use rss_contract::Timepoint;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

#[derive(Clone, Debug, Eq, PartialEq)]
/// Nonzero lowercase SHA-1 Git identity; parsing alone does not prove object existence or type.
pub struct CommitId(String);
impl CommitId {
    /// Parse exactly 40 lowercase hexadecimal bytes, rejecting the all-zero sentinel.
    /// Invalid text returns [`Error::InvalidInput`]; no Git object is inspected.
    pub fn parse(s: &str) -> Result<Self, Error> {
        if s.len() != 40
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || s.bytes().all(|b| b == b'0')
        {
            Err(Error::InvalidInput)
        } else {
            Ok(Self(s.into()))
        }
    }
    /// Borrow the validated lowercase hexadecimal identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
/// Verified fixed-commit content. Only Repository::read can construct it.
/// ```compile_fail
/// use rss_mdm_brew_source::{Snapshot, CommitId};
/// fn forge(commit: CommitId) -> Snapshot { Snapshot { blob: commit.clone(), commit, digest: [0;32] } }
/// ```
#[derive(Clone, Debug)]
pub struct Snapshot {
    commit: CommitId,
    blob: CommitId,
    digest: [u8; 32],
}
impl Snapshot {
    /// Borrow the fixed commit inspected by [`Repository::read`].
    pub fn commit(&self) -> &CommitId {
        &self.commit
    }
    /// Borrow the SHA-1 blob identity whose bytes were checked.
    pub fn blob(&self) -> &CommitId {
        &self.blob
    }
    /// Return the SHA-256 of the verified document bytes.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
#[derive(Clone, Debug)]
/// Prepared local commit bound to the exact repository, tenant, tap and original base.
/// Retain it for [`Repository::apply`] retries and reconciliation; preparation is not publication.
pub struct Prepared {
    repository: PathBuf,
    tenant: TenantId,
    tap: String,
    base: Option<CommitId>,
    target: CommitId,
    document: Document,
}
impl Prepared {
    /// Borrow the prepared commit ID; the object may still be unreachable from main.
    pub fn target(&self) -> &CommitId {
        &self.target
    }
    /// Borrow the expected document, including for a prepared removal.
    pub fn document(&self) -> &Document {
        &self.document
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Acknowledged local main-branch update, without remote push or device installation.
pub enum PublishResult {
    /// Git acknowledged the compare-and-swap update.
    Applied,
    /// Read-back found the prepared target already at the branch head.
    AlreadyApplied,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Comparison of one controlled document at a fixed commit.
pub enum DocumentPresence {
    /// A regular blob at the expected path has exactly the expected bytes.
    Matching,
    /// A readable regular blob exists at the path but has different bytes.
    Different,
    /// No tree entry exists at the expected path.
    Absent,
}
/// Explicitly authorized, dedicated bare repository; never clones or pushes.
pub struct Repository {
    path: PathBuf,
    tenant: TenantId,
    tap: String,
}
impl Repository {
    /// Bind an existing local bare SHA-1 repository to an authorized tenant/tap.
    /// Validates the tap as in [`PackageKey::new`], rejects a symlink at the supplied
    /// path, canonicalizes it and runs Git inspection commands. Non-bare repositories
    /// return [`Error::PathDenied`]; non-SHA-1 format returns [`Error::Unsupported`].
    /// Does not clone or create a repository. The host must authorize and protect
    /// the canonical directory; path validation alone is not access control.
    pub async fn open(path: &Path, tenant: TenantId, tap_name: &str) -> Result<Self, Error> {
        tap(tap_name)?;
        if std::fs::symlink_metadata(path)
            .map_err(|_| Error::Git)?
            .file_type()
            .is_symlink()
        {
            return Err(Error::PathDenied);
        }
        let path = path.canonicalize().map_err(|_| Error::Git)?;
        let r = Self {
            path,
            tenant,
            tap: tap_name.into(),
        };
        let bare = r
            .run(&["rev-parse", "--is-bare-repository"], None, None, None)
            .await?;
        if bare != b"true\n" {
            return Err(Error::PathDenied);
        }
        let format = r
            .run(&["rev-parse", "--show-object-format"], None, None, None)
            .await?;
        if format != b"sha1\n" {
            return Err(Error::Unsupported);
        }
        Ok(r)
    }
    fn document(&self, doc: &Document) -> Result<(), Error> {
        if doc.key().tenant() != self.tenant {
            return Err(Error::TenantMismatch);
        }
        if doc.key().tap() != self.tap {
            return Err(Error::IdentityMismatch);
        }
        Ok(())
    }
    async fn object_type(&self, specification: &str) -> Result<Vec<u8>, Error> {
        let input = format!("{specification}\n");
        let out = self
            .run(
                &["cat-file", "--batch-check=%(objecttype)"],
                Some(input.as_bytes()),
                None,
                None,
            )
            .await?;
        if out == format!("{specification} missing\n").as_bytes() {
            return Err(Error::NotFound);
        }
        Ok(out)
    }
    async fn commit(&self, id: &CommitId) -> Result<(), Error> {
        if self.object_type(id.as_str()).await? != b"commit\n" {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    /// Write unreachable blob/tree/commit objects using a temporary index, without changing main.
    /// `base` is an explicit original parent (`None` for an empty tree); this does not
    /// check that main still equals it. Tenant/tap and regular-file paths must match.
    /// `operation` follows [`PackageKey::new`] token rules; `at` fixes commit metadata.
    /// Preserve base, document, operation and time to reconstruct the same target after
    /// interruption. Errors may leave unreachable objects; they do not publish a branch.
    pub async fn prepare(
        &self,
        base: Option<CommitId>,
        document: Document,
        operation: &str,
        at: Timepoint,
    ) -> Result<Prepared, Error> {
        self.prepare_change(base, document, operation, at, false)
            .await
    }
    /// Prepare removal after [`Self::read`] verifies exact document bytes at `base`.
    /// Uses the same operation/time rules and object-write effects as [`Self::prepare`].
    /// Wrong bytes, missing objects, unsafe paths and provider failures remain errors;
    /// the branch is untouched until [`Self::apply`].
    pub async fn prepare_remove(
        &self,
        base: CommitId,
        document: Document,
        operation: &str,
        at: Timepoint,
    ) -> Result<Prepared, Error> {
        self.read(&base, &document).await?;
        self.prepare_change(Some(base), document, operation, at, true)
            .await
    }
    async fn prepare_change(
        &self,
        base: Option<CommitId>,
        document: Document,
        operation: &str,
        at: Timepoint,
        remove: bool,
    ) -> Result<Prepared, Error> {
        self.document(&document)?;
        token(operation)?;
        if let Some(b) = &base {
            self.commit(b).await?;
            self.check_path(b, &document).await?;
        }
        let temp = tempfile::tempdir().map_err(|_| Error::Git)?;
        let index = temp.path().join("index");
        if let Some(b) = &base {
            self.run(&["read-tree", b.as_str()], None, Some(&index), None)
                .await?;
        } else {
            self.run(&["read-tree", "--empty"], None, Some(&index), None)
                .await?;
        }
        if remove {
            let deletion = format!(
                "0 0000000000000000000000000000000000000000\t{}\n",
                document.path()
            );
            self.run(
                &["update-index", "--index-info"],
                Some(deletion.as_bytes()),
                Some(&index),
                None,
            )
            .await?;
        } else {
            let blob = self
                .run(
                    &["hash-object", "-w", "--stdin"],
                    Some(document.bytes()),
                    None,
                    None,
                )
                .await?;
            let blob = output_id(&blob)?;
            self.run(
                &[
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    "100644",
                    blob.as_str(),
                    document.path(),
                ],
                None,
                Some(&index),
                None,
            )
            .await?;
        }
        let tree = self.run(&["write-tree"], None, Some(&index), None).await?;
        let tree = output_id(&tree)?;
        let mut args = vec!["commit-tree", tree.as_str()];
        if let Some(b) = &base {
            args.extend(["-p", b.as_str()]);
        }
        let message = format!(
            "resource metadata v1\ntenant: {}\ntap: {}\noperation: {operation}\naction: {}\n",
            self.tenant,
            self.tap,
            if remove { "remove" } else { "publish" }
        );
        let target = output_id(
            &self
                .run(&args, Some(message.as_bytes()), None, Some(at))
                .await?,
        )?;
        Ok(Prepared {
            repository: self.path.clone(),
            tenant: self.tenant,
            tap: self.tap.clone(),
            base,
            target,
            document,
        })
    }
    async fn check_path(&self, commit: &CommitId, doc: &Document) -> Result<(), Error> {
        let directory = doc.path().split('/').next().ok_or(Error::PathDenied)?;
        for (path, mode) in [(directory, "040000"), (doc.path(), "100644")] {
            let out = self
                .run(&["ls-tree", commit.as_str(), "--", path], None, None, None)
                .await?;
            if !out.is_empty() && !out.starts_with(mode.as_bytes()) {
                return Err(Error::PathDenied);
            }
        }
        Ok(())
    }
    fn prepared(&self, p: &Prepared) -> Result<(), Error> {
        if p.tenant != self.tenant {
            return Err(Error::TenantMismatch);
        }
        if p.repository != self.path || p.tap != self.tap {
            return Err(Error::IdentityMismatch);
        }
        self.document(&p.document)
    }
    /// Read the real `refs/heads/main` reference, returning `None` if absent.
    /// Rejects symbolic/unexpected references with [`Error::PathDenied`]; provider
    /// failures remain errors. Does not modify the branch or inspect a remote.
    pub async fn head(&self) -> Result<Option<CommitId>, Error> {
        let out = self
            .run(
                &[
                    "for-each-ref",
                    "--format=%(objectname) %(refname) %(symref)",
                    "refs/heads/main",
                ],
                None,
                None,
                None,
            )
            .await?;
        if out.is_empty() {
            Ok(None)
        } else {
            let line = std::str::from_utf8(&out).map_err(|_| Error::Git)?;
            let fields: Vec<_> = line.trim_end_matches('\n').split(' ').collect();
            if fields.len() != 3 || fields[1] != "refs/heads/main" || !fields[2].is_empty() {
                return Err(Error::PathDenied);
            }
            CommitId::parse(fields[0]).map(Some)
        }
    }
    /// Compare and swap main from the original parent to the prepared target.
    /// Checks repository/tap/tenant binding before I/O. An existing target head returns
    /// [`PublishResult::AlreadyApplied`]; a different base returns [`Error::Conflict`].
    /// After an update error, read-back may establish success or conflict; otherwise
    /// returns [`Error::OutcomeUnknown`]. Cancellation may also interrupt after an effect.
    /// Retain the same [`Prepared`] and reconcile head/reachability before retrying;
    /// never replace the operation identity merely because acknowledgement was lost.
    pub async fn apply(&self, p: &Prepared) -> Result<PublishResult, Error> {
        self.apply_with(p, self.update_ref(p)).await
    }
    // Narrow command-result seam: the future is first polled after the original-head check.
    // Production always supplies the real Git CAS; fault injection stays private to tests.
    async fn apply_with(
        &self,
        p: &Prepared,
        update: impl std::future::Future<Output = Result<Vec<u8>, Error>>,
    ) -> Result<PublishResult, Error> {
        self.prepared(p)?;
        let current = self.head().await?;
        if current.as_ref() == Some(&p.target) {
            return Ok(PublishResult::AlreadyApplied);
        }
        if current != p.base {
            return Err(Error::Conflict);
        }
        match update.await {
            Ok(_) => Ok(PublishResult::Applied),
            Err(_) => match self.head().await {
                Ok(Some(head)) if head == p.target => Ok(PublishResult::AlreadyApplied),
                Ok(head) if head != p.base => Err(Error::Conflict),
                _ => Err(Error::OutcomeUnknown),
            },
        }
    }
    async fn update_ref(&self, p: &Prepared) -> Result<Vec<u8>, Error> {
        let old = p
            .base
            .as_ref()
            .map_or("0000000000000000000000000000000000000000", CommitId::as_str);
        self.run(
            &[
                "update-ref",
                "--no-deref",
                "refs/heads/main",
                p.target.as_str(),
                old,
            ],
            None,
            None,
            None,
        )
        .await
    }
    /// Inspect a fixed commit and compare its regular blob with the exact expected bytes.
    /// Checks tenant/tap, object types, safe tree modes and [`MAX_DOCUMENT`] before
    /// returning a [`Snapshot`]. Missing objects, unsafe paths, oversized content and
    /// mismatched bytes remain distinct errors. Performs local Git reads; this does
    /// not prove the commit is reachable from main or published remotely.
    pub async fn read(&self, commit: &CommitId, expected: &Document) -> Result<Snapshot, Error> {
        self.document(expected)?;
        self.commit(commit).await?;
        self.check_path(commit, expected).await?;
        let path = format!("{}:{}", commit.as_str(), expected.path());
        if self.object_type(&path).await? != b"blob\n" {
            return Err(Error::PathDenied);
        }
        let blob = output_id(
            &self
                .run(&["rev-parse", "--verify", &path], None, None, None)
                .await?,
        )?;
        let size = self
            .run(&["cat-file", "-s", blob.as_str()], None, None, None)
            .await?;
        let size = std::str::from_utf8(&size)
            .map_err(|_| Error::Git)?
            .trim()
            .parse::<usize>()
            .map_err(|_| Error::Git)?;
        if size > MAX_DOCUMENT {
            return Err(Error::BudgetExceeded);
        }
        let bytes = self
            .run(&["cat-file", "blob", blob.as_str()], None, None, None)
            .await?;
        if bytes != expected.bytes() {
            return Err(Error::DigestMismatch);
        }
        Ok(Snapshot {
            commit: commit.clone(),
            blob,
            digest: expected.digest(),
        })
    }
    /// Inspect a fixed commit without conflating absent content and provider errors.
    /// Uses [`Self::read`] validation for present content; only a byte mismatch becomes
    /// [`DocumentPresence::Different`]. Tenant, object, path and provider errors propagate.
    /// Performs local reads without changing the branch.
    pub async fn presence(
        &self,
        commit: &CommitId,
        expected: &Document,
    ) -> Result<DocumentPresence, Error> {
        self.document(expected)?;
        self.commit(commit).await?;
        self.check_path(commit, expected).await?;
        let out = self
            .run(
                &["ls-tree", commit.as_str(), "--", expected.path()],
                None,
                None,
                None,
            )
            .await?;
        if out.is_empty() {
            return Ok(DocumentPresence::Absent);
        }
        match self.read(commit, expected).await {
            Ok(_) => Ok(DocumentPresence::Matching),
            Err(Error::DigestMismatch) => Ok(DocumentPresence::Different),
            Err(e) => Err(e),
        }
    }
    /// Check whether an existing commit is an ancestor of the current real main branch.
    /// Returns `false` for an absent main or a non-ancestor; missing/invalid target
    /// objects and provider failures are errors. Performs local Git reads only.
    /// Use with the retained target to reconcile writes whose acknowledgement was lost;
    /// a prepared object alone is not proof of publication.
    pub async fn contains_commit(&self, target: &CommitId) -> Result<bool, Error> {
        self.commit(target).await?;
        let Some(head) = self.head().await? else {
            return Ok(false);
        };
        match self
            .run(
                &[
                    "merge-base",
                    "--is-ancestor",
                    target.as_str(),
                    head.as_str(),
                ],
                None,
                None,
                None,
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(Error::GitFailure {
                exit_code: Some(1), ..
            }) => Ok(false),
            Err(e) => Err(e),
        }
    }
    async fn run(
        &self,
        args: &[&str],
        input: Option<&[u8]>,
        index: Option<&Path>,
        at: Option<Timepoint>,
    ) -> Result<Vec<u8>, Error> {
        let stage = match args.first().copied() {
            Some("read-tree") => GitStage::ReadTree,
            Some("hash-object") => GitStage::HashObject,
            Some("update-index") => GitStage::UpdateIndex,
            Some("write-tree") => GitStage::WriteTree,
            Some("commit-tree") => GitStage::CommitTree,
            Some("for-each-ref") => GitStage::ReadRef,
            Some("update-ref") => GitStage::UpdateRef,
            Some("cat-file" | "ls-tree") => GitStage::ReadObject,
            _ => GitStage::Inspect,
        };
        let failure = Error::GitFailure {
            stage,
            exit_code: None,
        };
        let mut command = Command::new("/usr/bin/git");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_COUNT", "0")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_ALLOW_PROTOCOL", "file")
            .arg("--git-dir")
            .arg(&self.path)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.attributesFile=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if let Some(index) = index {
            command.env("GIT_INDEX_FILE", index);
        }
        if let Some(at) = at {
            let date = format!("@{} +0000", at.unix_seconds());
            for role in ["AUTHOR", "COMMITTER"] {
                command
                    .env(format!("GIT_{role}_NAME"), "RSS MDM")
                    .env(format!("GIT_{role}_EMAIL"), "resource@invalid")
                    .env(format!("GIT_{role}_DATE"), &date);
            }
        }
        let mut child = command.spawn().map_err(|_| failure)?;
        let mut stdin = child.stdin.take().ok_or(failure)?;
        let stdout = child.stdout.take().ok_or(failure)?;
        let operation = async {
            let writer = async {
                if let Some(input) = input {
                    stdin.write_all(input).await.map_err(|_| failure)?;
                }
                drop(stdin);
                Ok::<_, Error>(())
            };
            let reader = async {
                let mut out = Vec::new();
                stdout
                    .take((MAX_DOCUMENT + 1) as u64)
                    .read_to_end(&mut out)
                    .await
                    .map_err(|_| failure)?;
                if out.len() > MAX_DOCUMENT {
                    return Err(Error::BudgetExceeded);
                }
                Ok(out)
            };
            let (_, out) = tokio::try_join!(writer, reader)?;
            let status = child.wait().await.map_err(|_| failure)?;
            if !status.success() {
                return Err(Error::GitFailure {
                    stage,
                    exit_code: status.code(),
                });
            }
            Ok(out)
        };
        match tokio::time::timeout(Duration::from_secs(10), operation).await {
            Ok(Ok(out)) => Ok(out),
            result => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                match result {
                    Ok(Err(e)) => Err(e),
                    _ => Err(Error::GitTimeout(stage)),
                }
            }
        }
    }
}
fn output_id(out: &[u8]) -> Result<CommitId, Error> {
    CommitId::parse(std::str::from_utf8(out).map_err(|_| Error::Git)?.trim())
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "explicit real-provider T2 target"]
    async fn update_ref_response_loss_reconciles_the_actual_post_failure_head() {
        use std::cell::Cell;
        let dir = tempfile::tempdir().unwrap();
        assert!(
            Command::new("/usr/bin/git")
                .args(["init", "--bare", "--object-format=sha1"])
                .arg(dir.path())
                .output()
                .await
                .unwrap()
                .status
                .success()
        );
        let tenant = TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap();
        let r = Repository::open(dir.path(), tenant, "acme/private")
            .await
            .unwrap();
        let document = Cask::new(
            PackageKey::new(tenant, "acme/private", "app").unwrap(),
            "1",
            "App",
            "App package",
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
        .unwrap();
        let at = Timepoint::try_from_duration(Duration::from_secs(1700000000)).unwrap();
        let p = r
            .prepare(None, document.clone(), "first", at)
            .await
            .unwrap();
        let other = r
            .prepare(None, document.clone(), "concurrent", at)
            .await
            .unwrap();
        let failure = Error::GitFailure {
            stage: GitStage::UpdateRef,
            exit_code: None,
        };
        let called = Cell::new(0);
        // No update occurred: the failure branch must report uncertainty, retaining the base.
        assert_eq!(
            r.apply_with(&p, async {
                called.set(called.get() + 1);
                Err(failure)
            })
            .await,
            Err(Error::OutcomeUnknown)
        );
        assert_eq!(called.get(), 1);
        assert_eq!(r.head().await.unwrap(), None);
        // The real CAS ran, but its result was lost before the caller observed success.
        assert_eq!(
            r.apply_with(&p, async {
                called.set(called.get() + 1);
                r.update_ref(&p).await.unwrap();
                Err(failure)
            })
            .await,
            Ok(PublishResult::AlreadyApplied)
        );
        assert_eq!(called.get(), 2);
        assert_eq!(r.head().await.unwrap().as_ref(), Some(p.target()));
        assert_eq!(
            r.read(p.target(), &document).await.unwrap().digest(),
            document.digest()
        );
        // Replaying a completed target must not poll another command.
        assert_eq!(
            r.apply_with(&p, async { panic!("replay must not update ref") })
                .await,
            Ok(PublishResult::AlreadyApplied)
        );
        r.run(
            &["update-ref", "-d", "refs/heads/main", p.target().as_str()],
            None,
            None,
            None,
        )
        .await
        .unwrap();
        // A competing writer moves the ref only after apply read the original base.
        assert_eq!(
            r.apply_with(&p, async {
                called.set(called.get() + 1);
                r.update_ref(&other).await.unwrap();
                Err(failure)
            })
            .await,
            Err(Error::Conflict)
        );
        assert_eq!(called.get(), 3);
        assert_eq!(r.head().await.unwrap().as_ref(), Some(other.target()));
    }
}
