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
pub struct CommitId(String);
impl CommitId {
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
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub commit: CommitId,
    pub blob: CommitId,
    pub digest: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct Prepared {
    repository: PathBuf,
    tenant: TenantId,
    tap: String,
    base: Option<CommitId>,
    target: CommitId,
    document: Document,
}
impl Prepared {
    pub fn target(&self) -> &CommitId {
        &self.target
    }
    pub fn document(&self) -> &Document {
        &self.document
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishResult {
    Applied,
    AlreadyApplied,
}
/// Explicitly authorized, dedicated bare repository; never clones or pushes.
pub struct Repository {
    path: PathBuf,
    tenant: TenantId,
    tap: String,
}
impl Repository {
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
    async fn commit(&self, id: &CommitId) -> Result<(), Error> {
        if self
            .run(&["cat-file", "-t", id.as_str()], None, None, None)
            .await?
            != b"commit\n"
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    /// Writes unreachable objects first. No branch mutation occurs during preparation.
    pub async fn prepare(
        &self,
        base: Option<CommitId>,
        document: Document,
        operation: &str,
        at: Timepoint,
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
        let tree = self.run(&["write-tree"], None, Some(&index), None).await?;
        let tree = output_id(&tree)?;
        let mut args = vec!["commit-tree", tree.as_str()];
        if let Some(b) = &base {
            args.extend(["-p", b.as_str()]);
        }
        let message = format!(
            "resource metadata v1\ntenant: {}\ntap: {}\noperation: {operation}\n",
            self.tenant, self.tap
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
    /// CAS against the original parent. Caller retains Prepared for unknown-result recovery.
    pub async fn apply(&self, p: &Prepared) -> Result<PublishResult, Error> {
        self.prepared(p)?;
        let current = self.head().await?;
        if current.as_ref() == Some(&p.target) {
            return Ok(PublishResult::AlreadyApplied);
        }
        if current != p.base {
            return Err(Error::Conflict);
        }
        let old = p
            .base
            .as_ref()
            .map_or("0000000000000000000000000000000000000000", CommitId::as_str);
        match self
            .run(
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
        {
            Ok(_) => Ok(PublishResult::Applied),
            Err(_) => match self.head().await {
                Ok(Some(head)) if head == p.target => Ok(PublishResult::AlreadyApplied),
                Ok(head) if head != p.base => Err(Error::Conflict),
                _ => Err(Error::OutcomeUnknown),
            },
        }
    }
    /// Read a fixed commit and prove it contains the expected controlled document.
    pub async fn read(&self, commit: &CommitId, expected: &Document) -> Result<Snapshot, Error> {
        self.document(expected)?;
        self.commit(commit).await?;
        self.check_path(commit, expected).await?;
        let path = format!("{}:{}", commit.as_str(), expected.path());
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
    async fn run(
        &self,
        args: &[&str],
        input: Option<&[u8]>,
        index: Option<&Path>,
        at: Option<Timepoint>,
    ) -> Result<Vec<u8>, Error> {
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
        let mut child = command.spawn().map_err(|_| Error::Git)?;
        let mut stdin = child.stdin.take().ok_or(Error::Git)?;
        let stdout = child.stdout.take().ok_or(Error::Git)?;
        let operation = async {
            let writer = async {
                if let Some(input) = input {
                    stdin.write_all(input).await.map_err(|_| Error::Git)?;
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
                    .map_err(|_| Error::Git)?;
                if out.len() > MAX_DOCUMENT {
                    return Err(Error::BudgetExceeded);
                }
                Ok(out)
            };
            let (_, out) = tokio::try_join!(writer, reader)?;
            if !child.wait().await.map_err(|_| Error::Git)?.success() {
                return Err(Error::Git);
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
                    _ => Err(Error::Timeout),
                }
            }
        }
    }
}
fn output_id(out: &[u8]) -> Result<CommitId, Error> {
    CommitId::parse(std::str::from_utf8(out).map_err(|_| Error::Git)?.trim())
}
