use crate::*;
use sha2::{Digest as _, Sha256};

fn text(s: &str) -> Result<(), Error> {
    if s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control) {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
fn version(s: &str) -> Result<(), Error> {
    if s.is_empty()
        || s.len() > 128
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
fn url(s: &str) -> Result<(), Error> {
    let u = url::Url::parse(s).map_err(|_| Error::InvalidInput)?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(Error::InvalidInput);
    }
    text(s)
}
// Double-quoted Ruby literals: escape interpolation as well as quotes/backslashes.
fn quote(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('#', "\\#")
    )
}
fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}
#[derive(Clone, Eq, PartialEq)]
pub struct Artifact {
    url: String,
    sha256: [u8; 32],
}
impl Artifact {
    pub fn new(location: &str, sha256: [u8; 32]) -> Result<Self, Error> {
        url(location)?;
        Ok(Self {
            url: location.into(),
            sha256,
        })
    }
    pub fn url(&self) -> &str {
        &self.url
    }
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<(), Error> {
        if <[u8; 32]>::from(Sha256::digest(bytes)) == self.sha256 {
            Ok(())
        } else {
            Err(Error::DigestMismatch)
        }
    }
}
impl fmt::Debug for Artifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Artifact")
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum BottleTag {
    Arm64Sonoma,
    Sonoma,
}
impl BottleTag {
    fn symbol(self) -> &'static str {
        match self {
            Self::Arm64Sonoma => "arm64_sonoma",
            Self::Sonoma => "sonoma",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bottle {
    tag: BottleTag,
    root_url: String,
    sha256: [u8; 32],
}
impl Bottle {
    pub fn new(tag: BottleTag, root_url: &str, sha256: [u8; 32]) -> Result<Self, Error> {
        url(root_url)?;
        Ok(Self {
            tag,
            root_url: root_url.into(),
            sha256,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaskArtifact {
    App(String),
    /// Exact pkgutil receipt IDs, never arbitrary shell or Ruby.
    Pkg {
        path: String,
        receipts: Vec<String>,
    },
}
impl CaskArtifact {
    fn validate(&self) -> Result<(), Error> {
        let (s, suffix) = match self {
            Self::App(s) => (s, ".app"),
            Self::Pkg { path, receipts } => {
                if receipts.is_empty() || receipts.len() > 32 {
                    return Err(Error::InvalidInput);
                }
                let mut seen = std::collections::BTreeSet::new();
                for id in receipts {
                    if id.len() > 255
                        || id.split('.').count() < 2
                        || id.split('.').any(|s| {
                            s.is_empty()
                                || !s
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                        })
                        || !seen.insert(id)
                    {
                        return Err(Error::InvalidInput);
                    }
                }
                (path, ".pkg")
            }
        };
        if s.len() > 128
            || !s.ends_with(suffix)
            || s.starts_with('.')
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" ._-".contains(&b))
        {
            return Err(Error::PathDenied);
        }
        Ok(())
    }
    fn render(&self) -> String {
        match self {
            Self::App(s) => format!("app {}", quote(s)),
            Self::Pkg { path, receipts } => {
                let mut receipts = receipts.clone();
                receipts.sort();
                let patterns = receipts
                    .iter()
                    .map(|id| quote(&format!("^{}$", id.replace('.', "\\."))))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("pkg {}\n  uninstall pkgutil: [{}]", quote(path), patterns)
            }
        }
    }
}
#[derive(Clone, Debug)]
pub struct Cask {
    key: PackageKey,
    version: String,
    name: String,
    description: String,
    homepage: String,
    artifacts: Vec<(Architecture, Artifact)>,
    install: CaskArtifact,
}
impl Cask {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: PackageKey,
        release: &str,
        name: &str,
        description: &str,
        homepage: &str,
        mut artifacts: Vec<(Architecture, Artifact)>,
        install: CaskArtifact,
    ) -> Result<Self, Error> {
        version(release)?;
        text(name)?;
        text(description)?;
        url(homepage)?;
        install.validate()?;
        if artifacts.is_empty() || artifacts.len() > 2 {
            return Err(Error::InvalidInput);
        }
        artifacts.sort_by_key(|a| a.0);
        if artifacts.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(Error::Duplicate);
        }
        Ok(Self {
            key,
            version: release.into(),
            name: name.into(),
            description: description.into(),
            homepage: homepage.into(),
            artifacts,
            install,
        })
    }
    pub fn render(&self) -> Result<Document, Error> {
        let mut s = format!(
            "cask {} do\n  version {}\n  name {}\n  desc {}\n  homepage {}\n",
            quote(&self.key.name),
            quote(&self.version),
            quote(&self.name),
            quote(&self.description),
            quote(&self.homepage)
        );
        if self.artifacts.len() == 1 {
            s.push_str(match self.artifacts[0].0 {
                Architecture::Arm64 => "  depends_on arch: :arm64\n",
                Architecture::Intel => "  depends_on arch: :x86_64\n",
            });
        }
        for (arch, a) in &self.artifacts {
            s.push_str(&format!(
                "\n  {} do\n    url {}\n    sha256 {}\n  end\n",
                match arch {
                    Architecture::Arm64 => "on_arm",
                    Architecture::Intel => "on_intel",
                },
                quote(&a.url),
                quote(&hex(&a.sha256))
            ));
        }
        s.push_str(&format!("\n  {}\nend\n", self.install.render()));
        Document::new(self.key.clone(), format!("Casks/{}.rb", self.key.name), s)
    }
}
#[derive(Clone, Debug)]
pub struct Formula {
    key: PackageKey,
    version: String,
    description: String,
    homepage: String,
    source: Artifact,
    executable: String,
    bottles: Vec<Bottle>,
    dependencies: Vec<PackageKey>,
}
impl Formula {
    /// Fixed template installs one prebuilt executable from the source archive.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: PackageKey,
        release: &str,
        description: &str,
        homepage: &str,
        source: Artifact,
        executable: &str,
        mut bottles: Vec<Bottle>,
        mut dependencies: Vec<PackageKey>,
    ) -> Result<Self, Error> {
        version(release)?;
        text(description)?;
        url(homepage)?;
        token(executable)?;
        if bottles.is_empty() || bottles.len() > 2 || dependencies.len() > 64 {
            return Err(Error::InvalidInput);
        }
        bottles.sort_by_key(|b| b.tag);
        if bottles.windows(2).any(|w| w[0].tag == w[1].tag) {
            return Err(Error::Duplicate);
        }
        if bottles.iter().any(|b| b.root_url != bottles[0].root_url) {
            return Err(Error::Unsupported);
        }
        if dependencies.iter().any(|d| d.tenant != key.tenant) {
            return Err(Error::TenantMismatch);
        }
        if dependencies.iter().any(|d| d == &key) {
            return Err(Error::InvalidInput);
        }
        dependencies.sort_by(|a, b| (&a.tap, &a.name).cmp(&(&b.tap, &b.name)));
        if dependencies.windows(2).any(|w| w[0] == w[1]) {
            return Err(Error::Duplicate);
        }
        Ok(Self {
            key,
            version: release.into(),
            description: description.into(),
            homepage: homepage.into(),
            source,
            executable: executable.into(),
            bottles,
            dependencies,
        })
    }
    pub fn render(&self) -> Result<Document, Error> {
        let class = self
            .key
            .name
            .split('-')
            .map(|s| {
                let mut c = s.chars();
                c.next()
                    .map(|v| v.to_ascii_uppercase().to_string() + c.as_str())
                    .unwrap_or_default()
            })
            .collect::<String>();
        let mut s = format!(
            "class {class} < Formula\n  desc {}\n  homepage {}\n  url {}\n  version {}\n  sha256 {}\n\n  bottle do\n    root_url {}\n",
            quote(&self.description),
            quote(&self.homepage),
            quote(&self.source.url),
            quote(&self.version),
            quote(&hex(&self.source.sha256)),
            quote(&self.bottles[0].root_url)
        );
        for b in &self.bottles {
            s.push_str(&format!(
                "    sha256 {}: {}\n",
                b.tag.symbol(),
                quote(&hex(&b.sha256))
            ));
        }
        s.push_str("  end\n");
        for d in &self.dependencies {
            s.push_str(&format!(
                "  depends_on {}\n",
                quote(&format!("{}/{}", d.tap, d.name))
            ));
        }
        s.push_str(&format!(
            "\n  def install\n    bin.install {}\n  end\nend\n",
            quote(&self.executable)
        ));
        Document::new(self.key.clone(), format!("Formula/{}.rb", self.key.name), s)
    }
}
/// Only the controlled renderers can create a Git-writeable document.
#[derive(Clone, Eq, PartialEq)]
pub struct Document {
    key: PackageKey,
    path: String,
    bytes: Vec<u8>,
    digest: [u8; 32],
}
impl Document {
    fn new(key: PackageKey, path: String, text: String) -> Result<Self, Error> {
        if text.len() > MAX_DOCUMENT {
            return Err(Error::BudgetExceeded);
        }
        let bytes = text.into_bytes();
        let digest = Sha256::digest(&bytes).into();
        Ok(Self {
            key,
            path,
            bytes,
            digest,
        })
    }
    pub fn key(&self) -> &PackageKey {
        &self.key
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
impl fmt::Debug for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Document")
            .field("key", &self.key)
            .field("path", &self.path)
            .field("digest", &self.digest)
            .finish()
    }
}
