//! Native EnterpriseDesktopAppManagement MSI jobs; product software admission belongs to callers.
//! ref: Microsoft EnterpriseDesktopAppManagement CSP DownloadInstall XSD Schema.
use crate::{
    CodecError as E, CodecLimits, Result, Secret,
    native::Scope,
    syncml::{Command, Item, Meta},
    xml::Output,
};
use serde::{Deserialize, Serialize};

/// Native MSI enforcement settings. Command-line contents are intentionally not Debug-printable.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Enforcement {
    /// MSIEXEC options; never a command executed by the server.
    pub command_line: String,
    /// Native timeout in minutes.
    pub timeout_minutes: u8,
    /// Native download/installation retries.
    pub retry_count: u8,
    /// Minutes between native retries.
    pub retry_interval_minutes: u8,
    /// Whether the native download uses Microsoft Entra authentication.
    pub download_from_aad: bool,
}
/// Immutable native package/job input; it grants no right to distribute software.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallJob {
    /// MSI ProductCode UUID.
    pub product: String,
    /// Expected package version.
    pub version: String,
    /// One or more approved content locations, in native preference order.
    pub content_urls: Vec<String>,
    /// SHA-256 of the immutable MSI bytes.
    pub sha256: [u8; 32],
    /// Native installation job UUID.
    pub operation: String,
    /// Native installation scope.
    pub scope: Scope,
    /// Explicit client-side enforcement options.
    pub enforcement: Enforcement,
}
impl std::fmt::Debug for InstallJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MsiInstallJob([REDACTED])")
    }
}
/// A validated native MSI job, without a product-specific installation policy.
#[derive(Clone)]
pub struct Installer(InstallJob);
impl Installer {
    /// Validate native identities, content coordinates and bounded enforcement input.
    pub fn new(mut job: InstallJob) -> Result<Self> {
        job.product = canonical_uuid(&job.product)?;
        job.operation = canonical_uuid(&job.operation)?;
        if job.version.is_empty()
            || job.version.len() > 64
            || !job.version.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || job.sha256 == [0; 32]
            || job.content_urls.is_empty()
            || job.content_urls.len() > 16
        {
            return Err(E::InvalidValue);
        }
        crate::text(&job.enforcement.command_line, 8192, true)?;
        for url in &job.content_urls {
            let parsed = url::Url::parse(url).map_err(|_| E::InvalidValue)?;
            if url.len() > 2048
                || parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.fragment().is_some()
            {
                return Err(E::InvalidValue);
            }
        }
        Ok(Self(job))
    }
    /// Create the native DownloadInstall node.
    pub fn prepare(&self, id: u32) -> Command {
        Command::Add {
            id,
            meta: None,
            items: vec![self.item(None)],
        }
    }
    /// Execute the immutable native MSI job.
    pub fn install(&self, id: u32) -> Result<Command> {
        Ok(Command::Exec {
            id,
            meta: None,
            items: vec![self.item(Some(Secret(self.xml()?)))],
        })
    }
    fn item(&self, data: Option<Secret<String>>) -> Item {
        Item {
            target: Some(format!(
                "{}%7B{}%7D/DownloadInstall",
                root(self.0.scope),
                self.0.product.to_uppercase()
            )),
            source: None,
            meta: data.as_ref().map(|_| Meta {
                format: Some("xml".into()),
                media_type: Some("text/plain".into()),
                ..Meta::default()
            }),
            data,
        }
    }
    fn xml(&self) -> Result<String> {
        let job = &self.0;
        let limits = CodecLimits::default();
        let mut w = Output::new(limits.field_bytes, &limits);
        w.start(
            "MsiInstallJob",
            &[("id", &format!("{{{}}}", job.operation))],
        )?;
        w.start("Product", &[("Version", &job.version)])?;
        w.start("Download", &[])?;
        w.start("ContentURLList", &[])?;
        for url in &job.content_urls {
            w.scalar("ContentURL", url, 2048, false)?;
        }
        w.end("ContentURLList")?;
        w.end("Download")?;
        w.start("Validation", &[])?;
        let hash = job
            .sha256
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        w.scalar("FileHash", &hash, 64, false)?;
        w.end("Validation")?;
        w.start("Enforcement", &[])?;
        w.scalar("CommandLine", &job.enforcement.command_line, 8192, true)?;
        for (name, value) in [
            ("TimeOut", job.enforcement.timeout_minutes),
            ("RetryCount", job.enforcement.retry_count),
            ("RetryInterval", job.enforcement.retry_interval_minutes),
            (
                "DownloadFromAad",
                u8::from(job.enforcement.download_from_aad),
            ),
        ] {
            w.scalar(name, &value.to_string(), 3, false)?;
        }
        w.end("Enforcement")?;
        w.end("Product")?;
        w.end("MsiInstallJob")?;
        String::from_utf8(w.finish()?).map_err(|_| E::InvalidValue)
    }
}
fn root(scope: Scope) -> &'static str {
    match scope {
        Scope::Device => "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/",
        Scope::User => "./User/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/",
    }
}
fn canonical_uuid(value: &str) -> Result<String> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| E::InvalidValue)?;
    if id.is_nil() {
        Err(E::InvalidValue)
    } else {
        Ok(id.to_string())
    }
}
/// Build a native MSI property identity only if it exists in the fixed DDF schema.
pub fn property(scope: Scope, product: &str, property: &str) -> Result<String> {
    let template = format!("{}*/{property}", root(scope));
    if !crate::native::known_node(&template) {
        return Err(E::Unsupported);
    }
    Ok(format!(
        "{}%7B{}%7D/{property}",
        root(scope),
        canonical_uuid(product)?.to_uppercase()
    ))
}
/// Native MSI job progress, separate from delivery and Agent registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Download or enforcement is pending or running.
    Installing,
    /// Windows is waiting for a user session.
    UserRequired,
    /// Download or enforcement failed.
    Failed,
    /// Enforcement completed; product identity/version still need verification.
    Completed,
    /// An unrecognized or malformed OS status.
    Unknown,
}
/// Values defined by EnterpriseDesktopAppManagement/MSI/{ProductID}/Status.
pub fn progress(status: &str) -> Progress {
    match status {
        "10" | "20" | "25" | "40" | "50" | "55" => Progress::Installing,
        "48" => Progress::UserRequired,
        "30" | "60" => Progress::Failed,
        "70" => Progress::Completed,
        _ => Progress::Unknown,
    }
}
