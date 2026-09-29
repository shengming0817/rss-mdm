//! Closed Agent MSI compiler for EnterpriseDesktopAppManagement. No arbitrary command line.
//! ref: Microsoft EnterpriseDesktopAppManagement CSP, MsiInstallJob.
use crate::{
    CodecError as E, CodecLimits, Result, Secret,
    syncml::{Command, Item, Meta},
    xml::{Input, Output},
};
const ROOT: &str = "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/";
/// A validated fixed Agent installer. Product approval and identity pinning belong to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installer {
    product: String,
    version: String,
    url: String,
    hash: [u8; 32],
    operation: String,
}
impl Installer {
    /// Validate product/version/hash/content location and the public installation coordinate.
    pub fn new(
        product: &str,
        version: &str,
        url: &str,
        hash: [u8; 32],
        operation: &str,
    ) -> Result<Self> {
        let product = canonical_uuid(product)?;
        let operation = canonical_uuid(operation)?;
        if version.is_empty()
            || version.len() > 64
            || !version.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || hash == [0; 32]
        {
            return Err(E::InvalidValue);
        }
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
        Ok(Self {
            product,
            version: version.into(),
            url: url.into(),
            hash,
            operation,
        })
    }
    /// Add the DownloadInstall node before executing its fixed job.
    pub fn prepare(&self, id: u32) -> Command {
        Command::AgentInstall {
            id,
            command: AgentCommand::Prepare {
                product: self.product.clone(),
            },
        }
    }
    /// Dispatch the immutable package with fixed quiet/no-restart options and no secret.
    pub fn install(&self, id: u32) -> Command {
        Command::AgentInstall {
            id,
            command: AgentCommand::Install(self.clone()),
        }
    }
    fn xml(&self) -> Result<String> {
        let limits = CodecLimits::default();
        let mut w = Output::new(4096, &limits);
        w.start(
            "MsiInstallJob",
            &[("id", &format!("{{{}}}", self.operation))],
        )?;
        w.start("Product", &[("Version", &self.version)])?;
        w.start("Download", &[])?;
        w.start("ContentURLList", &[])?;
        w.scalar("ContentURL", &self.url, 2048, false)?;
        w.end("ContentURLList")?;
        w.end("Download")?;
        w.start("Validation", &[])?;
        let hash = self
            .hash
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        w.scalar("FileHash", &hash, 64, false)?;
        w.end("Validation")?;
        w.start("Enforcement", &[])?;
        w.scalar(
            "CommandLine",
            &format!(
                "/quiet /norestart RSS_INSTALLATION_OPERATION={}",
                self.operation
            ),
            256,
            false,
        )?;
        w.scalar("TimeOut", "5", 8, false)?;
        w.scalar("RetryCount", "0", 8, false)?;
        w.scalar("RetryInterval", "5", 8, false)?;
        w.end("Enforcement")?;
        w.end("Product")?;
        w.end("MsiInstallJob")?;
        String::from_utf8(w.finish()?).map_err(|_| E::InvalidValue)
    }
}
fn canonical_uuid(s: &str) -> Result<String> {
    let id = uuid::Uuid::parse_str(s).map_err(|_| E::InvalidValue)?;
    if id.is_nil() {
        return Err(E::InvalidValue);
    }
    Ok(id.to_string())
}
/// Exact product property URI. Unknown properties are rejected.
pub fn property(product: &str, property: &str) -> Result<String> {
    if !matches!(property, "Status" | "Publisher" | "Version") {
        return Err(E::Unsupported);
    }
    Ok(format!(
        "{ROOT}%7B{}%7D/{property}",
        canonical_uuid(product)?.to_uppercase()
    ))
}
/// Closed Add/Exec payload; constructed by the validated compiler or strict decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentCommand {
    /// The fixed DownloadInstall node. There is no generic Add interface.
    Prepare {
        /// Canonical product UUID, checked again during encoding.
        product: String,
    },
    /// The fixed MSI installation job.
    Install(Installer),
}
impl AgentCommand {
    /// Exact target URI of the validated command.
    pub fn target(&self) -> Result<String> {
        self.item()?.target.ok_or(E::Structure)
    }
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Prepare { .. } => "Add",
            Self::Install(_) => "Exec",
        }
    }
    pub(crate) fn item(&self) -> Result<Item> {
        let (product, data) = match self {
            Self::Prepare { product } => (canonical_uuid(product)?, None),
            Self::Install(i) => (i.product.clone(), Some(Secret(i.xml()?))),
        };
        Ok(Item {
            target: Some(format!(
                "{ROOT}%7B{}%7D/DownloadInstall",
                product.to_uppercase()
            )),
            source: None,
            meta: data.as_ref().map(|_| Meta {
                format: Some("xml".into()),
                media_type: Some("text/plain".into()),
                ..Meta::default()
            }),
            data,
        })
    }
    pub(crate) fn from_wire(name: &str, meta: Option<Meta>, items: &[Item]) -> Result<Self> {
        let [item] = items else {
            return Err(E::Unsupported);
        };
        if meta.is_some() || item.source.is_some() {
            return Err(E::Unsupported);
        }
        let uri = item.target.as_deref().ok_or(E::Structure)?;
        let suffix = "%7D/DownloadInstall";
        let product = uri
            .strip_prefix(&format!("{ROOT}%7B"))
            .and_then(|s| s.strip_suffix(suffix))
            .ok_or(E::Unsupported)?;
        let command = if name == "Add" {
            Self::Prepare {
                product: canonical_uuid(product)?,
            }
        } else {
            let xml = &item.data.as_ref().ok_or(E::Structure)?.0;
            let l = CodecLimits::default();
            let mut p = Input::new(xml.as_bytes(), 4096, &l)?;
            let job = p.start("", "MsiInstallJob")?;
            job.attrs(&[("", "id")])?;
            let operation = job
                .attr("", "id")
                .ok_or(E::Structure)?
                .trim_start_matches('{')
                .trim_end_matches('}')
                .to_owned();
            let node = p.start("", "Product")?;
            node.attrs(&[("", "Version")])?;
            let version = node.attr("", "Version").ok_or(E::Structure)?.to_owned();
            p.open("", "Download")?;
            p.open("", "ContentURLList")?;
            let url = p.scalar("", "ContentURL", 2048, false)?;
            p.end("", "ContentURLList")?;
            p.end("", "Download")?;
            p.open("", "Validation")?;
            let hash = p.scalar("", "FileHash", 64, false)?;
            p.end("", "Validation")?;
            let mut bytes = [0; 32];
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(E::InvalidValue);
            }
            for (i, b) in bytes.iter_mut().enumerate() {
                *b =
                    u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16).map_err(|_| E::InvalidValue)?;
            }
            let installer = Installer::new(product, &version, &url, bytes, &operation)?;
            // Exact regeneration rejects extra XML, parameters, retry policy and embedded authority.
            if installer.xml()? != *xml {
                return Err(E::Unsupported);
            }
            Self::Install(installer)
        };
        if command.item()? != *item {
            return Err(E::Unsupported);
        }
        Ok(command)
    }
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
