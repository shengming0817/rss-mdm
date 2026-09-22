//! Fixed DDF-derived firewall compiler. No uploads, networking or device authority.
//! ref: Microsoft DDFv2Feb2026 DDFDrop012026/Firewall.xml and DeviceStatus.xml.
use crate::{
    CodecError as E, CodecLimits, Result, Secret,
    syncml::{Command, Item, Meta},
    xml::Input,
};
/// Immutable official source revision selected by this product.
pub const REVISION: &str = "DDFv2Feb2026";
/// Sole writable CSP leaf.
pub const FIREWALL_URI: &str = "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall";
/// Device-wide observation; cannot verify the configured leaf.
pub const STATUS_URI: &str = "./Vendor/MSFT/DeviceStatus/Firewall/Status";
/// Authenticated device reports supply these values; this type is not attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Platform {
    version: [u32; 4],
    edition: u32,
}
impl Platform {
    /// Parse the exact Windows four-component version and numeric edition.
    pub fn new(version: &str, edition: u32) -> Result<Self> {
        let parts = version
            .split('.')
            .map(|s| {
                if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(E::InvalidValue);
                }
                s.parse::<u32>().map_err(|_| E::InvalidValue)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            version: parts.try_into().map_err(|_| E::InvalidValue)?,
            edition,
        })
    }
}
/// Stable compiler identity independent of device applicability or authority.
/// Products may freeze even an empty target set without inventing platform evidence.
pub fn identity(enabled: bool) -> Vec<u8> {
    let mut bytes = b"mdm.firewall-domain/v1\0".to_vec();
    bytes.extend_from_slice(include_bytes!("../ddf/selected.xml"));
    bytes.push(u8::from(enabled));
    bytes
}
/// Validated, closed single-leaf configuration. Does not carry permission to execute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Firewall {
    enabled: bool,
}
impl Firewall {
    /// Check both selected nodes' inherited applicability against supplied evidence.
    pub fn compile(enabled: bool, platform: &Platform) -> Result<Self> {
        validate_registry(include_bytes!("../ddf/selected.xml"), platform)?;
        Ok(Self { enabled })
    }
    /// Stable semantic compiler identity bytes, including the fixed DDF selection.
    /// Products hash these bytes when freezing plans; this is not SyncML wire data.
    pub fn identity(&self) -> Vec<u8> {
        identity(self.enabled)
    }
    /// Exact desired Boolean.
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// This leaf has no Delete or rollback contract.
    pub fn supports_cleanup(&self) -> bool {
        false
    }
    /// Produce a typed server Replace, with identity allocated by the response owner.
    pub fn replace(&self, id: u32) -> Command {
        Command::Replace {
            id,
            configuration: self.clone(),
        }
    }
    /// Produce a separate observation request; never a Get of the write-only leaf.
    pub fn observe(&self, id: u32) -> Command {
        Command::Get {
            id,
            meta: None,
            items: vec![Item {
                target: Some(STATUS_URI.into()),
                source: None,
                meta: None,
                data: None,
            }],
        }
    }
    pub(crate) fn items(&self) -> Vec<Item> {
        vec![Item {
            target: Some(FIREWALL_URI.into()),
            source: None,
            meta: Some(Meta {
                format: Some("bool".into()),
                ..Meta::default()
            }),
            data: Some(Secret(self.enabled.to_string())),
        }]
    }
    pub(crate) fn from_wire(meta: Option<Meta>, items: &[Item]) -> Result<Self> {
        let [item] = items else {
            return Err(E::Unsupported);
        };
        if meta.is_some()
            || item.target.as_deref() != Some(FIREWALL_URI)
            || item.source.is_some()
            || item.meta
                != Some(Meta {
                    format: Some("bool".into()),
                    ..Meta::default()
                })
        {
            return Err(E::Unsupported);
        }
        let enabled = match item.data.as_ref().map(|v| v.0.as_str()) {
            Some("true") => true,
            Some("false") => false,
            _ => return Err(E::InvalidValue),
        };
        Ok(Self { enabled })
    }
}
fn validate_registry(bytes: &[u8], platform: &Platform) -> Result<()> {
    let limits = CodecLimits::default();
    let mut p = Input::new(bytes, 4096, &limits)?;
    let root = p.start("", "Registry")?;
    root.attrs(&[("", "version")])?;
    if root.attr("", "version") != Some(REVISION) {
        return Err(E::Unsupported);
    }
    for (uri, operation, format) in [
        (FIREWALL_URI, "Replace", "bool"),
        (STATUS_URI, "Get", "int"),
    ] {
        let n = p.start("", "Node")?;
        n.attrs(&[
            ("", "uri"),
            ("", "operation"),
            ("", "format"),
            ("", "build"),
            ("", "editions"),
            ("", "csp"),
        ])?;
        if n.attr("", "uri") != Some(uri)
            || n.attr("", "operation") != Some(operation)
            || n.attr("", "format") != Some(format)
        {
            return Err(E::Unsupported);
        }
        let build = n.attr("", "build").ok_or(E::Structure)?;
        let min = Platform::new(&format!("{build}.0"), platform.edition)?;
        if platform.version[0..2] != [10, 0] || platform.version < min.version {
            return Err(E::Unsupported);
        }
        let editions = n.attr("", "editions").ok_or(E::Structure)?;
        let allowed = editions
            .split(';')
            .filter(|s| !s.is_empty())
            .map(|s| {
                u32::from_str_radix(s.strip_prefix("0x").ok_or(E::Structure)?, 16)
                    .map_err(|_| E::InvalidValue)
            })
            .collect::<Result<Vec<_>>>()?;
        if !allowed.contains(&platform.edition) || n.attr("", "csp").is_none() {
            return Err(E::Unsupported);
        }
        p.end("", "Node")?;
    }
    p.end("", "Registry")?;
    p.finish()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_rejects_untrusted_structure() {
        let platform = Platform::new("10.0.19045.0", 48).unwrap();
        let source = include_str!("../ddf/selected.xml");
        for bad in [
            source.replace("Replace", "Delete"),
            source.replace("DDFv2Feb2026", "latest"),
            source.replace("<Node ", "<Other "),
            format!("<!DOCTYPE Registry [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>{source}"),
            source.replace(
                "</Registry>",
                &format!(
                    "{} </Registry>",
                    &source[source.find("<Node").unwrap()..source.find("</Registry>").unwrap()]
                ),
            ),
        ] {
            assert!(validate_registry(bad.as_bytes(), &platform).is_err());
        }
    }
}
