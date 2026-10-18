//! Typed device provisioning through EnterpriseModernAppManagement.
//! ref: Microsoft EnterpriseModernAppManagement CSP AppInstallation/HostedInstall.
use crate::{
    CodecError, CodecLimits,
    native::{Request, Value, Verb},
    xml::Output,
};
const ROOT: &str = "./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppInstallation/*";
/// A single hosted package. Provisioning does not prove registration or service startup.
pub struct MsixInstall {
    family: String,
    uri: String,
}
impl MsixInstall {
    /// Require a concrete PFN and a credential-free HTTPS package location.
    pub fn new(family: String, uri: String) -> Result<Self, CodecError> {
        let (name, publisher) = family.rsplit_once('_').ok_or(CodecError::InvalidValue)?;
        let url = url::Url::parse(&uri).map_err(|_| CodecError::InvalidValue)?;
        if name.is_empty()
            || name.len() > 50
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            || publisher.len() != 13
            || !publisher
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || uri.len() > 2048
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(CodecError::InvalidValue);
        }
        Ok(Self { family, uri })
    }
    /// Compile typed inputs into the existing native command lifecycle.
    pub fn request(&self) -> Result<Request, CodecError> {
        let limits = CodecLimits::default();
        let mut xml = Output::new(limits.field_bytes, &limits);
        xml.start(
            "Application",
            &[("PackageUri", &self.uri), ("ValidateDependencies", "1")],
        )?;
        xml.end("Application")?;
        let document = String::from_utf8(xml.finish()?).map_err(|_| CodecError::InvalidValue)?;
        Ok(Request::Sequence {
            operations: vec![
                Request::Node {
                    node: ROOT.into(),
                    instance: vec![self.family.clone()],
                    operation: Verb::Add,
                    value: None,
                },
                Request::Node {
                    node: format!("{ROOT}/HostedInstall"),
                    instance: vec![self.family.clone()],
                    operation: Verb::Exec,
                    value: Some(Value::Xml(document)),
                },
            ],
        })
    }
    /// Read-only native progress query; retries never execute a second installer.
    pub fn status(&self) -> Request {
        Request::Sequence {
            operations: ["Status", "LastError"]
                .into_iter()
                .map(|property| Request::Node {
                    node: format!("{ROOT}/{property}"),
                    instance: vec![self.family.clone()],
                    operation: Verb::Get,
                    value: None,
                })
                .collect(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hosted_install_is_device_provisioning_without_msi_arguments() {
        let job = MsixInstall::new(
            "RSS.Agent_8wekyb3d8bbwe".into(),
            "https://mdm.example.test/package?x=1&y=2".into(),
        )
        .unwrap();
        let value = serde_json::to_value(job.request().unwrap()).unwrap();
        assert_eq!(value["operations"][0]["node"], ROOT);
        assert_eq!(value["operations"][1]["operation"], "exec");
        let xml = value["operations"][1]["value"]["value"].as_str().unwrap();
        assert!(xml.contains("x=1&amp;y=2"));
        assert!(!xml.contains("CommandLine"));
        assert!(job.status().read_only().unwrap());
        for uri in [
            "http://mdm.test/a.msix",
            "https://user:secret@mdm.test/a.msix",
            "https://mdm.test/a.msix#secret",
        ] {
            assert!(MsixInstall::new("RSS.Agent_8wekyb3d8bbwe".into(), uri.into()).is_err());
        }
    }
}
