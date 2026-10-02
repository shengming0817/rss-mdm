//! Native enrollment profile and independent installed-profile presence evidence.
use super::protocol::{dictionary, xml};
use crate::Error;
use plist::{Dictionary, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn child_uuid(parent: Uuid, kind: &str) -> Uuid {
    let digest = Sha256::digest(serde_json::to_vec(&(parent, kind)).expect("scalar UUID identity"));
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 15) | 128;
    bytes[8] = (bytes[8] & 63) | 128;
    Uuid::from_bytes(bytes)
}
fn payload(kind: &str, id: &str, uuid: Uuid) -> Dictionary {
    dictionary([
        ("PayloadType", kind.into()),
        ("PayloadVersion", 1_i64.into()),
        ("PayloadIdentifier", id.into()),
        ("PayloadUUID", uuid.to_string().into()),
        ("PayloadScope", "System".into()),
    ])
}
pub struct EnrollmentProfile<'a> {
    pub access_rights: u16,
    pub scep_url: &'a str,
    pub scep_provisioner: &'a str,
    pub apns_topic: &'a str,
    pub management_origin: &'a str,
    pub subject: &'a str,
}
pub fn enrollment(
    config: &EnrollmentProfile<'_>,
    enrollment: Uuid,
    attempt: Uuid,
    challenge: &str,
) -> Result<Vec<u8>, Error> {
    if config.access_rights == 0
        || config.access_rights > 8191
        || config.access_rights & 2 != 0 && config.access_rights & 1 == 0
        || config.access_rights & 128 != 0 && config.access_rights & 64 == 0
    {
        return Err(Error::Malformed);
    }
    let identifier = format!("com.rss-mdm.enrollment.{enrollment}");
    let mut scep = payload(
        "com.apple.security.scep",
        &format!("{identifier}.identity"),
        attempt,
    );
    scep.insert(
        "PayloadContent".into(),
        dictionary([
            ("URL", config.scep_url.into()),
            ("Name", config.scep_provisioner.into()),
            ("Challenge", challenge.into()),
            ("Key Type", "RSA".into()),
            ("Keysize", 2048_i64.into()),
            ("Key Usage", 5_i64.into()),
            (
                "Subject",
                Value::Array(vec![Value::Array(vec![Value::Array(vec![
                    "CN".into(),
                    config.subject.to_owned().into(),
                ])])]),
            ),
        ])
        .into(),
    );
    let mut mdm = payload(
        "com.apple.mdm",
        &format!("{identifier}.mdm"),
        child_uuid(enrollment, "mdm"),
    );
    for (key, value) in [
        ("IdentityCertificateUUID", attempt.to_string().into()),
        ("Topic", config.apns_topic.into()),
        (
            "ServerURL",
            format!("{}/mdm", config.management_origin).into(),
        ),
        (
            "CheckInURL",
            format!("{}/checkin", config.management_origin).into(),
        ),
        ("AccessRights", i64::from(config.access_rights).into()),
        ("CheckOutWhenRemoved", true.into()),
        ("SignMessage", false.into()),
        ("UseDevelopmentAPNS", false.into()),
        (
            "ServerCapabilities",
            Value::Array(vec!["com.apple.mdm.per-user-connections".into()]),
        ),
    ] {
        mdm.insert(key.into(), value);
    }
    let mut profile = payload("Configuration", &identifier, enrollment);
    profile.insert("PayloadDisplayName".into(), "RSS Device Planning".into());
    profile.insert(
        "PayloadContent".into(),
        Value::Array(vec![scep.into(), mdm.into()]),
    );
    xml(profile)
}
/// Malformed or mismatched evidence cannot prove either presence or absence.
pub fn presence(d: &Dictionary, identifier: &str, uuid: Uuid) -> Result<bool, Error> {
    let profiles = d
        .get("ProfileList")
        .and_then(Value::as_array)
        .ok_or(Error::Malformed)?;
    let mut found = false;
    let mut ids = std::collections::BTreeSet::new();
    for value in profiles {
        let item = value.as_dictionary().ok_or(Error::Malformed)?;
        let id = super::protocol::text(item, "PayloadIdentifier")?;
        let payload = Uuid::parse_str(super::protocol::text(item, "PayloadUUID")?)
            .map_err(|_| Error::Malformed)?;
        if !ids.insert(id) {
            return Err(Error::Malformed);
        }
        if id == identifier {
            if payload != uuid {
                return Err(Error::Conflict);
            }
            found = true;
        }
    }
    Ok(found)
}
#[cfg(test)]
#[path = "../tests/profile.rs"]
mod tests;
