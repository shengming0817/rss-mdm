//! Only the shipped device firewall template is accepted; payload format versions stay at one.
use super::protocol::{dictionary, xml};
use crate::Error;
use plist::{Dictionary, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) fn identifier(tenant: &str, device: &str) -> String {
    let digest = Sha256::digest(serde_json::to_vec(&(tenant, device)).expect("scalar identity"));
    format!("com.rss-mdm.firewall.{digest:x}")
}
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
pub(crate) fn firewall(identifier: &str, uuid: Uuid, enabled: bool) -> Result<Vec<u8>, Error> {
    let mut inner = payload(
        "com.apple.security.firewall",
        &format!("{identifier}.settings"),
        child_uuid(uuid, "firewall"),
    );
    inner.insert("EnableFirewall".into(), enabled.into());
    let mut profile = payload("Configuration", identifier, uuid);
    profile.insert("PayloadDisplayName".into(), "RSS Firewall".into());
    profile.insert("PayloadContent".into(), Value::Array(vec![inner.into()]));
    xml(profile)
}
pub(super) fn enrollment(
    config: &super::config::Config,
    enrollment: Uuid,
    attempt: Uuid,
    challenge: &str,
) -> Result<Vec<u8>, Error> {
    let identifier = format!("com.rss-mdm.enrollment.{enrollment}");
    let mut scep = payload(
        "com.apple.security.scep",
        &format!("{identifier}.identity"),
        attempt,
    );
    scep.insert(
        "PayloadContent".into(),
        dictionary([
            ("URL", config.scep_url.clone().into()),
            ("Name", config.scep_provisioner.clone().into()),
            ("Challenge", challenge.into()),
            ("Key Type", "RSA".into()),
            ("Keysize", 2048_i64.into()),
            ("Key Usage", 5_i64.into()),
            (
                "Subject",
                Value::Array(vec![Value::Array(vec![Value::Array(vec![
                    "CN".into(),
                    super::certificate::subject(enrollment, attempt).into(),
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
        ("Topic", config.apns_topic.clone().into()),
        (
            "ServerURL",
            format!("{}/mdm", config.management.origin).into(),
        ),
        (
            "CheckInURL",
            format!("{}/checkin", config.management.origin).into(),
        ),
        ("AccessRights", 19_i64.into()),
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
    profile.insert("PayloadDisplayName".into(), "RSS Device Management".into());
    profile.insert(
        "PayloadContent".into(),
        Value::Array(vec![scep.into(), mdm.into()]),
    );
    xml(profile)
}
/// Malformed or mismatched evidence cannot prove either presence or absence.
pub(crate) fn presence(d: &Dictionary, identifier: &str, uuid: Uuid) -> Result<bool, Error> {
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
pub(crate) fn presence_digest(
    identifier: &str,
    uuid: Uuid,
    present: bool,
) -> rss_device_command::StateDigest {
    rss_device_command::StateDigest::from_bytes(
        Sha256::digest(
            serde_json::to_vec(&("mdm.apple.profile-presence/v1", identifier, uuid, present))
                .expect("scalar target"),
        )
        .into(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_version_is_format_not_release_and_target_is_device_scoped() {
        let id = Uuid::new_v4();
        let d =
            super::super::protocol::decode(&firewall("com.rss.test", id, true).unwrap()).unwrap();
        assert_eq!(d["PayloadVersion"].as_signed_integer(), Some(1));
        assert_eq!(d["PayloadScope"].as_string(), Some("System"));
        let inner = d["PayloadContent"].as_array().unwrap()[0]
            .as_dictionary()
            .unwrap();
        assert_eq!(inner["EnableFirewall"].as_boolean(), Some(true));
        assert_ne!(identifier("tenant-a", "d"), identifier("tenant-b", "d"));
        assert_ne!(
            presence_digest("p", id, true),
            presence_digest("p", id, false)
        );
    }
    #[test]
    fn missing_list_wrong_version_and_duplicates_never_prove_absence() {
        let id = Uuid::new_v4();
        assert!(presence(&Dictionary::new(), "p", id).is_err());
        let profile = dictionary([
            ("PayloadIdentifier", "p".into()),
            ("PayloadUUID", Uuid::new_v4().to_string().into()),
        ]);
        let d = dictionary([("ProfileList", Value::Array(vec![profile.clone().into()]))]);
        assert!(matches!(presence(&d, "p", id), Err(Error::Conflict)));
        let d = dictionary([(
            "ProfileList",
            Value::Array(vec![profile.clone().into(), profile.into()]),
        )]);
        assert!(presence(&d, "p", id).is_err());
        assert!(
            !presence(
                &dictionary([("ProfileList", Value::Array(vec![]))]),
                "p",
                id
            )
            .unwrap()
        );
    }
}
