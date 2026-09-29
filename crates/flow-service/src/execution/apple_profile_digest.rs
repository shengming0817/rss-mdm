use sha2::Digest;
use uuid::Uuid;
pub fn presence_digest(
    identifier: &str,
    uuid: Uuid,
    present: bool,
) -> rss_device_command::StateDigest {
    rss_device_command::StateDigest::from_bytes(
        sha2::Sha256::digest(
            serde_json::to_vec(&("mdm.apple.profile-presence/v1", identifier, uuid, present))
                .expect("scalar target"),
        )
        .into(),
    )
}
