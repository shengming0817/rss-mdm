use rss_mdm_agent_wire::runtime::*;
#[allow(
    dead_code,
    reason = "shared fixture functions are consumed by separate integration targets"
)]
pub fn collection() -> CollectionDefinition {
    serde_json::from_value(serde_json::json!({"dataset":"inventory","version":"1","source":"agent.builtin","scope":{"kind":"device"},"fields":[field("device.model"),field("device.os.version")]})).unwrap()
}
#[allow(
    dead_code,
    reason = "shared fixture functions are consumed by separate integration targets"
)]
pub fn enrollment_collection() -> CollectionDefinition {
    let mut definition = field("channel.mdm.enrollment");
    definition["valueType"] = serde_json::json!({"kind":"enum","values":[
        MdmEnrollmentState::Unenrolled.as_str(),
        MdmEnrollmentState::ThisOrganization.as_str(),
        MdmEnrollmentState::OtherOrganization.as_str(),
        MdmEnrollmentState::Unknown.as_str(),
    ]});
    serde_json::from_value(serde_json::json!({"dataset":"channel.mdm.enrollment","version":"1","source":"agent.builtin","scope":{"kind":"device"},"fields":[definition]})).unwrap()
}
fn field(key: &str) -> serde_json::Value {
    serde_json::json!({"key":key,"version":1,"valueType":{"kind":"string","maxLength":256,"allowEmpty":false},"nullable":false,"manual":false,"sources":{"agent.builtin":0},"platforms":["windows","macos"],"sensitivity":"standard","unit":null,"searchable":true,"itemKey":null})
}

#[allow(
    dead_code,
    reason = "shared crypto assertion used by signature targets"
)]
pub fn verify_signature(
    signed: &rss_mdm_agent_wire::runtime::SignedTask,
    public_key: &[u8],
) -> Result<(), ring::error::Unspecified> {
    use base64::Engine;
    let bytes = signed
        .payload
        .signing_bytes(&signed.key_id)
        .map_err(|_| ring::error::Unspecified)?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|_| ring::error::Unspecified)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(&bytes, &signature)
}
