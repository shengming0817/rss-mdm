use rss_mdm_agent_wire::runtime::*;
#[allow(
    dead_code,
    reason = "shared fixture functions are consumed by separate integration targets"
)]
pub fn collection() -> CollectionDefinition {
    serde_json::from_value(serde_json::json!({"dataset":"inventory","version":"1","source":"agent.builtin","fields":[field("device.model"),field("device.os.version")]})).unwrap()
}
#[allow(
    dead_code,
    reason = "shared fixture functions are consumed by separate integration targets"
)]
pub fn enrollment_collection() -> CollectionDefinition {
    serde_json::from_value(serde_json::json!({"dataset":"channel.mdm.enrollment","version":"1","source":"agent.builtin","fields":[field("channel.mdm.enrollment")]})).unwrap()
}
fn field(key: &str) -> serde_json::Value {
    serde_json::json!({"key":key,"version":1,"valueType":{"kind":"string","maxLength":256,"allowEmpty":false},"nullable":false,"manual":false,"sources":{"agent.builtin":0},"platforms":["windows","macos"],"sensitivity":"standard","unit":null,"searchable":true,"itemKey":null})
}
