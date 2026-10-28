//! Frozen telemetry material; historical interpretation is distinct from live admission.
/// Product-frozen authority; never accepted from the Agent upload body.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenProfile {
    pub resource_digest: [u8; 32],
    pub profile: rss_mdm_resource::TelemetryProfile,
    pub fields: Vec<rss_mdm_inventory::FieldDefinition>,
    pub collector: FrozenCollector,
    pub source: rss_mdm_inventory::Source,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Exact template contents frozen with the assignment; Resource remains the definition owner.
pub enum FrozenCollector {
    Native {
        definition: rss_mdm_resource::AgentCollectionDefinition,
    },
    Script {
        definition: rss_mdm_resource::ScriptDefinition,
        reference: String,
        length: u64,
        digest: [u8; 32],
    },
}
