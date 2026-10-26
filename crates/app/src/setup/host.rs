//! Exact host input identity and a fresh process observation; neither implies device effects.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub host_id: Uuid,
    pub operation_id: Uuid,
    pub revision: u64,
    pub material_digest: String,
}
impl Binding {
    pub(crate) fn validate(&self) -> Result<(), crate::Error> {
        if self.host_id.is_nil()
            || self.operation_id.is_nil()
            || !(1..=i64::MAX as u64).contains(&self.revision)
            || self.material_digest.len() != 64
            || !self
                .material_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(crate::Error::Malformed);
        }
        Ok(())
    }
}
#[derive(schemars::JsonSchema, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Observation {
    #[serde(flatten)]
    binding: PublicBinding,
    process_generation: Uuid,
    tenant_id: String,
    instance_id: String,
}
#[derive(schemars::JsonSchema, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicBinding {
    host_id: Uuid,
    operation_id: Uuid,
    revision: u64,
    material_digest: String,
}
impl Observation {
    pub(crate) fn new(binding: &Binding, tenant: String, instance: String) -> Self {
        Self {
            binding: PublicBinding {
                host_id: binding.host_id,
                operation_id: binding.operation_id,
                revision: binding.revision,
                material_digest: binding.material_digest.clone(),
            },
            process_generation: Uuid::new_v4(),
            tenant_id: tenant,
            instance_id: instance,
        }
    }
}
