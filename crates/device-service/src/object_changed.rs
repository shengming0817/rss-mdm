//! Immutable object-relation facts; consumers retain their own relation cursors.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SCHEMA: &str = include_str!("../schema/object-changed-v1.json");
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectChanged {
    pub v: u8,
    pub tenant: Uuid,
    pub revision: i64,
    pub history_epoch: Uuid,
    pub object: rss_mdm_agent_wire::ObjectRef,
    pub old_devices: Vec<rss_mdm_agent_wire::DeviceId>,
    pub new_devices: Vec<rss_mdm_agent_wire::DeviceId>,
}
impl ObjectChanged {
    pub fn message_id(&self) -> String {
        format!("object.changed.v1:{}:{}", self.history_epoch, self.revision)
    }
    pub fn valid(&self) -> bool {
        self.v == 1
            && !self.tenant.is_nil()
            && !self.history_epoch.is_nil()
            && self.revision > 0
            && !self.object.uuid().is_nil()
            && self.old_devices.len() <= 1000
            && self.new_devices.len() <= 1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relation_changes_preserve_object_kind_and_both_endpoint_sets() {
        let device = rss_mdm_agent_wire::DeviceId::try_from(Uuid::from_u128(3)).unwrap();
        let event = ObjectChanged {
            v: 1,
            tenant: Uuid::from_u128(1),
            revision: 1,
            history_epoch: Uuid::from_u128(2),
            object: rss_mdm_agent_wire::ObjectRef::Association(device.into_uuid()),
            old_devices: vec![device],
            new_devices: vec![device],
        };
        assert!(event.valid());
        let mut value = serde_json::to_value(&event).unwrap();
        let decoded: ObjectChanged = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded.object, event.object);
        assert_eq!(decoded.old_devices, event.old_devices);
        assert_eq!(decoded.new_devices, event.new_devices);
        value["oldDevices"][0] = serde_json::json!("old-arbitrary-device");
        assert!(serde_json::from_value::<ObjectChanged>(value).is_err());
    }
}
