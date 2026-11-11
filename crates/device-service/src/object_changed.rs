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
    pub object: String,
    pub old_devices: Vec<String>,
    pub new_devices: Vec<String>,
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
            && !self.object.is_empty()
            && self.object.len() <= 1024
            && self.old_devices.len() <= 1000
            && self.new_devices.len() <= 1000
            && self
                .old_devices
                .iter()
                .chain(&self.new_devices)
                .all(|d| !d.is_empty() && d.len() <= 256 && !d.chars().any(char::is_control))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_relation_sides_accept_the_full_device_byte_boundary() {
        for device in ["x".repeat(256), "é".repeat(128)] {
            let mut event = ObjectChanged {
                v: 1,
                tenant: Uuid::from_u128(1),
                revision: 1,
                history_epoch: Uuid::from_u128(2),
                object: "object".into(),
                old_devices: vec![device.clone()],
                new_devices: vec![device.clone()],
            };
            assert!(event.valid(), "both relation sides accept 256 UTF-8 bytes");
            event.old_devices[0].push('x');
            assert!(!event.valid(), "the old side rejects 257 bytes");
            event.old_devices[0] = device;
            event.new_devices[0].push('x');
            assert!(!event.valid(), "the new side rejects 257 bytes");
        }
    }
}
