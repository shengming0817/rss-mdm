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
        self.v == 1 && !self.tenant.is_nil() && !self.history_epoch.is_nil() && self.revision > 0
            && !self.object.is_empty() && self.object.len() <= 1024
            && self.old_devices.len() <= 1000 && self.new_devices.len() <= 1000
            && self.old_devices.iter().chain(&self.new_devices).all(|d| !d.is_empty() && d.len() <= 255 && !d.chars().any(char::is_control))
    }
}
