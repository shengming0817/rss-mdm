//! Complete object publication hint; each consumer owns its history cursor.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SCHEMA: &str = include_str!("../schema/object-published-v1.json");
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectPublished {
    pub v: u8,
    pub tenant: Uuid,
    pub history_epoch: Uuid,
    pub snapshot_id: Uuid,
    pub through: i64,
}
impl ObjectPublished {
    pub fn message_id(&self) -> String {
        format!(
            "object.published.v1:{}:{}",
            self.history_epoch, self.snapshot_id
        )
    }
    pub fn valid(&self) -> bool {
        self.v == 1
            && !self.tenant.is_nil()
            && !self.history_epoch.is_nil()
            && !self.snapshot_id.is_nil()
            && self.through > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_identity_and_complete_watermark_are_required() {
        let mut event = ObjectPublished {
            v: 1,
            tenant: Uuid::from_u128(1),
            history_epoch: Uuid::from_u128(2),
            snapshot_id: Uuid::from_u128(3),
            through: 1,
        };
        assert!(event.valid());
        let id = event.message_id();
        event.snapshot_id = Uuid::from_u128(4);
        assert_ne!(id, event.message_id());
        event.through = 0;
        assert!(!event.valid());
        event.through = 1;
        event.snapshot_id = Uuid::nil();
        assert!(!event.valid());
    }
}
