use rss_mdm_inventory::ReportSource;
use serde::Deserialize;
#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Coordinates {
    pub source: ReportSource,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_inventory_rejects_caller_selected_generation() {
        assert!(
            serde_json::from_str::<Coordinates>(
                r#"{"registration":"old","source":"mdm.windows","epoch":"old"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Coordinates>(r#"{"channel":"mdm","source":"mdm.windows"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Coordinates>(r#"{"source":"mdm.windows"}"#).is_ok());
        assert!(serde_json::from_str::<Coordinates>(r#"{"source":"invented"}"#).is_err());
    }
}
