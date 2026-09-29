use rss_mdm_inventory::ReportSource;
use serde::Deserialize;
#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Coordinates {
    pub source: ReportSource,
}
#[cfg(test)]
#[path = "../../tests/device/coordinates_unit.rs"]
mod tests;
