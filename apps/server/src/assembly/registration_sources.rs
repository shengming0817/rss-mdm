//! The existing providers supply Registration with actual Scope and Inventory facts.
pub(crate) use rss_mdm_inventory_service::assets::enrollment::EnrollmentObservation as Inventory;
pub(crate) use rss_mdm_scope_service::registration::EnrollmentSources as Source;
