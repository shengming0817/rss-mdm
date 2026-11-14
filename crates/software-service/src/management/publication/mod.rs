pub mod error;
pub mod model;
mod receipts;
pub mod service;
pub mod wire;
mod worker;

pub const HTTP_ADMISSION_SQL: &str = include_str!("http_admission.sql");

pub mod directory;

/// Current installation permissions and objects of this owner.
pub const INSTALL_SQL: &str = include_str!("install.sql");

/// Current installation permissions and objects of this owner.
pub const RELATIONS_SQL: &str = include_str!("relations.sql");

/// Original publication work metadata for the existing shared worker.
pub const ACCESS_CONTRACT: &str = r#"{"tables":[],"functions":[{"name":"mdm_software_composition.work_scopes","search_path":"search_path=pg_catalog, pg_temp"}],"external_relations":[],"verified_schemas":[]}"#;
