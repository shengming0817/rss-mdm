pub mod error;
pub mod host;
pub mod model;
mod receipts;
pub mod service;
pub mod wire;

pub const HTTP_CATALOG_SQL: &str = include_str!("http_catalog.sql");
pub const HTTP_CATALOG_JSON: &str = include_str!("http_catalog.json");

pub const HTTP_ADMISSION_SQL: &str = include_str!("http_admission.sql");
