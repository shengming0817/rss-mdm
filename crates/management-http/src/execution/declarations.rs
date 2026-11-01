use uuid::Uuid;
pub static SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "device_declarations",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "declaration operation identity",
    context: &[],
};
pub struct Page {
    pub items: Vec<Item>,
    pub next_cursor: Option<String>,
    pub current_registration: bool,
}
pub struct Item {
    pub operation: Uuid,
    pub registration: Uuid,
    pub generation: i64,
    pub user: String,
    pub redacted: bool,
    pub observation: rss_mdm_policy_service::configuration::queries::records::NativeObservation,
}
