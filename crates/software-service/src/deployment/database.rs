pub(crate) fn db(_: sqlx::Error) -> crate::deployment::Error {
    crate::deployment::Error::Unavailable(crate::deployment::Failure::Database)
}

/// Check the product registration invariant when reading native database UUIDs.
pub(crate) fn device_id(id: uuid::Uuid) -> Result<rss_mdm_agent_wire::DeviceId, sqlx::Error> {
    rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}
pub(crate) fn device_ids(
    ids: Vec<uuid::Uuid>,
) -> Result<Vec<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    ids.into_iter().map(device_id).collect()
}
