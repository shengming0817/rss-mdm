pub(crate) fn db(_: sqlx::Error) -> crate::Error {
    crate::Error::Storage
}

/// Native UUID values are validated before becoming DA registration identities.
pub(crate) fn device_id(id: uuid::Uuid) -> Result<rss_mdm_agent_wire::DeviceId, sqlx::Error> {
    rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}
pub(crate) fn device_ids(
    ids: Vec<uuid::Uuid>,
) -> Result<Vec<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    ids.into_iter().map(device_id).collect()
}
