use super::*;

pub async fn require_device(tx: &mut PgTransaction<'_>, id: &str) -> Result<()> {
    checked_input(rss_mdm_scope::DeviceId::new(tx.tenant_id(), id))?;
    let tenant = tx.tenant_id().to_string();
    let id = id.to_owned();
    let registered = tx
        .with_connection(move |c| Box::pin(crate::device::read::registered(c, tenant, id)))
        .await?;
    if !registered {
        return Err(
            Error::Planning(crate::planning::error::PlanningError::Missing(
                crate::planning::error::Missing::Device,
            ))
            .into(),
        );
    }
    Ok(())
}
