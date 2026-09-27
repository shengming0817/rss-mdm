use super::*;
use sha2::{Digest, Sha256};

pub(super) fn identity(command: &Command, audit: &RequestAudit) -> Result<(Option<Uuid>, Vec<u8>)> {
    let id = match command {
        Command::Group { change, .. } => Some(change.operation_id),
        Command::GroupPreview { operation, .. } => Some(*operation),
        Command::Scope { change, .. } => Some(change.operation_id),
        _ => None,
    };
    if id.is_some_and(|id| id.is_nil()) {
        return Err(Error::Malformed.into());
    }
    let who = audit.snapshot();
    let bytes = checked_input(serde_json::to_vec(&(
        audit.tenant(),
        who.actor,
        who.instance,
        command,
    )))?;
    Ok((id, Sha256::digest(bytes).to_vec()))
}
pub(crate) async fn require_device(tx: &mut PgTransaction<'_>, id: &str) -> Result<()> {
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
