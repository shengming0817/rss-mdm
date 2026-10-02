use crate::Error;
use crate::transaction::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
pub async fn audit(
    tx: &mut PgTransaction<'_>,
    store: &rss_mdm_audit_integration::AuditStore,
    audit: &RequestAudit,
    operation: Option<(Uuid, &[u8])>,
    replayed: bool,
) -> Result<()> {
    let admitted = audit
        .snapshot()
        .software
        .as_ref()
        .is_some_and(|f| f.stage == "management_admission");
    let (status, result) = if admitted {
        (202, "unknown")
    } else {
        (200, "success")
    };
    let result = if let Some((id, fingerprint)) = operation {
        let fact = rss_mdm_audit_integration::Fact::business(
            audit,
            &format!(
                "planning:{}:{id}",
                audit.snapshot().actor.as_deref().unwrap_or("")
            ),
            fingerprint,
            status,
            result,
            None,
        )
        .map_err(Error::from)?;
        store.append_in(tx, &fact, replayed).await
    } else {
        store.append_request_in(tx, audit, status, result).await
    };
    result.map_err(Error::from)?;
    Ok(())
}
