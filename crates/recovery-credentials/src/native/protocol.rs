use super::*;
use rss_mdm_registration_service::DevicePrincipal;
use serde_json::json;
/// A server-side native validation failure cancels dispatch; it is never a device rejection.
pub(super) async fn settle_dispatch_failures(
    service: &Service,
    tx: &mut PgTransaction<'_>,
    principal: &DevicePrincipal,
    audit: &RequestAudit,
) -> Result<()> {
    use rss_mdm_audit_integration::Fact;
    let tenant = tx.tenant_id().to_string();
    let registration = principal.registration();
    let generation = principal.generation();
    let ids = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar::<_, Uuid>("SELECT o.id FROM mdm_recovery_tasks.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.dispatch_failure IS NOT NULL AND d.terminal_at IS NULL ORDER BY o.id LIMIT 64")
            .bind(tenant).bind(registration).bind(generation).fetch_all(c).await
    })).await?;
    for id in ids {
        let op = storage::load(tx, &service.transactions.protection, id).await?;
        let transition = service
            .transactions
            .store
            .cancel(tx, op.scope, &op.command_id()?, op.coordinate)
            .await?;
        if transition.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }

        let fact = Fact::business(
            audit,
            &format!("native-dispatch-failure:{id}"),
            200,
            "failed",
            None,
        )?
        .with_details(json!({"operation":id,"failure":op.dispatch_failure}))?;
        service
            .transactions
            .audit_store
            .append_in(tx, &fact)
            .await?;
        crate::native::wake::wake_native_in(
            &service.transactions.reconcile_messaging,
            tx,
            &op.device,
        )
        .await?;
    }
    Ok(())
}
