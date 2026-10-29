use super::*;
use crate::catalog::Operation;
pub(super) fn actor(proof: &AuthorizedPrincipal) -> String {
    serde_json::json!([proof.instance_id(), proof.principal_id()]).to_string()
}
pub async fn replace<C: ManagementContentPort>(
    app: &Access<C>,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    source: String,
    op: Operation<Import>,
) -> Result<Receipt, Error> {
    proof.require(Permission::SoftwareWrite, None)?;
    source_id(&source)?;
    if op.operation_id.is_nil() || op.expected_revision >= i64::MAX as u64 {
        return Err(invalid());
    }
    audit.set_action(
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target(&source);
    audit.operation(
        op.operation_id,
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.require_final_request();
    let fingerprint: [u8; 32] = Sha256::digest(
        serde_json::to_vec(&(
            "software-source-snapshot/v1",
            app.tenant.to_string(),
            actor(proof),
            &source,
            &op,
        ))
        .map_err(|_| invalid())?,
    )
    .into();
    // Parsing and projection run before acquiring the per-source lock or transaction.
    let prepared = op.input.prepare()?;
    transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        audit,
        (
            app,
            proof,
            audit,
            source,
            op.operation_id,
            op.expected_revision as i64,
            fingerprint,
            Some(prepared),
        ),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, audit, source, operation, expected, fingerprint, prepared) = ctx;
                authorize(tx, proof, Permission::SoftwareWrite).await?;
                app.audit.prepare_in(tx, audit, &[]).await?;
                storage::lock(tx, source, false).await?;
                let actor = actor(proof);
                if let Some(receipt) =
                    storage::receipt(tx, source, *operation, &actor, Some(fingerprint)).await?
                {
                    proof.check_live()?;
                    return Ok(receipt);
                }
                let receipt = storage::save(
                    tx,
                    source,
                    *expected,
                    *operation,
                    &actor,
                    fingerprint,
                    prepared.take().ok_or_else(invariant)?,
                )
                .await?;
                let fact = rss_mdm_audit_integration::Fact::business(
                    audit,
                    &format!("software-source-snapshot:{source}:{operation}"),
                    200,
                    "success",
                    None,
                )?;
                app.audit.append_in(tx, &fact).await?;
                proof.check_live()?;
                Ok(receipt)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
}
