//! Bounded, real association history for the checkpoint integration consumer.
//! ref: sqlx v0.8.6 sqlx-core/src/transaction.rs (one borrowed transaction).
use super::*;

impl Associations {
    /// Prepare ordered confirmations in one Audit-owned transaction.
    /// Only integration builds expose this entry; it shares validation, CAS,
    /// authorization, operation receipts and fact encoding with `confirm`.
    pub async fn seed_confirmation_history(
        &self,
        proof: &AuthorizedPrincipal,
        request: Confirm,
        count: usize,
    ) -> Result<Association> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        if !(1..=128).contains(&count) {
            return Err(Error::Malformed);
        }
        validate_confirm(&request)?;
        let audits: Vec<_> = (0..count)
            .map(|_| RequestAudit::new(self.tenant.to_string(), "device_association_confirm"))
            .collect();
        let budget = AuditBudget::new(Duration::from_secs(8));
        let attempt = self
            .audit
            .write(
                self.tenant,
                &budget.control(),
                (self, proof, request, &audits),
                |(service, proof, request, audits), tx| {
                    Box::pin(async move {
                        let mut last = None;
                        for audit in audits.iter() {
                            request.operation_id = Uuid::new_v4();
                            validate_confirm(request)?;
                            proof.bind_audit(audit)?;
                            let change = Change::Confirm(request);
                            audit.operation(change.operation(), change.action());
                            let digest = Sha256::digest(
                                serde_json::to_vec(&change).map_err(|_| Error::Malformed)?,
                            );
                            let result = service
                                .change_in(tx, proof, &change, audit, &digest)
                                .await?;
                            request.association_id = Some(result.id);
                            request.expected_version = result.version;
                            last = Some(result);
                        }
                        last.ok_or(Error::Malformed)
                    })
                },
            )
            .await;
        let result = attempt.fold(
            |v| {
                for audit in &audits {
                    audit.mark_committed();
                }
                Ok(v.into_value())
            },
            |e| Err(model::transaction_error(e)),
            |e| {
                for audit in &audits {
                    audit.mark_rolled_back();
                }
                Err(model::transaction_error(e))
            },
            |_| {
                for audit in &audits {
                    audit.mark_rollback_failed();
                }
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |e| Err(model::transaction_error(e)),
        );
        for audit in &audits {
            audit.finalize(
                result
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
        }
        result
    }
}
