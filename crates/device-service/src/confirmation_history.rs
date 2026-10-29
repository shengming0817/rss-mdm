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
        let mut audits = Vec::with_capacity(count);
        let budget = AuditBudget::new(Duration::from_secs(8));
        let attempt = self
            .audit
            .write(
                self.tenant,
                &budget.source_control(),
                (self, proof, request, &mut audits),
                |(service, proof, request, audits), tx| {
                    Box::pin(async move {
                        // These read sets remain protected by this transaction's
                        // authorization and asset-watermark locks. Only the same
                        // member pair is confirmed; CAS/current registrations and
                        // every operation receipt still use the shared writer.
                        let prepared = tx
                            .with_connection_context(
                                &mut (
                                    *proof,
                                    request.mdm.device.clone(),
                                    request.agent.device.clone(),
                                    request.association_id,
                                ),
                                |(proof, mdm, agent, association), c| {
                                    Box::pin(async move {
                                        rss_mdm_inventory_postgres::lock_watermark_in(
                                            c,
                                            TenantId::parse(proof.tenant_id())
                                                .map_err(|_| Error::Malformed)?,
                                        )
                                        .await?;
                                        let snapshot = read::authorization(c, proof).await?;
                                        let world = identity::local_world(
                                            c,
                                            TenantId::parse(proof.tenant_id())
                                                .map_err(|_| Error::Malformed)?,
                                            &[mdm.clone(), agent.clone()],
                                            &association.iter().copied().collect::<Vec<_>>(),
                                        )
                                        .await?;
                                        Ok::<_, Error>((snapshot, world))
                                    })
                                },
                            )
                            .await?;
                        let mut last = None;
                        for _ in 0..count {
                            audits.push(RequestAudit::new(
                                service.tenant.to_string(),
                                "device_association_confirm",
                                rss_mdm_audit_integration::AuditIntent::Management,
                            ));
                            let audit = audits.last().ok_or(Error::Malformed)?;
                            request.operation_id = Uuid::new_v4();
                            validate_confirm(request)?;
                            proof.bind_audit(audit)?;
                            let change = Change::Confirm(request);
                            audit.operation(
                                change.operation(),
                                change.action(),
                                rss_mdm_audit_integration::AuditIntent::Management,
                            );
                            let digest = Sha256::digest(
                                serde_json::to_vec(&change).map_err(|_| Error::Malformed)?,
                            );
                            let outcome = tx
                                .with_connection_context(
                                    &mut (*proof, &change, audit, &digest[..], &prepared),
                                    |(proof, change, audit, digest, prepared), c| {
                                        Box::pin(write_on(
                                            c,
                                            proof,
                                            change,
                                            audit,
                                            digest,
                                            (&prepared.0, &prepared.1),
                                        ))
                                    },
                                )
                                .await?;
                            let result = service.record_change(tx, &change, audit, outcome).await?;
                            proof.check_live()?;
                            audit.mark_commit_started();
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
                Ok(v)
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
