//! Downloads repeat current authorization after verified file work outside PG.
use super::*;
use rss_mdm_content_service::diagnostic::Metadata;
/// Response content prepared before the final current-qualification check.
/// Its stream owns the verified file pin and performs no further file reads.
pub struct Download {
    pub metadata: Metadata,
    pub etag: String,
    pub stream:
        futures::stream::BoxStream<'static, std::result::Result<bytes::Bytes, std::io::Error>>,
}
impl Queries {
    #[cfg(feature = "integration")]
    pub fn pause_diagnostic_download_after_file_work(
        &self,
        ready: Arc<tokio::sync::Notify>,
        resume: Arc<tokio::sync::Notify>,
    ) {
        *self
            .diagnostic_download_gate
            .lock()
            .expect("diagnostic download gate") = Some((ready, resume));
    }
    pub async fn diagnostic_artifact(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<Download, QueryError> {
        let reader = self
            .diagnostic_reader
            .as_ref()
            .ok_or(QueryError::Unsupported)?;
        // Preflight and final response settlement belong to separate PG transactions.
        // Only the final current-qualification check settles the request audit.
        let preflight_audit = audit.transaction_copy();
        let metadata = self
            .diagnostic_metadata(proof, device, id, &preflight_audit, None)
            .await;
        preflight_audit.finalize(metadata.as_ref().err().and_then(|error| {
            matches!(
                error,
                QueryError::Unavailable(_) | QueryError::CommitUnknown | QueryError::RollbackFailed
            )
            .then_some(rss_mdm_audit_integration::FailureReason::Transaction)
        }));
        let metadata = metadata?;
        let verified = reader
            .verify(
                &metadata
                    .artifact()
                    .map_err(crate::Error::from)
                    .map_err(QueryError::from)?,
            )
            .await
            .map_err(crate::Error::from)
            .map_err(QueryError::from)?;
        let etag = verified.etag();
        let stream = verified
            .stream(0, metadata.length)
            .await
            .map_err(crate::Error::from)
            .map_err(QueryError::from)?;
        #[cfg(feature = "integration")]
        {
            let gate = self
                .diagnostic_download_gate
                .lock()
                .expect("diagnostic download gate")
                .take();
            if let Some((ready, resume)) = gate {
                ready.notify_one();
                resume.notified().await;
            }
        }
        self.diagnostic_metadata(proof, device, id, audit, Some(&metadata))
            .await?;
        Ok(Download {
            metadata,
            etag,
            stream,
        })
    }
    async fn diagnostic_metadata(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        audit: &RequestAudit,
        expected: Option<&Metadata>,
    ) -> std::result::Result<Metadata, QueryError> {
        transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, proof, device, id, audit, expected),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, proof, device, id, audit, expected) = *ctx;
                    let permissions =
                        storage::authorized(tx, proof, device, Permission::OperationRead).await?;
                    permissions.require(proof, Permission::DeviceDiagnostics, Some(device))?;
                    storage::lock(tx, device).await?;
                    let op = storage::load(tx, &service.protection, id).await?;
                    if op.device != device
                        || crate::native::diagnostic::input(&op.request.task).is_none()
                    {
                        return Err(Error::Forbidden.into());
                    }
                    let current = storage::current_registration(
                        tx,
                        device,
                        rss_mdm_registration_service::Purpose::Primary,
                    )
                    .await?;
                    if current != (op.registration, op.registration_generation) {
                        return Err(Error::Conflict.into());
                    }
                    let tenant = service.tenant;
                    let registration = op.registration;
                    let generation = op.registration_generation;
                    let state = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(crate::native::diagnostic::load(c, tenant, id).await)
                            })
                        })
                        .await??;
                    if !matches!(state.transfer, crate::native::diagnostic::Transfer::Ready) {
                        return Err(Error::Conflict.into());
                    }
                    let metadata = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(rss_mdm_content_service::diagnostic::read_in(
                                    c,
                                    tenant,
                                    id,
                                    registration,
                                    generation,
                                )
                                .await)
                            })
                        })
                        .await?
                        .map_err(Error::from)?
                        .ok_or(Error::Conflict)?;
                    if expected.is_some_and(|old| old != &metadata) {
                        return Err(Error::Conflict.into());
                    }
                    if expected.is_some() {
                        service
                            .audit_store
                            .append_request_in(tx, audit, 200, "success")
                            .await?;
                    }
                    Ok(metadata)
                })
            },
        )
        .await
        .map_err(Into::into)
    }
}
