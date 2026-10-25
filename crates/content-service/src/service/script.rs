//! Exact administrator script reads use the same verified, pinned content as execution.
use super::*;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptSelection {
    pub platform: r::Platform,
    pub architecture: r::Architecture,
    pub variant: String,
}
async fn selected(
    app: &Access,
    proof: &AuthorizedPrincipal,
    id: &str,
    version: &str,
    input: &ScriptSelection,
) -> Result<([u8; 32], r::Artifact), Error> {
    transaction::inspect(
        &app.runtime,
        app.tenant,
        None,
        (proof, id, version, input),
        |ctx, tx| {
            Box::pin(async move {
                let (proof, id, label, input) = *ctx;
                transaction::lock_resource(tx).await?;
                transaction::authorize(tx, proof).await?.require(
                    proof,
                    Permission::ResourceRead,
                    None,
                )?;
                let (version, state) = rss_mdm_resource_postgres::lock_reference_in(
                    tx,
                    &r::Id::new(id).map_err(|_| Error::Malformed)?,
                    &r::Id::new(label).map_err(|_| Error::Malformed)?,
                )
                .await?
                .map_err(|_| Error::Missing)?;
                if state == r::State::Archived {
                    return Err(Error::Conflict.into());
                }
                let script = version
                    .select_script(
                        input.platform,
                        input.architecture,
                        &r::Id::new(&input.variant).map_err(|_| Error::Malformed)?,
                    )
                    .map_err(|_| Error::Malformed)?;
                Ok((version.digest().bytes(), script.artifact().clone()))
            })
        },
    )
    .await
}
/// Verify outside the transaction, then recheck current authority and exact reference before emission.
pub async fn download(
    app: &Access,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    version: &str,
    input: &ScriptSelection,
    secret: &rss_mdm_authorization_service::credential::RequestCredential,
) -> Result<crate::Verified, Error> {
    audit.intent(rss_mdm_audit_integration::AuditIntent::Sensitive(
        rss_mdm_audit_integration::SensitiveAction::ScriptContentRead,
    ));
    proof.require(Permission::ResourceRead, None)?;
    audit.resource_target(rss_mdm_audit_integration::TargetKind::Resource, id);
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.require_final_request();
    let (digest, artifact) = selected(app, proof, id, version, input).await?;
    let verified = store(app)?.verify(&artifact).await?;
    // The original browser session can be revoked while Content verifies the bytes.
    // Reauthenticate within the remaining transfer deadline before the final reference check.
    let (current, reference) = tokio::time::timeout_at(verified.deadline.instant().into(), async {
        let secret = secret.duplicate().map_err(|_| Error::Forbidden)?;
        let fresh = app
            .sessions
            .authenticate(&app.authorization, secret)
            .await?;
        if fresh.actor() != proof.actor()
            || fresh.credential_binding() != proof.credential_binding()
        {
            return Err(Error::Forbidden);
        }
        selected(app, &fresh, id, version, input).await
    })
    .await
    .map_err(|_| crate::Error::Deadline)??;
    if digest != current
        || reference.digest() != artifact.digest()
        || reference.length() != artifact.length()
        || reference.reference() != artifact.reference()
    {
        return Err(Error::Conflict);
    }
    Ok(verified)
}
