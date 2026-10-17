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
) -> Result<crate::Verified, Error> {
    proof.require(Permission::ResourceRead, None)?;
    audit.resource_target(rss_mdm_audit_integration::TargetKind::Resource, id);
    audit.set_action("management_read");
    audit.require_request_settlement();
    let (digest, artifact) = selected(app, proof, id, version, input).await?;
    let verified = store(app)?.verify(&artifact).await?;
    let (current, reference) = selected(app, proof, id, version, input).await?;
    if digest != current
        || reference.digest() != artifact.digest()
        || reference.length() != artifact.length()
        || reference.reference() != artifact.reference()
    {
        return Err(Error::Conflict);
    }
    Ok(verified)
}
