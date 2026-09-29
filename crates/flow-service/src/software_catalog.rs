use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    transaction::{self, TransactionOwner},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_software_service::catalog::{
    Catalog, ContentPort, Operation, SourceChange, VersionChange,
};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use serde_json::Value;
use std::sync::Arc;
pub struct Access {
    pub runtime: Arc<PgRuntime>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub tenant: TenantId,
    pub catalog: Catalog,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
}
async fn authorize(
    tx: &mut PgTransaction<'_>,
    proof: &AuthorizedPrincipal,
    permission: Permission,
) -> transaction::Result<()> {
    let snapshot = crate::action_admission::current(tx, proof).await?;
    snapshot.require(proof, permission, None)?;
    proof.check_live()?;
    Ok(())
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    platform: rss_mdm_resource::Platform,
    architecture: rss_mdm_resource::Architecture,
    variant: String,
    artifact: Option<String>,
}
pub async fn read_source(
    app: &Access,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: String,
    revision: String,
) -> Result<Value, Error> {
    auth.require(Permission::SoftwareRead, None)?;
    audit.set_action("management_read");
    audit.target(&id);
    transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        &audit,
        (&app, &auth, &id, &revision, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, revision, audit) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                let value = app.catalog.source_read_in(tx, id, revision).await?;
                app.audit
                    .append_request_in(tx, audit, 200, "success")
                    .await?;
                Ok(value)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
    .map_err(Error::from)
}
pub async fn write_source(
    app: &Access,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: String,
    revision: String,
    op: Operation<SourceChange>,
) -> Result<Value, Error> {
    let permission = match &op.input {
        SourceChange::Register { .. } => Permission::SoftwareWrite,
        SourceChange::Approve { .. } => Permission::SoftwareApprove,
        SourceChange::Withdraw { .. } => Permission::SoftwareWithdraw,
    };
    auth.require(permission, None)?;
    audit.set_action("management_write");
    audit.target(&id);
    audit.operation(op.operation_id, "management_write");
    transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        &audit,
        (&app, &auth, &id, &revision, &op, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, revision, op, audit) = *ctx;
                authorize(tx, proof, permission).await?;
                let value = app.catalog.source_in(tx, audit, id, revision, op).await?;
                proof.check_live()?;
                Ok(value)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
    .map_err(Error::from)
}
pub async fn read_version(
    app: &Access,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: String,
    version: String,
) -> Result<Value, Error> {
    auth.require(Permission::SoftwareRead, None)?;
    audit.set_action("management_read");
    audit.target(&id);
    transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        &audit,
        (&app, &auth, &id, &version, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, version, audit) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                let value = app.catalog.version_read_in(tx, id, version).await?;
                app.audit
                    .append_request_in(tx, audit, 200, "success")
                    .await?;
                Ok(value)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
    .map_err(Error::from)
}
pub async fn write_version(
    app: &Access,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: String,
    version: String,
    op: Operation<VersionChange>,
) -> Result<Value, Error> {
    let permission = match op.input {
        VersionChange::Approve { .. } => Permission::SoftwareApprove,
        VersionChange::Withdraw { .. } => Permission::SoftwareWithdraw,
    };
    auth.require(permission, None)?;
    audit.set_action("management_write");
    audit.target(&id);
    audit.operation(op.operation_id, "management_write");
    audit.require_request_settlement();
    let verified = if matches!(op.input, VersionChange::Approve { .. }) {
        let resource = transaction::inspect(
            &app.runtime,
            app.tenant,
            (&app, &auth, &id, &version, &op, &audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (app, proof, id, version, op, audit) = *ctx;
                    authorize(tx, proof, permission).await?;
                    if app
                        .catalog
                        .has_version_receipt_in(tx, audit, id, version, op)
                        .await?
                    {
                        Ok(None)
                    } else {
                        Ok(Some(app.catalog.version_in(tx, id, version).await?))
                    }
                })
            },
            TransactionOwner::SoftwareCatalog,
        )
        .await?;
        if let Some(resource) = resource {
            Some(
                app.content
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .as_ref()
                    .verify(&resource)
                    .await
                    .map_err(|_| Error::Malformed)?,
            )
        } else {
            None
        }
    } else {
        None
    };
    transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        &audit,
        (&app, &auth, &id, &version, &op, &audit, verified.as_deref()),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, version, op, audit, verified) = *ctx;
                authorize(tx, proof, permission).await?;
                let value = app
                    .catalog
                    .version_change_in(tx, audit, id, version, op, verified)
                    .await?;
                proof.check_live()?;
                Ok(value)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
    .map_err(Error::from)
}
pub async fn download(
    app: &Access,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: String,
    version: String,
    selection: Selection,
) -> Result<rss_mdm_content_service::Verified, Error> {
    auth.require(Permission::SoftwareRead, None)?;
    audit.require_request_settlement();
    audit.set_action("management_read");
    audit.target(&id);
    let frozen = transaction::inspect(
        &app.runtime,
        app.tenant,
        (&app, &auth, &id, &version, &selection),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, version, s) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                Ok(app
                    .catalog
                    .resolve_admitted_in(
                        tx,
                        id,
                        version,
                        s.platform,
                        s.architecture,
                        &rss_mdm_resource::Id::new(&s.variant).map_err(|_| Error::Malformed)?,
                    )
                    .await?)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await?;
    let selected = frozen
        .version()
        .resolve(selection.platform, selection.architecture, frozen.variant())
        .map_err(|_| Error::Malformed)?;
    let rss_mdm_resource::Declaration::Software { definition } = selected.declaration() else {
        return Err(Error::Malformed);
    };
    let artifact = match &selection.artifact {
        Some(reference) => definition
            .spec()
            .artifacts
            .values()
            .find(|a| &a.reference == reference)
            .ok_or(Error::Malformed)?
            .artifact()
            .map_err(|_| Error::Malformed)?,
        None => definition.primary().clone(),
    };
    let content = app
        .content
        .as_ref()
        .ok_or(Error::Unsupported)?
        .verify(&artifact)
        .await?;
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (&app, &auth, &frozen),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, frozen) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                app.catalog.recheck_admitted_in(tx, frozen).await?;
                Ok(())
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await?;
    Ok(content)
}
