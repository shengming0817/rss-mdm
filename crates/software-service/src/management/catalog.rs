use super::{
    Clock, Error, Failure,
    content::{ImportedContent, ManagementContentPort, StageImport},
    transaction::{self, TransactionOwner},
};
use crate::catalog::{Catalog, Operation, SourceChange, VersionChange};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use serde_json::Value;
use std::sync::Arc;
pub struct Access<C: ManagementContentPort> {
    pub runtime: Arc<PgRuntime>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub tenant: TenantId,
    pub catalog: Catalog,
    pub resources: Arc<rss_mdm_resource_postgres::ResourceStore>,
    pub clock: Arc<dyn Clock>,
    pub content: Option<Arc<C>>,
    pub imports: ImportConfig,
}
async fn authorize(
    tx: &mut PgTransaction<'_>,
    proof: &AuthorizedPrincipal,
    permission: Permission,
) -> transaction::Result<()> {
    let snapshot = transaction::current(tx, proof).await?;
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
pub async fn read_source<C: ManagementContentPort>(
    app: &Access<C>,
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
        audit,
        (&app, &auth, &id, &revision, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, revision, audit) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                let value = app
                    .catalog
                    .reader()
                    .source_read_in(tx, id, revision)
                    .await?;
                app.audit
                    .append_request_in(tx, audit, 200, "success")
                    .await?;
                Ok(value)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
}
pub async fn write_source<C: ManagementContentPort>(
    app: &Access<C>,
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
        audit,
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
}
pub async fn read_version<C: ManagementContentPort>(
    app: &Access<C>,
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
        audit,
        (&app, &auth, &id, &version, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, version, audit) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                let value = app
                    .catalog
                    .reader()
                    .version_read_in(tx, id, version)
                    .await?;
                app.audit
                    .append_request_in(tx, audit, 200, "success")
                    .await?;
                Ok(value)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
}
pub async fn write_version<C: ManagementContentPort>(
    app: &Access<C>,
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
                        .reader()
                        .has_version_receipt_in(tx, audit, id, version, op)
                        .await?
                    {
                        Ok(None)
                    } else {
                        Ok(Some(
                            app.catalog.reader().version_in(tx, id, version).await?,
                        ))
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
        audit,
        (&app, &auth, &id, &version, &op, audit, verified.as_deref()),
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
}
pub async fn download<C: ManagementContentPort>(
    app: &Access<C>,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: String,
    version: String,
    selection: Selection,
) -> Result<C::Download, Error> {
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
                    .reader()
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
            .materials()
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
        .verify_artifact(&artifact)
        .await?;
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (&app, &auth, &frozen),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, frozen) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                app.catalog.reader().recheck_admitted_in(tx, frozen).await?;
                Ok(())
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await?;
    Ok(content)
}

/// Import exact source bytes and retain them in the existing tenant content store.
pub async fn import<C: ManagementContentPort>(
    app: &Access<C>,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    op: Operation<crate::imports::ImportRequest>,
) -> Result<Value, Error> {
    use crate::imports;
    use sha2::{Digest, Sha256};
    auth.require(Permission::SoftwareWrite, None)?;
    auth.require(Permission::ResourceWrite, None)?;
    audit.set_action("management_write");
    audit.target(&op.input.resource);
    audit.operation(op.operation_id, "management_write");
    audit.require_request_settlement();
    let source = transaction::inspect(
        &app.runtime,
        app.tenant,
        (app, auth, audit, &op),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, audit, op) = *ctx;
                authorize(tx, proof, Permission::SoftwareWrite).await?;
                authorize(tx, proof, Permission::ResourceWrite).await?;
                if app.catalog.has_import_receipt_in(tx, audit, op).await? {
                    return Ok(None);
                }
                Ok(Some(
                    app.catalog.import_source_in(tx, &op.input.source).await?,
                ))
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await?;
    let mut retained = None;
    let prepared = if let Some(source) = source {
        let content = app.content.as_ref().ok_or(Error::Unsupported)?;
        let origins = app
            .imports
            .sources
            .get(&source.id)
            .ok_or(Error::Forbidden)?
            .clone();
        let reader = crate::publication::ArtifactReader::new(
            origins,
            4 * 1024 * 1024,
            std::time::Duration::from_secs(app.imports.transfer_seconds.min(30)),
        )
        .map_err(|_| Error::Malformed)?;
        let documents = tokio::time::timeout(
            std::time::Duration::from_secs(app.imports.transfer_seconds.min(30)),
            imports::fetch::fetch(app.tenant, &reader, &source, &op.input),
        )
        .await
        .map_err(|_| Error::Unavailable(Failure::ContentDeadline))?
        .map_err(import_failure)?;
        let prepared =
            imports::prepare(app.tenant, &source, &op.input, &documents).map_err(import_failure)?;
        let actor = format!("{}:{}", auth.instance_id(), auth.principal_id());
        let mut staged = Vec::new();
        for (artifact, bytes) in &prepared.originals {
            auth.check_live()?;
            let hash = Sha256::digest(
                [
                    b"rss-software-source-upload/v1\0".as_slice(),
                    op.operation_id.as_bytes(),
                    artifact.reference.as_bytes(),
                ]
                .concat(),
            );
            let upload = uuid::Uuid::from_bytes(hash[..16].try_into().expect("digest prefix"));
            staged.push(
                content
                    .stage_import(StageImport {
                        upload,
                        actor: &actor,
                        version: &prepared.version,
                        variant: &op.input.variant,
                        platform: op.input.platform,
                        architecture: op.input.architecture,
                        source: &op.input.source,
                        artifact,
                        bytes,
                    })
                    .await?,
            );
        }
        retained = Some(content.pin_imports(staged).await?);
        Some(prepared)
    } else {
        None
    };
    let result = transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        audit,
        (app, auth, audit, &op, prepared.as_ref(), &retained),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, audit, op, prepared, retained) = *ctx;
                authorize(tx, proof, Permission::SoftwareWrite).await?;
                authorize(tx, proof, Permission::ResourceWrite).await?;
                let value = app
                    .catalog
                    .import_in(tx, &app.resources, audit, op, prepared)
                    .await?;
                if let Some(evidence) = retained {
                    evidence.bind_in(tx).await?;
                }
                proof.check_live()?;
                Ok(value)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await;
    drop(retained);
    result
}

fn import_failure(error: crate::catalog::Error) -> Error {
    match transaction::Fault::from(error) {
        transaction::Fault::Request(e) => e,
        transaction::Fault::Storage(_) | transaction::Fault::Sql(_) => {
            Error::Unavailable(Failure::SoftwareCatalogInvariant)
        }
    }
}

/// Host-selected source access policy, retaining the existing content configuration values.
pub struct ImportConfig {
    pub sources: std::collections::BTreeMap<String, Vec<crate::publication::ArtifactOrigin>>,
    pub transfer_seconds: u64,
}
