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
    pub resources: Arc<crate::resource_catalog::ResourceCatalog>,
    pub clock: Arc<dyn rss_mdm_content_service::service::Clock>,
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
        audit,
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
        audit,
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

/// Import exact source bytes and retain them in the existing tenant content store.
pub async fn import(
    app: &Access,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    op: Operation<rss_mdm_software_service::imports::ImportRequest>,
) -> Result<Value, Error> {
    use rss_mdm_content_service::{Binding, bindings};
    use rss_mdm_software_service::imports;
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
    let mut uploads = Vec::new();
    let mut pins = Vec::new();
    let prepared = if let Some(source) = source {
        let content = app.content.as_ref().ok_or(Error::Unsupported)?;
        let origins = content
            .config
            .imports
            .get(&source.id)
            .ok_or(Error::Forbidden)?
            .clone();
        let reader = rss_mdm_software_service::publication::ArtifactReader::new(
            origins,
            4 * 1024 * 1024,
            std::time::Duration::from_secs(content.config.transfer_seconds.min(30)),
        )
        .map_err(|_| Error::Malformed)?;
        let documents = tokio::time::timeout(
            std::time::Duration::from_secs(content.config.transfer_seconds.min(30)),
            imports::fetch::fetch(app.tenant, &reader, &source, &op.input),
        )
        .await
        .map_err(|_| Error::from(rss_mdm_content_service::Error::Deadline))?
        .map_err(import_failure)?;
        let prepared =
            imports::prepare(app.tenant, &source, &op.input, &documents).map_err(import_failure)?;
        let actor = format!("{}:{}", auth.instance_id(), auth.principal_id());
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
            let now = app
                .clock
                .unix_seconds()
                .ok_or(Error::Unavailable(crate::Failure::Clock))?;
            let binding = Binding {
                storage_class: rss_mdm_content_service::StorageClass::Artifact,
                resource: op.input.resource.clone(),
                version: op.input.resource_version.clone(),
                variant: op.input.variant.clone(),
                platform: op.input.platform,
                architecture: op.input.architecture,
                resource_digest: prepared.version.digest().bytes(),
                source: Some(op.input.source.clone()),
                origin: None,
                reference: artifact.reference.clone(),
                length: artifact.length,
                sha256: artifact.sha256,
                actor: actor.clone(),
            };
            let session = content.begin(upload, binding, now).await?;
            if !session.complete {
                let offset = usize::try_from(session.offset).map_err(|_| Error::Malformed)?;
                let tail = bytes.get(offset..).ok_or(Error::Malformed)?.to_vec();
                if !tail.is_empty() {
                    content
                        .append(
                            &actor,
                            upload,
                            session.offset,
                            now,
                            std::io::Cursor::new(tail),
                        )
                        .await?;
                }
            }
            uploads.push(
                content
                    .finish(
                        &actor,
                        upload,
                        app.clock
                            .unix_seconds()
                            .ok_or(Error::Unavailable(crate::Failure::Clock))?,
                    )
                    .await?,
            );
        }
        let artifacts = prepared
            .originals
            .iter()
            .map(|(a, _)| a.artifact().map_err(|_| Error::Malformed))
            .collect::<Result<Vec<_>, _>>()?;
        pins = content.verify_materials(&artifacts).await?;
        Some(prepared)
    } else {
        None
    };
    let result = transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        audit,
        (app, auth, audit, &op, prepared.as_ref(), &uploads),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, audit, op, prepared, uploads) = *ctx;
                authorize(tx, proof, Permission::SoftwareWrite).await?;
                authorize(tx, proof, Permission::ResourceWrite).await?;
                let value = app
                    .catalog
                    .import_in(tx, app.resources.software_resources(), audit, op, prepared)
                    .await?;
                for upload in uploads {
                    bindings::bind_in(tx, upload).await?;
                }
                proof.check_live()?;
                Ok(value)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await;
    drop(pins);
    result
}

fn import_failure(error: rss_mdm_software_service::catalog::Error) -> Error {
    match transaction::Fault::from(error) {
        transaction::Fault::Request(e) => e,
        transaction::Fault::Storage(_) | transaction::Fault::Sql(_) => {
            Error::Unavailable(crate::Failure::SoftwareCatalogInvariant)
        }
    }
}
