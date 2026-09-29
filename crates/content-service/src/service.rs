//! Authorized content upload, import, durable binding and reclamation.
use crate::transaction::{self};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
mod error;
use crate::{Binding, Store, Upload};
pub use error::Error;
use futures::TryStreamExt;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_resource as r;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
pub struct Access {
    pub runtime: Arc<PgRuntime>,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub tenant: TenantId,
    pub content: Option<Arc<Store>>,
    pub clock: Arc<dyn Clock>,
    pub catalog: Arc<rss_mdm_software_service::catalog::Catalog>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub version: String,
    pub variant: String,
    pub platform: r::Platform,
    pub architecture: r::Architecture,
    pub artifact: Option<String>,
    pub operation: Option<Uuid>,
}
impl Selection {
    pub fn from_binding(b: &Binding) -> Self {
        Self {
            version: b.version.clone(),
            variant: b.variant.clone(),
            platform: b.platform,
            architecture: b.architecture,
            artifact: Some(b.reference.clone()),
            operation: None,
        }
    }
}
async fn resolve_in(
    tx: &mut PgTransaction<'_>,
    proof: &AuthorizedPrincipal,
    id: &str,
    input: &Selection,
) -> transaction::Result<Binding> {
    transaction::lock_resource(tx).await?;
    let snapshot = transaction::authorize(tx, proof).await?;
    snapshot.require(proof, Permission::ResourceWrite, None)?;
    let (version, state) = rss_mdm_resource_postgres::lock_reference_in(
        tx,
        &r::Id::new(id).map_err(|_| Error::Malformed)?,
        &r::Id::new(&input.version).map_err(|_| Error::Malformed)?,
    )
    .await?
    .map_err(|_| Error::Conflict)?;
    if state == r::State::Archived {
        return Err(Error::Conflict.into());
    }
    let variant = version
        .resolve(
            input.platform,
            input.architecture,
            &r::Id::new(&input.variant).map_err(|_| Error::Malformed)?,
        )
        .map_err(|_| Error::Malformed)?;
    let artifact = match variant.declaration() {
        r::Declaration::Software { definition } => {
            if let Some(reference) = &input.artifact {
                definition
                    .spec()
                    .artifacts
                    .values()
                    .find(|a| &a.reference == reference)
                    .ok_or(Error::Malformed)?
                    .artifact()
                    .map_err(|_| Error::Malformed)?
            } else {
                definition.primary().clone()
            }
        }
        r::Declaration::Script {
            artifact,
            definition,
        } => {
            if artifact.length() > 16_777_216
                || input
                    .artifact
                    .as_ref()
                    .is_some_and(|id| id != artifact.reference().as_str())
            {
                return Err(Error::Malformed.into());
            }
            if definition.spec().profile == r::ScriptProfile::OsqueryInfoV1
                && (artifact.length() != 32
                    || artifact.digest() != r::Digest::of(b"SELECT version FROM osquery_info;\n"))
            {
                return Err(Error::Malformed.into());
            }
            artifact.clone()
        }
        _ => return Err(Error::Malformed.into()),
    };
    let (source, origin) = match variant.declaration() {
        r::Declaration::Software { definition } => (
            Some(definition.spec().source.clone()),
            definition
                .spec()
                .artifacts
                .values()
                .find(|a| a.reference == artifact.reference().as_str())
                .and_then(|a| a.origin.clone()),
        ),
        _ => (None, None),
    };
    Ok(Binding {
        source,
        origin,
        resource: id.into(),
        version: input.version.clone(),
        variant: input.variant.clone(),
        platform: input.platform,
        architecture: input.architecture,
        resource_digest: version.digest().bytes(),
        reference: artifact.reference().as_str().into(),
        length: artifact.length(),
        sha256: artifact.digest().bytes(),
        actor: format!("{}:{}", proof.instance_id(), proof.principal_id()),
    })
}
pub async fn resolve(
    app: &Access,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    input: &Selection,
) -> Result<Binding, Error> {
    audit.require_request_settlement();
    proof.require(Permission::ResourceWrite, None)?;
    audit.target(id);
    audit.set_action("management_write");
    transaction::inspect(&app.runtime, app.tenant, (proof, id, input), |ctx, tx| {
        Box::pin(async move {
            let (proof, id, input) = *ctx;
            resolve_in(tx, proof, id, input).await
        })
    })
    .await
}
pub fn store(app: &Access) -> Result<&Arc<Store>, Error> {
    app.content.as_ref().ok_or(Error::Unsupported)
}
pub async fn current(
    app: &Access,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    upload: Uuid,
) -> Result<Upload, Error> {
    audit.operation(upload, "management_write");
    proof.require(Permission::ResourceWrite, None)?;
    let value = store(app)?
        .status(
            &format!("{}:{}", proof.instance_id(), proof.principal_id()),
            upload,
            app.clock.unix_seconds().ok_or(Error::Clock)?,
        )
        .await?;
    if value.binding.resource != id
        || value.binding.actor != format!("{}:{}", proof.instance_id(), proof.principal_id())
    {
        return Err(Error::Forbidden);
    }
    let binding = resolve(
        app,
        proof,
        audit,
        id,
        &Selection::from_binding(&value.binding),
    )
    .await?;
    if binding != value.binding {
        return Err(Error::Conflict);
    }
    Ok(value)
}
pub async fn record(
    app: &Access,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    upload: &Upload,
    source_catalog: Option<&rss_mdm_software_service::catalog::Catalog>,
) -> Result<(), Error> {
    audit.operation(upload.id, "management_write");
    let verified = store(app)?.verify(&upload.binding.artifact()?).await?;
    transaction::run(
        &app.audit_store,
        &app.runtime,
        app.tenant,
        audit,
        (app, proof, audit, upload, &verified, source_catalog),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, audit, upload, verified, source_catalog) = *ctx;
                tx.prepare_outbox_partitions(&[crate::event::partition(
                    app.tenant,
                    &upload.binding.resource,
                )?])
                .await?;
                if let Some(catalog) = source_catalog {
                    catalog
                        .source_admitted_in(
                            tx,
                            upload.binding.source.as_ref().ok_or(Error::Malformed)?,
                        )
                        .await?;
                }
                let current = resolve_in(
                    tx,
                    proof,
                    &upload.binding.resource,
                    &Selection::from_binding(&upload.binding),
                )
                .await?;
                if current != upload.binding
                    || !verified.matches(&current.artifact().map_err(Error::from)?)
                {
                    return Err(Error::Conflict.into());
                }
                let fresh = crate::bindings::bind_in(tx, upload).await?;
                if fresh {
                    crate::event::append(
                        &rss_transactional_messaging_postgres::PgOutboxWriter::new(
                            app.runtime.clone(),
                            crate::event::domain(),
                        ),
                        tx,
                        upload,
                    )
                    .await?;
                }
                let hash = transaction::fingerprint(&upload.binding)?;
                let fact = rss_mdm_audit_integration::Fact::business(
                    audit,
                    &format!("content:{}:{}", upload.binding.actor, upload.id),
                    &hash,
                    201,
                    "success",
                    None,
                )?;
                app.audit_store.append_in(tx, &fact, !fresh).await?;
                proof.check_live()?;
                Ok(())
            })
        },
    )
    .await
}
pub async fn reclaim_in(
    tx: &mut PgTransaction<'_>,
    candidate: crate::Garbage,
    authorize: impl FnOnce() -> Result<(), Error> + Send,
) -> Result<bool, Error> {
    let referenced = rss_mdm_resource_postgres::artifact_referenced_in(
        tx,
        r::Digest::from_bytes(candidate.digest),
    )
    .await
    .map_err(transaction::storage_error)?;
    authorize()?;
    if !referenced {
        candidate.remove().map_err(Error::from)?;
    }
    Ok(!referenced)
}

pub async fn cleanup(
    app: &Access,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
) -> Result<serde_json::Value, Error> {
    proof.require(Permission::ResourceWrite, None)?;
    audit.require_request_settlement();
    audit.set_action("management_write");
    let candidates = store(app)?
        .garbage(app.clock.unix_seconds().ok_or(Error::Clock)?)
        .await?;
    let mut removed = 0usize;
    for candidate in candidates {
        let deleted = transaction::inspect(
            &app.runtime,
            app.tenant,
            (proof, Some(candidate)),
            |ctx, tx| {
                Box::pin(async move {
                    let (proof, candidate) = ctx;
                    let proof = *proof;
                    transaction::lock_resource(tx).await?;
                    transaction::authorize(tx, proof).await?.require(
                        proof,
                        Permission::ResourceWrite,
                        None,
                    )?;
                    reclaim_in(tx, candidate.take().expect("one reclaim"), || {
                        proof.check_live().map_err(Error::from)
                    })
                    .await
                    .map_err(Into::into)
                })
            },
        )
        .await?;
        if deleted {
            removed += 1;
        }
    }
    Ok(serde_json::json!({"removed":removed}))
}
pub async fn mirror(
    app: &Access,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    input: &Selection,
) -> Result<(), Error> {
    let operation = input.operation.ok_or(Error::Malformed)?;
    audit.operation(operation, "management_write");
    let binding = resolve(app, proof, audit, id, input).await?;
    let source = binding.source.as_ref().ok_or(Error::Malformed)?;
    let catalog = app.catalog.as_ref();
    transaction::inspect(&app.runtime, app.tenant, (catalog, source), |ctx, tx| {
        Box::pin(async move {
            let (catalog, source) = *ctx;
            catalog.source_admitted_in(tx, source).await?;
            Ok(())
        })
    })
    .await?;
    let content = store(app)?;
    let origins = content
        .config
        .imports
        .get(&source.id)
        .ok_or(Error::Forbidden)?
        .clone();
    let reader = rss_mdm_software_service::publication::ArtifactReader::new(
        origins,
        content.config.max_artifact_bytes,
        std::time::Duration::from_secs(content.config.transfer_seconds.min(3600)),
    )
    .map_err(|_| Error::Malformed)?;
    let now = app.clock.unix_seconds().ok_or(Error::Clock)?;
    let session = content.begin(operation, binding.clone(), now).await?;
    if !session.complete {
        if session.offset != 0 {
            return Err(Error::Conflict);
        }
        let response = reader
            .open(
                binding.origin.as_deref().ok_or(Error::Malformed)?,
                binding.length,
            )
            .await
            .map_err(|_| Error::Import)?;
        let stream = tokio_util::io::StreamReader::new(
            response.bytes_stream().map_err(std::io::Error::other),
        );
        content
            .append(&session.binding.actor, operation, 0, now, stream)
            .await?;
    }
    let result = content
        .finish(
            &session.binding.actor,
            operation,
            app.clock.unix_seconds().ok_or(Error::Clock)?,
        )
        .await?;
    record(app, proof, audit, &result, Some(catalog)).await?;
    Ok(())
}
pub async fn receipt(
    app: &Access,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    operation: Uuid,
) -> Result<serde_json::Value, Error> {
    proof.require(Permission::ResourceRead, None)?;
    audit.set_action("management_read");
    audit.target(id);
    transaction::run(
        &app.audit_store,
        &app.runtime,
        app.tenant,
        audit,
        (app, proof, audit, &id, operation),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, audit, id, operation) = *ctx;
                transaction::authorize(tx, proof).await?.require(
                    proof,
                    Permission::ResourceRead,
                    None,
                )?;
                let actor = format!("{}:{}", proof.instance_id(), proof.principal_id());
                let value = crate::bindings::read_in(tx, &actor, id, operation)
                    .await?
                    .ok_or(Error::Missing)?;
                app.audit_store
                    .append_request_in(tx, audit, 200, "success")
                    .await?;
                Ok(value)
            })
        },
    )
    .await
}

/// Begin an authorized upload without holding a database transaction across I/O.
pub async fn begin_upload(
    app: &Access,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    upload: Uuid,
    input: &Selection,
) -> Result<Upload, Error> {
    audit.operation(upload, "management_write");
    let binding = resolve(app, proof, audit, id, input).await?;
    Ok(store(app)?
        .begin(
            upload,
            binding,
            app.clock.unix_seconds().ok_or(Error::Clock)?,
        )
        .await?)
}
pub enum Append {
    Written(Box<Upload>),
    OffsetConflict(u64),
}
pub async fn append_upload<R: tokio::io::AsyncRead + Unpin + Send>(
    app: &Access,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    upload: Uuid,
    offset: u64,
    reader: R,
) -> Result<Append, Error> {
    let old = current(app, proof, audit, id, upload).await?;
    if old.offset != offset {
        return Ok(Append::OffsetConflict(old.offset));
    }
    let result = store(app)?
        .append(
            &old.binding.actor,
            upload,
            offset,
            app.clock.unix_seconds().ok_or(Error::Clock)?,
            reader,
        )
        .await?;
    proof.check_live()?;
    Ok(Append::Written(Box::new(result)))
}
pub async fn complete_upload(
    app: &Access,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    upload: Uuid,
) -> Result<(), Error> {
    let old = current(app, proof, audit, id, upload).await?;
    let result = store(app)?
        .finish(
            &old.binding.actor,
            upload,
            app.clock.unix_seconds().ok_or(Error::Clock)?,
        )
        .await?;
    record(app, proof, audit, &result, None).await
}
pub async fn upload<R: tokio::io::AsyncRead + Unpin + Send>(
    app: &Access,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: &str,
    input: &Selection,
    reader: R,
) -> Result<(), Error> {
    let operation = input.operation.ok_or(Error::Malformed)?;
    let session = begin_upload(app, proof, audit, id, operation, input).await?;
    if !session.complete && session.offset != session.binding.length {
        let written = store(app)?
            .append(
                &session.binding.actor,
                operation,
                0,
                app.clock.unix_seconds().ok_or(Error::Clock)?,
                reader,
            )
            .await?;
        if written.offset != written.binding.length {
            return Err(Error::Malformed);
        }
    }
    let complete = store(app)?
        .finish(
            &session.binding.actor,
            operation,
            app.clock.unix_seconds().ok_or(Error::Clock)?,
        )
        .await?;
    record(app, proof, audit, &complete, None).await
}

pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> Option<i64>;
}
