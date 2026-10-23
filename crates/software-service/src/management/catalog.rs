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
    audit.require_request_settlement();
    audit.target(&id);
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (&app, &auth, &id, &revision),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, revision) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                let value = app
                    .catalog
                    .reader()
                    .source_read_in(tx, id, revision)
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
        SourceChange::Register { .. } | SourceChange::Enable => Permission::SoftwareWrite,
        SourceChange::Disable => Permission::SoftwareWithdraw,
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
    audit.require_request_settlement();
    audit.resource_target(rss_mdm_audit_integration::TargetKind::Resource, &id);
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (&app, &auth, &id, &version),
        |ctx, tx| {
            Box::pin(async move {
                let (app, proof, id, version) = *ctx;
                authorize(tx, proof, Permission::SoftwareRead).await?;
                let mut value = app
                    .catalog
                    .reader()
                    .version_read_in(tx, id, version)
                    .await?;
                let key = rss_mdm_resource::Id::new(id).map_err(|_| Error::Malformed)?;
                let resource = app
                    .resources
                    .get_in(tx, &key)
                    .await?
                    .map_err(|_| Error::Unavailable(super::Failure::SoftwareCatalogInvariant))?
                    .ok_or(Error::ResourceMissing)?;
                value["presentation"] =
                    serde_json::Value::Object(resource.resource.snapshot().presentation);
                value["resourceRevision"] = serde_json::json!(resource.storage_revision);

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
        VersionChange::Enable => Permission::SoftwareWrite,
        VersionChange::Withdraw => Permission::SoftwareWithdraw,
    };
    auth.require(permission, None)?;
    audit.set_action("management_write");
    audit.resource_target(rss_mdm_audit_integration::TargetKind::Resource, &id);
    audit.operation(op.operation_id, "management_write");
    audit.require_request_settlement();
    let verified = if matches!(op.input, VersionChange::Enable) {
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
                app.catalog.reader().lock_in(tx).await?;
                let records = if matches!(op.input, VersionChange::Withdraw) {
                    crate::publication::withdrawal_records_in(tx, id, version).await?
                } else {
                    Vec::new()
                };
                let partitions = records
                    .iter()
                    .map(|record| {
                        rss_mdm_audit_integration::source_partition(tx.tenant_id(), "mdm", record)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let value = app
                    .catalog
                    .version_change_in(tx, audit, id, version, op, verified, &partitions)
                    .await?;
                if matches!(op.input, VersionChange::Withdraw) {
                    crate::publication::withdraw_version_in(
                        tx,
                        &records,
                        value["lifecycle"]["at"].as_i64().ok_or(Error::Conflict)?,
                        app.audit.as_ref(),
                        &rss_mdm_software_release::ActorId::new(
                            app.tenant,
                            serde_json::json!([proof.instance_id(), proof.principal_id()])
                                .to_string(),
                        )
                        .map_err(|_| Error::Malformed)?,
                    )
                    .await?;
                }
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
    audit.resource_target(rss_mdm_audit_integration::TargetKind::Resource, &id);
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
    audit.resource_target(
        rss_mdm_audit_integration::TargetKind::Resource,
        &op.input.resource,
    );
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

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceQuery {
    pub after: Option<String>,
    #[serde(default = "directory_limit")]
    pub limit: usize,
    pub source: Option<String>,
    pub protocol: Option<String>,
    pub state: Option<String>,
}
fn directory_limit() -> usize {
    20
}
pub async fn sources<C: ManagementContentPort>(
    app: &Access<C>,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    q: SourceQuery,
) -> Result<Value, Error> {
    if !(1..=100).contains(&q.limit)
        || q.protocol.as_ref().is_some_and(|v| {
            !["private", "winget_rest", "winget_community", "brew_tap"].contains(&v.as_str())
        })
        || q.state
            .as_ref()
            .is_some_and(|v| !["enabled", "disabled"].contains(&v.as_str()))
    {
        return Err(Error::Malformed);
    }
    let after: Option<(String, String)> = q
        .after
        .as_ref()
        .map(|v| {
            if v.len() > 512 {
                return Err(Error::Malformed);
            }
            serde_json::from_str(v).map_err(|_| Error::Malformed)
        })
        .transpose()?;
    if q.source
        .as_ref()
        .is_some_and(|v| rss_mdm_resource::Id::new(v).is_err())
        || after.as_ref().is_some_and(|(a, b)| {
            rss_mdm_resource::Id::new(a).is_err() || rss_mdm_resource::Id::new(b).is_err()
        })
    {
        return Err(Error::Malformed);
    }
    auth.require(Permission::SoftwareRead, None)?;
    audit.set_action("management_read");
    audit.require_request_settlement();
    transaction::inspect(&app.runtime, app.tenant,(app,auth,&q,after),|ctx,tx|Box::pin(async move {
        let (app,proof,q,after)=ctx;
        authorize(tx,proof,Permission::SoftwareRead).await?;
        let tenant=tx.tenant_id().to_string();let after=after.clone();let source=q.source.clone();let protocol=q.protocol.clone();let state=q.state.clone();let limit=q.limit;
        let mut keys=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_as::<_,(String,String)>("SELECT id,revision FROM mdm_software.sources WHERE tenant_id=$1::uuid AND ($2::text IS NULL OR (id COLLATE \"C\",revision COLLATE \"C\")>($2,$3)) AND ($4::text IS NULL OR id=$4) AND ($5::text IS NULL OR definition->'protocol'->>'kind'=$5) AND ($6::text IS NULL OR lifecycle->>'state'=$6) ORDER BY id COLLATE \"C\",revision COLLATE \"C\" LIMIT $7")
                .bind(tenant).bind(after.as_ref().map(|v|v.0.clone())).bind(after.as_ref().map(|v|v.1.clone())).bind(source).bind(protocol).bind(state).bind((limit+1)as i64).fetch_all(c).await
        })).await?;
        let more=keys.len()>limit;keys.truncate(limit);
        let next=if more{keys.last().map(serde_json::to_string).transpose().map_err(|_|Error::Malformed)?}else{None};
        let mut items=Vec::new();for (id,revision) in keys {items.push(app.catalog.reader().source_read_in(tx,&id,&revision).await?);}
        authorize(tx,proof,Permission::SoftwareRead).await?;

        Ok(serde_json::json!({"items":items,"nextCursor":next}))
    }),TransactionOwner::SoftwareCatalog).await
}
