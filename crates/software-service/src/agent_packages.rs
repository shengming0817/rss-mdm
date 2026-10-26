//! Fixed Agent installers, admitted through existing Software, Resource and Content owners.
//! ref: sqlx-core/src/transaction.rs@v0.9.0.
use crate::management::{
    self,
    content::ManagementContentPort,
    transaction::{self, TransactionOwner},
};
use management::{Error, Failure};
use rss_mdm_agent_wire::{
    enroll::configuration as w,
    runtime::{TaskArchitecture, TaskPlatform},
};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_resource as r;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgRuntime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;
pub mod directory;
pub const INSTALL_SQL: &str = include_str!("agent_packages.sql");
pub const ACCESS_CONTRACT: &str = include_str!("agent_packages_access.json");
/// Safe domain reasons after authorization; no storage/provider details cross the HTTP boundary.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
#[error("Agent package rejected: {self:?}")]
pub enum Rejection {
    InstallerMismatch,
    LifecycleNotAdmitted,
    SourceNotAdmitted,
    BindingNotAdmitted,
}
fn publication_fault(error: crate::catalog::Error) -> transaction::Fault {
    match error {
        crate::catalog::Error::NotAdmitted => {
            Error::AgentPackage(Rejection::LifecycleNotAdmitted).into()
        }
        crate::catalog::Error::Dependency => {
            Error::AgentPackage(Rejection::SourceNotAdmitted).into()
        }
        other => other.into(),
    }
}
/// Publish a previously saved software version. Internal coordinates are returned by preparation.
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Publish {
    pub operation_id: Uuid,
    pub package_id: Uuid,
}
#[derive(Clone)]
struct Selection {
    pub resource: String,
    pub version: String,
    pub variant: String,
    pub target: w::Target,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    variant: String,
    software: r::SoftwareSpec,
    resource: String,
    version: String,
    digest: [u8; 32],
    lifecycle: [u8; 32],
    installer: r::SoftwareArtifact,
}
fn invalid() -> Error {
    Error::Malformed
}
fn storage() -> Error {
    Error::Unavailable(Failure::SoftwareCatalogStorage)
}
fn digest(v: &impl Serialize) -> Result<Vec<u8>, Error> {
    Ok(Sha256::digest(serde_json::to_vec(v).map_err(|_| invalid())?).to_vec())
}
fn target(t: w::Target) -> (r::Platform, r::Architecture) {
    (
        match t.platform {
            TaskPlatform::Windows => r::Platform::Windows,
            TaskPlatform::Macos => r::Platform::MacOS,
        },
        match t.architecture {
            TaskArchitecture::X86_64 => r::Architecture::X86_64,
            TaskArchitecture::Aarch64 => r::Architecture::Aarch64,
        },
    )
}
fn definition<'a>(v: &'a r::Version, i: &Selection) -> Result<&'a r::SoftwareDefinition, Error> {
    let (p, a) = target(i.target);
    let selected = v
        .variants()
        .iter()
        .find(|x| x.platform() == p && x.architecture() == a && x.key().as_str() == i.variant)
        .ok_or_else(invalid)?;
    let r::Declaration::Software { definition } = selected.declaration() else {
        return Err(Error::AgentPackage(Rejection::InstallerMismatch));
    };
    match (definition.spec().material.format, i.target.platform) {
        (
            r::SoftwareFormat::Exe | r::SoftwareFormat::Msi | r::SoftwareFormat::Msix,
            TaskPlatform::Windows,
        )
        | (r::SoftwareFormat::Pkg, TaskPlatform::Macos) => Ok(definition),
        _ => Err(invalid()),
    }
}
fn format(format: r::SoftwareFormat) -> Result<w::InstallerFormat, Error> {
    match format {
        r::SoftwareFormat::Exe => Ok(w::InstallerFormat::WindowsExe),
        r::SoftwareFormat::Msi => Ok(w::InstallerFormat::WindowsMsi),
        r::SoftwareFormat::Msix => Ok(w::InstallerFormat::WindowsMsix),
        r::SoftwareFormat::Pkg => Ok(w::InstallerFormat::MacosPkg),
        _ => Err(invalid()),
    }
}
struct Prepared {
    version: r::Version,
    package: w::Package,
    binding: Binding,
    verified: Box<dyn crate::catalog::VerifiedContent>,
}
fn filename(target: w::Target, format: w::InstallerFormat) -> String {
    let platform = match target.platform {
        TaskPlatform::Windows => "windows",
        TaskPlatform::Macos => "macos",
    };
    let arch = match target.architecture {
        TaskArchitecture::X86_64 => "x86_64",
        TaskArchitecture::Aarch64 => "aarch64",
    };
    format!("rss-agent-{platform}-{arch}.{}", format.extension())
}
async fn replay_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    operation: Uuid,
    hash: &[u8],
) -> transaction::Result<Option<w::Package>> {
    crate::catalog::Reader::new(tx.tenant_id())
        .operation_receipt_in(tx, operation, hash)
        .await?
        .map(|value| serde_json::from_value(value).map_err(|_| storage().into()))
        .transpose()
}
async fn prepare<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
    p: &AuthorizedPrincipal,
    i: &Selection,
) -> Result<Prepared, Error> {
    let version = transaction::inspect(
        &app.runtime,
        app.tenant,
        (app, p, i),
        |ctx, tx| {
            Box::pin(async move {
                let (app, p, i) = *ctx;
                let current = transaction::current(tx, p).await?;
                current.require(p, Permission::ReleasePublish, None)?;
                app.catalog.reader().lock_in(tx).await?;
                Ok(app
                    .catalog
                    .reader()
                    .version_in(tx, &i.resource, &i.version)
                    .await?)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await?;
    let verified = app
        .content
        .as_ref()
        .ok_or(Error::Unsupported)?
        .verify(&version)
        .await
        .map_err(|_| invalid())?;
    let (package, binding) = package_material(app.tenant, &version, i)?;
    Ok(Prepared {
        version,
        package,
        binding,
        verified,
    })
}
fn package_material(
    tenant: TenantId,
    version: &r::Version,
    i: &Selection,
) -> Result<(w::Package, Binding), Error> {
    let def = definition(version, i)?;
    let native_format = format(def.spec().material.format)?;
    let package = w::Package {
        release_id: Uuid::new_v4(),
        tenant_id: Uuid::parse_str(&tenant.to_string()).map_err(|_| invalid())?,
        target: i.target,
        version: def.spec().version.clone(),
        format: native_format,
        filename: filename(i.target, native_format),
        length: def.primary().length(),
        installer_sha256: def.primary().digest().bytes(),
    };
    let binding = Binding {
        variant: i.variant.clone(),
        software: def.spec().clone(),
        resource: i.resource.clone(),
        version: i.version.clone(),
        digest: version.digest().bytes(),
        lifecycle: [0; 32],
        installer: r::SoftwareArtifact {
            reference: def.primary().reference().as_str().into(),
            origin: None,
            length: def.primary().length(),
            sha256: def.primary().digest().bytes(),
        },
    };
    Ok((package, binding))
}

/// Prepare a current release from an already enabled, content-backed software version.
/// Publication endpoints retain ownership of receipts, audit and installer admission proofs.
#[cfg(feature = "integration")]
pub async fn fixture_release_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    version: &r::Version,
    target: w::Target,
    variant: &str,
) -> transaction::Result<w::Package> {
    let selection = Selection {
        resource: version.resource().as_str().to_owned(),
        version: version.label().as_str().to_owned(),
        variant: variant.into(),
        target,
    };
    let (package, binding) = package_material(tx.tenant_id(), version, &selection)?;
    if let Some(existing) = existing_in(tx, &package, &binding).await? {
        return Ok(existing);
    }
    insert_in(tx, &package, &binding).await?;
    Ok(package)
}

// Catalog/upload identities and content locations do not change executable material.
// Preserve every execution field, including secondary artifacts and signature evidence.
fn material(spec: &r::SoftwareSpec) -> Result<serde_json::Value, Error> {
    let mut value = serde_json::to_value(spec).map_err(|_| invalid())?;
    let object = value.as_object_mut().ok_or_else(invalid)?;
    for key in ["package", "source", "provenance", "export"] {
        object.remove(key);
    }
    let artifacts = object
        .get_mut("artifacts")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(invalid)?;
    for artifact in artifacts.values_mut() {
        artifact
            .as_object_mut()
            .ok_or_else(invalid)?
            .remove("reference");
        artifact
            .as_object_mut()
            .ok_or_else(invalid)?
            .remove("origin");
    }
    if let Some(signatures) = object
        .get_mut("signatures")
        .and_then(serde_json::Value::as_array_mut)
    {
        for signature in signatures {
            if let Some(evidence) = signature
                .get_mut("evidence")
                .and_then(serde_json::Value::as_object_mut)
            {
                evidence.remove("reference");
                evidence.remove("origin");
            }
        }
    }
    Ok(value)
}

async fn existing_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    package: &w::Package,
    expected: &Binding,
) -> transaction::Result<Option<w::Package>> {
    let tenant = tx.tenant_id();
    let package = package.clone();
    let row = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT id,binding,state FROM mdm_agent_packages.releases WHERE tenant_id=$1::uuid AND platform=$2 AND architecture=$3 AND format=$4 AND product_version=$5")
            .bind(tenant.to_string())
            .bind(serde_json::to_value(package.target.platform).map_err(|_| sqlx::Error::Protocol("platform".into()))?.as_str().ok_or_else(|| sqlx::Error::Protocol("platform".into()))?)
            .bind(serde_json::to_value(package.target.architecture).map_err(|_| sqlx::Error::Protocol("architecture".into()))?.as_str().ok_or_else(|| sqlx::Error::Protocol("architecture".into()))?)
            .bind(serde_json::to_value(package.format).map_err(|_| sqlx::Error::Protocol("format".into()))?.as_str().ok_or_else(|| sqlx::Error::Protocol("format".into()))?)
            .bind(package.version).fetch_optional(c).await
    })).await?;
    let Some(row) = row else { return Ok(None) };
    let binding: Binding = serde_json::from_value(row.try_get("binding").map_err(|_| storage())?)
        .map_err(|_| storage())?;
    if material(&binding.software)? != material(&expected.software)? {
        return Err(Error::Conflict.into());
    }
    if row.try_get::<String, _>("state").map_err(|_| storage())? != "published" {
        return Err(Error::Conflict.into());
    }
    let id: Uuid = row.try_get("id").map_err(|_| storage())?;
    // Reusing an old identity must not re-enable its Software/Resource lifecycle.
    let admitted = tx
        .with_connection(move |c| Box::pin(async move { Ok(current_on(c, tenant, id).await) }))
        .await??;
    Ok(Some(admitted.0))
}

async fn insert_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    package: &w::Package,
    binding: &Binding,
) -> transaction::Result<()> {
    let tenant = tx.tenant_id();
    let package = package.clone();
    let mut binding = binding.clone();
    let admitted = tx
        .with_connection(move |c| {
            Box::pin(async move {
                binding.lifecycle = match crate::catalog::binding_on(
                    c,
                    tenant,
                    &binding.resource,
                    &binding.version,
                    binding.digest,
                )
                .await
                {
                    Ok(Some(value)) => value,
                    Ok(None) => return Ok(Ok(false)),
                    Err(e) => return Ok(Err(e)),
                };
                sqlx::query(
                    "INSERT INTO mdm_agent_packages.releases(tenant_id,id,document,binding,state) VALUES($1::uuid,$2,$3,$4,'published')",
                )
                .bind(tenant.to_string())
                .bind(package.release_id)
                .bind(
                    serde_json::to_value(&package)
                        .map_err(|_| sqlx::Error::Protocol("package metadata".into()))?,
                )
                .bind(
                    serde_json::to_value(&binding)
                        .map_err(|_| sqlx::Error::Protocol("package binding".into()))?,
                )
                .execute(c)
                .await?;
                Ok(Ok(true))
            })
        })
        .await??;
    if !admitted {
        return Err(Error::AgentPackage(Rejection::BindingNotAdmitted).into());
    }
    Ok(())
}
pub async fn publish<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
    p: &AuthorizedPrincipal,
    i: &Publish,
    a: &RequestAudit,
) -> Result<w::Package, Error> {
    p.manage(Permission::ReleasePublish)?;
    p.bind_audit(a)?;
    if p.tenant_id() != app.tenant.to_string() || i.operation_id.is_nil() || i.package_id.is_nil() {
        return Err(invalid());
    }
    a.operation(
        i.operation_id,
        "agent_package_publish",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    a.require_final_request();
    let hash = digest(&(p.principal_id(), p.instance_id(), i))?;
    let replay = transaction::inspect(
        &app.runtime,
        app.tenant,
        (app, p, i, &hash),
        |ctx, tx| {
            Box::pin(async move {
                let (app, p, i, hash) = *ctx;
                let current = transaction::current(tx, p).await?;
                current.require(p, Permission::ReleasePublish, None)?;
                app.catalog.reader().lock_in(tx).await?;
                replay_in(tx, i.operation_id, hash).await
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await?;
    let prepared = if replay.is_none() {
        let resource = i.package_id.to_string();
        let version = transaction::inspect(
            &app.runtime,
            app.tenant,
            (app, p, &resource),
            |ctx, tx| {
                Box::pin(async move {
                    let (app, p, resource) = *ctx;
                    let snapshot = transaction::current(tx, p).await?;
                    snapshot.require(p, Permission::ReleasePublish, None)?;
                    app.catalog.reader().lock_in(tx).await?;
                    Ok(app.catalog.reader().version_in(tx, resource, "v1").await?)
                })
            },
            TransactionOwner::SoftwareCatalog,
        )
        .await?;
        if version.variants().len() != 1 {
            return Err(invalid());
        }
        let selected = &version.variants()[0];
        let target = w::Target {
            platform: match selected.platform() {
                r::Platform::Windows => TaskPlatform::Windows,
                r::Platform::MacOS => TaskPlatform::Macos,
            },
            architecture: match selected.architecture() {
                r::Architecture::X86_64 => TaskArchitecture::X86_64,
                r::Architecture::Aarch64 => TaskArchitecture::Aarch64,
            },
        };
        Some(
            prepare(
                app,
                p,
                &Selection {
                    resource,
                    version: "v1".into(),
                    variant: selected.key().as_str().into(),
                    target,
                },
            )
            .await?,
        )
    } else {
        None
    };
    transaction::run(
        &app.audit,
        &app.runtime,
        app.tenant,
        a,
        (app, p, i, a, hash, prepared),
        |ctx, tx| {
            Box::pin(async move {
                let (app, p, i, a, hash, prepared) = ctx;
                let current = transaction::current(tx, p).await?;
                current.require(p, Permission::ReleasePublish, None)?;
                let partitions = prepared
                    .as_ref()
                    .map(|prepared| app.catalog.publication_partition(&prepared.version))
                    .transpose()?
                    .into_iter()
                    .collect::<Vec<_>>();
                app.catalog.reader().lock_in(tx).await?;
                app.audit.prepare_in(tx, a, &partitions).await?;
                let old = replay_in(tx, i.operation_id, hash).await?;
                let replayed = old.is_some();
                let package = if let Some(old) = old {
                    old
                } else {
                    let prepared = prepared.as_mut().ok_or(Error::Conflict)?;
                    let existing = existing_in(tx, &prepared.package, &prepared.binding).await?;
                    let package = if let Some(existing) = existing {
                        existing
                    } else {
                        let enabled = match app
                            .catalog
                            .reader()
                            .publication_binding_in(tx, &prepared.version, false)
                            .await
                        {
                            Ok(_) => true,
                            Err(crate::catalog::Error::NotAdmitted) => false,
                            Err(e) => return Err(e.into()),
                        };
                        if !enabled {
                            current.require(p, Permission::SoftwareWrite, None)?;
                        }
                        app.catalog
                            .enable_for_publication_in(
                                tx,
                                &prepared.version,
                                prepared.verified.as_ref(),
                                p.principal_id(),
                                i.operation_id,
                            )
                            .await
                            .map_err(publication_fault)?;
                        insert_in(tx, &prepared.package, &prepared.binding).await?;
                        prepared.package.clone()
                    };
                    app.catalog
                        .reader()
                        .save_operation_in(
                            tx,
                            i.operation_id,
                            hash,
                            &serde_json::to_value(&package).map_err(|_| storage())?,
                        )
                        .await?;
                    package
                };
                let fact = Fact::business(
                    a,
                    &format!("agent-package:{}", i.operation_id),
                    200,
                    "success",
                    None,
                )?;
                (if replayed {
                    Ok(())
                } else {
                    app.audit.append_in(tx, &fact).await
                })?;
                p.check_live()?;
                Ok(package)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
}
/// Current publication lifecycle in the registration owner's borrowed connection.
/// Lock order is configuration -> software -> resource; publication never takes configuration locks.
pub async fn admitted_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    i: &w::Installation,
) -> Result<w::Package, Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("mdm-software:{tenant}"))
        .execute(&mut *c)
        .await
        .map_err(|_| storage())?;
    admitted_many_locked_on(c, tenant, &[i.release_id])
        .await?
        .remove(&i.release_id)
        .ok_or(Error::Forbidden)
}

/// Read publication facts in bulk. No publication or resource locks in a directory scan.
pub async fn admitted_many_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    ids: &[Uuid],
) -> Result<std::collections::BTreeMap<Uuid, w::Package>, Error> {
    admitted_batch(c, tenant, ids, false).await
}
pub async fn admitted_many_locked_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    ids: &[Uuid],
) -> Result<std::collections::BTreeMap<Uuid, w::Package>, Error> {
    // Publication withdrawal takes this same lock before reading or changing state.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("mdm-software:{tenant}"))
        .execute(&mut *c)
        .await
        .map_err(|_| storage())?;
    admitted_batch(c, tenant, ids, true).await
}
async fn admitted_batch(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    ids: &[Uuid],
    lock: bool,
) -> Result<std::collections::BTreeMap<Uuid, w::Package>, Error> {
    if ids.is_empty() {
        return Ok(Default::default());
    }
    let rows=sqlx::query("WITH selected AS MATERIALIZED(SELECT id,document,binding FROM mdm_agent_packages.releases WHERE tenant_id=$1::uuid AND id=ANY($2) AND state='published'),budget AS(SELECT coalesce(sum(octet_length(document::text)+octet_length(binding::text)),0)::bigint AS bytes FROM selected) SELECT selected.*,budget.bytes FROM budget LEFT JOIN selected ON budget.bytes<=16777216").bind(tenant.to_string()).bind(ids).fetch_all(&mut *c).await.map_err(|_|storage())?;
    if rows
        .first()
        .ok_or_else(storage)?
        .try_get::<i64, _>("bytes")
        .map_err(|_| storage())?
        > 16777216
    {
        return Err(storage());
    }
    let mut packages = Vec::new();
    let mut bindings = Vec::new();
    let mut requests = Vec::new();
    for row in rows {
        let Some(id) = row
            .try_get::<Option<Uuid>, _>("id")
            .map_err(|_| storage())?
        else {
            continue;
        };
        let package: w::Package =
            serde_json::from_value(row.try_get("document").map_err(|_| storage())?)
                .map_err(|_| storage())?;
        let binding: Binding =
            serde_json::from_value(row.try_get("binding").map_err(|_| storage())?)
                .map_err(|_| storage())?;
        requests.push(crate::catalog::BindingRequest {
            resource: binding.resource.clone(),
            version: binding.version.clone(),
            digest: binding.digest,
            allow_draft: false,
            selection: None,
        });
        bindings.push(binding.lifecycle);
        packages.push((id, package));
    }
    let resolved = if lock {
        crate::catalog::bindings_many_locked_on(c, tenant, &requests).await
    } else {
        crate::catalog::bindings_many_on(c, tenant, &requests).await
    }
    .map_err(|_| storage())?;
    Ok(packages
        .into_iter()
        .zip(bindings)
        .zip(resolved)
        .filter_map(|((package, expected), actual)| (actual == Some(expected)).then_some(package))
        .collect())
}

async fn current_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<(w::Package, Binding), Error> {
    let row=sqlx::query("SELECT document,binding FROM mdm_agent_packages.releases WHERE tenant_id=$1::uuid AND id=$2 AND state='published'").bind(tenant.to_string()).bind(id).fetch_optional(&mut *c).await.map_err(|_|storage())?.ok_or(Error::ResourceMissing)?;
    let package: w::Package =
        serde_json::from_value(row.try_get("document").map_err(|_| storage())?)
            .map_err(|_| storage())?;
    let binding: Binding = serde_json::from_value(row.try_get("binding").map_err(|_| storage())?)
        .map_err(|_| storage())?;
    admitted_on(c, tenant, &w::Installation { release_id: id }).await?;
    Ok((package, binding))
}
pub async fn list(
    runtime: &Arc<PgRuntime>,
    tenant: rss_request_context::TenantId,
) -> Result<Vec<w::Package>, Error> {
    transaction::inspect(runtime,tenant,tenant,|tenant,tx|{
  let tenant=*tenant;
  Box::pin(async move {Ok(tx.with_connection(move|c|Box::pin(async move{
   let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_agent_packages.releases WHERE tenant_id=$1::uuid AND state='published' ORDER BY id").bind(tenant.to_string()).fetch_all(&mut *c).await?;
   let mut out=Vec::new();
   for id in ids {match current_on(c,tenant,id).await {Ok((p,_))=>out.push(p),Err(Error::Forbidden|Error::ResourceMissing)=>{},Err(e)=>return Ok(Err(e))}}
   Ok(Ok(out))
  })).await??)})
 },TransactionOwner::SoftwareCatalog).await
}
pub async fn metadata_public<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
    id: Uuid,
) -> Result<w::Package, Error> {
    Ok(inspect_package(app, id).await?.0)
}
async fn inspect_package<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
    id: Uuid,
) -> Result<(w::Package, Binding), Error> {
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (app.tenant, id),
        |ctx, tx| {
            let (tenant, id) = *ctx;
            Box::pin(async move {
                Ok(tx
                    .with_connection(move |c| {
                        Box::pin(async move { Ok(current_on(c, tenant, id).await) })
                    })
                    .await??)
            })
        },
        TransactionOwner::SoftwareCatalog,
    )
    .await
}
pub async fn download<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
    id: Uuid,
) -> Result<(w::Package, C::Download), Error> {
    let (package, binding) = inspect_package(app, id).await?;
    let artifact = binding.installer.artifact().map_err(|_| storage())?;
    let file = app
        .content
        .as_ref()
        .ok_or(Error::Unsupported)?
        .verify_artifact(&artifact)
        .await?;
    // File verification performs I/O outside the lifecycle transaction; recheck before exposing it.
    let (current, current_binding) = inspect_package(app, id).await?;
    if current.installer_sha256 != package.installer_sha256
        || current_binding.digest != binding.digest
    {
        return Err(Error::Conflict);
    }
    Ok((package, file))
}
pub async fn withdraw<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
    p: &AuthorizedPrincipal,
    id: Uuid,
    operation: Uuid,
    a: &RequestAudit,
) -> Result<(), Error> {
    p.manage(Permission::SoftwareWithdraw)?;
    p.bind_audit(a)?;
    if p.tenant_id() != app.tenant.to_string() || operation.is_nil() {
        return Err(invalid());
    }
    a.operation(
        operation,
        "agent_package_withdraw",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let hash = digest(&(
        "agent_package_withdraw",
        p.principal_id(),
        p.instance_id(),
        id,
        operation,
    ))?;
    transaction::run(&app.audit,&app.runtime,app.tenant,a,(app,p,id,operation,a,hash),|ctx,tx|Box::pin(async move{
  let (app,p,id,operation,a,hash)=ctx;
  transaction::current(tx,p).await?.require(p,Permission::SoftwareWithdraw,None)?;
  app.catalog.reader().lock_in(tx).await?;
  app.audit.prepare_in(tx,a,&[]).await?;
  let tenant=app.tenant.to_string();let id=*id;let op=*operation;let d=hash.clone();
  let old=tx.with_connection(move|c|Box::pin(async move{
   if let Some(row)=sqlx::query("SELECT fingerprint FROM mdm_software.operations WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(op).fetch_optional(&mut *c).await?{return Ok(Some(row.try_get::<Vec<u8>,_>("fingerprint")?));}
   let n=sqlx::query("UPDATE mdm_agent_packages.releases SET state='withdrawn' WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(id).execute(&mut *c).await?.rows_affected();
   if n!=1{return Err(sqlx::Error::RowNotFound);}
   sqlx::query("INSERT INTO mdm_software.operations VALUES($1::uuid,$2,$3,jsonb_build_object('withdrawn',$4::uuid))").bind(&tenant).bind(op).bind(d).bind(id).execute(c).await?;
   Ok(None)
  })).await?;
  if old.as_ref().is_some_and(|v|v!=hash){return Err(Error::Conflict.into());}
  let fact=Fact::business(a, &format!("agent-package-withdraw:{operation}"), 200, "success", None)?;
  (if old.is_some() { Ok(()) } else { app.audit.append_in(tx, &fact).await })?;p.check_live()?;Ok(())
 }),TransactionOwner::SoftwareCatalog).await
}

/// Current published Agent candidate. Constructed only after release and software admission.
pub struct AdmittedPackage {
    pub metadata: w::Package,
    pub resource: String,
    pub version: String,
    pub variant: String,
    pub digest: [u8; 32],
    pub lifecycle: [u8; 32],
    pub software: r::SoftwareSpec,
}
/// Resolve an explicit release; ordinary Software resources cannot authorize Agent bootstrap.
pub async fn resolve_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<AdmittedPackage, Error> {
    let (metadata, binding) = current_on(c, tenant, id).await?;
    Ok(AdmittedPackage {
        metadata,
        resource: binding.resource,
        version: binding.version,
        variant: binding.variant,
        digest: binding.digest,
        lifecycle: binding.lifecycle,
        software: binding.software,
    })
}

/// Historical package identities are observation targets, not deployment authority.
/// Withdrawn packages remain detectable so another format cannot silently reinstall the Agent.
pub async fn known_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
) -> Result<Vec<AdmittedPackage>, Error> {
    let rows = sqlx::query("SELECT document,binding FROM mdm_agent_packages.releases WHERE tenant_id=$1::uuid ORDER BY id")
        .bind(tenant.to_string()).fetch_all(c).await.map_err(|_| storage())?;
    rows.into_iter()
        .map(|row| {
            let metadata = serde_json::from_value(row.try_get("document").map_err(|_| storage())?)
                .map_err(|_| storage())?;
            let binding: Binding =
                serde_json::from_value(row.try_get("binding").map_err(|_| storage())?)
                    .map_err(|_| storage())?;
            Ok(AdmittedPackage {
                metadata,
                resource: binding.resource,
                version: binding.version,
                variant: binding.variant,
                digest: binding.digest,
                lifecycle: binding.lifecycle,
                software: binding.software,
            })
        })
        .collect()
}
