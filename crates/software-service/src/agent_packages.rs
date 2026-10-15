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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;
pub const INSTALL_SQL: &str = include_str!("agent_packages.sql");
pub const ACCESS_CONTRACT: &str = include_str!("agent_packages_access.json");
/// Candidate metadata is itself an immutable, digest-verified Resource artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub wire_version: u8,
    pub tenant_id: Uuid,
    pub target: w::Target,
    pub version: String,
    pub origin: String,
    pub signing_keys: std::collections::BTreeMap<String, String>,
    pub packaging: Packaging,
}
/// External builders own signing and notarization. Publication freezes their reviewed evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Packaging {
    NsisExe {
        publisher: String,
        signature_evidence: String,
    },
    MacosPkg {
        team: String,
        notarization_evidence: String,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Publish {
    pub operation_id: Uuid,
    pub resource: String,
    pub version: String,
    pub variant: String,
    pub target: w::Target,
    pub channel: w::Channel,
    pub manifest_artifact: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    resource: String,
    version: String,
    digest: [u8; 32],
    lifecycle: [u8; 32],
    installer: r::SoftwareArtifact,
}
pub struct PublicationMaterials<D> {
    pub installer: D,
    pub manifest: Vec<u8>,
}
/// Content adapter pins both originals while this owner publishes their exact binding.
pub trait Materials: ManagementContentPort {
    fn publication_materials(
        &self,
        installer: &r::Artifact,
        manifest: &r::Artifact,
    ) -> impl std::future::Future<Output = Result<PublicationMaterials<Self::Download>, Error>> + Send;
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
fn definition<'a>(v: &'a r::Version, i: &Publish) -> Result<&'a r::SoftwareDefinition, Error> {
    let (p, a) = target(i.target);
    let selected = v
        .variants()
        .iter()
        .find(|x| x.platform() == p && x.architecture() == a && x.key().as_str() == i.variant)
        .ok_or_else(invalid)?;
    let r::Declaration::Software { definition } = selected.declaration() else {
        return Err(invalid());
    };
    let system = match &definition.spec().behavior {
        r::SoftwareBehavior::Exe(x) => {
            i.target.platform == TaskPlatform::Windows
                && x.scope == r::SoftwareScope::System
                && x.layout.len() == 2
                && x.layout.values().any(|key| key == &i.manifest_artifact)
        }
        r::SoftwareBehavior::Pkg(x) => {
            i.target.platform == TaskPlatform::Macos && x.scope == r::SoftwareScope::System
        }
        _ => false,
    };
    if !system {
        return Err(invalid());
    }
    Ok(definition)
}
fn metadata(
    manifest: &Manifest,
    i: &Publish,
    tenant: TenantId,
    installer: &r::Artifact,
    bytes: &[u8],
    id: Uuid,
) -> Result<w::Package, Error> {
    let bounded = |s: &str| !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control);
    let packaging = match &manifest.packaging {
        Packaging::NsisExe {
            publisher,
            signature_evidence,
        } => {
            i.target.platform == TaskPlatform::Windows
                && bounded(publisher)
                && bounded(signature_evidence)
        }
        Packaging::MacosPkg {
            team,
            notarization_evidence,
        } => {
            i.target.platform == TaskPlatform::Macos
                && team.len() == 10
                && team
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                && bounded(notarization_evidence)
        }
    };
    let origin = url::Url::parse(&manifest.origin).map_err(|_| invalid())?;
    if manifest.wire_version != 1
        || manifest.tenant_id.to_string() != tenant.to_string()
        || manifest.target != i.target
        || !bounded(&manifest.version)
        || manifest.signing_keys.is_empty()
        || manifest.signing_keys.len() > 16
        || manifest.signing_keys.iter().any(|(id, key)| {
            id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || key.len() != 43
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
        || manifest.origin.len() > 2048
        || !packaging
        || origin.scheme() != "https"
        || origin.origin().ascii_serialization() != manifest.origin
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        return Err(invalid());
    }
    Ok(w::Package {
        release_id: id,
        tenant_id: manifest.tenant_id,
        channel: i.channel,
        target: i.target,
        version: manifest.version.clone(),
        filename: filename(i.target).into(),
        length: installer.length(),
        installer_sha256: installer.digest().bytes(),
        candidate_sha256: Sha256::digest(bytes).into(),
        origin: manifest.origin.clone(),
        signing_keys: manifest.signing_keys.clone(),
    })
}
struct Prepared<D> {
    version: r::Version,
    package: w::Package,
    binding: Binding,
    _materials: PublicationMaterials<D>,
    verified: Box<dyn crate::catalog::VerifiedContent>,
}
fn filename(target: w::Target) -> &'static str {
    match (target.platform, target.architecture) {
        (TaskPlatform::Windows, TaskArchitecture::X86_64) => "rss-agent-windows-x86_64.exe",
        (TaskPlatform::Windows, TaskArchitecture::Aarch64) => "rss-agent-windows-aarch64.exe",
        (TaskPlatform::Macos, TaskArchitecture::X86_64) => "rss-agent-macos-x86_64.pkg",
        (TaskPlatform::Macos, TaskArchitecture::Aarch64) => "rss-agent-macos-aarch64.pkg",
    }
}
async fn replay_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    operation: Uuid,
    hash: &[u8],
) -> transaction::Result<Option<w::Package>> {
    let tenant = tx.tenant_id().to_string();
    let old=tx.with_connection(move|c|Box::pin(async move {
  sqlx::query("SELECT request_digest,document FROM mdm_agent_packages.releases WHERE tenant_id=$1::uuid AND operation_id=$2").bind(tenant).bind(operation).fetch_optional(c).await
 })).await?;
    old.map(|row| {
        if row.try_get::<Vec<u8>, _>("request_digest")? != hash {
            return Err(Error::Conflict.into());
        }
        serde_json::from_value(row.try_get("document")?).map_err(|_| storage().into())
    })
    .transpose()
}
async fn prepare<C: Materials>(
    app: &management::catalog::Access<C>,
    p: &AuthorizedPrincipal,
    i: &Publish,
) -> Result<Prepared<C::Download>, Error> {
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
    let def = definition(&version, i)?;
    let candidate = def
        .spec()
        .artifacts
        .get(&i.manifest_artifact)
        .ok_or_else(invalid)?
        .artifact()
        .map_err(|_| invalid())?;
    if candidate == *def.primary() || candidate.length() > 32768 {
        return Err(invalid());
    }
    let materials = app
        .content
        .as_ref()
        .ok_or(Error::Unsupported)?
        .publication_materials(def.primary(), &candidate)
        .await?;
    candidate
        .verify(&materials.manifest)
        .map_err(|_| invalid())?;
    let manifest: Manifest = serde_json::from_slice(&materials.manifest).map_err(|_| invalid())?;
    if manifest.version != def.spec().version {
        return Err(invalid());
    }
    let package = metadata(
        &manifest,
        i,
        app.tenant,
        def.primary(),
        &materials.manifest,
        Uuid::new_v4(),
    )?;
    let binding = Binding {
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
    Ok(Prepared {
        version,
        package,
        binding,
        _materials: materials,
        verified,
    })
}
async fn insert_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    i: &Publish,
    hash: &[u8],
    package: &w::Package,
    binding: &Binding,
) -> transaction::Result<()> {
    let tenant = tx.tenant_id();
    let op = i.operation_id;
    let hash = hash.to_vec();
    let package = package.clone();
    let mut binding = binding.clone();
    let admitted=tx.with_connection(move|c|Box::pin(async move {
  binding.lifecycle=match crate::catalog::binding_on(c,tenant,&binding.resource,&binding.version,binding.digest).await { Ok(Some(value))=>value,Ok(None)=>return Ok(Ok(false)),Err(e)=>return Ok(Err(e)) };
  sqlx::query("INSERT INTO mdm_agent_packages.releases VALUES($1::uuid,$2,$3,$4,$5,$6,'published')").bind(tenant.to_string()).bind(package.release_id).bind(op).bind(hash).bind(serde_json::to_value(&package).map_err(|_|sqlx::Error::Protocol("package metadata".into()))?).bind(serde_json::to_value(&binding).map_err(|_|sqlx::Error::Protocol("package binding".into()))?).execute(c).await?;
  Ok(Ok(true))
 })).await??;
    if !admitted {
        return Err(Error::Forbidden.into());
    }
    Ok(())
}
pub async fn publish<C: Materials>(
    app: &management::catalog::Access<C>,
    p: &AuthorizedPrincipal,
    i: &Publish,
    a: &RequestAudit,
) -> Result<w::Package, Error> {
    p.manage(Permission::ReleasePublish)?;
    p.bind_audit(a)?;
    if p.tenant_id() != app.tenant.to_string() || i.operation_id.is_nil() {
        return Err(invalid());
    }
    a.operation(i.operation_id, "agent_package_publish");
    a.require_request_settlement();
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
        Some(prepare(app, p, i).await?)
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
                if let Some(prepared) = prepared.as_ref() {
                    tx.prepare_outbox_partitions(&[app
                        .catalog
                        .publication_partition(&prepared.version)?])
                        .await?;
                }
                app.catalog.reader().lock_in(tx).await?;
                let old = replay_in(tx, i.operation_id, hash).await?;
                let replayed = old.is_some();
                let package = if let Some(old) = old {
                    old
                } else {
                    let prepared = prepared.as_mut().ok_or(Error::Conflict)?;
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
                        .await?;
                    insert_in(tx, i, hash, &prepared.package, &prepared.binding).await?;
                    prepared.package.clone()
                };
                let fact = Fact::business(
                    a,
                    &format!("agent-package:{}", i.operation_id),
                    hash,
                    200,
                    "success",
                    None,
                )?;
                app.audit.append_in(tx, &fact, replayed).await?;
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
    let row=sqlx::query("SELECT document,binding,state FROM mdm_agent_packages.releases WHERE tenant_id=$1::uuid AND id=$2").bind(tenant.to_string()).bind(i.release_id).fetch_optional(&mut *c).await.map_err(|_|storage())?.ok_or(Error::ResourceMissing)?;
    let package: w::Package =
        serde_json::from_value(row.try_get("document").map_err(|_| storage())?)
            .map_err(|_| storage())?;
    let binding: Binding = serde_json::from_value(row.try_get("binding").map_err(|_| storage())?)
        .map_err(|_| storage())?;
    if row.try_get::<String, _>("state").map_err(|_| storage())? != "published"
        || i.candidate_sha256 != package.candidate_sha256
        || !crate::catalog::admitted_on(
            c,
            tenant,
            &binding.resource,
            &binding.version,
            binding.digest,
            binding.lifecycle,
        )
        .await
        .map_err(|_| storage())?
    {
        return Err(Error::Forbidden);
    }
    Ok(package)
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
    admitted_on(
        c,
        tenant,
        &w::Installation {
            release_id: id,
            candidate_sha256: package.candidate_sha256,
        },
    )
    .await?;
    Ok((package, binding))
}
pub async fn list<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
) -> Result<Vec<w::Package>, Error> {
    transaction::inspect(&app.runtime,app.tenant,app.tenant,|tenant,tx|{
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
    a.operation(operation, "agent_package_withdraw");
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
  let tenant=app.tenant.to_string();let id=*id;let op=*operation;let d=hash.clone();
  let old=tx.with_connection(move|c|Box::pin(async move{
   if let Some(row)=sqlx::query("SELECT fingerprint FROM mdm_software.operations WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(op).fetch_optional(&mut *c).await?{return Ok(Some(row.try_get::<Vec<u8>,_>("fingerprint")?));}
   let n=sqlx::query("UPDATE mdm_agent_packages.releases SET state='withdrawn' WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(id).execute(&mut *c).await?.rows_affected();
   if n!=1{return Err(sqlx::Error::RowNotFound);}
   sqlx::query("INSERT INTO mdm_software.operations VALUES($1::uuid,$2,$3,'null')").bind(&tenant).bind(op).bind(d).execute(c).await?;
   Ok(None)
  })).await?;
  if old.as_ref().is_some_and(|v|v!=hash){return Err(Error::Conflict.into());}
  let fact=Fact::business(a,&format!("agent-package-withdraw:{operation}"),hash,200,"success",None)?;
  app.audit.append_in(tx,&fact,old.is_some()).await?;p.check_live()?;Ok(())
 }),TransactionOwner::SoftwareCatalog).await
}
