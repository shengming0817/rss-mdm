//! Native execution reads the same frozen publication and lifecycle authorities as hosted clients.
use super::read::current_published;
use super::storage::Subject;
use super::{self as publication, spec, storage as db, *};
use rss_mdm_agent_wire::runtime::{brew_documents_digest, winget_document_digest};
use rss_mdm_resource as r;
use rss_mdm_software_release as rel;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
/// Exact native readonly protocol of a frozen publication.
pub enum NativeExportProtocol {
    /// Public frozen WinGet REST source.
    Winget { uri: String, identifier: String },
    /// Scoped immutable Git source; the credential value is never returned.
    Brew {
        uri: String,
        commit: String,
        tap: String,
        credential_reference: String,
    },
}
/// Derived read identity for an enabled and published Resource version.
pub struct NativeExport {
    pub target: String,
    pub tenant: TenantId,

    pub publication: [u8; 32],
    pub target_digest: [u8; 32],
    pub resource: String,
    pub resource_version: String,
    pub resource_digest: [u8; 32],
    pub definition_digest: [u8; 32],
    pub document_sha256: [u8; 32],
    pub dependencies: Vec<(String, String, [u8; 32])>,
    pub artifacts: Vec<PublicArtifact>,
    pub protocol: NativeExportProtocol,
}
pub struct ExportReader {
    sources: super::config::ExportSources,
    catalog: crate::catalog::Reader,
}
impl ExportReader {
    pub(super) fn new(sources: super::config::ExportSources) -> Self {
        Self {
            catalog: crate::catalog::Reader::new(sources.tenant),
            sources,
        }
    }
    fn tenant(&self) -> rss_request_context::TenantId {
        self.sources.tenant
    }
    fn native_identifier(&self, publication: Option<[u8; 32]>) -> String {
        match publication {
            Some(id) => format!("rss.{}", super::hex(&id)),
            None => format!("rss.{}", super::hex(&self.sources.digest)),
        }
    }

    /// Borrow the execution transaction so current Resource, source and publication locks are shared.
    pub async fn native_export_in(
        &self,
        tx: &mut PgTransaction<'_>,

        expected: &r::Version,
    ) -> InTransaction<Option<NativeExport>> {
        if tx.tenant_id() != self.tenant() {
            return Ok(Err(Error::Identity));
        }
        tx.with_connection_context(&mut (self, expected), |(owner, expected), c| {
            Box::pin(async move { Ok(owner.native_export_on(c, expected, true).await) })
        })
        .await?
    }
    /// Borrow the page snapshot or the original locked execution transaction.
    pub(crate) async fn native_export_on(
        &self,
        c: &mut sqlx::PgConnection,
        expected: &r::Version,
        locked: bool,
    ) -> InTransaction<Option<NativeExport>> {
        if expected.tenant() != self.tenant() {
            return Ok(Err(Error::Identity));
        }
        self.catalog_lock_on(c, locked).await?;
        let binding = self.sources.binding().identity.clone();
        let tenant = self.tenant().to_string();
        let resource = expected.resource().as_str().to_owned();
        let version = expected.label().as_str().to_owned();
        let ids: Vec<Vec<u8>> = {
            sqlx::query_scalar("SELECT DISTINCT p.publication FROM mdm_software_composition.projections p JOIN mdm_software_composition.targets t ON t.tenant_id=p.tenant_id AND t.id LIKE ('p:'||encode(p.publication,'hex')||':%') JOIN mdm_software_composition.subjects s ON s.tenant_id=t.tenant_id AND s.record=t.record WHERE p.tenant_id=$1::uuid AND p.binding=$2 AND s.resource=$3 AND s.version=$4 LIMIT 2").bind(tenant).bind(binding).bind(resource).bind(version).fetch_all(&mut *c).await
        }?;
        if ids.is_empty() {
            return Ok(Ok(None));
        }
        if ids.len() != 1 {
            return Ok(Err(Error::Content));
        }
        let id: [u8; 32] = ids[0].clone().try_into().map_err(|_| db::fault())?;
        let (version, subject, target) = input!(self.published_on(c, id, locked).await?);
        if version.digest() != expected.digest() {
            return Ok(Err(Error::Content));
        }
        let dependencies = input!(self.native_dependencies_on(c, &version, locked).await?);
        let prepared = input!(spec::prepare(&self.sources, &version, &dependencies));
        if db::encode(&prepared.document)? != db::encode(&subject.document)? {
            return Ok(Err(Error::Content));
        }
        let record_id = input!(
            rel::PublicationKey::new(self.tenant(), &target.record).map_err(|_| Error::Identity)
        );
        let record = input!(
            self.release_on(c, &record_id, locked)
                .await?
                .map_err(|_| Error::Content)
        );
        if record.snapshot().content.digest() != prepared.content.digest() {
            return Ok(Err(Error::Content));
        }
        let (protocol, document_sha256) =
            match (&self.sources.binding().protocol, &prepared.document) {
                (
                    super::config::ExportProtocol::Winget { base, .. },
                    ExportDocument::Winget { manifest },
                ) => (
                    NativeExportProtocol::Winget {
                        uri: format!("{base}exports/{}/", publication::hex(&id)),
                        identifier: self.native_identifier(Some(id)),
                    },
                    input!(
                        winget_document_digest(&input!(
                            serde_json::to_value(manifest).map_err(|_| Error::Content)
                        ))
                        .map_err(|_| Error::Content)
                    ),
                ),
                (
                    super::config::ExportProtocol::Brew {
                        base,
                        credential_reference,
                        ..
                    },
                    ExportDocument::Brew { recipe },
                ) => {
                    let tap = format!("rss/{}", publication::hex(&version.digest().bytes()));
                    let docs = input!(recipe.documents(self.tenant(), &tap));
                    let digest = input!(
                        brew_documents_digest(docs.iter().map(|d| (d.path(), d.bytes())))
                            .map_err(|_| Error::Content)
                    );
                    (
                        NativeExportProtocol::Brew {
                            uri: format!("{base}exports/{}.git", publication::hex(&id)),
                            commit: target.snapshot.ok_or_else(db::fault)?,
                            tap,
                            credential_reference: credential_reference.clone(),
                        },
                        digest,
                    )
                }
                _ => return Ok(Err(Error::Unsupported)),
            };
        let base = &self.sources.artifacts_base;
        Ok(Ok(Some(NativeExport {
            target: self.sources.logical.clone(),
            tenant: self.tenant(),
            publication: id,
            target_digest: self.sources.digest,
            resource: subject.resource,
            resource_version: subject.version,
            resource_digest: subject.resource_digest,
            definition_digest: prepared.content.digest().bytes(),
            document_sha256,
            dependencies: dependencies
                .iter()
                .map(|v| {
                    (
                        v.resource().as_str().to_owned(),
                        v.label().as_str().to_owned(),
                        v.digest().bytes(),
                    )
                })
                .collect(),
            artifacts: input!(derive::exported_materials(&version, &dependencies, base)),
            protocol,
        })))
    }
    async fn native_dependencies_on(
        &self,
        c: &mut sqlx::PgConnection,
        root: &r::Version,
        locked: bool,
    ) -> InTransaction<Vec<r::Version>> {
        match self.catalog.dependency_versions_on(c, root, locked).await {
            Ok(versions) => Ok(Ok(versions)),
            Err(crate::catalog::Error::Storage(e)) => Err(e),
            Err(crate::catalog::Error::Sql(e)) => Err(e.into()),
            Err(_) => Ok(Err(Error::Content)),
        }
    }
    async fn catalog_lock_on(
        &self,
        c: &mut sqlx::PgConnection,
        locked: bool,
    ) -> std::result::Result<(), rss_transactional_messaging_postgres::PgError> {
        if locked {
            sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
                .bind(format!("mdm-software:{}", self.tenant()))
                .execute(c)
                .await?;
        }
        Ok(())
    }
    async fn release_on(
        &self,
        c: &mut sqlx::PgConnection,
        id: &rel::PublicationKey,
        locked: bool,
    ) -> rss_mdm_software_release_postgres::InTransaction<rel::Publication> {
        if locked {
            rss_mdm_software_release_postgres::lock_publication_reference_on(c, id).await
        } else {
            Ok(
                rss_mdm_software_release_postgres::read_publication_reference_on(c, id)
                    .await?
                    .and_then(|value| {
                        value.ok_or(rss_mdm_software_release_postgres::Rejection::NotFound)
                    }),
            )
        }
    }
}

impl ExportReader {
    pub(super) async fn published_in(
        &self,
        tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,

        publication: [u8; 32],
    ) -> InTransaction<(r::Version, db::Subject, db::Target)> {
        if tx.tenant_id() != self.tenant() {
            return Ok(Err(Error::Identity));
        }
        tx.with_connection_context(&mut (self,), |(owner,), c| {
            Box::pin(async move { Ok(owner.published_on(c, publication, true).await) })
        })
        .await?
    }
    async fn published_on(
        &self,
        c: &mut sqlx::PgConnection,
        publication: [u8; 32],
        locked: bool,
    ) -> InTransaction<(r::Version, db::Subject, db::Target)> {
        self.catalog_lock_on(c, locked).await?;
        let tenant = self.tenant().to_string();
        let prefix = format!("p:{}:%", hex(&publication));
        let keys: Vec<String> = {
            sqlx::query_scalar("SELECT id FROM mdm_software_composition.targets WHERE tenant_id=$1::uuid AND id LIKE $2 ORDER BY length(id) DESC,id COLLATE \"C\" DESC LIMIT 2").bind(tenant).bind(prefix).fetch_all(&mut *c).await
        }?;
        let mut selected = None;
        for key in keys {
            let call = db::call_on(c, self.tenant(), db::Table::Publish, &key)
                .await?
                .ok_or_else(db::fault)?;
            let target = call.target;
            if (target.publication, target.binding.as_slice())
                != (publication, self.sources.binding().identity.as_slice())
            {
                continue;
            }
            self.source_lock_on(c, &target, locked).await?;
            if db::projection_on(c, self.tenant(), &target)
                .await?
                .as_deref()
                != Some(publication.as_slice())
            {
                continue;
            }
            let id = input!(
                rel::PublicationKey::new(self.tenant(), &target.record)
                    .map_err(|_| Error::Identity)
            );
            let record = input!(
                self.release_on(c, &id, locked)
                    .await?
                    .map_err(|_| Error::Content)
            );
            if !current_published(&record, &target)
                || db::call_on(
                    c,
                    self.tenant(),
                    db::Table::Withdraw,
                    &target.withdrawal_key(),
                )
                .await?
                .is_some()
            {
                continue;
            }
            let subject = db::subject_on(c, self.tenant(), &target.record)
                .await?
                .ok_or_else(db::fault)?;
            input!(
                self.resource_usable_on(c, &subject, target.lifecycle, locked)
                    .await?
            );
            let version = input!(
                self.catalog
                    .version_on(c, &subject.resource, &subject.version, locked)
                    .await
                    .map_err(|_| Error::Content)
            );
            selected = Some((version, subject, target));
            break;
        }
        Ok(selected.ok_or(Error::PublicationNotFound))
    }
    async fn source_lock_on(
        &self,
        c: &mut sqlx::PgConnection,
        target: &db::Target,
        locked: bool,
    ) -> std::result::Result<(), sqlx::Error> {
        if locked {
            sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,2389))")
                .bind(format!(
                    "mdm-software:{}:source:{}:{}",
                    self.tenant(),
                    hex(&target.binding),
                    target.slot
                ))
                .execute(&mut *c)
                .await?;
        }
        Ok(())
    }
    pub(super) async fn resource_usable(
        &self,
        tx: &mut PgTransaction<'_>,
        subject: &Subject,
        lifecycle: [u8; 32],
    ) -> InTransaction<()> {
        if tx.tenant_id() != self.tenant() {
            return Ok(Err(Error::Identity));
        }
        tx.with_connection_context(&mut (self, subject), |(owner, subject), c| {
            Box::pin(async move { Ok(owner.resource_usable_on(c, subject, lifecycle, true).await) })
        })
        .await?
    }
    async fn resource_usable_on(
        &self,
        c: &mut sqlx::PgConnection,
        subject: &Subject,
        lifecycle: [u8; 32],
        locked: bool,
    ) -> InTransaction<()> {
        self.catalog_lock_on(c, locked).await?;
        let version = input!(
            self.catalog
                .version_on(c, &subject.resource, &subject.version, locked)
                .await
                .map_err(|_| Error::Content)
        );
        if version.digest().bytes() != subject.resource_digest {
            return Ok(Err(Error::Content));
        }
        let request = crate::catalog::BindingRequest {
            resource: subject.resource.clone(),
            version: subject.version.clone(),
            digest: subject.resource_digest,
            allow_draft: false,
            selection: None,
        };
        let binding = if locked {
            crate::catalog::bindings_many_locked_on(c, self.tenant(), &[request]).await
        } else {
            crate::catalog::bindings_many_on(c, self.tenant(), &[request]).await
        };
        if input!(binding.map_err(|_| Error::Content)).pop().flatten() != Some(lifecycle) {
            return Ok(Err(Error::Content));
        }
        Ok(Ok(()))
    }
}
