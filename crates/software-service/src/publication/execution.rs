//! Native execution reads the same frozen publication and approval authorities as hosted clients.
use super::{self as publication, spec, storage as db, *};
use rss_mdm_resource as r;
use rss_mdm_software_release as rel;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
use sha2::{Digest, Sha256};
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
/// Derived read identity for an already approved and published Resource version.
pub struct NativeExport {
    pub source: String,
    pub tenant: TenantId,
    pub ring: rel::Ring,
    pub publication: [u8; 32],
    pub source_digest: [u8; 32],
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
    fn native_identifier(&self, ring: rel::Ring, publication: Option<[u8; 32]>) -> String {
        match publication {
            Some(id) => format!("rss.{}", super::hex(&id)),
            None => format!(
                "rss.{}.{}",
                super::hex(&self.sources.digest),
                super::config::index(ring)
            ),
        }
    }

    /// Borrow the execution transaction so current Resource, source and publication locks are shared.
    pub async fn native_export_in(
        &self,
        tx: &mut PgTransaction<'_>,
        ring: rel::Ring,
        expected: &r::Version,
    ) -> InTransaction<Option<NativeExport>> {
        if tx.tenant_id() != self.tenant() || expected.tenant() != self.tenant() {
            return Ok(Err(Error::Identity));
        }
        input!(self.catalog.lock_in(tx).await.map_err(|_| Error::Content));
        let binding = self.sources.binding(ring).identity.clone();
        let tenant = tx.tenant_id().to_string();
        let resource = expected.resource().as_str().to_owned();
        let version = expected.label().as_str().to_owned();
        let ids:Vec<Vec<u8>>=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT DISTINCT p.publication FROM mdm_software_composition.projections p JOIN mdm_software_composition.targets t ON t.tenant_id=p.tenant_id AND t.id LIKE ('p:'||encode(p.publication,'hex')||':%') JOIN mdm_software_composition.subjects s ON s.tenant_id=t.tenant_id AND s.candidate=t.candidate WHERE p.tenant_id=$1::uuid AND p.binding=$2 AND s.resource=$3 AND s.version=$4 LIMIT 2").bind(tenant).bind(binding).bind(resource).bind(version).fetch_all(c).await
        })).await?;
        if ids.is_empty() {
            return Ok(Ok(None));
        }
        if ids.len() != 1 {
            return Ok(Err(Error::Content));
        }
        let id: [u8; 32] = ids[0].clone().try_into().map_err(|_| db::fault())?;
        let (version, subject, target) = input!(self.published_in(tx, ring, id).await?);
        if version.digest() != expected.digest() {
            return Ok(Err(Error::Content));
        }
        let dependencies = input!(self.native_dependencies_in(tx, &version).await?);
        let prepared = input!(spec::prepare(&self.sources, &version, &dependencies));
        if db::encode(&prepared.document)? != db::encode(&subject.document)? {
            return Ok(Err(Error::Content));
        }
        let candidate_id = input!(
            rel::CandidateId::new(self.tenant(), &target.candidate).map_err(|_| Error::Identity)
        );
        let candidate = input!(
            rss_mdm_software_release_postgres::lock_candidate_reference_in(tx, &candidate_id)
                .await?
                .map_err(|_| Error::Content)
        );
        if candidate.snapshot().content.digest() != prepared.content.digest() {
            return Ok(Err(Error::Content));
        }
        let (protocol, document) = match (&self.sources.binding(ring).protocol, &prepared.document)
        {
            (
                super::config::ExportProtocol::Winget { base, .. },
                ExportDocument::Winget { manifest },
            ) => (
                NativeExportProtocol::Winget {
                    uri: format!("{base}exports/{}/", publication::hex(&id)),
                    identifier: self.native_identifier(ring, Some(id)),
                },
                db::encode(manifest)?,
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
                let bytes = db::encode(
                    &docs
                        .iter()
                        .map(|d| (d.path(), d.bytes()))
                        .collect::<Vec<_>>(),
                )?;
                (
                    NativeExportProtocol::Brew {
                        uri: format!("{base}exports/{}.git", publication::hex(&id)),
                        commit: target.snapshot.ok_or_else(db::fault)?,
                        tap,
                        credential_reference: credential_reference.clone(),
                    },
                    bytes,
                )
            }
            _ => return Ok(Err(Error::Unsupported)),
        };
        let base = match &self.sources.binding(ring).protocol {
            super::config::ExportProtocol::Winget { artifacts_base, .. }
            | super::config::ExportProtocol::Brew { artifacts_base, .. } => artifacts_base,
        };
        Ok(Ok(Some(NativeExport {
            source: self.sources.logical.clone(),
            tenant: self.tenant(),
            ring,
            publication: id,
            source_digest: self.sources.digest,
            resource: subject.resource,
            resource_version: subject.version,
            resource_digest: subject.resource_digest,
            definition_digest: prepared.content.digest().bytes(),
            document_sha256: Sha256::digest(document).into(),
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
    async fn native_dependencies_in(
        &self,
        tx: &mut PgTransaction<'_>,
        root: &r::Version,
    ) -> InTransaction<Vec<r::Version>> {
        match self.catalog.dependency_versions_in(tx, root).await {
            Ok(versions) => Ok(Ok(versions)),
            Err(crate::catalog::Error::Storage(e)) => Err(e),
            Err(crate::catalog::Error::Sql(e)) => Err(e.into()),
            Err(_) => Ok(Err(Error::Content)),
        }
    }
}

impl ExportReader {
    pub(super) async fn published_in(
        &self,
        tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        ring: rel::Ring,
        publication: [u8; 32],
    ) -> InTransaction<(r::Version, db::Subject, db::Target)> {
        input!(self.catalog.lock_in(tx).await.map_err(|_| Error::Content));
        let tenant = self.tenant().to_string();
        let prefix = format!("p:{}:%", hex(&publication));
        let keys:Vec<String>=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT id FROM mdm_software_composition.targets WHERE tenant_id=$1::uuid AND id LIKE $2 ORDER BY length(id) DESC,id COLLATE \"C\" DESC LIMIT 2").bind(tenant).bind(prefix).fetch_all(c).await})).await?;
        let mut selected = None;
        for key in keys {
            let call = db::call(tx, db::Table::Publish, &key)
                .await?
                .ok_or_else(db::fault)?;
            let target = call.target;
            if (
                target.publication,
                target.binding.as_slice(),
                input!(target.ring()),
            ) != (
                publication,
                self.sources.binding(ring).identity.as_slice(),
                ring,
            ) {
                continue;
            }
            db::lock(
                tx,
                "source",
                &format!("{}:{}", hex(&target.binding), target.slot),
            )
            .await?;
            if db::projection(tx, &target).await?.as_deref() != Some(publication.as_slice()) {
                continue;
            }
            let id = input!(
                rel::CandidateId::new(self.tenant(), &target.candidate)
                    .map_err(|_| Error::Identity)
            );
            let candidate = input!(
                rss_mdm_software_release_postgres::lock_candidate_reference_in(tx, &id)
                    .await?
                    .map_err(|_| Error::Content)
            );
            if !current_published(&candidate, ring, &target) {
                continue;
            }
            let subject = db::subject(tx, &target.candidate)
                .await?
                .ok_or_else(db::fault)?;
            input!(self.resource_usable(tx, &subject).await?);
            let (version, _) = input!(
                rss_mdm_resource_postgres::lock_reference_in(
                    tx,
                    &input!(r::Id::new(&subject.resource).map_err(|_| Error::Content)),
                    &input!(r::Id::new(&subject.version).map_err(|_| Error::Content))
                )
                .await?
                .map_err(|_| Error::Content)
            );
            selected = Some((version, subject, target));
            break;
        }
        Ok(selected.ok_or(Error::CandidateNotFound))
    }
    pub(super) async fn resource_usable(
        &self,
        tx: &mut PgTransaction<'_>,
        subject: &Subject,
    ) -> InTransaction<()> {
        let id = db::required(
            "service::resource_usable",
            resource::Id::new(&subject.resource),
        )?;
        let version = db::required(
            "service::resource_usable",
            resource::Id::new(&subject.version),
        )?;
        input!(
            self.catalog
                .lock_in(tx)
                .await
                .map_err(|cause| Error::Content.context("service::admission_lock", cause))
        );
        let (v, state) = input!(
            rss_mdm_resource_postgres::lock_reference_in(tx, &id, &version)
                .await?
                .map_err(|cause| Error::Content.context("service::resource_usable", cause))
        );
        if v.digest().bytes() != subject.resource_digest
            || !matches!(state, resource::State::Frozen | resource::State::Active)
        {
            return Ok(Err(Error::Content));
        }
        input!(
            self.catalog
                .publication_admitted_in(tx, &v)
                .await
                .map_err(|cause| Error::Content.context("service::resource_usable", cause))
        );
        Ok(Ok(()))
    }
}
