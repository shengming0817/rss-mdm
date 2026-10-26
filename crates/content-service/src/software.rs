//! File staging adapter for software management; software owns source and resource decisions.
use crate::{Binding, Store, Upload, Verified, bindings};
use rss_mdm_software_service::{
    catalog,
    management::{
        self as software, Error, Failure, Fault,
        content::{ImportedContent, ManagementContentPort, StageImport},
    },
};
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
pub struct SoftwareContent {
    store: Arc<Store>,
    clock: Arc<dyn crate::service::Clock>,
}
impl SoftwareContent {
    pub fn new(store: Arc<Store>, clock: Arc<dyn crate::service::Clock>) -> Self {
        Self { store, clock }
    }
    fn now(&self) -> Result<i64, Error> {
        self.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))
    }
}
impl catalog::ContentPort for SoftwareContent {
    fn verify<'a>(&'a self, version: &'a rss_mdm_resource::Version) -> catalog::ContentFuture<'a> {
        catalog::ContentPort::verify(self.store.as_ref(), version)
    }
}
/// Uploaded originals awaiting batch verification.
pub struct StagedImport {
    upload: Upload,
    artifact: rss_mdm_resource::Artifact,
}
/// All uploaded originals and verified pins retained through transaction settlement.
pub struct ImportEvidence {
    uploads: Vec<Upload>,
    _pins: Vec<crate::reader::Pinned>,
}
impl ImportedContent for ImportEvidence {
    async fn bind_in<'a>(&'a self, tx: &'a mut PgTransaction<'_>) -> Result<(), Fault> {
        for upload in &self.uploads {
            bindings::bind_in(tx, upload).await.map_err(|e| match e {
                bindings::Error::Content(e) => Fault::Request(error(e)),
                bindings::Error::Storage(e) => Fault::Storage(e),
                bindings::Error::Sql(e) => Fault::Sql(e),
            })?;
        }
        Ok(())
    }
}
impl ManagementContentPort for SoftwareContent {
    type Download = Verified;
    type UploadPin = crate::reader::Pinned;
    type StagedImport = StagedImport;
    type ImportEvidence = ImportEvidence;
    async fn prepare_upload(
        &self,
        input: &software::content::PrepareUpload,
        resource: &str,
        upload: uuid::Uuid,
        actor: &str,
    ) -> Result<software::content::PreparedUpload, Error> {
        let binding = Binding {
            purpose: crate::Purpose::Software {
                resource: resource.into(),
                filename: input.filename.clone(),
            },
            reference: "installer".into(),
            length: input.length,
            sha256: input.sha256,
            actor: actor.into(),
        };
        let result = self
            .store
            .begin(
                upload,
                binding,
                self.now()?,
                self.store.upload_budget().map_err(error)?,
            )
            .await
            .map_err(error)?;
        Ok(software::content::PreparedUpload {
            package_id: resource.into(),
            resource: resource.into(),
            upload,
            offset: result.offset,
            length: result.binding.length,
            complete: result.complete,
            href: format!("/api/v1/resources/{resource}/uploads/{upload}"),
        })
    }
    async fn inspect_upload(
        &self,
        id: uuid::Uuid,
        actor: &str,
        resource: &str,
    ) -> Result<software::content::InspectedUpload<Self::UploadPin>, Error> {
        let upload = self
            .store
            .status(actor, id, self.now()?)
            .await
            .map_err(error)?;
        let crate::Purpose::Software {
            resource: owner,
            filename,
        } = &upload.binding.purpose
        else {
            return Err(Error::Malformed);
        };
        if owner != resource || !upload.complete {
            return Err(Error::Conflict);
        }
        let kind = crate::installer::Kind::from_name(filename).ok_or(Error::Malformed)?;
        let artifact = upload.binding.artifact().map_err(error)?;
        let pin = self
            .store
            .pin_ready(&artifact, crate::StorageClass::Artifact)
            .await
            .map_err(error)?;
        let inspection = pin
            .manifest
            .inspections
            .get(&kind)
            .cloned()
            .unwrap_or_else(|| {
                if artifact.length() > crate::installer::AUTO_LIMIT {
                    software::content::InstallerInspection::SkippedSizeLimit
                } else {
                    software::content::InstallerInspection::NotRequested
                }
            });
        Ok(software::content::InspectedUpload {
            inspection,
            format: kind.format(),
            artifact: rss_mdm_resource::SoftwareArtifact {
                reference: artifact.reference().as_str().into(),
                origin: None,
                length: artifact.length(),
                sha256: artifact.digest().bytes(),
            },
            filename: filename.clone(),
            _pin: pin,
        })
    }
    async fn parse_upload(&self, id: uuid::Uuid, actor: &str, resource: &str) -> Result<(), Error> {
        let upload = self
            .store
            .status(actor, id, self.now()?)
            .await
            .map_err(error)?;
        if upload.binding.owner().map_err(error)? != resource {
            return Err(Error::Forbidden);
        }
        self.store
            .parse_upload(actor, id, self.now()?)
            .await
            .map_err(error)
    }
    async fn verify_artifact(
        &self,
        artifact: &rss_mdm_resource::Artifact,
    ) -> Result<Verified, Error> {
        self.store.verify(artifact).await.map_err(error)
    }
    async fn stage_import(&self, input: StageImport<'_>) -> Result<StagedImport, Error> {
        if input.version.tenant() != self.store.tenant {
            return Err(Error::Forbidden);
        }
        let artifact = input.artifact.artifact().map_err(|_| Error::Malformed)?;
        let binding = Binding {
            purpose: crate::Purpose::Resource(crate::ResourceBinding {
                inspection: input
                    .version
                    .variants()
                    .iter()
                    .find(|v| v.key().as_str() == input.variant)
                    .and_then(|v| match v.declaration() {
                        rss_mdm_resource::Declaration::Software { definition }
                            if definition.primary() == &artifact =>
                        {
                            Some(definition.spec().material.format)
                        }
                        _ => None,
                    }),
                storage_class: crate::StorageClass::Artifact,
                resource: input.version.resource().as_str().to_owned(),
                version: input.version.label().as_str().to_owned(),
                variant: input.variant.to_owned(),
                platform: input.platform,
                architecture: input.architecture,
                resource_digest: input.version.digest().bytes(),
                source: Some(input.source.clone()),
                origin: None,
            }),
            reference: input.artifact.reference.clone(),
            length: input.artifact.length,
            sha256: input.artifact.sha256,
            actor: input.actor.to_owned(),
        };
        let budget = self.store.upload_budget().map_err(error)?;
        let session = self
            .store
            .begin(input.upload, binding, self.now()?, budget)
            .await
            .map_err(error)?;
        if !session.complete {
            let offset = usize::try_from(session.offset).map_err(|_| Error::Malformed)?;
            let tail = input.bytes.get(offset..).ok_or(Error::Malformed)?.to_vec();
            if !tail.is_empty() {
                self.store
                    .append(
                        input.actor,
                        input.upload,
                        session.offset,
                        self.now()?,
                        std::io::Cursor::new(tail),
                        budget,
                    )
                    .await
                    .map_err(error)?;
            }
        }
        let upload = self
            .store
            .finish(input.actor, input.upload, self.now()?, budget)
            .await
            .map_err(error)?;
        Ok(StagedImport { upload, artifact })
    }
    async fn pin_imports(&self, staged: Vec<StagedImport>) -> Result<ImportEvidence, Error> {
        let artifacts = staged
            .iter()
            .map(|s| (s.artifact.clone(), crate::StorageClass::Artifact))
            .collect::<Vec<_>>();
        let pins = self.store.pin_materials(&artifacts).await.map_err(error)?;
        Ok(ImportEvidence {
            uploads: staged.into_iter().map(|s| s.upload).collect(),
            _pins: pins,
        })
    }
}
fn error(error: crate::Error) -> software::Error {
    match error {
        crate::Error::Malformed => Error::Malformed,
        crate::Error::Conflict => Error::Conflict,
        crate::Error::Configuration => Error::Unavailable(Failure::ContentConfiguration),
        crate::Error::Storage => Error::Unavailable(Failure::ContentStorage),
        crate::Error::Invariant => Error::Unavailable(Failure::ContentInvariant),
        crate::Error::Metadata => Error::Unavailable(Failure::ContentMetadata),
        crate::Error::Deadline => Error::Unavailable(Failure::ContentDeadline),
        crate::Error::CommitUnknown => Error::CommitUnknown,
        crate::Error::Cleanup => Error::Unavailable(Failure::ContentCleanup),
    }
}
