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
        self.store.as_ref().verify(version)
    }
}
/// A single uploaded original and its verified file pin, retained through transaction settlement.
pub struct ImportEvidence {
    upload: Upload,
    _pin: Verified,
}
impl ImportedContent for ImportEvidence {
    async fn bind_in<'a>(&'a self, tx: &'a mut PgTransaction<'_>) -> Result<(), Fault> {
        bindings::bind_in(tx, &self.upload)
            .await
            .map(|_| ())
            .map_err(|e| match e {
                bindings::Error::Content(e) => Fault::Request(error(e)),
                bindings::Error::Storage(e) => Fault::Storage(e),
                bindings::Error::Sql(e) => Fault::Sql(e),
            })
    }
}
impl ManagementContentPort for SoftwareContent {
    type Download = Verified;
    type ImportEvidence = ImportEvidence;
    async fn verify_artifact(
        &self,
        artifact: &rss_mdm_resource::Artifact,
    ) -> Result<Verified, Error> {
        self.store.verify(artifact).await.map_err(error)
    }
    async fn stage_import(&self, input: StageImport<'_>) -> Result<ImportEvidence, Error> {
        if input.version.tenant() != self.store.tenant {
            return Err(Error::Forbidden);
        }
        let artifact = input.artifact.artifact().map_err(|_| Error::Malformed)?;
        let binding = Binding {
            storage_class: crate::StorageClass::Artifact,
            resource: input.version.resource().as_str().to_owned(),
            version: input.version.label().as_str().to_owned(),
            variant: input.variant.to_owned(),
            platform: input.platform,
            architecture: input.architecture,
            resource_digest: input.version.digest().bytes(),
            source: Some(input.source.clone()),
            origin: None,
            reference: input.artifact.reference.clone(),
            length: input.artifact.length,
            sha256: input.artifact.sha256,
            actor: input.actor.to_owned(),
        };
        let session = self
            .store
            .begin(input.upload, binding, self.now()?)
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
                    )
                    .await
                    .map_err(error)?;
            }
        }
        let upload = self
            .store
            .finish(input.actor, input.upload, self.now()?)
            .await
            .map_err(error)?;
        let pin = self.store.verify(&artifact).await.map_err(error)?;
        Ok(ImportEvidence { upload, _pin: pin })
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
        crate::Error::Cleanup => Error::Unavailable(Failure::ContentCleanup),
    }
}
