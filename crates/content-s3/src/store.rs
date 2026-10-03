use crate::{body, config::Secrets, model, provider, *};
use aws_sdk_s3::{Client, types::BucketVersioningStatus};
use futures::StreamExt;
use rss_request_context::Clock;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const OPERATION: &str = "rss-content-operation";
/// Product-owned connection. Instance concurrency is not distributed upload admission.
pub struct Store {
    pub(crate) client: Client,
    pub(crate) bucket: String,
    pub(crate) namespace: String,
    pub(crate) scope: [u8; 32],
    permits: Arc<Semaphore>,
    clock: Arc<dyn Clock>,
}
impl Store {
    /// Validate TLS/access and enabled versioning under the caller's connection budget.
    /// Conditional/multipart provider semantics are verified by the real-provider T2 target.
    pub async fn connect(
        config: Config,
        secrets: Arc<dyn Secrets>,
        clock: Arc<dyn Clock>,
        budget: Budget,
    ) -> Result<Self> {
        let client = config.client(secrets)?;
        let posture = provider::call(
            &budget,
            client.get_bucket_versioning().bucket(&config.bucket).send(),
        )
        .await?;
        if posture.status() != Some(&BucketVersioningStatus::Enabled) {
            return Err(Error::Configuration);
        }
        let mut hash = Sha256::new();
        for value in [
            &config.endpoint,
            &config.region,
            &config.bucket,
            &config.namespace,
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        Ok(Self {
            client,
            bucket: config.bucket,
            namespace: config.namespace,
            scope: hash.finalize().into(),
            permits: Arc::new(Semaphore::new(config.max_concurrent)),
            clock,
        })
    }
    pub fn budget(
        &self,
        timeout: Duration,
        idle: Duration,
        bytes: u64,
        pages: usize,
    ) -> Result<Budget> {
        Budget::new(self.clock.clone(), timeout, idle, bytes, pages)
    }
    pub fn target(&self, relative_key: &str) -> Result<Target> {
        model::relative(relative_key)?;
        if self.namespace.len() + relative_key.len() + 1 > 1024 {
            return Err(Error::Input);
        }
        Ok(Target {
            scope: self.scope,
            key: relative_key.to_owned(),
        })
    }
    pub fn write(&self, target: Target, operation: &str, content: Content) -> Result<Write> {
        self.key(&target)?;
        model::token(operation, 128)?;
        if content.length > i64::MAX as u64 {
            return Err(Error::Input);
        }
        Ok(Write {
            target,
            operation: operation.to_owned(),
            content,
        })
    }
    /// Restore an unverified exact coordinate. Never silently resolve to the current version.
    pub fn object(&self, target: Target, version: &str) -> Result<Object> {
        self.key(&target)?;
        model::version(version)?;
        Ok(Object {
            target,
            version: version.to_owned(),
        })
    }
    pub(crate) fn key(&self, target: &Target) -> Result<String> {
        if target.scope != self.scope {
            return Err(Error::Input);
        }
        self.target(&target.key)?;
        Ok(format!("{}/{}", self.namespace, target.key))
    }
    pub(crate) fn exact(&self, object: &Object) -> Result<String> {
        model::version(&object.version)?;
        self.key(&object.target)
    }
    pub(crate) fn check_write(&self, write: &Write, budget: &Budget) -> Result<String> {
        self.write(write.target.clone(), &write.operation, write.content)?;
        self.check_budget(budget, write.content.length)?;
        self.key(&write.target)
    }
    pub(crate) fn check_budget(&self, budget: &Budget, length: u64) -> Result<()> {
        if budget.deadline.is_expired(self.clock.now()) || length > budget.bytes {
            return Err(Error::Budget);
        }
        Ok(())
    }
    pub(crate) fn permit(&self) -> Result<OwnedSemaphorePermit> {
        self.permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)
    }
    pub async fn inspect(&self, object: &Object, budget: Budget) -> Result<Metadata> {
        let _permit = self.permit()?;
        let key = self.exact(object)?;
        self.check_budget(&budget, 0)?;
        self.head(&object.target, Some(&object.version), &key, &budget)
            .await
    }
    pub(crate) async fn head(
        &self,
        target: &Target,
        version: Option<&str>,
        key: &str,
        budget: &Budget,
    ) -> Result<Metadata> {
        let request = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .set_version_id(version.map(str::to_owned));
        let output = match tokio::time::timeout_at(budget.deadline.instant().into(), request.send())
            .await
            .map_err(|_| Error::Budget)?
        {
            Ok(value) => value,
            Err(error)
                if error
                    .raw_response()
                    .is_some_and(|r| r.status().as_u16() == 404) =>
            {
                // A generic HEAD 404 may mean a missing bucket. Confirm the configured bucket.
                provider::call(
                    budget,
                    self.client
                        .get_bucket_versioning()
                        .bucket(&self.bucket)
                        .send(),
                )
                .await?;
                return Err(Error::Missing);
            }
            Err(error) => return Err(provider::classify(&error)),
        };
        let actual = output.version_id().ok_or(Error::Integrity)?;
        model::version(actual).map_err(|_| Error::Integrity)?;
        if version.is_some_and(|expected| expected != actual) {
            return Err(Error::Integrity);
        }
        let object = self.object(target.clone(), actual)?;
        let length = u64::try_from(output.content_length().ok_or(Error::Integrity)?)
            .map_err(|_| Error::Integrity)?;
        let operation = output.metadata().and_then(|m| m.get(OPERATION)).cloned();
        Ok(Metadata {
            object,
            length,
            operation,
        })
    }
    /// Create-only PUT. Dropping this future is not proof that no write occurred:
    /// persist Write before polling, then recover with the same target/operation.
    pub async fn put(
        &self,
        write: &Write,
        source: ByteStreamInput,
        budget: Budget,
    ) -> Result<Mutation<Written>> {
        let key = self.check_write(write, &budget)?;
        if write.content.length > 5 * 1024 * 1024 * 1024 {
            return Err(Error::Input);
        }
        let _permit = self.permit()?;
        let mut source: ByteStreamInput = Box::pin(source.fuse());
        body::empty_input(&mut source, write.content, &budget).await?;
        let request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .if_none_match("*")
            .metadata(OPERATION, &write.operation)
            .content_length(write.content.length as i64)
            .checksum_sha256(provider::encode(write.content.sha256))
            .body(body::upload(source, write.content, budget.clone()));
        match provider::mutation(&budget, request.send()).await? {
            Mutation::Unknown(error) => Ok(Mutation::Unknown(error)),
            Mutation::Confirmed(output) => self.written(write, output.version_id(), &budget).await,
        }
    }
    pub(crate) async fn written(
        &self,
        write: &Write,
        version: Option<&str>,
        budget: &Budget,
    ) -> Result<Mutation<Written>> {
        let Some(version) = version else {
            return Ok(Mutation::Unknown(Error::Integrity));
        };
        let object = match self.object(write.target.clone(), version) {
            Ok(object) => object,
            Err(_) => return Ok(Mutation::Unknown(Error::Integrity)),
        };
        Ok(Mutation::Confirmed(
            self.verify_written(object, write.content, budget).await,
        ))
    }
    async fn verify_written(&self, object: Object, content: Content, budget: &Budget) -> Written {
        match self.verify_inner(&object, content, budget).await {
            Ok(verified) => Written::Verified(verified),
            Err(error) => Written::Unverified { object, error },
        }
    }
    /// Revalidate complete bytes after process restart or an uncertain write response.
    pub async fn verify(
        &self,
        object: &Object,
        content: Content,
        budget: Budget,
    ) -> Result<Verified> {
        let _permit = self.permit()?;
        self.verify_inner(object, content, &budget).await
    }
    async fn verify_inner(
        &self,
        object: &Object,
        content: Content,
        budget: &Budget,
    ) -> Result<Verified> {
        self.check_budget(budget, content.length)?;
        let key = self.exact(object)?;
        let output = provider::call(
            budget,
            self.client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .version_id(&object.version)
                .send(),
        )
        .await?;
        if output.version_id() != Some(object.version.as_str())
            || output.content_length().and_then(|n| u64::try_from(n).ok()) != Some(content.length)
        {
            return Err(Error::Integrity);
        }
        let mut stream = body::download(
            output.body,
            content.length,
            Some(content.sha256),
            budget.clone(),
            None,
        );
        while let Some(bytes) = stream.next().await {
            bytes?;
        }
        Ok(Verified {
            object: object.clone(),
            content,
        })
    }
    /// Current HEAD can locate a candidate, but only matching operation + full verification
    /// establishes a match. Absence/mismatch never establishes rollback.
    pub async fn recover(&self, write: &Write, budget: Budget) -> Result<Recovery> {
        let key = self.check_write(write, &budget)?;
        let _permit = self.permit()?;
        let metadata = match self.head(&write.target, None, &key, &budget).await {
            Ok(meta) => meta,
            Err(Error::Missing) => return Ok(Recovery::Unresolved),
            Err(error) => return Err(error),
        };
        if metadata.operation.as_deref() != Some(write.operation.as_str()) {
            return Ok(Recovery::Unresolved);
        }
        Ok(Recovery::Matched(
            self.verify_written(metadata.object, write.content, &budget)
                .await,
        ))
    }
    /// Range uses [start,end); the handle binds the already verified immutable version.
    /// The returned stream keeps its permit until EOF/drop, with terminal error on truncation.
    pub async fn read(
        &self,
        verified: &Verified,
        start: u64,
        end: u64,
        budget: Budget,
    ) -> Result<ByteStreamOutput> {
        if start > end
            || start == end && verified.content.length != 0
            || end > verified.content.length
        {
            return Err(Error::Input);
        }
        self.check_budget(&budget, end - start)?;
        let key = self.exact(&verified.object)?;
        let permit = self.permit()?;
        let partial = start != 0 || end != verified.content.length;
        let range = partial.then(|| format!("bytes={start}-{}", end - 1));
        let output = provider::call(
            &budget,
            self.client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .version_id(&verified.object.version)
                .set_range(range)
                .send(),
        )
        .await?;
        if output.version_id() != Some(verified.object.version.as_str())
            || output.content_length().and_then(|n| u64::try_from(n).ok()) != Some(end - start)
            || partial
                && output.content_range()
                    != Some(
                        format!("bytes {start}-{}/{}", end - 1, verified.content.length).as_str(),
                    )
        {
            return Err(Error::Integrity);
        }
        Ok(body::download(
            output.body,
            end - start,
            (!partial).then_some(verified.content.sha256),
            budget,
            Some(permit),
        ))
    }
    /// Delete exactly the chosen version. Never issue an unversioned DELETE or bulk cleanup.
    pub async fn delete(&self, object: &Object, budget: Budget) -> Result<Mutation<()>> {
        self.check_budget(&budget, 0)?;
        let key = self.exact(object)?;
        let _permit = self.permit()?;
        match provider::mutation(
            &budget,
            self.client
                .delete_object()
                .bucket(&self.bucket)
                .key(&key)
                .version_id(&object.version)
                .send(),
        )
        .await?
        {
            Mutation::Unknown(error) => Ok(Mutation::Unknown(error)),
            Mutation::Confirmed(_) => match self
                .head(&object.target, Some(&object.version), &key, &budget)
                .await
            {
                Err(Error::Missing) => Ok(Mutation::Confirmed(())),
                Ok(_) => Ok(Mutation::Unknown(Error::Integrity)),
                Err(error) => Ok(Mutation::Unknown(error)),
            },
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit.rs"]
mod tests;
