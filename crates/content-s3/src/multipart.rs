use crate::{model, provider, store::OPERATION, *};
use aws_sdk_s3::types::{ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart};

const MIN_PART: u64 = 5 * 1024 * 1024;
impl Store {
    /// Restored material remains host input; validate before every operation.
    pub fn upload(&self, write: Write, original_id: &str) -> Result<Upload> {
        self.write(write.target.clone(), &write.operation, write.content)?;
        model::token(original_id, 2048)?;
        Ok(Upload {
            write,
            id: original_id.to_owned(),
        })
    }
    fn upload_key(&self, upload: &Upload, budget: &Budget) -> Result<String> {
        self.upload(upload.write.clone(), &upload.id)?;
        self.check_budget(budget, 0)?;
        self.key(&upload.write.target)
    }
    /// Caller persists Write before polling. Initiation can succeed without delivering an ID.
    pub async fn begin(&self, write: &Write, budget: Budget) -> Result<Mutation<Upload>> {
        let key = self.check_write(write, &budget)?;
        if write.content.length == 0 {
            return Err(Error::Input);
        }
        let _permit = self.permit()?;
        let request = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .metadata(OPERATION, &write.operation)
            .checksum_algorithm(ChecksumAlgorithm::Sha256);
        match provider::mutation(&budget, request.send()).await? {
            Mutation::Unknown(error) => Ok(Mutation::Unknown(error)),
            Mutation::Confirmed(output) => match output
                .upload_id()
                .and_then(|id| self.upload(write.clone(), id).ok())
            {
                Some(upload) => Ok(Mutation::Confirmed(upload)),
                None => Ok(Mutation::Unknown(Error::Integrity)),
            },
        }
    }
    /// Exact-key discovery for a lost initiation response. Candidates are not authority:
    /// the caller explicitly selects a returned ID. Empty/multiple results remain unresolved.
    pub async fn candidates(&self, target: &Target, budget: Budget) -> Result<Candidates> {
        let key = self.key(target)?;
        self.check_budget(&budget, 0)?;
        let _permit = self.permit()?;
        let (mut key_marker, mut id_marker) = (None, None);
        let mut ids = Vec::new();
        for _ in 0..budget.pages {
            let output = provider::call(
                &budget,
                self.client
                    .list_multipart_uploads()
                    .bucket(&self.bucket)
                    .prefix(&key)
                    .set_key_marker(key_marker.clone())
                    .set_upload_id_marker(id_marker.clone())
                    .max_uploads(1000)
                    .send(),
            )
            .await?;
            for upload in output.uploads() {
                if upload.key() == Some(key.as_str()) {
                    let id = upload.upload_id().ok_or(Error::Integrity)?;
                    model::token(id, 2048).map_err(|_| Error::Integrity)?;
                    ids.push(id.to_owned());
                }
            }
            if !output.is_truncated().unwrap_or(false) {
                return Ok(Candidates { ids });
            }
            let next_key = output.next_key_marker().ok_or(Error::Integrity)?.to_owned();
            let next_id = output
                .next_upload_id_marker()
                .ok_or(Error::Integrity)?
                .to_owned();
            if key_marker.as_deref() == Some(&next_key) && id_marker.as_deref() == Some(&next_id) {
                return Err(Error::Integrity);
            }
            key_marker = Some(next_key);
            id_marker = Some(next_id);
        }
        Err(Error::Budget)
    }
    pub async fn part(
        &self,
        upload: &Upload,
        number: i32,
        content: Content,
        source: ByteStreamInput,
        budget: Budget,
    ) -> Result<Mutation<Part>> {
        let key = self.upload_key(upload, &budget)?;
        if !(1..=10_000).contains(&number)
            || content.length == 0
            || content.length > 5 * 1024 * 1024 * 1024
            || content.length > upload.write.content.length
        {
            return Err(Error::Input);
        }
        self.check_budget(&budget, content.length)?;
        let _permit = self.permit()?;
        let request = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload.id)
            .part_number(number)
            .content_length(content.length as i64)
            .checksum_sha256(provider::encode(content.sha256))
            .body(crate::body::upload(source, content, budget.clone()));
        match provider::mutation(&budget, request.send()).await? {
            Mutation::Unknown(error) => Ok(Mutation::Unknown(error)),
            Mutation::Confirmed(output) => {
                let checksum = provider::checksum(output.checksum_sha256());
                match (output.e_tag(), checksum) {
                    (Some(etag), Ok(actual)) if actual == content.sha256 => {
                        Ok(Mutation::Confirmed(Part {
                            upload: upload.clone(),
                            number,
                            length: content.length,
                            etag: etag.to_owned(),
                            sha256: Some(actual),
                        }))
                    }
                    _ => Ok(Mutation::Unknown(Error::Integrity)),
                }
            }
        }
    }
    pub async fn status(&self, upload: &Upload, budget: Budget) -> Result<UploadState> {
        let _permit = self.permit()?;
        self.status_inner(upload, &budget).await
    }
    async fn status_inner(&self, upload: &Upload, budget: &Budget) -> Result<UploadState> {
        let key = self.upload_key(upload, budget)?;
        let mut marker = 0;
        let mut parts = Vec::new();
        for _ in 0..budget.pages {
            let output = match provider::call(
                budget,
                self.client
                    .list_parts()
                    .bucket(&self.bucket)
                    .key(&key)
                    .upload_id(&upload.id)
                    .part_number_marker(marker.to_string())
                    .max_parts(1000)
                    .send(),
            )
            .await
            {
                Ok(output) => output,
                Err(Error::Missing) if parts.is_empty() => return Ok(UploadState::Absent),
                Err(error) => return Err(error),
            };
            for part in output.parts() {
                let number = part.part_number().ok_or(Error::Integrity)?;
                let length = u64::try_from(part.size().ok_or(Error::Integrity)?)
                    .map_err(|_| Error::Integrity)?;
                if number <= marker
                    || !(1..=10_000).contains(&number)
                    || length > upload.write.content.length
                    || parts.last().is_some_and(|p: &Part| p.number >= number)
                {
                    return Err(Error::Integrity);
                }
                parts.push(Part {
                    upload: upload.clone(),
                    number,
                    length,
                    etag: part.e_tag().ok_or(Error::Integrity)?.to_owned(),
                    sha256: part
                        .checksum_sha256()
                        .map(|value| provider::checksum(Some(value)))
                        .transpose()?,
                });
            }
            if !output.is_truncated().unwrap_or(false) {
                return Ok(UploadState::Active(parts));
            }
            let next = output
                .next_part_number_marker()
                .ok_or(Error::Integrity)?
                .parse::<i32>()
                .map_err(|_| Error::Integrity)?;
            if next <= marker || next > 10_000 {
                return Err(Error::Integrity);
            }
            marker = next;
        }
        Err(Error::Budget)
    }
    /// Complete exactly this ordered, acknowledged manifest. No latest-part adoption.
    pub async fn complete(
        &self,
        upload: &Upload,
        parts: &[Part],
        budget: Budget,
    ) -> Result<Mutation<Written>> {
        let key = self.upload_key(upload, &budget)?;
        validate_manifest(upload, parts)?;
        self.check_budget(&budget, upload.write.content.length)?;
        let _permit = self.permit()?;
        match self.status_inner(upload, &budget).await? {
            UploadState::Active(actual) if matches_manifest(&actual, parts) => (),
            UploadState::Active(_) => return Err(Error::Conflict),
            UploadState::Absent => return Err(Error::Missing),
        }
        let manifest = parts
            .iter()
            .map(|p| {
                CompletedPart::builder()
                    .part_number(p.number)
                    .e_tag(&p.etag)
                    .set_checksum_sha256(p.sha256.map(provider::encode))
                    .build()
            })
            .collect();
        let request = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload.id)
            .if_none_match("*")
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(manifest))
                    .build(),
            );
        match provider::mutation(&budget, request.send()).await? {
            Mutation::Unknown(error) => Ok(Mutation::Unknown(error)),
            Mutation::Confirmed(output) => {
                self.written(&upload.write, output.version_id(), &budget)
                    .await
            }
        }
    }
    /// Abort only the original selected ID. Confirmation requires absence after the request;
    /// no absent-upload result is converted into an object deletion or a failed-write claim.
    pub async fn abort(&self, upload: &Upload, budget: Budget) -> Result<Mutation<()>> {
        let key = self.upload_key(upload, &budget)?;
        let _permit = self.permit()?;
        match provider::mutation(
            &budget,
            self.client
                .abort_multipart_upload()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(&upload.id)
                .send(),
        )
        .await
        {
            Ok(Mutation::Unknown(error)) => return Ok(Mutation::Unknown(error)),
            Err(error) if error != Error::Missing => return Err(error),
            _ => (),
        }
        match self.status_inner(upload, &budget).await {
            Ok(UploadState::Absent) => Ok(Mutation::Confirmed(())),
            Ok(_) => Ok(Mutation::Unknown(Error::Transient)),
            Err(error) => Ok(Mutation::Unknown(error)),
        }
    }
}
fn matches_manifest(actual: &[Part], selected: &[Part]) -> bool {
    actual.len() == selected.len()
        && actual.iter().zip(selected).all(|(a, b)| {
            a.upload == b.upload
                && a.number == b.number
                && a.length == b.length
                && a.etag == b.etag
                && match (a.sha256, b.sha256) {
                    (Some(actual), Some(expected)) => actual == expected,
                    _ => true, // Unknown part hints never replace mandatory full-object verification.
                }
        })
}
fn validate_manifest(upload: &Upload, parts: &[Part]) -> Result<()> {
    if parts.is_empty() || parts.len() > 10_000 {
        return Err(Error::Input);
    }
    let mut length = 0u64;
    for (index, part) in parts.iter().enumerate() {
        if &part.upload != upload
            || part.number != index as i32 + 1
            || part.etag.is_empty()
            || part.length == 0
            || part.length > 5 * 1024 * 1024 * 1024
            || index + 1 != parts.len() && part.length < MIN_PART
        {
            return Err(Error::Input);
        }
        length = length.checked_add(part.length).ok_or(Error::Input)?;
    }
    if length != upload.write.content.length {
        return Err(Error::Integrity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_preserves_original_upload_and_contiguous_parts() -> Result<()> {
        let target = Target {
            scope: [1; 32],
            key: "blob".into(),
        };
        let write = Write {
            target,
            operation: "op".into(),
            content: Content {
                length: MIN_PART + 1,
                sha256: [0; 32],
            },
        };
        let upload = Upload {
            write,
            id: "original".into(),
        };
        let first = Part {
            upload: upload.clone(),
            number: 1,
            length: MIN_PART,
            etag: "one".into(),
            sha256: Some([1; 32]),
        };
        let last = Part {
            upload: upload.clone(),
            number: 2,
            length: 1,
            etag: "two".into(),
            sha256: Some([2; 32]),
        };
        assert!(validate_manifest(&upload, &[first.clone(), last.clone()]).is_ok());
        assert_eq!(
            validate_manifest(&upload, &[last.clone(), first.clone()]),
            Err(Error::Input)
        );
        let mut observed = first.clone();
        observed.sha256 = None;
        assert!(matches_manifest(
            std::slice::from_ref(&observed),
            std::slice::from_ref(&first)
        ));
        observed.etag = "changed".into();
        assert!(!matches_manifest(&[observed], std::slice::from_ref(&first)));
        let mut different_hash = first.clone();
        different_hash.sha256 = Some([9; 32]);
        assert!(!matches_manifest(
            &[different_hash],
            std::slice::from_ref(&first)
        ));
        let mut changed = last.clone();
        changed.upload.id = "replacement".into();
        assert_eq!(
            validate_manifest(&upload, &[first.clone(), changed]),
            Err(Error::Input)
        );
        assert_eq!(validate_manifest(&upload, &[first]), Err(Error::Integrity));
        Ok(())
    }
}
