//! Resource/content authority is resolved before lending native supply to Apple channel.
use crate::device::DevicePrincipal;
use crate::*;
use rss_mdm_apple_mdm::native::{ddm::AssetBinding, request::Request};
use rss_mdm_resource as r;
pub(crate) async fn resolve(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    request: &Request,
    target: &NativeTarget,
) -> Result<Vec<AssetBinding>> {
    let Request::Declarations {
        assets,
        declarations,
    } = request
    else {
        return Ok(Vec::new());
    };
    if assets.len() > 4096 {
        return Err(Error::Malformed.into());
    }
    let mut bindings = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for asset in assets {
        if !ids.insert(&asset.identifier) {
            return Err(Error::Malformed.into());
        }
        let id = r::Id::new(&asset.resource).map_err(|_| Error::Malformed)?;
        let label = r::Id::new(&asset.version).map_err(|_| Error::Malformed)?;
        let (version, state) = rss_mdm_resource_postgres::lock_reference_in(tx, &id, &label)
            .await?
            .map_err(|_| Error::NotFound)?;
        if state == r::State::Archived || version.digest().bytes() != asset.version_digest {
            return Err(Error::Conflict.into());
        }
        let mut variants = version
            .variants()
            .iter()
            .filter(|v| v.platform() == r::Platform::MacOS && v.key().as_str() == asset.variant);
        let variant = variants.next().ok_or(Error::Malformed)?;
        if variants.next().is_some() {
            return Err(Error::Malformed.into());
        }
        let r::Declaration::Configuration { artifact } = variant.declaration() else {
            return Err(Error::Malformed.into());
        };
        if artifact.length() == 0 || artifact.length() > 16 * 1024 * 1024 {
            return Err(Error::Malformed.into());
        }
        let verified = service
            .inputs
            .verify_artifact(
                artifact,
                rss_mdm_content_service::StorageClass::NativeConfiguration,
            )
            .await?;
        let legacy=declarations.iter().any(|d|d.declaration_type=="com.apple.configuration.legacy" && (d.identifier==asset.identifier || d.payload.0.get("ProfileAssetReference").is_some_and(|v|matches!(v,rss_mdm_apple_mdm::native::input::FieldValue::String(id) if id==&asset.identifier))));
        let profile = if legacy {
            use futures::TryStreamExt;
            let chunks = verified
                .stream(0, artifact.length())
                .await
                .map_err(|_| Error::Unavailable(Failure::ContentStorage))?
                .try_collect::<Vec<_>>()
                .await
                .map_err(|_| Error::Unavailable(Failure::ContentStorage))?;
            let bytes: Vec<u8> = chunks.into_iter().flat_map(|v| v.to_vec()).collect();
            let channel = if target.user_key().is_empty() {
                rss_mdm_apple_mdm::applicability::Channel::Device
            } else {
                rss_mdm_apple_mdm::applicability::Channel::User
            };
            Some(
                rss_mdm_apple_mdm::native::profiles::from_native(
                    &bytes,
                    &asset.profile_schemas,
                    channel,
                )
                .map_err(|_| Error::Malformed)?,
            )
        } else {
            if !asset.profile_schemas.is_empty() {
                return Err(Error::Malformed.into());
            }
            None
        };
        let apple_silicon = match variant.architecture() {
            r::Architecture::Aarch64 => true,
            r::Architecture::X86_64 => false,
        };
        bindings.push(AssetBinding {
            selection: asset.clone(),
            reference: artifact.reference().as_str().into(),
            length: artifact.length(),
            sha256: artifact.digest().bytes(),
            apple_silicon,
            profile,
        });
    }
    Ok(bindings)
}

impl ExecutionService {
    pub async fn apple_asset(
        &self,
        p: &DevicePrincipal,
        operation: Uuid,
        reader: Box<dyn channels::AppleAssetRead>,
        audit: &RequestAudit,
    ) -> std::result::Result<(AssetBinding, rss_mdm_content_service::Verified), Error> {
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, p, operation, audit, Some(reader)),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, p, operation, audit, reader) = ctx;
                    let service = *service;
                    let p = *p;
                    let tenant = service.tenant.to_string();
                    let instance = service.instance.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::authorization::lock_on(c, &tenant, &instance).await)
                        })
                    })
                    .await??;
                    crate::transaction::lock(tx).await?;
                    storage::lock(tx, p.device()).await?;
                    let op = storage::load(tx, &service.protection, *operation).await?;
                    if op.registration != p.registration()
                        || op.registration_generation != p.generation()
                        || op.device != p.device()
                    {
                        return Err(Error::Unauthorized.into());
                    }
                    let now = storage::now(tx).await?;
                    if !storage::approval_valid(&service.source, &service.protection, tx, &op, now)
                        .await?
                    {
                        return Err(Error::Forbidden.into());
                    }
                    let Task::Macos { request } = &op.request.task else {
                        return Err(Error::Malformed.into());
                    };
                    let progress = service.required_command(tx, &op).await?.status();
                    if (progress.is_terminal() && progress != dc::Status::Applied)
                        || (!progress.is_terminal() && now >= op.request.deadline)
                    {
                        return Err(Error::Forbidden.into());
                    }
                    let current = resolve(service, tx, request, &op.request.target).await?;
                    let reader = reader.take().ok_or(Error::Conflict)?;
                    let principal = p.clone();
                    let selected = tx
                        .with_connection(move |c| {
                            Box::pin(async move { Ok(reader.binding(c, &principal).await) })
                        })
                        .await?
                        .map_err(Error::from)?
                        .ok_or(Error::NotFound)?;
                    let expected = serde_json::to_vec(&selected).map_err(|_| Error::Malformed)?;
                    if !current
                        .iter()
                        .map(serde_json::to_vec)
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(|_| Error::Malformed)?
                        .contains(&expected)
                    {
                        return Err(Error::Conflict.into());
                    }
                    let artifact = r::Artifact::new(
                        r::Id::new(&selected.reference).map_err(|_| Error::Malformed)?,
                        selected.length,
                        r::Digest::from_bytes(selected.sha256),
                    )
                    .map_err(|_| Error::Malformed)?;
                    let verified = service
                        .inputs
                        .verify_artifact(
                            &artifact,
                            rss_mdm_content_service::StorageClass::NativeConfiguration,
                        )
                        .await?;
                    service
                        .audit_store
                        .append_request_in(tx, audit, 200, "success")
                        .await?;
                    Ok((selected, verified))
                })
            },
        )
        .await
    }
}
