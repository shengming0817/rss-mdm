//! Script resource rules and live content binding, shared by all planning entrances.
use super::ResourceCatalog;
use crate::{Error, transaction::*};
use rss_mdm_content_service::{Store, Verified};
use rss_mdm_policy::{Architecture, Platform, ResourceBinding};
use rss_mdm_resource::{self as r, PreparedScript};
use serde_json::Value;
use std::sync::Arc;

fn select<'a>(
    version: &'a r::Version,
    binding: &ResourceBinding,
    parameters: &'a Value,
) -> Result<PreparedScript<'a>> {
    let exact = binding.exact().ok_or(Error::Malformed)?;
    checked_input(version.prepare_script(
        match exact.platform {
            Platform::Windows => r::Platform::Windows,
            Platform::Macos => r::Platform::MacOS,
        },
        match exact.architecture {
            Architecture::X86_64 => r::Architecture::X86_64,
            Architecture::Aarch64 => r::Architecture::Aarch64,
        },
        &checked_input(r::Id::new(&exact.variant))?,
        parameters,
    ))
}

/// Rebind a live content proof to the exact selection read in the caller's transaction.
pub(crate) fn prepare<'a>(
    version: &'a r::Version,
    binding: &ResourceBinding,
    parameters: &'a Value,
    verified: &Verified,
) -> Result<PreparedScript<'a>> {
    let prepared = select(version, binding, parameters)?;
    if !verified.matches(prepared.artifact()) {
        return Err(Error::Conflict.into());
    }
    Ok(prepared)
}

impl ResourceCatalog {
    /// Validate the resource before content I/O; the caller later rebinds this proof.
    pub(crate) async fn verify_script(
        &self,
        binding: &ResourceBinding,
        parameters: &Value,
        content: Option<&Arc<Store>>,
    ) -> std::result::Result<Verified, Error> {
        let artifact = inspect(
            &self.runtime,
            self.tenant,
            (self, binding, parameters),
            |ctx, tx| {
                Box::pin(async move {
                    let (catalog, binding, parameters) = *ctx;
                    let version = catalog
                        .active_version_in(tx, binding.id(), binding.version())
                        .await?;
                    Ok(select(&version, binding, parameters)?.artifact().clone())
                })
            },
            TransactionOwner::Planning,
        )
        .await?;
        Ok(content.ok_or(Error::Unsupported)?.verify(&artifact).await?)
    }
}
