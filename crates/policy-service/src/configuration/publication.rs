//! Authored configuration freezes and protects its content under the Policy version identity.
use super::*;
use rss_mdm_authorization_service::{Snapshot, context::AuthorizedPrincipal};
use rss_mdm_policy::{Architecture, ExactResourceBinding, Exit, Platform};
use rss_mdm_resource as resource;
pub struct Publications {
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
}
async fn active_in(
    tx: &mut PgTransaction<'_>,
    binding: &ExactResourceBinding,
) -> Result<resource::Version> {
    let (version, state) = checked(
        rss_mdm_resource_postgres::lock_reference_in(
            tx,
            &checked_input(resource::Id::new(&binding.id))?,
            &checked_input(resource::Id::new(&binding.version))?,
        )
        .await?,
    )?;
    if state != resource::State::Active {
        return Err(Error::Conflict.into());
    }
    Ok(version)
}
fn variant<'a>(
    version: &'a resource::Version,
    binding: &ExactResourceBinding,
) -> Result<&'a resource::Variant> {
    checked_input(version.resolve(
        match binding.platform {
            Platform::Windows => resource::Platform::Windows,
            Platform::Macos => resource::Platform::MacOS,
        },
        match binding.architecture {
            Architecture::X86_64 => resource::Architecture::X86_64,
            Architecture::Aarch64 => resource::Architecture::Aarch64,
        },
        &checked_input(resource::Id::new(&binding.variant))?,
    ))
}
impl Publications {
    pub async fn prepare(
        &self,
        binding: &ExactResourceBinding,
    ) -> std::result::Result<rss_mdm_content_service::Verified, Error> {
        let artifact =
            crate::transaction::inspect(&self.runtime, self.tenant, binding, |binding, tx| {
                Box::pin(async move {
                    let version = active_in(tx, binding).await?;
                    let resource::Declaration::Configuration { artifact } =
                        variant(&version, binding)?.declaration()
                    else {
                        return Err(Error::Malformed.into());
                    };
                    Ok(artifact.clone())
                })
            })
            .await?;
        let content = self.content.as_ref().ok_or(Error::Unsupported)?;
        Ok(content
            .verify_class(
                &artifact,
                rss_mdm_content_service::StorageClass::NativeConfiguration,
                content.upload_budget()?.operation_deadline(),
            )
            .await?)
    }
    pub async fn freeze_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &rss_mdm_policy::Policy,
        verified: Option<&rss_mdm_content_service::Verified>,
        proof: &AuthorizedPrincipal,
        snapshot: &Snapshot,
    ) -> Result<serde_json::Value> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        let rss_mdm_policy::Action::Configuration {
            resource: binding,
            exit,
        } = &policy.definition.action
        else {
            return Err(Error::Unsupported.into());
        };
        let (native, version) = self
            .validate_in(tx, binding, *exit, verified, proof, snapshot)
            .await?;
        let frozen = frozen::Frozen::Configuration {
            native: Protected::seal(
                &self.protection,
                self.tenant,
                Owner::Policy {
                    policy: policy.id,
                    version: policy.version,
                },
                &native,
            )?,
            platform: binding.platform,
            exit: *exit,
            resource_digest: version.digest().bytes(),
        };
        checked_input(serde_json::to_value(frozen))
    }
    pub(crate) async fn validate_in(
        &self,
        tx: &mut PgTransaction<'_>,
        binding: &ExactResourceBinding,
        exit: Exit,
        verified: Option<&rss_mdm_content_service::Verified>,
        proof: &AuthorizedPrincipal,
        snapshot: &Snapshot,
    ) -> Result<(Configuration, resource::Version)> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        let version = active_in(tx, binding).await?;
        let resource::Declaration::Configuration { artifact } =
            variant(&version, binding)?.declaration()
        else {
            return Err(Error::Malformed.into());
        };
        let native = Configuration::read(
            verified
                .filter(|v| v.matches(artifact))
                .ok_or(Error::Conflict)?,
        )?;
        if matches!(exit, Exit::Remove) && native.remove.is_none() {
            return Err(Error::Unsupported.into());
        }
        let expected = match binding.platform {
            Platform::Windows => rss_mdm_inventory::ReportSource::MdmWindows,
            Platform::Macos => rss_mdm_inventory::ReportSource::MdmApple,
        };
        if native.apply.source() != expected {
            return Err(Error::Malformed.into());
        }
        let mut permissions = native.apply.permissions()?;
        if let Some(remove) = &native.remove {
            permissions.extend(remove.permissions()?);
        }
        permissions.sort();
        permissions.dedup();
        for permission in permissions {
            if permission.device() {
                snapshot.require_all_devices(proof, permission)?;
            } else {
                snapshot.require(proof, permission, None)?;
            }
        }
        Ok((native, version))
    }
}
