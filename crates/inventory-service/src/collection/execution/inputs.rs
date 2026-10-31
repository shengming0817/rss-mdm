//! Exact collection Resource preparation on the caller's runtime.
use super::{frozen::*, participants::NativeDelivery};
use crate::{Error, transaction::*};
use rss_mdm_content_service::{StorageClass, Store, Verified};
use rss_mdm_inventory::Channel;
use rss_mdm_policy::{ExactResourceBinding, Frequency, schedule::Schedule};
use rss_mdm_resource as r;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;
pub struct Inputs {
    runtime: Arc<PgRuntime>,
    tenant: rss_request_context::TenantId,
    content: Option<Arc<Store>>,
    native: Arc<dyn NativeDelivery>,
}
pub struct Publication<'a> {
    pub channel: Channel,
    pub binding: &'a ExactResourceBinding,
    pub schedule: &'a Schedule,
    pub frequency: Frequency,
    pub lifetime: u32,
}
impl Inputs {
    pub fn bind(
        runtime: Arc<PgRuntime>,
        tenant: rss_request_context::TenantId,
        content: Option<Arc<Store>>,
        native: Arc<dyn NativeDelivery>,
    ) -> Self {
        Self {
            runtime,
            tenant,
            content,
            native,
        }
    }
    fn validate_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
    async fn version_in(
        &self,
        tx: &mut PgTransaction<'_>,
        binding: &ExactResourceBinding,
    ) -> Result<r::Version> {
        self.validate_in(tx)?;
        let identity = binding.identity();
        let (version, state) = checked(
            rss_mdm_resource_postgres::lock_reference_in(
                tx,
                &checked_input(r::Id::new(identity.id()))?,
                &checked_input(r::Id::new(identity.version()))?,
            )
            .await?,
        )?;
        if state != r::State::Active {
            return Err(Error::Conflict.into());
        }
        Ok(version)
    }
    pub async fn prepare_resource(
        &self,
        binding: &ExactResourceBinding,
        channel: Channel,
    ) -> std::result::Result<Verified, Error> {
        let artifact = inspect(
            &self.runtime,
            self.tenant,
            (self, binding),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, binding) = *ctx;
                    let version = service.version_in(tx, binding).await?;
                    Ok(artifact(select(&version, binding)?, channel)?.clone())
                })
            },
            TransactionOwner::Collections,
        )
        .await?;
        let content = self
            .content
            .as_ref()
            .ok_or(Error::Unavailable(crate::Failure::Runtime))?;
        let deadline = content
            .upload_budget()
            .map_err(content_error)?
            .operation_deadline();
        content
            .verify_class(&artifact, StorageClass::Artifact, deadline)
            .await
            .map_err(content_error)
    }
    pub async fn publish_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &Publication<'_>,
        verified: &Verified,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        snapshot: &rss_mdm_authorization_service::Snapshot,
    ) -> Result<Published> {
        self.validate_in(tx)?;
        let version = self.version_in(tx, input.binding).await?;
        let selected = select(&version, input.binding)?;
        if !verified.matches(artifact(selected, input.channel)?) {
            return Err(Error::Conflict.into());
        }
        let frozen_input = CollectionInput {
            platform: input.binding.platform,
            architecture: input.binding.architecture,
            schedule: input.schedule.clone(),
            run_lifetime_seconds: input.lifetime,
        };
        use rss_mdm_authorization_service::Permission as P;
        snapshot.require_all_devices(proof, P::InventoryCollect)?;
        match selected.declaration() {
            r::Declaration::AgentCollection { definition, .. }
                if input.channel == Channel::Agent =>
            {
                snapshot.require_all_devices(proof, P::InventorySensitiveRead)?;
                if definition
                    .spec()
                    .mappings
                    .values()
                    .any(|m| m.counter_normalization.is_some())
                {
                    return Err(Error::Malformed.into());
                }
                let fields = crate::collection::preparation::prepare_agent_fields(
                    tx,
                    self.tenant,
                    selected,
                    definition,
                )
                .await?;
                Ok(Published::AgentCollection {
                    frequency: input.frequency,
                    action: Box::new(FrozenAgent {
                        input: frozen_input,
                        fields,
                        definition: definition.clone(),
                        resource_digest: version.digest().bytes(),
                        resource: rss_mdm_agent_wire::runtime::TaskResource {
                            id: version.resource().as_str().into(),
                            version: version.label().as_str().into(),
                            variant: selected.key().as_str().into(),
                        },
                    }),
                })
            }
            r::Declaration::NativeCollection { definition, .. }
                if input.channel == Channel::Mdm =>
            {
                let mut permissions = self.native.permissions(definition)?;
                if permissions.contains(&P::Credentials) {
                    return Err(Error::Forbidden.into());
                }
                permissions.push(P::InventoryCollect);
                permissions.sort();
                permissions.dedup();
                for permission in &permissions {
                    snapshot.require_all_devices(proof, *permission)?;
                }
                let source = match definition.spec().adapter {
                    r::NativeAdapter::WindowsRead => rss_mdm_inventory::Source::MdmWindows,
                    _ => rss_mdm_inventory::Source::MdmApple,
                };
                let collection = crate::collection::preparation::freeze_collection(
                    tx,
                    self.tenant,
                    &version,
                    selected,
                    source,
                    definition.spec().mappings.keys(),
                )
                .await?;
                Ok(Published::NativeCollection {
                    frequency: input.frequency,
                    action: Box::new(FrozenNative {
                        input: frozen_input,
                        definition: definition.clone(),
                        collection,
                        resource_digest: version.digest().bytes(),
                        permissions,
                    }),
                })
            }
            _ => Err(Error::Malformed.into()),
        }
    }
}
fn select<'a>(version: &'a r::Version, binding: &ExactResourceBinding) -> Result<&'a r::Variant> {
    checked_input(version.resolve(
        match binding.platform {
            rss_mdm_policy::Platform::Windows => r::Platform::Windows,
            rss_mdm_policy::Platform::Macos => r::Platform::MacOS,
        },
        match binding.architecture {
            rss_mdm_policy::Architecture::X86_64 => r::Architecture::X86_64,
            rss_mdm_policy::Architecture::Aarch64 => r::Architecture::Aarch64,
        },
        &checked_input(r::Id::new(&binding.variant))?,
    ))
}
fn artifact(variant: &r::Variant, channel: Channel) -> Result<&r::Artifact> {
    match variant.declaration() {
        r::Declaration::AgentCollection { artifact, .. } if channel == Channel::Agent => {
            Ok(artifact)
        }
        r::Declaration::NativeCollection { artifact, .. } if channel == Channel::Mdm => {
            Ok(artifact)
        }
        _ => Err(Error::Malformed.into()),
    }
}
fn content_error(error: rss_mdm_content_service::Error) -> Error {
    use rss_mdm_content_service::Error as C;
    match error {
        C::CommitUnknown => Error::CommitUnknown,
        C::Malformed => Error::Malformed,
        C::Conflict => Error::Conflict,
        C::Configuration | C::Invariant | C::Metadata => {
            Error::Unavailable(crate::Failure::Database)
        }
        C::Storage | C::Cleanup => Error::Unavailable(crate::Failure::Runtime),
        C::Deadline => Error::Unavailable(crate::Failure::RequestDeadline),
    }
}
