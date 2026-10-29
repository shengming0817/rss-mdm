//! Policy freezes a Resource profile without manufacturing an execution task.
use super::*;
use crate::Failure;
/// Read and authorize the exact profile/template without publishing collection state.
pub async fn prepare_in(
    tx: &mut PgTransaction<'_>,
    binding: &rss_mdm_policy::ExactResourceBinding,
    proof: &AuthorizedPrincipal,
    snapshot: &rss_mdm_authorization_service::Snapshot,
    validator: &dyn crate::inputs::ProfileValidator,
) -> Result<FrozenProfile> {
    use rss_mdm_resource as r;
    let (version, state) = checked(
        rss_mdm_resource_postgres::lock_reference_in(
            tx,
            &checked_input(r::Id::new(&binding.id))?,
            &checked_input(r::Id::new(&binding.version))?,
        )
        .await?,
    )?;
    if state != r::State::Active {
        return Err(Error::Conflict.into());
    }
    let variant = checked_input(version.resolve(
        match binding.platform {
            rss_mdm_policy::Platform::Windows => r::Platform::Windows,
            rss_mdm_policy::Platform::Macos => r::Platform::MacOS,
        },
        match binding.architecture {
            rss_mdm_policy::Architecture::X86_64 => r::Architecture::X86_64,
            rss_mdm_policy::Architecture::Aarch64 => r::Architecture::Aarch64,
        },
        &checked_input(r::Id::new(&binding.variant))?,
    ))?;
    let r::Declaration::TelemetryProfile { definition, .. } = variant.declaration() else {
        return Err(Error::Malformed.into());
    };
    let referenced = &definition.spec().template;
    let (template, template_state) = checked(
        rss_mdm_resource_postgres::lock_reference_in(
            tx,
            &checked_input(r::Id::new(&referenced.resource))?,
            &checked_input(r::Id::new(&referenced.version))?,
        )
        .await?,
    )?;
    if template_state != r::State::Active {
        return Err(Error::Conflict.into());
    }
    let fields = validator
        .validate_in(tx, &template, definition)
        .await
        .map_err(|e| match e {
            crate::inputs::ProfileValidationError::Invalid => Error::Malformed,
            crate::inputs::ProfileValidationError::Conflict => Error::Conflict,
            crate::inputs::ProfileValidationError::Unavailable => {
                Error::Unavailable(crate::Failure::PolicyStorage)
            }
        })?;
    let variant = checked_input(template.resolve(
        referenced.platform,
        referenced.architecture,
        &checked_input(r::Id::new(&referenced.variant))?,
    ))?;
    let source = match variant.declaration() {
        r::Declaration::AgentCollection { .. } => rss_mdm_inventory::Source::AgentNative,
        r::Declaration::Script { definition, .. }
            if definition.spec().profile == r::ScriptProfile::Osquery =>
        {
            rss_mdm_inventory::Source::AgentOsquery
        }
        r::Declaration::Script { .. } => rss_mdm_inventory::Source::AgentScript,
        _ => return Err(Error::Malformed.into()),
    };
    let mut permissions = vec![Permission::InventoryCollect, Permission::InventoryRead];
    if matches!(
        source,
        rss_mdm_inventory::Source::AgentScript | rss_mdm_inventory::Source::AgentOsquery
    ) {
        permissions.push(Permission::ScriptExecute);
    }
    for permission in permissions {
        snapshot.require_all_devices(proof, permission)?;
    }
    Ok(FrozenProfile {
        resource_digest: template.digest().bytes(),
        profile: definition.clone(),
        fields,
        collector: match variant.declaration() {
            r::Declaration::AgentCollection { definition, .. } => FrozenCollector::Native {
                definition: definition.clone(),
            },
            r::Declaration::Script {
                definition,
                artifact,
            } => FrozenCollector::Script {
                definition: definition.clone(),
                reference: artifact.reference().as_str().into(),
                length: artifact.length(),
                digest: artifact.digest().bytes(),
            },
            _ => return Err(Error::Malformed.into()),
        },
        source,
    })
}

/// Shared transaction-bound resolver for targeted configuration evaluation.
pub async fn resolve_target_on(
    tenant: rss_request_context::TenantId,
    objects: std::sync::Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    c: &mut sqlx::PgConnection,
    device: &str,
    policy: Uuid,
    version: Uuid,
) -> std::result::Result<FrozenProfile, Error> {
    let (definition, frozen) =
        rss_mdm_policy_postgres::telemetry::current_on(c, tenant, policy, version)
            .await
            .map_err(|_| Error::Unavailable(Failure::PolicyStorage))?
            .ok_or(Error::Forbidden)?;
    let admission = rss_mdm_execution_service::scope::targets::admission_on(
        objects.as_ref(),
        c,
        tenant,
        definition.scope,
        rss_mdm_inventory::Channel::Agent,
        device,
    )
    .await
    .map_err(|_| Error::Conflict)?;
    if !matches!(
        admission,
        rss_mdm_execution_service::source_authority::ScopeAdmission::Eligible { .. }
    ) {
        return Err(Error::Forbidden);
    }
    serde_json::from_value(frozen).map_err(|_| Error::Unavailable(Failure::PolicyStorage))
}

pub(super) async fn freeze(
    tx: &mut PgTransaction<'_>,
    binding: &rss_mdm_policy::ExactResourceBinding,
    proof: &AuthorizedPrincipal,
    snapshot: &rss_mdm_authorization_service::Snapshot,
    validator: &dyn crate::inputs::ProfileValidator,
    policy: Uuid,
    version_id: Uuid,
) -> Result<Value> {
    use rss_mdm_resource as r;
    let frozen = prepare_in(tx, binding, proof, snapshot, validator).await?;
    let definition = &frozen.profile;
    let source = frozen.source;
    if definition.spec().projection != r::TelemetryProjection::History {
        let collection = checked_input(rss_mdm_inventory::CollectionDefinition::new(
            &format!("telemetry.{policy}"),
            version_id.to_string(),
            source,
            frozen
                .fields
                .iter()
                .map(|f| {
                    Ok(rss_mdm_inventory::CollectionField {
                        definition: f.clone(),
                        scope: rss_mdm_inventory::CollectionScope::Device,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        ))?;
        let tenant = tx.tenant_id();
        tx.with_connection(move |c| {
            Box::pin(async move {
                rss_mdm_inventory_postgres::register_collection_in(c, tenant, &collection)
                    .await
                    .map_err(|_| {
                        sqlx::Error::Protocol("telemetry collection registration failed".into())
                    })
            })
        })
        .await?;
    }
    checked_input(serde_json::to_value(frozen))
}

use crate::telemetry::{FrozenCollector, FrozenProfile};
