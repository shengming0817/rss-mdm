//! Policy freezes a Resource profile without manufacturing an execution task.
use super::*;
/// Read and authorize the exact profile/template without publishing collection state.
pub async fn prepare_in(
    tx: &mut PgTransaction<'_>,
    binding: &rss_mdm_policy::ExactResourceBinding,
    proof: &AuthorizedPrincipal,
    snapshot: &rss_mdm_authorization_service::Snapshot,
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
    let catalog = crate::assets::catalog_in(tx, tx.tenant_id(), i64::MAX).await?;
    let fields =
        crate::resource_catalog::telemetry::validate(tx, tx.tenant_id(), &catalog, definition)
            .await?;
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
    let grants = permissions
        .into_iter()
        .map(|permission| {
            rss_mdm_authorization_service::OperationAuthority::all_devices(
                snapshot, proof, permission,
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(FrozenProfile {
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
        grants,
    })
}

/// Product-frozen authority; never accepted from the Agent upload body.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenProfile {
    pub profile: rss_mdm_resource::TelemetryProfile,
    pub fields: Vec<rss_mdm_inventory::FieldDefinition>,
    pub collector: FrozenCollector,
    pub source: rss_mdm_inventory::Source,
    pub grants: Vec<rss_mdm_authorization_service::OperationAuthority>,
}
/// Resolve the current assignment and recheck live Scope and author authority on each use.
pub async fn resolve_on(
    planning: &crate::planning::Planning,
    c: &mut sqlx::PgConnection,
    device: &str,
    policy: Uuid,
    version: Uuid,
) -> std::result::Result<FrozenProfile, Error> {
    use rss_mdm_execution_service::source_authority::{Channel, ScopeAdmission, SourceAuthority};
    use sqlx::Row;
    let tenant = planning.tenant;
    let row = sqlx::query("SELECT p.definition,v.frozen FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.id=$2 AND p.current_version=$3 AND p.state='enabled' AND v.action_kind='telemetry_profile'")
        .bind(tenant.to_string()).bind(policy).bind(version).fetch_optional(&mut *c).await.map_err(|_| Error::Unavailable(crate::Failure::FlowStorage))?.ok_or(Error::Forbidden)?;
    let definition: rss_mdm_policy::Definition =
        serde_json::from_value(row.try_get("definition").map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
    let frozen: FrozenProfile =
        serde_json::from_value(row.try_get("frozen").map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
    let now: i64 = sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::bigint")
        .fetch_one(&mut *c)
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::FlowStorage))?;
    let mut permissions = vec![Permission::InventoryCollect, Permission::InventoryRead];
    if matches!(
        frozen.source,
        rss_mdm_inventory::Source::AgentScript | rss_mdm_inventory::Source::AgentOsquery
    ) {
        permissions.push(Permission::ScriptExecute);
    }
    if permissions.len() != frozen.grants.len() {
        return Err(Error::Forbidden);
    }
    for (permission, grant) in permissions.into_iter().zip(&frozen.grants) {
        if !grant
            .valid(c, permission, now)
            .await
            .map_err(|_| Error::Forbidden)?
        {
            return Err(Error::Forbidden);
        }
    }
    let current: Option<Uuid> = sqlx::query_scalar("SELECT current_version FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$2 AND state='enabled' FOR SHARE")
        .bind(tenant.to_string()).bind(policy).fetch_optional(&mut *c).await.map_err(|_| Error::Unavailable(crate::Failure::FlowStorage))?;
    if current != Some(version) {
        return Err(Error::Forbidden);
    }
    let source = crate::planning::execution_source::ExecutionSource::new(planning.objects.clone());
    if !matches!(
        source
            .admission_on(c, tenant, definition.scope, Channel::Agent, device)
            .await
            .map_err(|_| Error::Forbidden)?,
        ScopeAdmission::Eligible { .. }
    ) {
        return Err(Error::Forbidden);
    }
    Ok(frozen)
}

/// Exact template contents frozen with the assignment; Resource remains the definition owner.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FrozenCollector {
    Native {
        definition: rss_mdm_resource::AgentCollectionDefinition,
    },
    Script {
        definition: rss_mdm_resource::ScriptDefinition,
        reference: String,
        length: u64,
        digest: [u8; 32],
    },
}

pub(super) async fn freeze(
    tx: &mut PgTransaction<'_>,
    binding: &rss_mdm_policy::ExactResourceBinding,
    proof: &AuthorizedPrincipal,
    snapshot: &rss_mdm_authorization_service::Snapshot,
    policy: Uuid,
    version_id: Uuid,
) -> Result<Value> {
    use rss_mdm_resource as r;
    let frozen = prepare_in(tx, binding, proof, snapshot).await?;
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

/// The existing Scope owner provides the same immutable target page for periodic collection.
pub async fn preview_targets_on(
    planning: &crate::planning::Planning,
    c: &mut sqlx::PgConnection,
    scope: Uuid,
    after: Option<&str>,
) -> std::result::Result<
    (
        Vec<rss_mdm_execution_service::source_authority::AssignmentObject>,
        Uuid,
    ),
    Error,
> {
    use rss_mdm_execution_service::source_authority::{Channel, SourceAuthority};
    let source = crate::planning::execution_source::ExecutionSource::new(planning.objects.clone());
    let targets = source
        .assignment_objects_on(c, planning.tenant, scope, Channel::Agent, after)
        .await
        .map_err(|_| Error::Conflict)?;
    let result = source
        .preview_scope_on(c, planning.tenant, scope, Channel::Agent, None)
        .await
        .map_err(|_| Error::Conflict)?
        .result;
    Ok((targets, result))
}
