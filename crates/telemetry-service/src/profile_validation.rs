//! Profile authoring rules over owner-provided immutable material; no service callbacks.
use crate::Error;
use rss_mdm_resource as r;
fn input<T>(value: Result<T, impl std::fmt::Debug>) -> Result<T, Error> {
    value.map_err(|_| Error::Invalid)
}
pub fn validate(
    template: &r::Version,
    profile: &r::TelemetryProfile,
    facts: &[rss_mdm_inventory::FieldDefinition],
) -> Result<Vec<rss_mdm_inventory::FieldDefinition>, Error> {
    let spec = profile.spec();
    let variant = input(template.resolve(
        spec.template.platform,
        spec.template.architecture,
        &input(r::Id::new(&spec.template.variant))?,
    ))?;
    let (source, keys) = match variant.declaration() {
        r::Declaration::AgentCollection { definition, .. } => {
            if !spec.parameters.is_empty()
                || definition.spec().plan.spec().scope
                    != rss_mdm_agent_wire::CollectionScope::Device
            {
                return Err(Error::Invalid);
            }
            (
                rss_mdm_inventory::Source::AgentNative,
                definition.spec().mappings.keys().collect::<Vec<_>>(),
            )
        }
        r::Declaration::Script { definition, .. } => match &definition.spec().purpose {
            r::ScriptPurpose::Collection {
                mappings, scope, ..
            } => {
                if spec.budget.execution_millis < 1000
                    || *scope != r::TemplateScope::Device
                    || definition.spec().run_as != r::RunAs::System
                {
                    return Err(Error::Invalid);
                }
                input(definition.validate_parameters(&serde_json::json!(spec.parameters)))?;
                (
                    if definition.spec().profile == r::ScriptProfile::Osquery {
                        rss_mdm_inventory::Source::AgentOsquery
                    } else {
                        rss_mdm_inventory::Source::AgentScript
                    },
                    mappings.keys().collect(),
                )
            }
            _ => return Err(Error::Invalid),
        },
        _ => return Err(Error::Invalid),
    };
    let platform = match spec.template.platform {
        r::Platform::Windows => rss_mdm_inventory::Platform::Windows,
        r::Platform::MacOS => rss_mdm_inventory::Platform::Macos,
    };
    let mut fields = Vec::new();
    let mut resources = 0u32;
    for frozen in &spec.fields {
        let field = facts
            .iter()
            .find(|f| f.key.as_str() == frozen.key && f.version == frozen.version)
            .ok_or(Error::Conflict)?;
        if field.version != frozen.version
            || !keys.iter().any(|key| key.as_str() == field.key.as_str())
            || !field.sources.contains_key(&source)
            || !field.platforms.contains(&platform)
        {
            return Err(Error::Conflict);
        }
        if spec.projection != r::TelemetryProjection::Current && field.time_series.is_none() {
            return Err(Error::Invalid);
        }
        if let r::Declaration::AgentCollection { definition, .. } = variant.declaration() {
            let mapping = &definition.spec().mappings[field.key.as_str()];
            rss_mdm_inventory_service::collection::native::validate_agent_mapping(
                field, definition, mapping,
            )
            .map_err(|_| Error::Invalid)?;
            if mapping.counter_normalization.is_some()
                && spec.projection == r::TelemetryProjection::Current
            {
                return Err(Error::Invalid);
            }
        }
        resources = resources
            .checked_add(field.time_series.as_ref().map_or(1, |b| b.max_resources))
            .ok_or(Error::Invalid)?;
        fields.push(field.clone());
    }
    if resources > spec.budget.resources || resources > spec.budget.points {
        return Err(Error::Invalid);
    }
    Ok(fields)
}

/// Stateless owner implementation, operating only on the borrowed transaction.
pub struct ProfileValidator;
impl rss_mdm_policy_service::inputs::ProfileValidator for ProfileValidator {
    fn validate_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        template: &'a r::Version,
        profile: &'a r::TelemetryProfile,
    ) -> rss_mdm_policy_service::inputs::Pending<
        'a,
        Vec<rss_mdm_inventory::FieldDefinition>,
        rss_mdm_policy_service::inputs::ProfileValidationError,
    > {
        Box::pin(async move {
            use rss_mdm_policy_service::inputs::ProfileValidationError as E;
            let fields =
                rss_mdm_inventory_service::collection::resource_authoring::profile_fields_in(
                    tx, profile,
                )
                .await
                .map_err(|e| match e {
                    rss_mdm_inventory_service::transaction::Fault::Request(
                        rss_mdm_inventory_service::Error::Malformed,
                    ) => E::Invalid,
                    rss_mdm_inventory_service::transaction::Fault::Request(
                        rss_mdm_inventory_service::Error::Conflict,
                    ) => E::Conflict,
                    _ => E::Unavailable,
                })?;
            validate(template, profile, &fields).map_err(|e| match e {
                Error::Invalid => E::Invalid,
                Error::Conflict => E::Conflict,
                _ => E::Unavailable,
            })
        })
    }
}

/// Reuse profile rules against exact fields in the caller's page snapshot.
pub(crate) async fn validate_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    template: &r::Version,
    profile: &r::TelemetryProfile,
) -> Result<Vec<rss_mdm_inventory::FieldDefinition>, Error> {
    let fields = rss_mdm_inventory_service::collection::resource_authoring::profile_fields_on(
        c, tenant, profile,
    )
    .await
    .map_err(|e| match e {
        rss_mdm_inventory_service::transaction::Fault::Request(
            rss_mdm_inventory_service::Error::Malformed,
        ) => Error::Invalid,
        rss_mdm_inventory_service::transaction::Fault::Request(
            rss_mdm_inventory_service::Error::Conflict,
        ) => Error::Conflict,
        _ => Error::Storage,
    })?;
    validate(template, profile, &fields)
}
