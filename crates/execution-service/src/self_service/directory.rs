//! Current self-service qualification belongs to the business owner.
use super::*;
pub async fn describe_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    proof: Option<&AuthorizedPrincipal>,
    source: wire::SelfServiceCaller,
    id: Uuid,
    now: i64,
) -> Result<Option<wire::SelfServiceDirectoryItem>> {
    let Some(policy) =
        crate::sources::storage::read_in(&service.transactions.policy_reader, tx, id).await?
    else {
        return Ok(None);
    };
    let Some(config) = &policy.definition.self_service else {
        return Ok(None);
    };
    if !policy.state.is_enabled()
        || !config.published
        || (source == wire::SelfServiceCaller::Ai && config.allow_ai != Some(true))
    {
        return Ok(None);
    }
    let Some(basis) = access::select(config, proof)? else {
        return Ok(None);
    };
    let Some(subject) = access::qualify_in(service, tx, config, &basis).await? else {
        return Ok(None);
    };
    let plan = db::load_source(
        &service.transactions.policy_reader,
        tx,
        db::Source::Policy {
            version: policy.version,
        },
    )
    .await?;
    let Some(prepared) =
        prepare_in(service, tx, &plan, &target(p), Uuid::new_v4(), None, now).await?
    else {
        return Ok(None);
    };
    let (input_schema, output_schema) = match &plan {
        db::ScheduledPolicy::Software(_) => (
            json!({"type":"object","properties":{},"additionalProperties":false}),
            serde_json::to_value(schemars::schema_for!(wire::SelfServiceSoftwareEffect))
                .map_err(|_| Error::Malformed)?,
        ),
        _ => (
            json!({"type":"object","properties":{},"additionalProperties":false}),
            serde_json::to_value(schemars::schema_for!(wire::EnrollmentEntryOutcome))
                .map_err(|_| Error::Malformed)?,
        ),
    };
    let mut metadata = metadata(config)?;
    metadata.risk_level = effective_risk(&policy);
    Ok(Some(wire::SelfServiceDirectoryItem {
        capability: wire::CapabilityDescriptor {
            id,
            object_type: wire::CapabilityObject::Policy,
            tool_name: wire::policy_tool_name(id),
            alias: policy.definition.alias.clone(),
            scope: policy.definition.scope,
            instance: service.transactions.instance.clone(),
            tenant: checked_input(Uuid::parse_str(&p.tenant().to_string()))?,
            revision: policy.revision as u64,
            version: policy.version,
            operations: vec![wire::CapabilityOperation::Invoke],
            input_schema,
            output_schema,
        },
        policy_id: id,
        policy_revision: policy.revision as u64,
        policy_version: policy.version,
        subject,
        self_service: metadata,
        task: prepared.task.ok_or(Error::Conflict)?,
    }))
}
