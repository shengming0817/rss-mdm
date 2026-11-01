//! Current self-service qualification belongs to the business owner.
use super::*;
#[allow(
    clippy::too_many_arguments,
    reason = "self-service directory description borrows explicit product and current authorization facts"
)]
pub async fn describe_in(
    profile: rss_mdm_install_support::StorageProfile,
    service: &Service,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    proof: Option<&AuthorizedPrincipal>,
    source: wire::SelfServiceCaller,
    id: Uuid,
    now: i64,
) -> Result<Option<wire::SelfServiceDirectoryItem>> {
    if profile != p.profile() {
        return Err(crate::Error::Forbidden.into());
    }

    let Some(policy) =
        crate::enrollment::tasks::policy::current_in(&service.transactions.policy_reader, tx, id)
            .await?
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
    let Some(subject) = access::qualify_in(profile, service, tx, config, &basis).await? else {
        return Ok(None);
    };
    if !matches!(
        policy.definition.action,
        rss_mdm_policy::Action::RequestMdmEnrollment { .. }
    ) {
        return Ok(None);
    }
    let plan = crate::enrollment::tasks::policy::read_in(&service.transactions, tx, policy.version)
        .await?;
    let Some(prepared) = prepare_in(
        profile,
        service,
        tx,
        &plan,
        &target(p),
        Uuid::new_v4(),
        None,
        now,
    )
    .await?
    else {
        return Ok(None);
    };
    let input_schema = json!({"type":"object","properties":{},"additionalProperties":false});
    let output_schema = json!({"type":"object","properties":{"outcome":{"type":"string"}},"additionalProperties":false});
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
