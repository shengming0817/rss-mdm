//! The same persisted device facts gate preview, staging and execution.
use crate::agent_facts;
use crate::{Error, Target, transaction::Result};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_policy::{Architecture, Platform};
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Eligibility {
    Eligible,
    Ineligible,
    Unknown,
}
pub fn matches(
    binding: &agent_facts::Binding,
    platform: Platform,
    architecture: Architecture,
    profile: wire::ExecutorProfile,
    profiles: &[wire::ExecutorProfile],
) -> bool {
    let platform = match platform {
        Platform::Windows => "windows",
        Platform::Macos => "macos",
    };
    let architecture = match architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
    };
    binding.inventory()
        && binding.script()
        && binding.platform == platform
        && binding.architecture == architecture
        && profiles.contains(&profile)
}
pub fn environment(input: &wire::TaskClaimRequest) -> rss_mdm_resource::CollectionEnvironment {
    let version = input.execution_context().os_version;
    rss_mdm_resource::CollectionEnvironment {
        os_version: Some(
            version
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join("."),
        ),
        build: Some(u32::from(version[2])),
        edition: input.environment().edition.clone(),
        tools: input.environment().tools.clone(),
    }
}
pub async fn check_in(
    tx: &mut PgTransaction<'_>,
    store: Arc<dyn agent_facts::Store>,
    target: &Target,
    platform: Platform,
    architecture: Architecture,
    profile: wire::ExecutorProfile,
) -> Result<Eligibility> {
    let tenant = tx.tenant_id();
    tx.with_connection_context(&mut (target, store), |(target, store), c| {
        Box::pin(async move {
            Ok(check_on(
                c,
                tenant,
                store.clone(),
                target,
                platform,
                architecture,
                profile,
            )
            .await)
        })
    })
    .await?
}
pub async fn check_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    store: Arc<dyn agent_facts::Store>,
    target: &Target,
    platform: Platform,
    architecture: Architecture,
    profile: wire::ExecutorProfile,
) -> Result<Eligibility> {
    let mut agents =
        agent_facts::agent_targets_on(c, tenant, store.clone(), vec![target.device.clone()])
            .await?;
    let Some(agent) = agents.pop() else {
        return Ok(Eligibility::Unknown);
    };
    if agent.registration != target.registration || agent.generation != target.generation {
        return Ok(Eligibility::Ineligible);
    }
    let tenant = tenant.to_string();
    let registration = target.registration;
    let Some(input) = store.announcement(c, tenant, registration).await? else {
        return Ok(Eligibility::Unknown);
    };
    let profiles = input.profiles();
    Ok(
        if matches(&agent.binding, platform, architecture, profile, profiles) {
            Eligibility::Eligible
        } else {
            Eligibility::Ineligible
        },
    )
}
pub async fn collection_requirements_in(
    store: Arc<dyn crate::agent_facts::Store>,
    tx: &mut PgTransaction<'_>,
    target: &Target,
    requirements: &rss_mdm_resource::Applicability,
) -> Result<bool> {
    let tenant = tx.tenant_id();
    tx.with_connection_context(&mut (target, requirements), |(target, requirements), c| {
        Box::pin(async move {
            Ok(collection_requirements_on(store, c, tenant, target, requirements).await)
        })
    })
    .await?
}
pub async fn collection_requirements_on(
    store: Arc<dyn crate::agent_facts::Store>,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    target: &Target,
    requirements: &rss_mdm_resource::Applicability,
) -> Result<bool> {
    let tenant = tenant.to_string();
    let registration = target.registration;
    let Some(input) = store.announcement(c, tenant, registration).await? else {
        return Ok(false);
    };
    let environment = environment(&input);
    let capabilities: std::collections::BTreeSet<String> = crate::stored(serde_json::from_value(
        serde_json::to_value(input.profiles()).map_err(|_| Error::Malformed)?,
    ))?;

    Ok(requirements.allows(&environment, "agent", &capabilities))
}
pub async fn require_in(
    tx: &mut PgTransaction<'_>,
    store: Arc<dyn agent_facts::Store>,
    target: &Target,
    frozen: &rss_mdm_script_service::FrozenScript,
) -> Result<bool> {
    if let rss_mdm_resource::ScriptPurpose::Collection { applicability, .. } =
        &frozen.definition.spec().purpose
        && !collection_requirements_in(store.clone(), tx, target, applicability).await?
    {
        return Ok(false);
    }
    let Some(binding) =
        agent_facts::agent_binding_in(tx, store.clone(), target.registration).await?
    else {
        return Ok(false);
    };
    let platform = match frozen.input.platform {
        Platform::Windows => wire::TaskPlatform::Windows,
        Platform::Macos => wire::TaskPlatform::Macos,
    };
    if rss_mdm_software_service::preparation::execution::identity_target(
        frozen.execution_identity(),
        platform,
        &binding.execution_context,
    )
    .is_err()
    {
        return Ok(false);
    }
    Ok(check_in(
        tx,
        store,
        target,
        frozen.input.platform,
        frozen.input.architecture,
        frozen.executor_profile(),
    )
    .await?
        == Eligibility::Eligible)
}
