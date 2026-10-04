//! The same persisted device facts gate preview, staging and execution.
use crate::{Target, channels, transaction::Result};
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
    binding: &channels::AgentBinding,
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
pub async fn announce_in(
    tx: &mut PgTransaction<'_>,
    registration: uuid::Uuid,
    profiles: &[wire::ExecutorProfile],
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let profiles = crate::checked_input(serde_json::to_value(profiles))?;
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.action_polls(tenant_id,registration,profiles) VALUES($1::uuid,$2,$3) ON CONFLICT(tenant_id,registration) DO UPDATE SET profiles=excluded.profiles").bind(tenant).bind(registration).bind(profiles).execute(c).await?; Ok(())
    })).await?;
    Ok(())
}
pub async fn check_in(
    tx: &mut PgTransaction<'_>,
    store: Arc<dyn channels::Agent>,
    target: &Target,
    platform: Platform,
    architecture: Architecture,
    profile: wire::ExecutorProfile,
) -> Result<Eligibility> {
    let mut agents = channels::agent_targets_in(tx, store, vec![target.device.clone()]).await?;
    let Some(agent) = agents.pop() else {
        return Ok(Eligibility::Unknown);
    };
    if agent.registration != target.registration || agent.generation != target.generation {
        return Ok(Eligibility::Ineligible);
    }
    let tenant = tx.tenant_id().to_string();
    let registration = target.registration;
    let profiles: Option<serde_json::Value> = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT profiles FROM mdm_commands.action_polls WHERE tenant_id=$1::uuid AND registration=$2").bind(tenant).bind(registration).fetch_optional(c).await.map(|row:Option<Option<serde_json::Value>>|row.flatten())
    })).await?;
    let Some(profiles) = profiles else {
        return Ok(Eligibility::Unknown);
    };
    let profiles: Vec<wire::ExecutorProfile> = crate::stored(serde_json::from_value(profiles))?;
    Ok(
        if matches(&agent.binding, platform, architecture, profile, &profiles) {
            Eligibility::Eligible
        } else {
            Eligibility::Ineligible
        },
    )
}
pub async fn require_in(
    tx: &mut PgTransaction<'_>,
    store: Arc<dyn channels::Agent>,
    target: &Target,
    frozen: &crate::action_contract::FrozenAction,
) -> Result<bool> {
    let Some(binding) = channels::agent_binding_in(tx, store.clone(), target.registration).await?
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
