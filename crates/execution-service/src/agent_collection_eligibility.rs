//! One native capability check for preview, Offer and Start.
use crate::{Target, channels, transaction::Result};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_policy::{Architecture, Platform};
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
pub fn matches(
    binding: &channels::AgentBinding,
    platform: Platform,
    architecture: Architecture,
    plan: &wire::NativeCollectionPlan,
    engines: &wire::NativeEngines,
) -> bool {
    binding.inventory()
        && binding.native_collection()
        && binding.platform
            == match platform {
                Platform::Windows => "windows",
                Platform::Macos => "macos",
            }
        && binding.architecture
            == match architecture {
                Architecture::X86_64 => "x86_64",
                Architecture::Aarch64 => "aarch64",
            }
        && plan.supported_by(engines)
}
pub async fn check_in(
    tx: &mut PgTransaction<'_>,
    store: Arc<dyn channels::Agent>,
    target: &Target,
    platform: Platform,
    architecture: Architecture,
    plan: &wire::NativeCollectionPlan,
) -> Result<bool> {
    let targets = channels::agent_targets_in(tx, store, vec![target.device.clone()]).await?;
    let Some(agent) = targets
        .into_iter()
        .find(|a| a.registration == target.registration && a.generation == target.generation)
    else {
        return Ok(false);
    };
    let tenant = tx.tenant_id().to_string();
    let registration = target.registration;
    let value:Option<serde_json::Value>=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT profiles->'nativeEngines' FROM mdm_commands.action_polls WHERE tenant_id=$1::uuid AND registration=$2").bind(tenant).bind(registration).fetch_optional(c).await.map(|v:Option<Option<serde_json::Value>>|v.flatten())})).await?;
    let Some(value) = value else {
        return Ok(false);
    };
    let engines = crate::stored(serde_json::from_value(value))?;
    Ok(matches(
        &agent.binding,
        platform,
        architecture,
        plan,
        &engines,
    ))
}
