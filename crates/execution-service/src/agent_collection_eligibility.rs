//! One native capability check for preview, Offer and Start.
use crate::agent_facts;
use crate::{Target, transaction::Result};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_policy::{Architecture, Platform};
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
pub fn matches(
    binding: &agent_facts::Binding,
    platform: Platform,
    architecture: Architecture,
    definition: &rss_mdm_resource::AgentCollectionDefinition,
    environment: &rss_mdm_agent_wire::CollectionEnvironment,
) -> bool {
    let plan = &definition.spec().plan;
    let version = binding.execution_context.os_version;
    let facts = rss_mdm_resource::CollectionEnvironment {
        os_version: Some(
            version
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join("."),
        ),
        build: Some(u32::from(version[2])),
        edition: environment.edition.clone(),
        tools: environment.tools.clone(),
    };
    let capabilities = environment
        .native_engines
        .keys()
        .map(|e| {
            serde_json::to_value(e)
                .expect("closed engine")
                .as_str()
                .expect("engine name")
                .to_owned()
        })
        .chain(binding.capabilities.iter().map(|capability| {
            serde_json::to_value(capability)
                .expect("closed capability")
                .as_str()
                .expect("capability name")
                .to_owned()
        }))
        .collect();
    definition
        .spec()
        .applicability
        .allows(&facts, "agent", &capabilities)
        && binding.inventory()
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
        && plan.platform()
            == match platform {
                Platform::Windows => wire::TaskPlatform::Windows,
                Platform::Macos => wire::TaskPlatform::Macos,
            }
        && wire::NativeExecutionBinding::bind(plan, &binding.execution_context).is_ok()
        && plan.supported_by(&environment.native_engines)
}
pub async fn check_in(
    tx: &mut PgTransaction<'_>,
    store: Arc<dyn agent_facts::Store>,
    target: &Target,
    platform: Platform,
    architecture: Architecture,
    definition: &rss_mdm_resource::AgentCollectionDefinition,
) -> Result<bool> {
    let tenant = tx.tenant_id();
    tx.with_connection_context(
        &mut (target, definition, store),
        |(target, definition, store), c| {
            Box::pin(async move {
                Ok(check_on(
                    c,
                    tenant,
                    store.clone(),
                    target,
                    platform,
                    architecture,
                    definition,
                )
                .await)
            })
        },
    )
    .await?
}
pub async fn check_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    store: Arc<dyn agent_facts::Store>,
    target: &Target,
    platform: Platform,
    architecture: Architecture,
    definition: &rss_mdm_resource::AgentCollectionDefinition,
) -> Result<bool> {
    if definition
        .spec()
        .mappings
        .values()
        .any(|m| m.counter_normalization.is_some())
    {
        return Ok(false);
    }
    let targets =
        agent_facts::agent_targets_on(c, tenant, store.clone(), vec![target.device.clone()])
            .await?;
    let Some(agent) = targets
        .into_iter()
        .find(|a| a.registration == target.registration && a.generation == target.generation)
    else {
        return Ok(false);
    };
    let tenant = tenant.to_string();
    let registration = target.registration;
    let Some(announcement) = store.announcement(c, tenant, registration).await? else {
        return Ok(false);
    };
    let environment = announcement.environment();
    Ok(matches(
        &agent.binding,
        platform,
        architecture,
        definition,
        environment,
    ))
}
