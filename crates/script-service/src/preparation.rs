//! Publication captures Script inputs in the caller's existing transaction.
use crate::frozen::*;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_inventory_service::collection::preparation::freeze_collection;
use rss_mdm_policy::{Architecture, Platform, schedule::Schedule};
use rss_mdm_resource as r;
/// Freeze checked resources under the caller's existing execution transaction.
pub async fn freeze_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    tenant: rss_request_context::TenantId,
    prepared: &r::SelectedScript<'_>,
    parameters: rss_mdm_policy::ParameterSources,
    schedule: Schedule,
    run_lifetime_seconds: u32,
) -> crate::transaction::Result<FrozenScript> {
    let script = prepared.definition();
    let collection = if let r::ScriptPurpose::Collection { mappings, .. } = &script.spec().purpose {
        let source = if script.spec().profile == r::ScriptProfile::Osquery {
            rss_mdm_inventory::Source::AgentOsquery
        } else {
            rss_mdm_inventory::Source::AgentScript
        };
        Some(
            freeze_collection(
                tx,
                tenant,
                prepared.version(),
                prepared.variant(),
                source,
                mappings.keys(),
            )
            .await?,
        )
    } else {
        None
    };
    let artifact = prepared.artifact();
    Ok(FrozenScript {
        collection,
        resource: wire::TaskResource {
            id: prepared.version().resource().as_str().into(),
            version: prepared.version().label().as_str().into(),
            variant: prepared.variant().key().as_str().into(),
        },
        parameters,
        input: ScriptInput {
            platform: match prepared.variant().platform() {
                r::Platform::Windows => Platform::Windows,
                r::Platform::MacOS => Platform::Macos,
            },
            architecture: match prepared.variant().architecture() {
                r::Architecture::X86_64 => Architecture::X86_64,
                r::Architecture::Aarch64 => Architecture::Aarch64,
            },
            schedule,
            run_lifetime_seconds,
        },
        definition: script.clone(),
        resource_digest: prepared.version().digest().bytes(),
        artifact_reference: artifact.reference().as_str().into(),
        content: wire::TaskContent {
            length: artifact.length(),
            sha256: artifact.digest().bytes(),
        },
    })
}
