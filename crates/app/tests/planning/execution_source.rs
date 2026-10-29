//! Candidate pagination owns its PG prerequisites, without a protocol host or publication jobs.
use crate::planning::test_support::*;
use crate::test_support::{agent_execution, identity};
use anyhow::{Result, ensure};
use rss_mdm_execution_service::{
    configuration::{Configuration, Owner, Protected},
    frozen::Frozen,
    source_authority::{CandidateKind, ScopeAdmission, SourceAuthority},
};
use sqlx::Connection;

#[tokio::test]
#[ignore = "make t2 MODULE=policy.service: ExecutionSource PG pagination"]
async fn empty_candidate_page_preserves_progress_to_the_next_matching_policy() -> Result<()> {
    let tenant = tenant();
    let device = crate::test_support::case::name("candidate-page-device");
    seed_device(device);
    let planning = planning(tenant).await;
    let excluded = Uuid::new_v4();
    let included = Uuid::new_v4();
    agent_execution::seed_scope(&planning, excluded, json!([])).await?;
    agent_execution::seed_scope(&planning, included, json!([{"kind":"device","id":device}]))
        .await?;
    let subject = crate::test_support::case::admin();
    identity::seed_grants(
        &tenant.to_string(),
        subject,
        identity::device_grants(None, &["inventory_read", "configuration_write"])?,
    )
    .await?;
    let (identity, resources) = identity::identity(&tenant.to_string()).await?;
    resources.finish(async {
        let config = identity::config(&tenant.to_string())?;
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(config.access_options()?).await?;
        let access = rss_mdm_authorization_service::Store::from_pool(pool.clone(), Arc::new(crate::lifecycle::RuntimeTimer));
        let proof = crate::authorization::context::AuthorizedPrincipal::new(identity.authority.inspect_session(tenant, identity::credential_for(&tenant.to_string(), "admin")?, crate::identity::deadline()).await?)?
            .load_authorization(&access).await?;
        let native: Configuration = serde_json::from_value(json!({"target":{"kind":"device"},"apply":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana","instance":[],"operation":"replace","value":{"type":"integer","value":"1"}}}},"remove":null}))?;
        native.validate()?;
        let bytes = serde_json::to_vec(&native)?;
        let key = config.native_protector()?;
        let resource = Uuid::new_v4();
        let artifact = rss_mdm_resource::Artifact::new(rss_mdm_resource::Id::new("candidate-input")?, bytes.len() as u64, rss_mdm_resource::Digest::of(&bytes))?;
        let version = rss_mdm_resource::Version::new(tenant, rss_mdm_resource::Id::new(resource.to_string())?, rss_mdm_resource::Id::new("1")?, rss_mdm_resource::Kind::Configuration,
            vec![rss_mdm_resource::Variant::new(rss_mdm_resource::Platform::Windows, rss_mdm_resource::Architecture::X86_64, rss_mdm_resource::Id::new("native")?, rss_mdm_resource::Declaration::Configuration { artifact })])?;
        let mut publications = Vec::new();
        // Exactly one page of exclusions and one eligible candidate. IDs define scan order.
        for index in 1..=17 {
            let id = Uuid::from_u128(index);
            let definition = serde_json::from_value(json!({"scope":if index == 17 {included} else {excluded},"action":{"kind":"configuration","resource":{"id":resource,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"retain"}}))?;
            let policy = rss_mdm_policy::Policy::apply(id, None, 0, &rss_mdm_policy::Change::Put { definition: Box::new(definition), enabled: true }, Uuid::new_v4(), None)?.policy;
            let frozen = Frozen::Configuration { native: Protected::seal(&key, tenant, Owner::Policy { policy: id, version: policy.version }, &native)?, platform: rss_mdm_execution_service::action_contract::Platform::Windows, exit: rss_mdm_policy::Exit::Retain, resource_digest: version.digest().bytes() };
            publications.push(rss_mdm_policy_postgres::Publication { change: rss_mdm_policy::Change::Put { definition: Box::new(policy.definition.clone()), enabled: policy.state.is_enabled() }, policy, frozen: Some(serde_json::to_value(frozen)?), author: serde_json::to_value(proof.actor())?, at: 1 });
        }
        planning.policy.runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
            rss_mdm_resource_postgres::fixture::active_version_in(tx, version, rss_contract::Timepoint::try_from(1_i64).expect("fixture time")).await?;
            for publication in publications {
                rss_mdm_policy_postgres::fixture::published_in(tx, &publication).await?;
            }
            Ok(())
        })).await.fold(Ok, |e| Err(anyhow::anyhow!(e)), |e| Err(anyhow::anyhow!(e)), |_| Err(anyhow::anyhow!("candidate seed rollback unknown")), |_| Err(anyhow::anyhow!("candidate seed commit unknown")), |e| Err(anyhow::anyhow!(e)))?;
        let source = rss_mdm_policy_service::management::source::execution(planning.objects.clone());
        let mut connection = sqlx::PgConnection::connect_with(&crate::device::test_support::options("mdm_command_runtime")?.password("runtime-fixture")).await?;
        let mut tx = connection.begin().await?;
        crate::Database::configure_transaction(&mut tx, &tenant.to_string()).await?;
        let first = source.candidates_on(&mut tx, tenant, device, CandidateKind::Configuration, Uuid::nil()).await?;
        ensure!(first.items.is_empty() && first.has_more && first.scanned_after == Uuid::from_u128(16));
        let next = source.candidates_on(&mut tx, tenant, device, CandidateKind::Configuration, first.scanned_after).await?;
        ensure!(next.items.len() == 1 && next.items[0].policy == Uuid::from_u128(17) && next.items[0].scope == included && matches!(next.items[0].admission, ScopeAdmission::Eligible { .. }) && !next.has_more && next.scanned_after == Uuid::from_u128(17));
        tx.rollback().await?;
        connection.close().await?;
        pool.close().await;
        Ok(())
    }).await?;
    planning.close().await;
    Ok(())
}
