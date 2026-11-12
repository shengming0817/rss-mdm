//! Published owner identity, original transaction and exact registration are all required.
use super::*;
use rss_mdm_inventory_service::collection::execution::scheduled::VerifiedNativeCollectionVersion;
use rss_mdm_software_service::deployment::actions::scheduled::VerifiedSoftwareVersion;
fn rejected(error: impl std::fmt::Debug) -> rss_transactional_messaging_postgres::PgError {
    sqlx::Error::Protocol(format!("test participant: {error:?}")).into()
}
async fn probe(h: &Harness, version: Uuid) -> Result<(bool, bool)> {
    let reader = rss_mdm_policy_postgres::PolicyReader::bind(
        rss_mdm_install_support::StorageProfile::Mdm,
        h.a.resources.storage.runtime.clone(),
        h.c.tenant,
    );
    Ok(h.a
        .resources
        .storage
        .runtime
        .local_tx_with_context(
            h.c.tenant,
            script::transaction::deadline(),
            reader,
            move |reader, tx| {
                Box::pin(async move {
                    let software = VerifiedSoftwareVersion::verify_in(reader, tx, version)
                        .await
                        .map_err(rejected)?
                        .is_some();
                    let collection =
                        VerifiedNativeCollectionVersion::verify_in(reader, tx, version)
                            .await
                            .map_err(rejected)?
                            .is_some();
                    Ok((software, collection))
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?)
}
async fn wake(
    h: &Harness,
    version: Uuid,
    target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
    rollback: bool,
) -> Result<()> {
    let reader = rss_mdm_policy_postgres::PolicyReader::bind(
        rss_mdm_install_support::StorageProfile::Mdm,
        h.a.resources.storage.runtime.clone(),
        h.c.tenant,
    );
    let messaging = rss_reconcile_postgres::PgMessagingStore::new(
        h.a.resources.storage.runtime.clone(),
        h.c.tenant,
        script::transaction::deadline(),
    )
    .await?;
    h.a.resources
        .storage
        .runtime
        .local_tx_with_context(
            h.c.tenant,
            script::transaction::deadline(),
            (reader, messaging, target),
            move |(reader, messaging, target), tx| {
                Box::pin(async move {
                    if let Some(proof) = VerifiedSoftwareVersion::verify_in(reader, tx, version)
                        .await
                        .map_err(rejected)?
                    {
                        proof
                            .wake_assignment_in(messaging, tx, target)
                            .await
                            .map_err(rejected)?;
                    }
                    if let Some(proof) =
                        VerifiedNativeCollectionVersion::verify_in(reader, tx, version)
                            .await
                            .map_err(rejected)?
                    {
                        proof
                            .wake_assignment_in(messaging, tx, target)
                            .await
                            .map_err(rejected)?;
                    }
                    if rollback {
                        return Err(rejected("rollback after owner wake"));
                    }
                    Ok(())
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    Ok(())
}
async fn scheduled(h: &Harness) -> Result<Vec<(String, String)>> {
    Ok(sqlx::query_as("SELECT reconciler,entity FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND entity LIKE 'scheduled:%' ORDER BY reconciler,entity")
        .bind(h.c.tenant.to_string()).fetch_all(&h.c.operator).await?)
}
#[tokio::test]
#[ignore = "T2: immutable owner proofs admit only matching current versions and exact active registrations in the original transaction"]
async fn published_owner_proofs_are_not_interchangeable_or_cached_authority() -> Result<()> {
    let h = Harness::open().await?;
    let (_, foreign) = h.policy("foreign-execution").await?;
    let (definition, frozen, _) = super::mixed::agent(&h)?;
    let agent_collection = super::mixed::publish(&h, Uuid::new_v4(), 1, definition, frozen).await?;
    let (native_policy, _, native_object) = super::retirement::native(&h, None).await?;
    let native_version: Uuid = sqlx::query_scalar(
        "SELECT current_version FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(h.c.tenant.to_string())
    .bind(native_policy)
    .fetch_one(&h.c.operator)
    .await?;
    let resource = super::super::software_t2::support::software(&h.c, "proof-software").await?;
    let (software_policy, software_version) = super::super::software_t2::support::policy(
        &h.c,
        &resource,
        h.scope,
        rss_mdm_policy::SoftwareChannel::Agent,
        vec![super::super::software_t2::support::stage(h.scope)],
    )
    .await?;
    assert_eq!(probe(&h, foreign).await?, (false, false));
    assert_eq!(probe(&h, agent_collection).await?, (false, false));
    assert_eq!(probe(&h, native_version).await?, (false, true));
    assert_eq!(probe(&h, software_version).await?, (true, false));
    assert!(probe(&h, Uuid::new_v4()).await.is_err());
    let agent = &h.object.members[0];
    assert!(wake(&h, software_version, agent, true).await.is_err());
    assert!(scheduled(&h).await?.is_empty());
    wake(&h, software_version, &native_object.members[0], false).await?;
    wake(&h, native_version, agent, false).await?;
    assert!(scheduled(&h).await?.is_empty());
    wake(&h, software_version, agent, false).await?;
    wake(&h, native_version, &native_object.members[0], false).await?;
    let before = scheduled(&h).await?;
    assert_eq!(before.len(), 2);
    assert_ne!(before[0].0, before[1].0);
    let mut stale = agent.clone();
    stale.device = rss_mdm_agent_wire::DeviceId::new_v4();
    wake(&h, software_version, &stale, false).await?;
    assert_eq!(scheduled(&h).await?, before);
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query(
        "UPDATE mdm_policy.policies SET state='disabled' WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(h.c.tenant.to_string())
    .bind(software_policy)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    assert_eq!(probe(&h, software_version).await?, (false, false));
    let (definition, frozen, _) = super::mixed::agent(&h)?;
    super::mixed::publish(&h, native_policy, 2, definition, frozen).await?;
    assert_eq!(probe(&h, native_version).await?, (false, false));
    h.close().await
}
