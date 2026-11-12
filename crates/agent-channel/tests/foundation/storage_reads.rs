//! Public storage reads execute in DA before any MDM private schema exists.
use super::*;
use rss_mdm_policy_postgres::{directory, events};
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::PgError;

pub async fn verify(c: &Context) -> Result<()> {
    scope(c).await?;
    let runtime = c.inputs.runtime("da_policy_runtime", c.tenant).await?;
    let cutoff = rss_request_context::Clock::now(&context::Timer) + Duration::from_secs(10);
    assert!(
        !rss_mdm_policy_service::worker::configuration_input_suspended(
            &runtime, c.tenant, None, cutoff,
        )
        .await?
    );
    assert_eq!(
        rss_mdm_policy_service::worker::queue_health(DA, &runtime, c.tenant, None, cutoff,).await?,
        [0; 5]
    );
    let batch_query = rss_mdm_policy_service::events::queries::BATCHES.parse("")?;
    let member_query = rss_mdm_policy_service::events::queries::MEMBERS.parse("")?;
    let batch = Uuid::new_v4();
    let member = Uuid::new_v4();
    let registration = Uuid::new_v4();
    let result = runtime
        .local_tx(
            c.tenant,
            OperationDeadline::from_remaining(Duration::from_secs(10)),
            move |tx| {
                Box::pin(async move {
                    events::insert_batch_in(
                        DA,
                        tx,
                        events::Batch {
                            id: batch,
                            operation: Uuid::new_v4(),
                            actor: "directory-proof".into(),
                            caller: json!({"target":{"registration":registration}}),
                            device: rss_mdm_agent_wire::DeviceId::parse(
                                "3967e292-f46e-5275-9cfb-ec946da5ef40",
                            )
                            .unwrap(),
                            input: json!({"event":"foundation"}),
                            fingerprint: vec![1; 32],
                            at: now(),
                            deadline: now() + 60,
                        },
                    )
                    .await?;
                    events::insert_member_in(
                        DA,
                        tx,
                        events::Member {
                            batch,
                            id: member,
                            policy: Uuid::new_v4(),
                            revision: 1,
                            version: Uuid::new_v4(),
                            target: json!({"registration":registration}),
                            authority: json!({}),
                            decision: json!({"state":"pending"}),
                        },
                    )
                    .await?;
                    for (query, members, expected) in
                        [(&batch_query, false, batch), (&member_query, true, member)]
                    {
                        let rows = directory::events_in(
                            DA,
                            tx,
                            query,
                            None,
                            directory::EventTarget {
                                device: &rss_mdm_agent_wire::DeviceId::parse(
                                    "3967e292-f46e-5275-9cfb-ec946da5ef40",
                                )
                                .expect("valid device"),
                                batch: Some(batch),
                            },
                            members,
                            if members {
                                &rss_mdm_policy_service::events::queries::MEMBER_BINDINGS
                            } else {
                                &rss_mdm_policy_service::events::queries::BATCH_BINDINGS
                            },
                        )
                        .await
                        .map_err(|e| {
                            PgError::from(sqlx::Error::Protocol(format!(
                                "DA Policy directory: {e:?}"
                            )))
                        })?;
                        assert_eq!(rows.len(), 1);
                        assert_eq!(rows[0]["id"], json!(expected));
                    }
                    Ok(())
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err);
    runtime.close().await;
    result?;
    Ok(())
}

async fn scope(c: &Context) -> Result<()> {
    let runtime = c.inputs.runtime("da_scope_runtime", c.tenant).await?;
    let store = rss_mdm_scope_postgres::ScopeBinding::new(DA, runtime.clone(), c.tenant);
    let result = runtime
        .local_tx_with_context(
            c.tenant,
            OperationDeadline::from_remaining(Duration::from_secs(10)),
            &store,
            |store, tx| {
                Box::pin(async move {
                    store.queue_counts_in(tx).await.map_err(|e| {
                        PgError::from(sqlx::Error::Protocol(format!("DA Scope health: {e:?}")))
                    })
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err);
    runtime.close().await;
    assert_eq!(result?, [0; 5]);
    let mut tx = c.access.begin().await?;
    for profile in [DA, StorageProfile::Mdm] {
        let reader = rss_mdm_scope_service::channels::ChannelTargets::new(profile, None);
        assert!(matches!(
            reader
                .lifecycle_objects_on(&mut tx, c.tenant, Uuid::new_v4(), None, 1)
                .await,
            Err(rss_mdm_scope_service::channels::SourceError::Unsupported)
        ));
    }
    tx.rollback().await?;
    Ok(())
}
