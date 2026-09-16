use rss_mdm_policy_postgres::*;
mod support;
use support::*;
#[path = "support/ack.rs"]
mod ack;
#[tokio::test]
#[ignore = "real TLS PG commit acknowledgement loss"]
async fn protocol_ack_loss_and_fault_ack_recover_original_request() {
    for protocol in [false, true] {
        let proxy = ack::AckProxy::start().await;
        let runtime = runtime_at(if protocol { Some(proxy.port) } else { None }).await;
        let s = PolicyStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        let key = core::PolicyId::new(tenant(), unique()).unwrap();
        for (revision, command) in [
            (
                0,
                Command::Create {
                    policy: key.clone(),
                },
            ),
            (
                1,
                Command::Transition {
                    policy: key.clone(),
                    transition: core::Transition::Activate(
                        core::Version::new(
                            key.clone(),
                            1,
                            core::PayloadRef::new(
                                core::PayloadId::new(tenant(), unique()).unwrap(),
                                1,
                                [1; 32],
                            )
                            .unwrap(),
                            core::RemovalRule::CancelOutstandingRetainEffects,
                        )
                        .unwrap(),
                    ),
                },
            ),
            (
                2,
                Command::SelectTargets {
                    policy: key.clone(),
                    snapshot: core::TargetSnapshot::new(
                        core::TargetSnapshotId::new(tenant(), unique()).unwrap(),
                        1,
                        core::SnapshotCompleteness::Complete,
                        vec![core::DeviceId::new(tenant(), "device").unwrap()],
                    )
                    .unwrap(),
                    references: vec![],
                },
            ),
        ] {
            s.execute(
                &Request {
                    id: core::RequestId::new(tenant(), unique()).unwrap(),
                    expected_storage_revision: revision,
                    as_of: at(10),
                    command,
                },
                deadline(),
            )
            .await
            .unwrap();
        }
        let id = core::RequestId::new(tenant(), unique()).unwrap();
        let request = Request {
            id: id.clone(),
            expected_storage_revision: 3,
            as_of: at(10),
            command: Command::Replan {
                policy: key.clone(),
            },
        };
        let gate = if protocol {
            Some(ack::CommitGate::start("mdm_policy", id.value()).await)
        } else {
            runtime.inject_next_transaction_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
            None
        };
        let result = {
            let deadline = rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                std::time::Duration::from_secs(7),
            );
            let mut operation = Box::pin(s.execute(&request, deadline));
            if let Some(gate) = &gate {
                tokio::select! {_=gate.entered()=>{},r=&mut operation=>panic!("request returned before COMMIT gate: {r:?}")}
                proxy
                    .discard
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                gate.release();
            }
            operation.await
        };
        assert!(matches!(result, Err(Error::CommitUnknown(_))), "{result:?}");
        drop(gate);
        runtime.close().await;
        drop(proxy);
        let runtime = support::runtime().await;
        let s = PolicyStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        let first = s.execute(&request, deadline()).await.unwrap();
        assert_eq!(first, s.execute(&request, deadline()).await.unwrap());
        assert_eq!(first.storage_revision, 4);
        let current = s.get(&key, deadline()).await.unwrap().unwrap();
        assert!(current.plan_is_fresh());
        assert_eq!(current.current_plan_request(), Some(&id));
        let plan = s.plan(&key, &id, deadline()).await.unwrap().unwrap();
        assert_eq!(Some(plan.id()), current.current_plan_id());
        assert_eq!(plan.request(), &id);
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id='policy.v1:{}'",
                id.value()
            )),
            "1"
        );
        runtime.close().await;
    }
}
