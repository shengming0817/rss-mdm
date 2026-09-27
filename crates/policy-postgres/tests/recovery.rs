use rss_mdm_policy_postgres::*;
mod support;
use support::*;
#[path = "support/ack.rs"]
mod ack;
#[path = "support/operations.rs"]
mod operations;
use operations::*;
use rss_transactional_messaging::policy::OperationDeadline;
use uuid::Uuid;
#[tokio::test]
#[ignore = "real TLS PG commit acknowledgement loss"]
async fn protocol_ack_loss_and_fault_ack_recover_original_request() {
    for protocol in [false, true] {
        let proxy = ack::AckProxy::start().await;
        let runtime = runtime_at(protocol.then_some(proxy.port)).await;
        let store = PolicyStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        let id = Uuid::new_v4();
        let input = publication(
            id,
            None,
            core::Change::Put {
                definition: definition(),
                enabled: true,
            },
        );
        let request = Uuid::new_v4();
        let gate = if protocol {
            Some(ack::CommitGate::start("mdm_policy", &request.to_string()).await)
        } else {
            runtime.inject_next_transaction_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
            None
        };
        let result = {
            let mut call = Box::pin(execute(
                &runtime,
                &store,
                request,
                &input,
                OperationDeadline::from_remaining(std::time::Duration::from_secs(7)),
            ));
            if let Some(gate) = &gate {
                tokio::select! {_=gate.entered()=>{},r=&mut call=>panic!("early settlement: {r:?}")};
                proxy
                    .discard
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                gate.release();
            }
            call.await
        };
        assert!(matches!(result, Err(Error::CommitUnknown(_))), "{result:?}");
        drop(gate);
        runtime.close().await;
        drop(proxy);
        let runtime = support::runtime().await;
        let store = PolicyStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        let recovered = execute(&runtime, &store, request, &input, deadline())
            .await
            .unwrap();
        assert_eq!(
            recovered,
            execute(&runtime, &store, request, &input, deadline())
                .await
                .unwrap()
        );
        assert_eq!(
            store.get(id, deadline()).await.unwrap().unwrap().revision,
            1
        );
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM mdm_policy.versions WHERE policy='{id}'"
            )),
            "1"
        );
        runtime.close().await;
    }
}
