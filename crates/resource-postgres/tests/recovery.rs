use rss_mdm_resource_postgres::*;
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
        let s = ResourceStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        let id = core::Id::new(unique()).unwrap();
        let request = Request {
            id: id.clone(),
            resource: core::Id::new(unique()).unwrap(),
            expected_storage_revision: 0,
            as_of: at(10),
            command: Command::Create(core::Kind::Script),
        };
        let gate = if protocol {
            Some(ack::CommitGate::start("mdm_resource", id.as_str()).await)
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
        let s = ResourceStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        let first = s.execute(&request, deadline()).await.unwrap();
        assert_eq!(first, s.execute(&request, deadline()).await.unwrap());
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id='resource.v1:'||encode(sha256(convert_to('{}','UTF8')),'hex')",
                id.as_str()
            )),
            "1"
        );
        runtime.close().await;
    }
}
