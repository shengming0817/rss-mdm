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
async fn protocol_ack_loss_recovers_original_request() {
    {
        let proxy = ack::AckProxy::start().await;
        let runtime = runtime_at(Some(proxy.port)).await;
        let store = PolicyStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        let id = Uuid::new_v4();
        let input = publication(
            id,
            None,
            core::Change::Put {
                definition: Box::new(definition()),
                enabled: true,
            },
        );
        let request = Uuid::new_v4();
        let gate = ack::CommitGate::start("mdm_policy", &request.to_string()).await;
        let result = {
            let mut call = Box::pin(execute(
                &runtime,
                &store,
                request,
                &input,
                OperationDeadline::from_remaining(std::time::Duration::from_secs(7)),
            ));
            {
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
        let persisted: serde_json::Value = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let row = sql(&format!("SELECT receipt FROM mdm_policy.requests WHERE tenant_id='{}' AND id='{request}'", tenant()));
                if !row.is_empty() { break serde_json::from_str(&row).unwrap(); }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await.expect("original commit was not durable");
        let recovered = execute(&runtime, &store, request, &input, deadline())
            .await
            .unwrap();
        assert_eq!(recovered, persisted);
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
