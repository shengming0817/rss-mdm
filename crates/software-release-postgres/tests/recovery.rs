use rss_mdm_software_release_postgres::*;
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
        let s = ReleaseStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        let id = core::RequestId::new(tenant(), unique()).unwrap();
        let package = unique();
        let content = core::Content::new(
            core::SoftwareIdentity::new(core::SoftwareIdentityFields {
                source: "recovery".into(),
                package: package.clone(),
                version: "1".into(),
                platform: "windows".into(),
            })
            .unwrap(),
            core::Digest::from_bytes([1; 32]),
            core::Digest::from_bytes([2; 32]),
            core::Digest::from_bytes([3; 32]),
            vec![
                core::VariantContent::new(
                    "x64",
                    "msi",
                    vec![
                        core::Artifact::new("installer", core::Digest::from_bytes([4; 32]))
                            .unwrap(),
                    ],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let request = core::Candidate::new(
            core::CandidateId::new(tenant(), package).unwrap(),
            content,
            at(10),
        );
        let gate = if protocol {
            Some(ack::CommitGate::start("mdm_software_release", id.value()).await)
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
            let mut operation = Box::pin(s.create(&id, &request, deadline));
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
        let s = ReleaseStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        let first = s.create(&id, &request, deadline()).await.unwrap();
        assert_eq!(first, s.create(&id, &request, deadline()).await.unwrap());
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id='software-release.v1:{}'",
                id.value()
            )),
            "1"
        );
        runtime.close().await;
    }
}
