//! Recovery proof starts from durable issuance, then restores the same authority.
use crate::agent_pki_tests::{
    audit, authorize_request, chain, deployment, grant, now, root, service, signing,
};
use crate::device::test_support::{admin, case_a, case_b};
use crate::test_support::agent_tls::peer;
use rss_mdm_agent_wire::{enroll as wire, runtime};
use rss_mdm_certificate::agent::PROFILE;
use std::sync::Arc;
use uuid::Uuid;
#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki-recovery"]
async fn restored_ca_preserves_authorized_agent_issuance_and_activation() -> anyhow::Result<()> {
    let (pool, source, fixture_audit) = crate::audit_test_support::request_store().await?;
    let mut resources = crate::test_support::runtime::Resources::default();
    resources.resource(crate::test_support::runtime::PoolResource(pool.clone()));
    resources.resource(crate::test_support::runtime::SourceResource(source));
    let registration = Arc::new(rss_mdm_registration_service::Store::from_pool(
        pool.clone(),
        Arc::new(crate::registration_lifecycle::Bridge),
    ));
    resources
        .finish(async {
            let s = service(deployment(), pool.clone(), fixture_audit.clone()).await?;
            let p = admin(case_a(), "admin-a").await?;
            let foreign = admin(case_b(), "admin-b").await?;
            let g = grant()?;
            // This rejection is the authorization helper's tenant guard.
            assert_eq!(
                authorize_request(&s, &foreign, &g, &audit())
                    .await
                    .unwrap_err()
                    .code,
                wire::ErrorCode::PermissionDenied
            );
            let receipt = authorize_request(&s, &p, &g, &audit()).await?;
            let input = signing(&g, receipt.grant_id)?;
            let mut wrong = input.clone();
            wrong.secret = runtime::Secret::parse(&crate::enrollment::random())?;
            assert_eq!(
                s.issue(&wrong, &audit()).await.unwrap_err().code,
                wire::ErrorCode::InvalidIdentity
            );
            let candidate = s.issue(&input, &audit()).await?;
            std::fs::write(root().join("agent-recovery-request"), b"issuance persisted")?;
            tokio::time::timeout(std::time::Duration::from_secs(180), async {
                loop {
                    anyhow::ensure!(
                        !root().join("agent-recovery-failed").exists(),
                        "CA recovery failed"
                    );
                    if root().join("agent-recovery-complete").exists() {
                        return Ok::<_, anyhow::Error>(());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            })
            .await??;
            assert!(root().join("agent-backup-restored").exists());
            let next = grant()?;
            let next_receipt = authorize_request(&s, &p, &next, &audit()).await?;
            let next_candidate = s
                .issue(&signing(&next, next_receipt.grant_id)?, &audit())
                .await?;
            assert_ne!(next_candidate.issuance_id, candidate.issuance_id);

            let replay = s.issue(&input, &audit()).await?;
            assert_eq!(
                serde_json::to_value(&candidate)?,
                serde_json::to_value(replay)?
            );
            let evidence = peer(s.trust(), &chain(&candidate)?, &root()).await?;
            let verified = s.trust().verify_peer(&evidence, now())?;
            assert_eq!(verified.metadata().profile, PROFILE);
            assert_eq!(
                verified.metadata().not_after - verified.metadata().not_before,
                365 * 86400
            );
            assert_eq!(
                s.authenticate(&evidence).await.err().unwrap().code,
                wire::ErrorCode::InvalidIdentity
            );
            let activate = wire::ActivationRequest {
                wire_version: 1,
                issuance_id: candidate.issuance_id,
                operation_id: Uuid::new_v4(),
            };
            let active = s.activate(&evidence, &activate, &audit()).await?;
            let retry = s.activate(&evidence, &activate, &audit()).await?;
            assert_eq!(serde_json::to_value(&active)?, serde_json::to_value(retry)?);
            assert_eq!(
                s.authenticate(&evidence).await?.registration(),
                active.runtime.registration_id
            );
            let devices = crate::device::DeviceService::new(
                registration.clone(),
                case_a().into(),
                fixture_audit.clone(),
            );
            devices
                .revoke(
                    &p,
                    &active.runtime.device_id,
                    active.runtime.registration_id,
                    Uuid::new_v4(),
                )
                .await?;
            assert_eq!(
                s.authenticate(&evidence).await.err().unwrap().code,
                wire::ErrorCode::CredentialRevoked
            );
            Ok(())
        })
        .await
}
