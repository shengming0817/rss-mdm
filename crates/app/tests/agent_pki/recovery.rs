//! Recovery proof starts from durable issuance, then restores the same authority.
use crate::Database;
use crate::agent_pki_tests::{
    audit, authorize_request, chain, deployment, grant, now, root, service, signing,
};
use crate::device::test_support::{admin, case_a, case_b, options};
use crate::test_support::agent_tls::peer;
use rss_mdm_agent_wire::{enroll as wire, runtime};
use rss_mdm_certificate::agent::PROFILE;
use uuid::Uuid;
#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki-recovery"]
async fn restored_ca_signs_only_live_authorized_agent_csrs_and_tls_preserves_purpose()
-> anyhow::Result<()> {
    let s = service(deployment()).await?;
    let p = admin(case_a(), "admin-a").await?;
    let foreign = admin(case_b(), "admin-b").await?;
    let g = grant()?;
    assert!(authorize_request(&s, &foreign, &g, &audit()).await.is_err());
    let receipt = authorize_request(&s, &p, &g, &audit()).await?;
    let input = signing(&g, receipt.grant_id)?;
    let mut wrong = input.clone();
    wrong.secret = runtime::Secret::parse(&crate::enrollment::random())?;
    assert!(s.issue(&wrong, &audit()).await.is_err());
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
    assert!(
        s.authenticate(&evidence).await.is_err(),
        "candidate entered runtime before activation"
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
    let db = Database::connect(options("mdm_access")?).await?;
    let devices = crate::device::DeviceService::new(
        db.registration(),
        case_a().into(),
        db.audit_store(&crate::config::AuditConfig::Plain).await?,
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
}
