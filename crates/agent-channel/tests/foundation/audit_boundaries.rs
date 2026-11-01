//! Real owners reject foreign audit identity before changing business, receipt or audit rows.
use super::*;

pub fn rejected_audits(c: &Context) -> [RequestAudit; 2] {
    [
        RequestAudit::new(
            StorageProfile::Mdm,
            c.tenant.to_string(),
            "boundary",
            AuditIntent::Management,
        ),
        RequestAudit::new(
            DA,
            Uuid::new_v4().to_string(),
            "boundary",
            AuditIntent::Management,
        ),
    ]
}

pub async fn snapshot(c: &Context) -> Result<Vec<serde_json::Value>> {
    let mut result = Vec::new();
    // Fixed tables cover both inserts and updates at each affected owner boundary.
    macro_rules! rows {
        ($table:literal) => {
            concat!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM ", $table, " t")
        };
    }
    for query in [
        rows!("rss_da.registrations"),
        rows!("rss_da.report_sources"),
        rows!("rss_da.agent_bindings"),
        rows!("rss_da.agent_task_attempts"),
        rows!("rss_da.agent_task_receipts"),
        rows!("rss_da.agent_task_polls"),
        rows!("rss_da.enrollment_runs"),
        rows!("rss_da.enrollment_receipts"),
        rows!("rss_da.pki_installations"),
        rows!("rss_da.pki_operations"),
        rows!("rss_da.signing_acknowledgements"),
        rows!("rss_da.signing_observations"),
        rows!("rss_audit.records"),
    ] {
        result.push(sqlx::query_scalar(query).fetch_one(&c.operator).await?);
    }
    Ok(result)
}

pub async fn task_trust(
    c: &Context,
    p: &registration::DevicePrincipal,
    signing: Arc<rss_mdm_task_trust::Signing>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    trust: &rss_mdm_agent_wire::task_trust::Trust,
) -> Result<()> {
    use rss_mdm_agent_wire::task_trust::{Acknowledgement, Observation, ObservationState};
    let service = rss_mdm_task_trust::Service::new(
        c.tenant,
        signing,
        protection,
        c.access_audit.clone(),
        Arc::new(rss_mdm_agent_channel::signature_retirement::PendingSignatures::new(DA)),
    )?;
    let ack = Acknowledgement {
        operation: Uuid::new_v4(),
        version: 1,
        registration: p.registration(),
        generation: p.generation() as u64,
        revision: trust.revision,
        digest: trust.installation_digest()?,
    };
    let observation = Observation {
        operation: Uuid::new_v4(),
        version: 1,
        registration: p.registration(),
        generation: p.generation() as u64,
        sequence: 1,
        target_revision: Some(trust.revision),
        target_digest: Some(trust.installation_digest()?),
        actual_revision: Some(trust.revision),
        actual_digest: Some(trust.installation_digest()?),
        state: ObservationState::Applied,
        reason: None,
        observed_at: now(),
    };
    let before = snapshot(c).await?;
    for audit in rejected_audits(c) {
        assert!(matches!(
            service.device_trust(p, &audit).await,
            Err(rss_mdm_task_trust::Error::Forbidden)
        ));
        assert!(matches!(
            service.acknowledge_task_trust(p, &audit, &ack).await,
            Err(rss_mdm_task_trust::Error::Forbidden)
        ));
        assert!(matches!(
            service.observe_task_trust(p, &audit, &observation).await,
            Err(rss_mdm_task_trust::Error::Forbidden)
        ));
        audit.finalize(None);
        assert_eq!(snapshot(c).await?, before);
    }
    let audit = RequestAudit::new(
        DA,
        c.tenant.to_string(),
        "task_trust",
        AuditIntent::Management,
    );
    assert_eq!(service.device_trust(p, &audit).await?, *trust);
    service.acknowledge_task_trust(p, &audit, &ack).await?;
    audit.finalize(None);
    let audit = RequestAudit::new(
        DA,
        c.tenant.to_string(),
        "task_trust",
        AuditIntent::Management,
    );
    service.observe_task_trust(p, &audit, &observation).await?;
    audit.finalize(None);
    assert_ne!(snapshot(c).await?, before);
    Ok(())
}

pub async fn registration(
    c: &Context,
    service: &registration::agent::Service,
    peer: &rss_mdm_certificate::ClientCertificateEvidence,
    trust: &rss_mdm_agent_wire::pki::Trust,
) -> Result<()> {
    let input = rss_mdm_agent_wire::pki::Acknowledgement {
        operation: Uuid::new_v4(),
        version: 1,
        revision: trust.revision,
        digest: trust.installation_digest(),
    };
    let before = snapshot(c).await?;
    for audit in rejected_audits(c) {
        assert!(matches!(
            service.acknowledge_trust(peer, &input, &audit).await,
            Err(registration::agent::Failure {
                source: Some(registration::Error::Forbidden),
                ..
            })
        ));
        audit.finalize(None);
        assert_eq!(snapshot(c).await?, before);
    }
    let audit = RequestAudit::new(DA, c.tenant.to_string(), "pki_ack", AuditIntent::Management);
    service.acknowledge_trust(peer, &input, &audit).await?;
    audit.finalize(None);
    assert_ne!(snapshot(c).await?, before);
    Ok(())
}
