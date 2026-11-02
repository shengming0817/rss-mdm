//! Production HTTP + TLS + PostgreSQL report admission, replay, paging and effect isolation.
use super::*;
use rss_mdm_agent_wire::da;
pub async fn verify(
    c: &Context,
    client: &reqwest::Client,
    peer: &reqwest::Client,
    base: &str,
    token: &str,
    registration: &da::Registration,
    signed: &da::SignedConfiguration,
) -> Result<()> {
    let identity = da::ReportIdentity {
        service_id: registration.service_id,
        tenant: registration.tenant,
        registration: registration.registration,
        generation: registration.generation as i64,
    };
    let mut report = da::StatusReport {
        identity: identity.clone(),
        sequence: 1,
        observed_at: Some(0),
        client_version: "foundation".into(),
        contract_version: 1,
        binding: da::Health::Ready,
        factor: da::Health::Ready,
        health: da::Health::Ready,
        configuration_digest: Some(signed.digest.clone()),
        errors: vec![],
    };
    let url = format!("{base}/status-reports");
    assert_eq!(client.post(&url).json(&report).send().await?.status(), 401);
    let first: serde_json::Value =
        material::success(peer.post(&url).json(&report).send().await?).await?;
    let repeated: serde_json::Value =
        material::success(peer.post(&url).json(&report).send().await?).await?;
    assert_eq!(
        first, repeated,
        "exact retry preserves the original receipt time"
    );
    assert_eq!(first["evidence"], "reported");
    report.health = da::Health::Blocked;
    assert_eq!(peer.post(&url).json(&report).send().await?.status(), 409);
    report.health = da::Health::Ready;
    report.sequence = 2;
    report.identity.generation += 1;
    assert_eq!(peer.post(&url).json(&report).send().await?.status(), 403);
    report.identity = identity.clone();
    let application = da::ApplicationReport {
        identity,
        operation_id: Uuid::new_v4(),
        sequence: 1,
        artifact: signed.decode()?.operation_id,
        digest: signed.digest.clone(),
        sources: vec![da::ReportedSource {
            artifact: signed.decode()?.operation_id,
            digest: signed.digest.clone(),
            delivery: da::DeliveryPermission::ManagedMandatory,
            state: da::SourceState::Present,
        }],
        state: da::ApplicationState::Applied,
        error: None,
    };
    // Even a false managed-delivery claim cannot obtain verified status or signing-key ACK.
    let before:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.bindings),(SELECT count(*) FROM rss_da.signing_acknowledgements)").fetch_one(&c.operator).await?;
    let accepted: serde_json::Value = material::success(
        peer.post(format!("{base}/configuration-reports"))
            .json(&application)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(accepted["evidence"], "reported");
    let retry: serde_json::Value = material::success(
        peer.post(format!("{base}/configuration-reports"))
            .json(&application)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(accepted, retry);
    let after:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.bindings),(SELECT count(*) FROM rss_da.signing_acknowledgements)").fetch_one(&c.operator).await?;
    assert_eq!(before, after);
    let diagnostic: serde_json::Value = material::success(
        client
            .get(format!(
                "{base}/admin/devices/{}/configuration",
                registration.device
            ))
            .bearer_auth(token)
            .send()
            .await?,
    )
    .await?;
    assert!(diagnostic["evidence"].is_null());
    assert_eq!(diagnostic["resolution"]["fields"][1]["source"], "da");
    assert_eq!(diagnostic["resolution"]["fields"][1]["locked"], false);
    for sequence in 2..=4 {
        report.sequence = sequence;
        material::success::<serde_json::Value>(peer.post(&url).json(&report).send().await?).await?;
    }
    report.sequence = 1;
    assert_eq!(
        peer.post(&url).json(&report).send().await?.status(),
        409,
        "history pruning cannot reset sequence high-water"
    );
    let history = format!("{base}/admin/devices/{}/reports", registration.device);
    let page: serde_json::Value = material::success(
        client
            .get(&history)
            .bearer_auth(token)
            .query(&[("limit", "1")])
            .send()
            .await?,
    )
    .await?;
    assert_eq!(page["items"][0]["receipt"]["sequence"], 4);
    assert_eq!(
        page["items"][0]["stale"], false,
        "device observedAt does not determine freshness"
    );
    let cursor = page["nextCursor"].as_str().unwrap();
    let next: serde_json::Value = material::success(
        client
            .get(&history)
            .bearer_auth(token)
            .query(&[("limit", "1"), ("cursor", cursor)])
            .send()
            .await?,
    )
    .await?;
    assert_eq!(next["items"][0]["receipt"]["sequence"], 3);
    assert!(next["nextCursor"].is_null());
    assert_eq!(
        client
            .get(&history)
            .bearer_auth(token)
            .query(&[("kind", "application"), ("limit", "1"), ("cursor", cursor)])
            .send()
            .await?
            .status(),
        409
    );
    assert_eq!(
        client
            .get(&history)
            .bearer_auth(token)
            .query(&[("limit", "101")])
            .send()
            .await?
            .status(),
        400
    );
    assert_eq!(
        client
            .get(&history)
            .bearer_auth(token)
            .query(&[("limit", "1"), ("limit", "2")])
            .send()
            .await?
            .status(),
        400
    );
    // A retained offline snapshot is stale by the original server receipt time.
    sqlx::query("UPDATE rss_da.report_heads SET receipt=jsonb_set(receipt,'{receivedAt}',to_jsonb($1::bigint)) WHERE tenant_id=$2::uuid AND registration=$3 AND kind='status'").bind(now()-901).bind(c.tenant.to_string()).bind(registration.registration).execute(&c.operator).await?;
    let stale: serde_json::Value = material::success(
        client
            .get(format!(
                "{base}/admin/devices/{}/status",
                registration.device
            ))
            .bearer_auth(token)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(stale["stale"], true);
    let limited = material::device_administrator(c, &registration.device).await?;
    assert_eq!(
        client
            .get(&history)
            .bearer_auth(limited)
            .send()
            .await?
            .status(),
        403,
        "configuration write does not grant report read"
    );
    let current: serde_json::Value =
        material::success(peer.get(format!("{base}/configuration")).send().await?).await?;
    assert_eq!(current["state"], "present");
    // The fixed per-tenant host budget is shared across status and application reports.
    for sequence in 5..=9 {
        report.sequence = sequence;
        material::success::<serde_json::Value>(peer.post(&url).json(&report).send().await?).await?;
    }
    report.sequence = 10;
    assert_eq!(peer.post(&url).json(&report).send().await?.status(), 429);
    Ok(())
}
