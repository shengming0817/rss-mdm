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
    let management = c.management_base();
    let identity = da::ReportIdentity {
        service_id: registration.service_id,
        tenant: registration.tenant,
        device_id: registration.device,
    };
    let mut report = da::StatusReport {
        identity: identity.clone(),
        sequence: 1,
        observed_at: Some(0),
        client_version: "foundation".into(),
        modules: da::ClientModules {
            da: da::ModuleObservation {
                installed: Some(true),
                enabled: Some(true),
            },
            mdm: da::ModuleObservation {
                installed: None,
                enabled: Some(false),
            },
            application: da::ModuleApplication::Pending,
        },
        contract_version: 1,
        binding: da::Health::Ready,
        factor: da::Health::Ready,
        health: da::Health::Ready,
        configuration_digest: Some(signed.digest.clone()),
        errors: vec![],
    };
    let url = format!("{base}/status-reports");
    assert_eq!(client.post(&url).json(&report).send().await?.status(), 401);
    // Keep the first report durable on the DA side while the Observation owner is busy.
    let mut gate = c.operator.begin().await?;
    sqlx::query("LOCK TABLE rss_observation.objects IN SHARE MODE")
        .execute(&mut *gate)
        .await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_report_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'lost DA acknowledgement'; END $$; CREATE TRIGGER reject_report_ack BEFORE UPDATE OF delivery_pending ON rss_da.report_history FOR EACH ROW WHEN (OLD.delivery_pending AND NOT NEW.delivery_pending) EXECUTE FUNCTION public.reject_report_ack()").execute(&c.operator).await?;
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
    report.identity.device_id = rss_mdm_agent_wire::DeviceId::new_v4();
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
                "{management}/admin/devices/{}/configuration",
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
    report.client_version = "\\".repeat(128);
    report.errors = vec![da::Diagnostic::InvalidConfiguration; 16];
    report.observed_at = Some(i64::MAX);
    let second: serde_json::Value =
        material::success(peer.post(&url).json(&report).send().await?).await?;
    let retry: serde_json::Value =
        material::success(peer.post(&url).json(&report).send().await?).await?;
    assert_eq!(retry, second);
    report.sequence = 3;
    assert_eq!(peer.post(&url).json(&report).send().await?.status(), 429);
    gate.rollback().await?;
    tokio::time::timeout(Duration::from_secs(20),async{
        loop{
            let count:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.report_history WHERE tenant_id=$1 AND delivery_pending),(SELECT count(*) FROM rss_observation.batches WHERE tenant_id=$1)").bind(Uuid::parse_str(&c.tenant.to_string())?).fetch_one(&c.operator).await?;
            if count==(3,1){return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await??;
    sqlx::raw_sql("DROP TRIGGER reject_report_ack ON rss_da.report_history; DROP FUNCTION public.reject_report_ack()").execute(&c.operator).await?;
    tokio::time::timeout(Duration::from_secs(20),async{
        loop{
            let remaining:i64=sqlx::query_scalar("SELECT count(*) FROM rss_da.report_history WHERE tenant_id=$1::uuid AND delivery_pending").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
            if remaining==0{return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await??;
    let received: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_observation.batches WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&c.operator)
            .await?;
    assert_eq!(received, 3);
    for sequence in 3..=4 {
        report.sequence = sequence;
        material::success::<serde_json::Value>(peer.post(&url).json(&report).send().await?).await?;
    }
    report.sequence = 1;
    assert_eq!(
        peer.post(&url).json(&report).send().await?.status(),
        409,
        "history pruning cannot reset sequence high-water"
    );
    let history = format!("{management}/admin/devices/{}/reports", registration.device);
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
    let invalidated = client
        .get(&history)
        .bearer_auth(token)
        .query(&[("kind", "application"), ("limit", "1"), ("cursor", cursor)])
        .send()
        .await?;
    assert_eq!(invalidated.status(), 409);
    assert_eq!(
        invalidated.json::<serde_json::Value>().await?["code"],
        "query_cursor_invalidated"
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
    sqlx::query("UPDATE rss_da.report_heads SET receipt = jsonb_set(receipt, '{receivedAt}', to_jsonb(CAST($1 AS bigint))) WHERE tenant_id = CAST($2 AS uuid) AND device = $3 AND kind = 'status'").bind(now()-901).bind(c.tenant.to_string()).bind(registration.device.into_uuid()).execute(&c.operator).await?;
    let stale: serde_json::Value = material::success(
        client
            .get(format!(
                "{management}/admin/devices/{}/status",
                registration.device
            ))
            .bearer_auth(token)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(stale["stale"], true);
    assert_eq!(
        stale["report"]["modules"],
        serde_json::to_value(report.modules)?
    );
    assert_eq!(
        stale["report"]["observedAt"],
        serde_json::json!(report.observed_at)
    );
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
    let assets_url = format!(
        "{management}/admin/devices/{}/inventory",
        registration.device
    );
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let facts: Vec<serde_json::Value> =
                material::success(client.get(&assets_url).bearer_auth(token).send().await?).await?;
            if facts.len() == 2
                && facts
                    .iter()
                    .any(|asset| asset["kind"] == "status" && asset["sequence"] == 4)
            {
                anyhow::ensure!(facts.iter().all(|asset| asset["evidence"] == "reported"
                    && asset["position"].as_i64().is_some_and(|v| v > 0)));
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    // Establish the current database window explicitly; exercise both streams, and only
    // rebuild this prerequisite if the server clock actually crosses a minute boundary.
    let mut application = application;
    report.sequence = 5;
    for attempt in 0..3 {
        let minute: i64 = sqlx::query_scalar("UPDATE rss_da.report_budget SET minute=floor(extract(epoch FROM clock_timestamp()))::bigint/60,reports=9,bytes=0 WHERE tenant_id=$1::uuid RETURNING minute")
            .bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
        application.sequence += 1;
        application.operation_id = Uuid::new_v4();
        let accepted: serde_json::Value = material::success(
            peer.post(format!("{base}/configuration-reports"))
                .json(&application)
                .send()
                .await?,
        )
        .await?;
        let response = peer.post(&url).json(&report).send().await?;
        if response.status() == 429 && accepted["receivedAt"].as_i64().unwrap() / 60 == minute {
            return Ok(());
        }
        let current: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint/60")
                .fetch_one(&c.operator)
                .await?;
        anyhow::ensure!(
            current != minute && attempt < 2,
            "quota must reject inside the same window: {}",
            response.status()
        );
        if response.status().is_success() {
            report.sequence += 1;
        } else {
            anyhow::ensure!(response.status() == 429, "unexpected budget response");
        }
    }
    unreachable!("bounded quota proof exits with a result")
}
