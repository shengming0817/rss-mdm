//! Live product intake and relay with an already enrolled device and issued policy version.
use super::*;
use crate::{
    authority_t2_support::{Context as AuthorityContext, Inputs},
    device_material_support as device,
};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_telemetry_service::Service;
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};

pub(super) struct Upload {
    principal: rss_mdm_registration_service::DevicePrincipal,
    input: wire::TelemetryUpload,
    history: Value,
    cursor: String,
    sample: i64,
}

async fn device_context(
    config: &crate::config::Config,
    primary: &crate::config::Database,
    dir: &Path,
    tenant: TenantId,
) -> Result<AuthorityContext> {
    let inputs = Inputs {
        installation: crate::migration::Installation {
            instance_id: config.identity.instance_id.clone(),
            target: config.storage_binding.target,
            lineage: config.storage_binding.lineage,
            audit_mode: config.audit.mode(),
        },
        databases: [(
            "installed".into(),
            [
                ("postgres".into(), primary.clone()),
                ("mdm_access".into(), config.access_database.clone()),
                (
                    "mdm_identity_runtime".into(),
                    config.identity.database.clone(),
                ),
            ]
            .into(),
        )]
        .into(),
        directory: dir.to_owned(),
    };
    let operator = inputs.pool("installed", "postgres").await?;
    AuthorityContext::connect("installed", inputs, operator, tenant, &config.audit).await
}

async fn issued(
    c: &AuthorityContext,
    config: &crate::config::Config,
    principal: &rss_mdm_registration_service::DevicePrincipal,
    value: i64,
) -> Result<(wire::TelemetryUpload, Value)> {
    use rss_mdm_inventory as inv;
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../crates/agent-wire/tests/fixtures/telemetry-v1-vectors.json"
    ))?;
    let mut original = vector["signed"]["configuration"].clone();
    original["fields"][0]["timeSeries"]["retention"]["key"] = json!("shared_metrics");
    original["fields"][0]["platforms"] = json!(["windows"]);
    let field: inv::FieldDefinition = serde_json::from_value(original["fields"][0].clone())?;
    let profile: rss_mdm_resource::TelemetryProfile = serde_json::from_value(
        json!({"template":{"resource":"metric-script","version":"v1","variant":"default","platform":"windows","architecture":"x86_64"},"parameters":{},"fields":[{"key":field.key,"version":1}],"projection":"history","sampleMillis":5000,"uploadMillis":10000,"budget":{"points":64,"bytes":65536,"resources":1,"executionMillis":1000,"outputBytes":4096},"boost":null,"backfillSeconds":3600}),
    )?;
    let script = serde_json::from_value(
        json!({"profile":rss_mdm_resource::ScriptProfile::PowerShell7,"sql":null,"runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":original["collector"]["outputSchema"],"purpose":{"kind":"collection","scope":{"kind":"device"},"applicability":{"minimumOsVersion":null,"minimumBuild":null,"editions":[],"enrollments":[],"tools":{},"capabilities":[]},"mappings":original["collector"]["mappings"]},"timeoutSeconds":1,"outputBytes":4096,"maxRows":1}),
    )?;
    let epoch = Uuid::new_v4();
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let protection = config.native_protector()?;
    let trust = device::seed_trust(
        c,
        &protection,
        &[rss_mdm_agent_wire::task_trust::KeyState::Active],
    )
    .await?;
    device::seed_ack(c, &trust, principal.device()).await?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    original["tenantId"] = json!(c.tenant.to_string());
    original["deviceId"] = json!(principal.device());
    original["policy"] = json!(policy);
    original["policyVersion"] = json!(version);
    original["sourceEpoch"] = json!(epoch);
    original["issuedAt"] = json!(now - 10);
    original["expiresAt"] = json!(now + 280);
    original["binding"] = json!(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            c.tenant.to_string(),
            principal.device(),
            "agent.script",
            epoch,
            policy,
            version,
            &profile
        ))?)
    ));
    let wire: wire::TelemetryConfiguration = serde_json::from_value(original)?;
    let frozen = rss_mdm_policy_service::telemetry::FrozenProfile {
        resource_digest: wire.resource_digest,
        profile,
        fields: vec![field.clone()],
        source: inv::Source::AgentScript,
        collector: rss_mdm_policy_service::telemetry::FrozenCollector::Script {
            definition: script,
            reference: "fixture.ps1".into(),
            length: 4,
            digest: [7; 32],
        },
    };
    let frozen = serde_json::to_value(frozen)?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    ensure!(
        rss_mdm_inventory_postgres::publish_retention_policy_in(
            &mut tx,
            c.tenant,
            &inv::RetentionPolicy {
                key: "shared_metrics".into(),
                revision: 1,
                raw_seconds: 86400,
                summary_seconds: 86400,
                restore_seconds: 0
            }
        )
        .await?
    );
    ensure!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &field).await?);
    sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,device,source,epoch,next_sequence,enabled) VALUES($1::uuid,$2,'agent.script',$3,0,true)").bind(c.tenant.to_string()).bind(principal.device().into_uuid()).bind(epoch).execute(&mut *tx).await?;
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":Uuid::new_v4(),"action":{"kind":"telemetry_profile","resource":{"id":"profile","version":"v1","variant":"default","platform":"windows","architecture":"x86_64"}}}),
    )?;
    definition.validate()?;
    let author = rss_mdm_authorization_service::Actor::Account {
        user: c.user(Uuid::new_v4()),
    };
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'archived',$4,$5,$6)").bind(c.tenant.to_string()).bind(policy).bind(version).bind(serde_json::to_value(definition)?).bind(serde_json::to_value(author)?).bind(now).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,resource,resource_version,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,'telemetry_profile','profile','v1',$4,$5)").bind(c.tenant.to_string()).bind(version).bind(policy).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).execute(&mut *tx).await?;
    let signing = rss_mdm_task_trust::Signing::new(
        rss_mdm_install_support::StorageProfile::Mdm,
        rss_mdm_task_trust::Use::AgentTask,
        protection,
    )?;
    let signed = signing.sign_telemetry_on(&mut tx, principal, wire).await?;
    tx.commit().await?;
    let first = (now - 1) * 1_000_000;
    let mut points = Vec::new();
    for sequence in 1..=2 {
        points.push(wire::TelemetryObservation {
            id: Uuid::new_v4(),
            sequence,
            observed_at: first + sequence as i64,
            values: [(
                wire::FieldKey::parse("custom.load")?,
                wire::TelemetryReading::Valid {
                    value: wire::Scalar::Integer(value + sequence as i64 - 1),
                    interval_start: None,
                },
            )]
            .into(),
        });
    }
    let query = json!({"device":principal.device(),"field":"custom.load","resource":"device","startMicros":first.to_string(),"endMicros":(first+10).to_string(),"maxPoints":1,"mode":"history"});
    Ok((
        wire::TelemetryUpload {
            configuration: signed,
            batch_id: Uuid::new_v4(),
            observations: points,
        },
        query,
    ))
}
async fn page(
    browser: &mut Browser,
    tenant: TenantId,
    query: &Value,
    expected: i64,
) -> Result<Value> {
    let (status, page) = browser
        .call(
            Method::POST,
            &format!("/api/v1/tenants/{tenant}/telemetry/history"),
            Some(query.clone()),
            None,
        )
        .await?;
    ensure!(
        status == 200 && page["rows"].as_array().is_some_and(|r| r.len() == 1),
        "tenant history: {status} {page}"
    );
    ensure!(
        page["rows"][0]["sample"]["reading"]["value"]["value"]["value"].as_str()
            == Some(expected.to_string().as_str()),
        "tenant-specific value"
    );
    Ok(page)
}
impl Upload {
    pub(super) async fn publish(
        running: &maintenance::Running,
        browser: &mut Browser,
        tenant: Uuid,
        primary: &crate::config::Database,
        runtime: &Value,
        dir: &Path,
        sample: i64,
    ) -> Result<Self> {
        let service = running.telemetry.get().context("live telemetry ingress")?;
        let config: crate::config::Config = serde_json::from_value(runtime.clone())?;
        let tenant = TenantId::parse(&tenant.to_string())?;
        let c = device_context(&config, primary, dir, tenant).await?;
        let (registration, grant) = device::seed_registration(&c).await?;
        let principal = device::authenticated_agent(
            &c,
            grant,
            &registration,
            vec![
                wire::Capability::InventoryCollectionV1,
                wire::Capability::TelemetryCollectV1,
            ],
        )
        .await?;
        let (input, history) = issued(&c, &config, &principal, sample)
            .await
            .context("issue signed historical configuration")?;
        let request = crate::authority_t2_support::telemetry_intake(principal.binding());
        c.close().await;
        let accepted = service
            .receive(
                &principal,
                &input,
                serde_json::to_vec(&input)?.len(),
                request,
            )
            .await
            .context("admit device upload")?;
        ensure!(!accepted.replayed);
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                let receipt = service.status(&principal, input.batch_id).await?;
                if matches!(receipt.delivery, wire::TelemetryDelivery::Published) {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        })
        .await
        .context("await product relay delivery")??;
        let first = page(browser, tenant, &history, sample).await?;
        let cursor = first["next"]
            .as_str()
            .context("history continuation")?
            .to_owned();
        Ok(Self {
            principal,
            input,
            history,
            cursor,
            sample,
        })
    }
    pub(super) async fn more(&self, service: &Arc<Service>, offset: u64) -> Result<Uuid> {
        let mut upload = self.input.clone();
        upload.batch_id = Uuid::new_v4();
        for point in &mut upload.observations {
            point.id = Uuid::new_v4();
            point.sequence += offset;
            point.observed_at += 100 * offset as i64;
        }
        let receipt = service
            .receive(
                &self.principal,
                &upload,
                serde_json::to_vec(&upload)?.len(),
                crate::authority_t2_support::telemetry_intake(self.principal.binding()),
            )
            .await?;
        ensure!(!receipt.replayed && matches!(receipt.delivery, wire::TelemetryDelivery::Pending));
        Ok(upload.batch_id)
    }
    pub(super) async fn wait_for_worker_exit(&self, service: &Arc<Service>) -> Result<()> {
        let cutoff = rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            + Duration::from_secs(10);
        tokio::time::timeout_at(cutoff.into(), async {
            while service
                .diagnostics(self.principal.binding(), cutoff)
                .await?
                .running
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("telemetry worker must finish while the HTTP admission permit remains held")??;
        Ok(())
    }
    pub(super) async fn published(&self, service: &Arc<Service>, id: Uuid) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(70), async {
            loop {
                if matches!(
                    service.status(&self.principal, id).await?.delivery,
                    wire::TelemetryDelivery::Published
                ) {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .context("original accepted batch completes during reader rotation")??;
        Ok(())
    }
    pub(super) async fn original_receipt(&self, service: &Arc<Service>) -> Result<()> {
        let receipt = service
            .receive(
                &self.principal,
                &self.input,
                serde_json::to_vec(&self.input)?.len(),
                crate::authority_t2_support::telemetry_intake(self.principal.binding()),
            )
            .await?;
        ensure!(receipt.replayed && matches!(receipt.delivery, wire::TelemetryDelivery::Published));
        Ok(())
    }
    pub(super) async fn reject_foreign_cursor(
        &self,
        browser: &mut Browser,
        other: &Self,
    ) -> Result<()> {
        let mut query = self.history.clone();
        query["after"] = json!(other.cursor);
        let (status, _) = browser
            .call(
                Method::POST,
                &format!(
                    "/api/v1/tenants/{}/telemetry/history",
                    self.principal.tenant()
                ),
                Some(query),
                None,
            )
            .await?;
        ensure!(
            matches!(status, 400 | 403 | 409),
            "foreign continuation {status}"
        );
        Ok(())
    }
    pub(super) async fn replay(&self, service: &Arc<Service>, browser: &mut Browser) -> Result<()> {
        let replay = service
            .receive(
                &self.principal,
                &self.input,
                serde_json::to_vec(&self.input)?.len(),
                crate::authority_t2_support::telemetry_intake(self.principal.binding()),
            )
            .await?;
        ensure!(replay.replayed && matches!(replay.delivery, wire::TelemetryDelivery::Published));
        let mut query = self.history.clone();
        query["after"] = json!(self.cursor);
        let next = page(browser, self.principal.tenant(), &query, self.sample + 1).await?;
        ensure!(next["next"].is_null(), "exactly two original samples");
        Ok(())
    }
}
