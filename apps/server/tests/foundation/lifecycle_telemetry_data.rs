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
    Box::pin(AuthorityContext::connect(
        "installed",
        inputs,
        operator,
        tenant,
        &config.audit,
    ))
    .await
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
        let c = Box::pin(device_context(&config, primary, dir, tenant)).await?;
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
    async fn aggregate(&self, browser: &mut Browser, after: Option<&str>) -> Result<(u16, Value)> {
        let mut query = self.history.clone();
        let start = self.input.observations[0].observed_at;
        query["startMicros"] = json!(start.to_string());
        query["endMicros"] = json!((start + 2).to_string());
        if let Some(cursor) = after {
            query["after"] = json!(cursor);
        }
        let request = json!({"query":query,"definitionVersion":"1","source":"agent.script","epoch":self.input.configuration().source_epoch,
            "dimensions":{},"resolutionMicros":"1","operation":"mean","coverage":{"coverage":"observedOnly"},"maxGapMicros":null});
        browser
            .call(
                Method::POST,
                &format!(
                    "/api/v1/tenants/{}/telemetry/aggregate",
                    self.principal.tenant()
                ),
                Some(request),
                None,
            )
            .await
    }

    pub(super) async fn aggregate_pages(&self, browser: &mut Browser) -> Result<String> {
        let (status, first) = self.aggregate(browser, None).await?;
        ensure!(
            status == 200 && first["buckets"].as_array().is_some_and(|b| b.len() == 1),
            "first aggregate page {status}: {first}"
        );
        let cursor = first["next"].as_str().context("aggregate continuation")?;
        let (status, second) = self.aggregate(browser, Some(cursor)).await?;
        ensure!(
            status == 200
                && second["next"].is_null()
                && second["buckets"].as_array().is_some_and(|b| b.len() == 1)
                && first["buckets"][0]["window"] != second["buckets"][0]["window"],
            "second aggregate page {status}: {second}"
        );
        let mut latest = self.history.clone();
        latest["mode"] = json!("latest");
        let (status, body) = browser
            .call(
                Method::POST,
                &format!(
                    "/api/v1/tenants/{}/telemetry/history",
                    self.principal.tenant()
                ),
                Some(latest),
                None,
            )
            .await?;
        ensure!(
            status == 200 && body["rows"].as_array().is_some_and(|r| !r.is_empty()),
            "latest {status}: {body}"
        );
        Ok(cursor.to_owned())
    }

    pub(super) async fn verify_snapshot(
        &self,
        browser: &mut Browser,
        root: &Path,
        ch: &Value,
    ) -> Result<()> {
        use rss_timeseries::{
            Authorized, Batch, Id, Interval, Maintainer, MaintenanceAction, MaintenanceBudget,
            MaintenanceRequest, Outcome, ReceiptQuery, Sample, SampleInput, Selection, Stream,
            Timestamp, Writer,
        };
        use rss_timeseries_clickhouse::{Credentials, CursorKey, ProjectionProgress};
        let cursor = self.aggregate_pages(browser).await?;
        let (_, baseline) = self.aggregate(browser, Some(&cursor)).await?;
        let tenant = self.principal.tenant();
        let id = Uuid::parse_str(&tenant.to_string())?;
        let original: Sample = serde_json::from_str(&recovery::admin_sql(ch, &format!(
            "SELECT payload FROM rss_ts_ch.raw WHERE tenant='{id}' AND generation='{}' AND observed_at={} LIMIT 1 FORMAT TabSeparatedRaw",
            self.input.configuration().source_epoch, self.input.observations[0].observed_at)).await?)?;
        let config: crate::telemetry::Config = serde_json::from_value(ch["configuration"].clone())?;
        let rss_mdm_telemetry_service::backend::Backend::ClickHouse(owner) =
            config.open_backend().await?
        else {
            anyhow::bail!("expected ClickHouse")
        };
        let cutoff = || {
            rss_request_context::Deadline::from_timeout(
                &rss_mdm_telemetry_service::backend::SystemClock,
                Duration::from_secs(10),
            )
        };
        let reader = Credentials::new(
            recovery::reader(ch, id)?,
            crate::config::secret(&root.join("a-password"))?.to_string(),
        )?;
        let store = owner
            .bind_tenant(
                tenant,
                reader,
                CursorKey::new([3; 32]),
                std::num::NonZeroU64::MIN,
                cutoff()?,
            )
            .await?;
        let scope = original.input().stream.scope().clone();
        let authority = ScopeAuthority(scope.clone());
        let new_batch = |name: &str| -> Result<_> {
            let mut input: SampleInput = original.clone().into();
            input.stream =
                Stream::new(scope.clone(), Id::new(name)?, Id::new("sample-generation")?);
            input.id = Id::new(name)?;
            let batch = Batch::new(
                input.stream.clone(),
                Id::new(name)?,
                vec![Sample::new(input)?],
            )?;
            let identity = ReceiptQuery {
                stream: batch.stream().clone(),
                batch_id: batch.id().clone(),
                digest: batch.digest()?,
            };
            Ok((
                Authorized::<Batch>::verify(&authority, batch)?,
                Authorized::<ReceiptQuery>::verify(&authority, identity)?,
            ))
        };
        let (first, first_id) = new_batch("pending-other-stream")?;
        let (second, second_id) = new_batch("following-other-stream")?;
        recovery::admin_sql(ch, "REVOKE INSERT ON rss_ts_ch.raw FROM metric_writer").await?;
        let interrupted = store.write(&first, cutoff()?).await;
        recovery::admin_sql(ch, "GRANT INSERT ON rss_ts_ch.raw TO metric_writer").await?;
        ensure!(!matches!(
            interrupted,
            Ok(Outcome::Accepted(_) | Outcome::Replay(_))
        ));
        ensure!(matches!(
            store.progress(&first_id, cutoff()?).await?,
            ProjectionProgress::Prepared
        ));
        ensure!(matches!(
            store.write(&second, cutoff()?).await,
            Err(rss_timeseries::Error::Unavailable)
        ));
        ensure!(matches!(
            store.progress(&second_id, cutoff()?).await?,
            ProjectionProgress::NotVisible
        ));
        let recovered = store.recover(&scope, &authority, cutoff()?).await?;
        ensure!(
            matches!(recovered, Outcome::Accepted(Some(ref r)) | Outcome::Replay(Some(ref r)) if r.identity().batch_id == first_id.request().batch_id)
        );
        ensure!(matches!(
            store.write(&second, cutoff()?).await?,
            Outcome::Accepted(_)
        ));
        ensure!(matches!(
            store.progress(&second_id, cutoff()?).await?,
            ProjectionProgress::Published
        ));
        let (status, continued) = self.aggregate(browser, Some(&cursor)).await?;
        ensure!(
            status == 200 && continued["buckets"] == baseline["buckets"],
            "unrelated stream changed continuation"
        );
        let series = original.input().series.clone();
        let start = self.input.observations[0].observed_at;
        let delete = MaintenanceRequest::new(
            Id::new("snapshot-test-delete")?,
            MaintenanceAction::Delete {
                selection: Selection::Exact {
                    stream: original.input().stream.clone(),
                    series,
                },
                window: Interval::new(Timestamp::new(start)?, Timestamp::new(start + 2)?)?,
                restore_until: Timestamp::new(i64::MAX - 1)?,
            },
            MaintenanceBudget {
                rows: std::num::NonZeroU32::MIN,
                buckets: std::num::NonZeroU32::MIN,
            },
        )?;
        let step = store
            .step(
                &Authorized::<MaintenanceRequest>::verify(&authority, delete)?,
                None,
                cutoff()?,
            )
            .await?;
        ensure!(matches!(step, Outcome::Accepted(_) | Outcome::Replay(_)));
        let (status, changed) = self.aggregate(browser, Some(&cursor)).await?;
        ensure!(
            status == 409 && changed["code"] == "query_cursor_invalidated",
            "changed aggregate {status}: {changed}"
        );
        let mut history = self.history.clone();
        history["after"] = json!(self.cursor);
        let (status, lost) = browser
            .call(
                Method::POST,
                &format!("/api/v1/tenants/{tenant}/telemetry/history"),
                Some(history),
                None,
            )
            .await?;
        ensure!(
            status == 409 && lost["code"] == "query_result_unavailable",
            "expired history {status}: {lost}"
        );
        owner.close(cutoff()?).await?;
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
        let (status, body) = browser
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
            status == 400 && body["code"] == "malformed_request",
            "foreign continuation {status} {body}"
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

struct ScopeAuthority(rss_timeseries::Scope);
impl rss_timeseries::Authority for ScopeAuthority {
    fn authorize(
        &self,
        access: rss_timeseries::Access<'_>,
    ) -> std::result::Result<(), rss_timeseries::Error> {
        use rss_timeseries::Access;
        let scope = match access {
            Access::Write(batch) => batch.stream().scope(),
            Access::Receipt(query) => query.stream.scope(),
            Access::Maintain(request) => request.scope(),
            _ => return Err(rss_timeseries::Error::Unauthorized),
        };
        if scope == &self.0 {
            Ok(())
        } else {
            Err(rss_timeseries::Error::Unauthorized)
        }
    }
}
