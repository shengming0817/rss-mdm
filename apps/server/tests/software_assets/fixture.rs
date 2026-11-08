use super::*;
use rss_mdm_inventory_service::{assets as a, inventory_runtime as rt};
pub(super) struct Fixture {
    pub assets: Arc<a::AssetService>,
}
impl Fixture {
    pub async fn open(c: &Context) -> Result<Self> {
        let clock = rt::Clock::new(crate::clock::monotonic());
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_projection::Control::new(&clock, clock.cutoff(), &cancel);
        let observation = rt::ObservationResource::open(
            c.inputs.database("shared", "mdm_runtime").options()?,
            clock.clone(),
        )
        .await?;
        let projection = rt::ProjectionResource::open(
            c.inputs.database("shared", "mdm_runtime").options()?,
            clock.clone(),
            &control,
        )
        .await?;
        let inventory = Arc::new(rt::InventoryRuntime::new(
            observation.store.clone(),
            projection.store.clone(),
            c.database.inventory(),
            c.audit.clone(),
            c.tenant,
            clock,
            Arc::new(rt::Readiness::default()),
        ));
        let owner = planning::owner(c, "mdm_inventory_runtime").await?;
        let groups = rss_mdm_group_postgres::GroupStore::new(
            owner.runtime.clone(),
            c.tenant,
            rss_mdm_inventory_service::transaction::deadline(),
        )
        .await?;
        let messaging = rss_reconcile_postgres::PgMessagingStore::new(
            owner.runtime.clone(),
            c.tenant,
            rss_mdm_inventory_service::transaction::deadline(),
        )
        .await?;
        let tenant = c.tenant;
        owner
            .runtime
            .local_tx(
                c.tenant,
                rss_mdm_inventory_service::transaction::deadline(),
                |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |connection| {
                            Box::pin(async move {
                                rss_mdm_inventory_service::admit_storage_in(
                                    rss_mdm_install_support::StorageProfile::Mdm,
                                    connection,
                                    tenant,
                                )
                                .await
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                |_| Ok(()),
                |e| Err(anyhow::anyhow!("{e:?}")),
                |e| Err(anyhow::anyhow!("{e:?}")),
                |_| Err(anyhow::anyhow!("unknown")),
                |_| Err(anyhow::anyhow!("unknown")),
                |e| Err(anyhow::anyhow!("{e:?}")),
            )?;
        Ok(Self {
            assets: Arc::new(a::AssetService::new(a::AssetDependencies {
                inventory,
                audit_store: owner.audit,
                runtime: owner.runtime,
                tenant: c.tenant,
                clock: Arc::new(crate::clock::SystemClock),
                cursor_key: vec![7; 32],
                reconcile_messaging: messaging,
                software_sources: s::Sources {
                    objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
                    groups: groups.source_reader(),
                },
            })),
        })
    }
    pub async fn settle(&self, c: &Context, task: Uuid) -> Result<()> {
        anyhow::ensure!(self.work(c, task, 256).await?, "query did not finish");
        Ok(())
    }
    pub async fn work(&self, c: &Context, task: Uuid, steps: usize) -> Result<bool> {
        use rss_reconcile::{DurableStore, ReconcileStep, Reconciler};
        let timer = rss_mdm_device_service::control::recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control =
            rss_reconcile::Control::new(&timer, std::time::Duration::from_secs(60), &cancel);
        let pool = c.inputs.pool("shared", "mdm_scheduler_runtime").await?;
        let schedule = rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await?;
        let worker = a::runtime::QueryWork::new(self.assets.clone(), schedule.clone());
        let target = a::tasks::target(c.tenant, task);
        let mut batch = schedule
            .claim_due(
                target.scope(),
                64,
                std::time::Duration::from_secs(90),
                &control,
            )
            .await?;
        let index = batch
            .claims
            .iter()
            .position(|claim| claim.target() == &target)
            .context("query claim")?;
        let claim = batch.claims.swap_remove(index);
        for _ in 0..steps {
            let ReconcileStep::Ready(diff) = worker.observe(&claim, &control).await? else {
                anyhow::bail!("query deferred")
            };
            if diff.drift() == rss_reconcile::DriftKind::Converged {
                schedule
                    .finish(&claim, rss_reconcile::Completion::Converged, &control)
                    .await?;
                for other in &batch.claims {
                    schedule.release(other, &control).await?;
                }
                return Ok(true);
            }
            worker.apply(&claim, diff, &control).await?;
        }
        schedule.release(&claim, &control).await?;
        for other in &batch.claims {
            schedule.release(other, &control).await?;
        }
        Ok(false)
    }
}
pub(super) struct Http {
    base: String,
    task: tokio::task::JoinHandle<()>,
    client: reqwest::Client,
}
impl Http {
    pub async fn open(
        c: &Context,
        fixture: &Fixture,
        proof: Arc<rss_mdm_authorization_service::context::AuthorizedPrincipal>,
    ) -> Result<Self> {
        let tenant = c.tenant.to_string();
        let access = c.access();
        let sessions = rss_mdm_authorization_service::session::SessionAuthority::new(
            c.authority.clone(),
            c.tenant,
        );
        let router = rss_mdm_management_http::assets::routes()
            .into_axum()
            .with_state(Arc::new(rss_mdm_management_http::assets::http::HttpState {
                assets: fixture.assets.clone(),
            }))
            .layer(axum::middleware::from_fn(
                move |mut request: axum::extract::Request, next: axum::middleware::Next| {
                    let proof = proof.clone();
                    let tenant = tenant.clone();
                    let auth = rss_mdm_authorization_service::context::RequestAuth {
                        proof: proof.clone(),
                        sessions: sessions.clone(),
                        deadline: access.now() + std::time::Duration::from_secs(8),
                    };
                    async move {
                        let audit = rss_mdm_audit_integration::RequestAudit::new(
                            rss_mdm_audit_integration::Origin::Request,
                            rss_mdm_install_support::StorageProfile::Mdm,
                            tenant,
                            "software-assets-t2",
                            rss_mdm_audit_integration::AuditIntent::Management,
                        );
                        proof.bind_audit(&audit).unwrap();
                        request.extensions_mut().insert(audit);
                        request.extensions_mut().insert(auth);
                        next.run(request).await
                    }
                },
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Ok(Self {
            base,
            task,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()?,
        })
    }
    pub async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        input: Option<Value>,
    ) -> Result<(u16, Value)> {
        let mut request = self.client.request(method, format!("{}{path}", self.base));
        if let Some(value) = input {
            request = request.json(&value);
        }
        let response = request.send().await?;
        let status = response.status().as_u16();
        let value = response.json().await?;
        Ok((status, value))
    }
    pub async fn get(&self, path: &str) -> Result<Value> {
        let (status, value) = self.call(reqwest::Method::GET, path, None).await?;
        anyhow::ensure!(status == 200, "GET {path}: {status} {value}");
        Ok(value)
    }
    pub async fn close(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}
pub(super) fn installation(id: &str, version: &str) -> Scalar {
    Scalar::Object(
        [
            ("id", id),
            ("native_id", id),
            ("name", "Editor"),
            ("version", version),
            ("publisher", "Acme"),
            ("scope", "device"),
            ("owner", ""),
            ("origin", "win32.uninstall.64"),
            ("location", ""),
            ("installation_state", "installed"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), Scalar::String(v.into())))
        .collect(),
    )
}
pub(super) async fn definitions(c: &Context) -> Result<rss_mdm_inventory::CollectionDefinition> {
    definitions_for(c, &[s::SoftwareSource::Installations]).await
}
pub(super) async fn definitions_for(
    c: &Context,
    software: &[s::SoftwareSource],
) -> Result<rss_mdm_inventory::CollectionDefinition> {
    use rss_mdm_inventory::*;
    let fields: Vec<_> = builtin::fields()
        .into_iter()
        .filter(|f| {
            f.key.as_str() == "device.os.name"
                || software.iter().any(|s| s.field() == f.key.as_str())
        })
        .collect();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    for field in &fields {
        anyhow::ensure!(
            rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, field).await?
        );
    }
    let definition = CollectionDefinition::new(
        "software-assets",
        1,
        Source::MdmWindows,
        fields
            .into_iter()
            .map(|definition| CollectionField {
                definition,
                scope: CollectionScope::Device,
            })
            .collect(),
    )?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, c.tenant, &definition).await?;
    tx.commit().await?;
    Ok(definition)
}
/// Legal persisted source input; tests exercise the production array verifier and asset readers.
pub(super) async fn facts(
    c: &Context,
    object: &rss_mdm_inventory_service::objects::DeviceObject,
    definition: &rss_mdm_inventory::CollectionDefinition,
    items: Vec<Scalar>,
) -> Result<()> {
    facts_for(
        c,
        object,
        definition,
        s::SoftwareSource::Installations,
        items,
    )
    .await
}
pub(super) async fn facts_for(
    c: &Context,
    object: &rss_mdm_inventory_service::objects::DeviceObject,
    definition: &rss_mdm_inventory::CollectionDefinition,
    software: s::SoftwareSource,
    items: Vec<Scalar>,
) -> Result<()> {
    use rss_mdm_inventory::*;
    let registration = &object.members[0].device;
    let source = match object.members[0].channel {
        Channel::Mdm => ReportSource::MdmWindows,
        Channel::Agent => ReportSource::AgentBuiltin,
    };
    let definition = CollectionDefinition::new(
        "software-assets",
        1,
        if source == ReportSource::MdmWindows {
            Source::MdmWindows
        } else {
            Source::AgentBuiltin
        },
        definition.bindings().to_vec(),
    )?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    let epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND source = $3").bind(c.tenant.to_string()).bind(registration).bind(source.as_str()).fetch_one(&mut *tx).await?;
    let scope = rss_mdm_registration_service::device::scope_dataset(
        rss_mdm_install_support::StorageProfile::Mdm,
        c.tenant,
        registration,
        source.as_str(),
        epoch,
        "software-assets",
    )?;
    let (sequence, _) = rss_mdm_registration_service::device::store::allocate_report_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        &c.tenant.to_string(),
        &registration.to_string(),
        source,
        &epoch.to_string(),
        1,
        i64::from(u32::MAX),
    )
    .await?
    .context("sequence")?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, c.tenant, &definition).await?;
    let projection = rss_mdm_inventory_postgres::projection_scope(c.tenant);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    for (key, value) in [
        ("device.os.name", Scalar::String("Windows".into())),
        (software.field(), Scalar::Array(items)),
    ] {
        let field = builtin::fields()
            .into_iter()
            .find(|f| f.key.as_str() == key)
            .unwrap();
        let value = field.canonical_value(value)?;
        let (scalar, version) = if let Scalar::Array(items) = &value {
            let field_bytes = serde_json::to_vec(&field)?;
            let definition_digest = format!("{:x}", Sha256::digest(&field_bytes));
            let bytes = serde_json::to_vec(&value)?;
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let version = format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&(1, &definition_digest, &digest))?)
            );
            let added=sqlx::query("INSERT INTO mdm.array_versions(tenant_id,version,format,field,definition_digest,item_count,canonical_bytes,digest,definition) VALUES($1::uuid,$2,1,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING").bind(c.tenant.to_string()).bind(&version).bind(key).bind(definition_digest).bind(items.len() as i64).bind(bytes.len() as i64).bind(digest).bind(field_bytes).execute(&mut *tx).await?.rows_affected();
            if added > 0 {
                let mut prefix = 0;
                for (ordinal, item) in items.iter().enumerate() {
                    let bytes = serde_json::to_vec(item)?;
                    prefix += bytes.len() + usize::from(ordinal > 0);
                    sqlx::query("INSERT INTO mdm.array_items(tenant_id,version,ordinal,payload,digest,prefix_bytes) VALUES($1::uuid,$2,$3,$4,sha256($4),$5)").bind(c.tenant.to_string()).bind(&version).bind(ordinal as i64).bind(bytes).bind(prefix as i64).execute(&mut *tx).await?;
                }
            }
            (None, Some(version))
        } else {
            (Some(serde_json::to_string(&value)?), None)
        };
        sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,value_version,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence,field_scope) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,'known',$11,$15,$12,$13,$14) ON CONFLICT(tenant_id,journal,generation,scope,field,field_scope) DO UPDATE SET value=excluded.value,value_version=excluded.value_version,batch_id=excluded.batch_id,observed_at=excluded.observed_at,received_at=excluded.received_at,collection_sequence=excluded.collection_sequence,state='known'")
            .bind(c.tenant.to_string()).bind(projection.source().source()).bind(projection.generation()).bind(scope.encode()?).bind(serde_json::to_string(&definition.coverage()?)?).bind(key).bind(scalar).bind(version).bind(Uuid::new_v4().to_string()).bind(now).bind(registration.to_string()).bind(epoch.to_string()).bind(sequence).bind(CollectionScope::Device.canonical()?).bind(source.as_str()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub(super) async fn agent_endpoint(
    c: &Context,
) -> Result<rss_mdm_inventory_service::objects::DeviceObject> {
    use rss_mdm_inventory_service::objects::{DeviceObject, ObjectRef};
    use rss_mdm_registration_service::device::endpoints::PrimaryRegistration;
    let grant = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    let device = Uuid::new_v4().to_string();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_access.certificate_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,state,expires_at) VALUES($1::uuid,$2,$2,'download','software-fixture',$3,$4,'windows',repeat('0',64),repeat('1',64),'consumed',clock_timestamp()+interval '1 hour')")
        .bind(c.tenant.to_string()).bind(grant).bind(&c.inputs.installation.instance_id).bind(&device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.devices (tenant_id, id, channel, certificate_grant_id, state, purpose, epoch) VALUES (CAST($1 AS uuid), $2, 'agent', $3, 'active', 'primary', $4)")
        .bind(c.tenant.to_string()).bind(&device).bind(grant).bind(epoch).execute(&mut *tx).await?;
    let credential = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_access.credentials (tenant_id, id, device, channel, locator, state, purpose) VALUES (CAST($1 AS uuid), $2, $3, 'agent', $4, 'active', 'primary')")
        .bind(c.tenant.to_string()).bind(credential).bind(&device).bind(format!("{:x}",Sha256::digest(credential.as_bytes()))).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.report_sources (tenant_id, device, source, epoch, next_sequence, enabled) VALUES (CAST($1 AS uuid), $2, 'agent.builtin', $3, 0, TRUE)")
        .bind(c.tenant.to_string()).bind(&device).bind(epoch).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(DeviceObject {
        object: ObjectRef::Endpoint(device.clone()),
        association_version: None,
        verified: true,
        members: vec![PrimaryRegistration {
            device,
            channel: rss_mdm_inventory::Channel::Agent,
        }],
    })
}
