//! Minimal legal frozen inputs shared by cross-owner read and poll proofs.
use super::*;
use rss_mdm_inventory_service::collection::execution as collection;
use rss_mdm_policy::{Definition, schedule::Schedule};
use sha2::{Digest, Sha256};
pub(super) fn manual() -> Schedule {
    serde_json::from_value(json!({"trigger":{"kind":"manual"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null})).unwrap()
}
pub(super) fn interval() -> Schedule {
    serde_json::from_value(json!({"trigger":{"kind":"interval","anchor":0,"seconds":3600},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null})).unwrap()
}
pub(super) fn agent(
    h: &Harness,
) -> Result<(
    Definition,
    Value,
    rss_mdm_resource::AgentCollectionDefinition,
)> {
    let blueprint = rss_mdm_resource::blueprints::get("windows.agent.memory", "1").unwrap();
    let rss_mdm_resource::blueprints::Definition::AgentCollection { template } =
        blueprint.definition
    else {
        unreachable!()
    };
    let fields = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .filter(|f| template.spec().mappings.contains_key(f.key.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), template.spec().mappings.len());
    let definition: Definition = serde_json::from_value(
        json!({"scope":h.scope,"action":{"kind":"agent_collection","resource":{"id":"windows.agent.memory","version":"1","variant":"default","platform":"windows","architecture":"x86_64"},"schedule":interval(),"frequency":"every_trigger","runLifetimeSeconds":300}}),
    )?;
    definition.validate()?;
    let frozen = collection::frozen::Published::AgentCollection {
        action: Box::new(collection::frozen::FrozenAgent {
            fields,
            input: collection::frozen::CollectionInput {
                platform: rss_mdm_policy::Platform::Windows,
                architecture: rss_mdm_policy::Architecture::X86_64,
                schedule: interval(),
                run_lifetime_seconds: 300,
            },
            resource: w::TaskResource {
                id: "windows.agent.memory".into(),
                version: "1".into(),
                variant: "default".into(),
            },
            definition: template.clone(),
            resource_digest: [3; 32],
        }),
        frequency: rss_mdm_policy::Frequency::EveryTrigger,
    };
    Ok((definition, serde_json::to_value(frozen)?, template))
}
pub(super) fn enrollment(h: &Harness) -> Result<(Definition, Value)> {
    let organization = Uuid::parse_str(&h.c.tenant.to_string())?;
    let definition: Definition = serde_json::from_value(
        json!({"scope":h.scope,"action":{"kind":"request_mdm_enrollment","organization":organization,"schedule":manual(),"runLifetimeSeconds":300}}),
    )?;
    definition.validate()?;
    let entries = rss_mdm_execution_service::enrollment::Entries {
        windows: Some("https://mdm.example.test/".into()),
        macos: None,
    };
    entries.validate()?;
    let frozen = rss_mdm_execution_service::frozen::Frozen::MdmEnrollment {
        action: Box::new(rss_mdm_execution_service::enrollment::FrozenEnrollment {
            organization,
            schedule: manual(),
            run_lifetime_seconds: 300,
            entries,
            actor: rss_mdm_authorization_service::Actor::Account {
                user: h.c.user(Uuid::new_v4()),
            },
        }),
    };
    Ok((definition, serde_json::to_value(frozen)?))
}
pub(super) async fn publish(
    h: &Harness,
    policy: Uuid,
    number: i64,
    definition: Definition,
    frozen: Value,
) -> Result<Uuid> {
    let version = Uuid::new_v4();
    let mut tx = command::seed_transaction(&h.c).await?;
    if matches!(
        frozen["kind"].as_str(),
        Some("agent_collection" | "native_collection")
    ) {
        let published: collection::frozen::Published = serde_json::from_value(frozen.clone())?;
        let fields = match published {
            collection::frozen::Published::AgentCollection { action, .. } => action.fields,
            collection::frozen::Published::NativeCollection { action, .. } => {
                action.collection.fields().cloned().collect()
            }
        };
        for field in fields {
            seed_field(&mut tx, h.c.tenant, &field).await?;
        }
    }
    let author = rss_mdm_authorization_service::Actor::Account {
        user: h.c.user(Uuid::new_v4()),
    };
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,$3,$4,$3,'enabled',$5,$6,$7) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision,current_version=excluded.current_version,version_number=excluded.version_number,definition=excluded.definition").bind(h.c.tenant.to_string()).bind(policy).bind(number).bind(version).bind(serde_json::to_value(&definition)?).bind(serde_json::to_value(author)?).bind(now()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint,resource,resource_version) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)").bind(h.c.tenant.to_string()).bind(version).bind(policy).bind(number).bind(definition.action.kind().as_str()).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).bind(definition.action.resource().map(|r|r.id())).bind(definition.action.resource().map(|r|r.version())).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(version)
}
pub(super) async fn run(h: &Harness, version: Uuid, collection: bool, at: i64) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let state = rss_mdm_task_state::RunState::new(at + 300, at)?;
    let sql = if collection {
        "INSERT INTO mdm_inventory.collection_tasks(tenant_id,id,policy_version,channel,origin,source_objects,device,registration,generation,occurrence,created_at,available_at,deadline,agent_state,dispatch_fingerprint,gateway_accepted) VALUES($1::uuid,$2,$3,'agent','\"policy\"',$4,$5,$6,$7,$8,$9,$9,$10,$11,$12,true)"
    } else {
        "INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,origin,source_objects,device,registration,generation,occurrence,created_at,available_at,deadline,state,dispatch_fingerprint,gateway_accepted) VALUES($1::uuid,$2,$3,'\"policy\"',$4,$5,$6,$7,$8,$9,$9,$10,$11,$12,true)"
    };
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query(sql)
        .bind(h.c.tenant.to_string())
        .bind(id)
        .bind(version)
        .bind(json!([h.object]))
        .bind(h.p.device())
        .bind(h.p.registration())
        .bind(h.p.generation())
        .bind(id.to_string())
        .bind(at)
        .bind(at + 300)
        .bind(serde_json::to_value(state)?)
        .bind(vec![0u8; 32])
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(id)
}
#[tokio::test]
#[ignore = "T2: authorized history spans every owner and old Policy kind with stable keyset continuation"]
async fn history_pages_across_owners_and_historical_policy_versions() -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_management_http::execution::task_reads::{RUNS_SCHEMA, Reads};
    let h = Harness::open().await?;
    let at = now();
    let (policy, v1) = h.policy("history").await?;
    let script = h.run(v1, "history", at + 300).await?;
    let (definition, frozen) = enrollment(&h)?;
    let v2 = publish(&h, policy, 2, definition, frozen).await?;
    let execution = run(&h, v2, false, at).await?;
    let (definition, frozen, _) = agent(&h)?;
    let v3 = publish(&h, policy, 3, definition, frozen).await?;
    let collection = run(&h, v3, true, at - 1).await?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_script.runs SET available_at=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string())
        .bind(script)
        .bind(at)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let account =
        h.c.account(&[
            Permission::PolicyRead,
            Permission::OperationRead,
            Permission::InventoryRead,
        ])
        .await?;
    let proof = h.c.authenticate(&account).await?;
    let codec = rss_mdm_query::cursor::CursorCodec::new(&[4; 32])?;
    let first = Reads::runs(
        h.a.task_reads.as_ref(),
        &proof,
        &h.c.request(&proof)?,
        policy,
        &RUNS_SCHEMA.page(Some(2), None, 4096)?,
        &codec,
    )
    .await?;
    assert_eq!(first.items.len(), 2);
    let cursor = first.next_cursor.as_deref().expect("more owners remain");
    let second = Reads::runs(
        h.a.task_reads.as_ref(),
        &proof,
        &h.c.request(&proof)?,
        policy,
        &RUNS_SCHEMA.page(Some(2), Some(cursor.to_owned()), 4096)?,
        &codec,
    )
    .await?;
    assert_eq!(second.items.len(), 1);
    assert!(second.next_cursor.is_none());
    let positions = first
        .items
        .iter()
        .chain(&second.items)
        .map(|v| v.position())
        .collect::<Vec<_>>();
    let mut expected = vec![(at, script), (at, execution), (at - 1, collection)];
    expected.sort_by(|a, b| b.cmp(a));
    assert_eq!(positions, expected);
    let kinds = first
        .items
        .iter()
        .chain(&second.items)
        .map(|v| {
            serde_json::to_value(v).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        kinds,
        ["execution".into(), "script".into(), "collection".into()].into()
    );
    h.close().await
}
async fn seed_field(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    field: &rss_mdm_inventory::FieldDefinition,
) -> Result<()> {
    let catalog = rss_mdm_inventory_postgres::catalog_in(c, tenant).await?;
    if catalog.definition(field.key).is_err() {
        anyhow::ensure!(
            rss_mdm_inventory_postgres::publish_field_in(c, tenant, 0, field).await?,
            "field seed CAS"
        );
    }
    Ok(())
}
async fn unenrolled(h: &Harness) -> Result<()> {
    use rss_mdm_inventory::*;
    let tenant = h.c.tenant;
    let registration = h.p.registration();
    let at = now();
    let report = Uuid::new_v4();
    let mut tx = command::seed_transaction(&h.c).await?;
    let epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND source='agent.builtin'").bind(tenant.to_string()).bind(registration).fetch_one(&mut *tx).await?;
    let field = builtin::fields()
        .into_iter()
        .find(|f| f.key == builtin::MDM_ENROLLMENT)
        .unwrap();
    seed_field(&mut tx, tenant, &field).await?;
    let key = field.key;
    let definition = CollectionDefinition::new(
        key.as_str(),
        1,
        Source::AgentBuiltin,
        vec![CollectionField {
            definition: field,
            scope: CollectionScope::Device,
        }],
    )?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, tenant, &definition).await?;
    let scope = rss_mdm_registration_service::device::scope_dataset(
        tenant,
        registration,
        "agent.builtin",
        epoch,
        key.as_str(),
    )?;
    let value = Scalar::String("unenrolled".into());
    let progress = CollectionProgress::native(
        definition.clone(),
        [(
            key,
            NativeValue::Value(CollectedValue::Value(value.clone())),
        )]
        .into(),
        at,
    )?;
    let (sequence, _) = rss_mdm_registration_service::device::store::allocate_report_in(
        &mut tx,
        &tenant.to_string(),
        &registration.to_string(),
        ReportSource::AgentBuiltin,
        &epoch.to_string(),
        1,
        i64::from(u32::MAX),
    )
    .await?
    .unwrap();
    let batch = rss_mdm_inventory_postgres::seal_collection_in(
        &mut tx,
        rss_mdm_inventory_postgres::CollectionCompletion {
            scope: &scope,
            run: &report.to_string(),
            sequence: sequence.try_into()?,
            observed_at: at,
            progress: &progress,
        },
    )
    .await?;
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,reason,batch,digest,sealed_at,delivery_pending) VALUES($1::uuid,$2,$3,'agent.builtin',$4,$5,$6,$7,$8,'snapshot','complete',$9,$10,$7,false)").bind(tenant.to_string()).bind(report).bind(registration).bind(epoch).bind(scope.encode()?).bind(sequence).bind(at).bind(serde_json::to_string(&progress)?).bind(batch.encode()).bind(batch.fingerprint(&scope)?.iter().map(|b|format!("{b:02x}")).collect::<String>()).execute(&mut *tx).await?;
    let projection = rss_mdm_inventory_postgres::projection_scope(tenant);
    sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence,field_scope) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$9,'known',$10,'agent.builtin',$11,$12,$13)").bind(tenant.to_string()).bind(projection.source().source()).bind(projection.generation()).bind(scope.encode()?).bind(serde_json::to_string(&definition.coverage()?)?).bind(key.as_str()).bind(serde_json::to_string(&value)?).bind(report.to_string()).bind(at).bind(registration.to_string()).bind(epoch.to_string()).bind(sequence).bind(CollectionScope::Device.canonical()?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES($1::uuid,$2,'agent.native',$3,true)").bind(tenant.to_string()).bind(registration).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "T2: real Agent poll merges legal owners in order and advances only over inspected candidates"]
async fn poll_interleaves_owners_and_skips_ineligible_prefix() -> Result<()> {
    let mut h = Harness::open().await?;
    unenrolled(&h).await?;
    h.scope = planning::published(&h.c, &h.object).await?.scope;
    let at = now() - 4;
    let (_, blocked_version) = h.policy_as("ineligible", "logged_in_user").await?;
    let blocked = h.run(blocked_version, "ineligible", now() + 300).await?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_script.runs SET available_at=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string())
        .bind(blocked)
        .bind(at)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let (definition, frozen) = enrollment(&h)?;
    let v = publish(&h, Uuid::new_v4(), 1, definition, frozen).await?;
    let execution = run(&h, v, false, at + 1).await?;
    let (_, v) = h.policy("eligible").await?;
    let script = h.run(v, "eligible", now() + 300).await?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_script.runs SET available_at=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string())
        .bind(script)
        .bind(at + 2)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let (definition, frozen, template) = agent(&h)?;
    let v = publish(&h, Uuid::new_v4(), 1, definition, frozen).await?;
    let collection = run(&h, v, true, at + 3).await?;
    for (expected, kind) in [
        (execution, "enrollment"),
        (script, "script"),
        (collection, "collection"),
    ] {
        let input = w::TaskClaimRequest::new(
            Uuid::new_v4(),
            vec![w::ExecutorProfile::PowerShell7],
            context(),
        )?
        .with_environment(rss_mdm_agent_wire::CollectionEnvironment {
            edition: None,
            tools: Default::default(),
            native_engines: template.spec().plan.requirements(),
        })?;
        let response = h.delivery.claim(&h.p, &input, &request(&h.c)).await?;
        let task = response.task().expect("each eligible owner is reachable");
        assert_eq!(task.payload.task_id(), expected);
        assert_eq!(
            match &task.payload {
                w::TaskPayload::Enrollment(_) => "enrollment",
                w::TaskPayload::Script(_) => "script",
                w::TaskPayload::Collection(_) => "collection",
                _ => "unexpected",
            },
            kind
        );
        let cursor:(i64,Uuid)=sqlx::query_as("SELECT offer_after_at,offer_after_id FROM mdm_agent.task_polls WHERE tenant_id=$1::uuid AND registration=$2").bind(h.c.tenant.to_string()).bind(h.p.registration()).fetch_one(&h.c.operator).await?;
        assert_eq!(
            cursor.1, expected,
            "later candidates have not been inspected"
        );
    }
    assert_eq!(h.state(blocked).await?["execution"], "not_started");
    h.close().await
}

#[tokio::test]
#[ignore = "T2: a capable acknowledged Agent cannot be previewed for collection without the host signing key"]
async fn agent_collection_preview_requires_host_signing() -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_management_http::execution::task_reads::Reads;
    let h = Harness::open().await?;
    let unsigned = command::open(&h.c, false).await?;
    assert!(unsigned.signing.loaded_key().is_none());
    let (definition, _, template) = agent(&h)?;
    let announcement = w::TaskClaimRequest::new(
        Uuid::new_v4(),
        vec![w::ExecutorProfile::PowerShell7],
        context(),
    )?
    .with_environment(rss_mdm_agent_wire::CollectionEnvironment {
        edition: None,
        tools: Default::default(),
        native_engines: template.spec().plan.requirements(),
    })?;
    assert!(
        h.delivery
            .claim(&h.p, &announcement, &request(&h.c))
            .await?
            .task()
            .is_none()
    );
    let preview = collection::preview::Preview::Agent {
        definition: template,
        platform: rss_mdm_policy::Platform::Windows,
        architecture: rss_mdm_policy::Architecture::X86_64,
    };
    let mut tx = command::seed_transaction(&h.c).await?;
    assert!(
        unsigned
            .task_reads
            .collections
            .eligible_on(
                &mut tx,
                &preview,
                Arc::new(super::super::agent_facts::AgentFacts),
                &collection::model::Target {
                    device: h.p.device().into(),
                    registration: h.p.registration(),
                    generation: h.p.generation(),
                }
            )
            .await?
    );
    tx.rollback().await?;
    let account =
        h.c.account(&[
            Permission::PolicyRead,
            Permission::ResourceRead,
            Permission::ScopeRead,
            Permission::InventoryRead,
            Permission::InventoryCollect,
            Permission::InventorySensitiveRead,
        ])
        .await?;
    let proof = h.c.authenticate(&account).await?;
    let input = rss_mdm_policy::pages::Preview {
        definition: Box::new(definition),
        scope_result: None,
    };
    let result = Reads::preview(
        unsigned.task_reads.as_ref(),
        &proof,
        &h.c.request(&proof)?,
        &input,
        &rss_mdm_policy::pages::PREVIEW_SCHEMA.page(Some(10), None, 4096)?,
        &rss_mdm_query::cursor::CursorCodec::new(&[5; 32])?,
    )
    .await;
    assert!(matches!(
        result,
        Err(rss_mdm_management_http::Error::Conflict)
    ));
    command::close(unsigned).await?;
    h.close().await
}
