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
pub(super) async fn run(h: &Harness, version: Uuid, at: i64) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let state = rss_mdm_task_state::RunState::new(at + 300, at)?;
    let sql = "INSERT INTO mdm_inventory.collection_tasks(tenant_id,id,policy_version,channel,origin,source_objects,device,registration,generation,occurrence,created_at,available_at,deadline,agent_state,dispatch_fingerprint,gateway_accepted) VALUES($1::uuid,$2,$3,'agent','\"policy\"',$4,$5,$6,$7,$8,$9,$9,$10,$11,$12,true)";
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

#[tokio::test]
#[ignore = "T2: a capable acknowledged Agent cannot be previewed for collection without the host signing key"]
async fn agent_collection_preview_requires_host_signing() -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_management_http::execution::task_reads::Reads;
    let h = Harness::open().await?;
    let unsigned = Fixture::open(&h.c, false).await?;
    assert!(unsigned.resources.signing.loaded_key().is_none());
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
    let proof = std::sync::Arc::new(h.c.authenticate(&account).await?);
    let input = rss_mdm_policy::pages::Preview {
        definition: Box::new(definition),
        scope_result: None,
    };
    let result = Reads::preview(
        unsigned.task_reads.as_ref(),
        &h.c.read_auth(proof.clone()),
        &h.c.request(&proof)?,
        &input,
        &rss_mdm_policy::pages::PREVIEW_SCHEMA.page(Some(10), None, 4096)?,
        &rss_mdm_query::cursor::CursorCodec::new(&[5; 32])?,
    )
    .await;
    assert!(
        matches!(result, Err(rss_mdm_management_http::Error::Conflict)),
        "preview error: {:?}",
        result.err()
    );
    Fixture::close(unsigned).await?;
    h.close().await
}
