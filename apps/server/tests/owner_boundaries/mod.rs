//! Real independent Group and Compliance consumers of Inventory's bounded facts.
use crate::{authority_t2_support::Context, planning_t2_support as planning};
use anyhow::{Context as _, Result};
use rss_mdm_authorization_service::{Permission as P, context::AuthorizedPrincipal};
use rss_mdm_compliance_service as compliance;
use rss_mdm_group_service as group;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;
struct Owners {
    storage: crate::owner_storage::OwnerRuntime,
    groups: Arc<group::Groups>,
    compliance: compliance::Compliance,
}
impl Owners {
    async fn open(c: &Context) -> Result<Self> {
        let storage = planning::owner(c, "mdm_inventory_runtime").await?;
        let groups = Arc::new(
            rss_mdm_group_postgres::GroupStore::new(
                storage.runtime.clone(),
                c.tenant,
                group::transaction::deadline(),
            )
            .await?,
        );
        let messaging = rss_reconcile_postgres::PgMessagingStore::new(
            storage.runtime.clone(),
            c.tenant,
            group::transaction::deadline(),
        )
        .await?;
        let clock = Arc::new(crate::clock::InventoryClock(Arc::new(
            crate::clock::SystemClock,
        )));
        let service = group::Groups::new(group::Dependencies {
            read_pool: c.inputs.pool("shared", "mdm_access").await?,
            objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
            tenant: c.tenant,
            groups: groups.clone(),
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[7; 32]),
            audit_store: storage.audit.clone(),
            runtime: storage.runtime.clone(),
            reconcile_messaging: messaging.clone(),
            clock: clock.clone(),
        })
        .await?;
        let compliance = compliance::Compliance::new(compliance::Dependencies {
            audit_store: storage.audit.clone(),
            runtime: storage.runtime.clone(),
            tenant: c.tenant,
            clock,
            groups,
            reconcile_messaging: messaging,
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[7; 32]),
        });
        Ok(Self {
            storage,
            groups: Arc::new(service),
            compliance,
        })
    }
    async fn create(
        &self,
        c: &Context,
        proof: &AuthorizedPrincipal,
        criteria: Option<group::criteria::Condition>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let result = self
            .groups
            .execute(
                &group::Command::Group {
                    id,
                    change: Box::new(group::operation::Operation {
                        operation_id: Uuid::new_v4(),
                        expected_revision: 0,
                        input: group::GroupChange::Create {
                            presentation: serde_json::from_value(
                                json!({"name":format!("boundary-{id}"),"description":""}),
                            )?,
                            criteria,
                            asset_context: rss_mdm_group::AssetContext::Endpoint,
                        },
                    }),
                },
                &c.request(proof)?,
                proof,
            )
            .await
            .with_context(|| format!("Group creation {id}"))?;
        if let Some(task) = result.get("task").and_then(serde_json::Value::as_str) {
            use rss_reconcile::{DurableStore, ReconcileStep, Reconciler};
            let task = Uuid::parse_str(task)?;
            let timer = rss_mdm_device_service::control::recovery::Timer::new();
            let cancel = tokio_util::sync::CancellationToken::new();
            let control =
                rss_reconcile::Control::new(&timer, std::time::Duration::from_secs(15), &cancel);
            let pool = c.inputs.pool("shared", "mdm_scheduler_runtime").await?;
            let schedule = rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await?;
            let worker = group::runtime::GroupWork::new(self.groups.clone(), schedule.clone());
            let target = group::tasks::target(c.tenant, task);
            let mut batch = schedule
                .claim_due(
                    target.scope(),
                    64,
                    std::time::Duration::from_secs(30),
                    &control,
                )
                .await?;
            let index = batch
                .claims
                .iter()
                .position(|claim| claim.target() == &target)
                .expect("accepted task has a durable target");
            let claim = batch.claims.swap_remove(index);
            for _ in 0..8 {
                let ReconcileStep::Ready(diff) = worker.observe(&claim, &control).await? else {
                    anyhow::bail!("Group observation deferred")
                };
                if diff.drift() == rss_reconcile::DriftKind::Converged {
                    break;
                }
                worker.apply(&claim, diff, &control).await?;
            }
            let (completed,failure):(bool,Option<String>)=sqlx::query_as("SELECT completed,failure FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(task).fetch_one(&c.operator).await?;
            pool.close().await;
            anyhow::ensure!(
                completed && failure.is_none(),
                "Group definition did not publish: {completed}, {failure:?}"
            );
        }
        Ok(id)
    }
}
async fn scope(c: &Context, groups: &[Uuid]) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let definition = rss_mdm_scope::ScopeDefinition {
        targets: groups
            .iter()
            .copied()
            .map(rss_mdm_scope::Reference::Group)
            .collect(),
        limitations: None,
        exclusions: Default::default(),
    };
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_scope.scopes(tenant_id,id,revision) VALUES($1::uuid,$2,1)")
        .bind(c.tenant.to_string())
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mdm_scope.scope_versions(tenant_id,id,revision,definition) VALUES($1::uuid,$2,1,$3)").bind(c.tenant.to_string()).bind(id).bind(serde_json::to_value(definition)?).execute(&mut *tx).await?;
    for group in groups {
        sqlx::query("INSERT INTO mdm_scope.scope_sources(tenant_id,scope,kind,target) VALUES($1::uuid,$2,'group',$3)").bind(c.tenant.to_string()).bind(id).bind(group.to_string()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(id)
}
#[tokio::test]
#[ignore = "T2: mixed recursive references deduplicate paths before authorization and keyset paging, while hidden references still block deletion"]
async fn mixed_references_are_owned_authorized_and_stable_across_pages() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            P::InventoryRead,
            P::GroupRead,
            P::GroupWrite,
            P::ScopeRead,
            P::PolicyRead,
            P::ComplianceWrite,
            P::ComplianceRuleRead,
        ])
        .await?;
    let proof = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let root = owners.create(&c, &proof, None).await?;
    let child=owners.create(&c,&proof,Some(serde_json::from_value(json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"group","groupId":root,"op":"member_of"}}))?)).await?;
    let scoped = scope(&c, &[root, child]).await?;
    let resource = super::software_t2::support::software(&c, "reference-software").await?;
    let (policy, _) = super::software_t2::support::policy(
        &c,
        &resource,
        scoped,
        rss_mdm_policy::SoftwareChannel::Agent,
        vec![super::software_t2::support::stage(scoped)],
    )
    .await?;
    let field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|field| field.key.as_str() == "device.os.name")
        .expect("builtin OS name");
    let mut seed = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    assert!(rss_mdm_inventory_postgres::publish_field_in(&mut seed, c.tenant, 0, &field).await?);
    seed.commit().await?;
    let rule = Uuid::new_v4();
    let definition: compliance::Definition = serde_json::from_value(
        json!({"presentation":{"name":"boundary"},"severity":"low","enabled":true,"platform":"all","target":{"kind":"groups","ids":[root,child]},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"device.os.name","op":"eq","value":{"kind":"string","value":"Windows"}}}}),
    )?;
    owners
        .compliance
        .execute(
            &compliance::Command::Put {
                id: rule,
                request: Box::new(compliance::operation::Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 0,
                    input: definition,
                }),
            },
            &c.request(&proof)?,
            &proof,
        )
        .await?;
    let mut entries = Vec::new();
    let mut cursor = None;
    loop {
        let raw = cursor
            .as_ref()
            .map_or_else(|| "limit=1".to_string(), |v| format!("limit=1&cursor={v}"));
        let page = owners
            .groups
            .references(
                &proof,
                root,
                &group::references::Query::parse(&raw)?,
                &c.request(&proof)?,
            )
            .await?;
        assert!(page.deletion_blocked);
        assert!(page.items.len() <= 1);
        entries.extend(page.items);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
        assert!(entries.len() < 10, "bounded reference set must terminate");
    }
    let keys = entries
        .iter()
        .map(group::references::Entry::key)
        .collect::<Vec<_>>();
    assert!(keys.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(keys.len(), 6);
    for id in [child, scoped, policy, rule] {
        assert!(entries.iter().any(|e| e.source.id == id));
    }
    assert_eq!(entries.iter().filter(|e| e.source.id == policy).count(), 1);
    assert!(
        entries
            .iter()
            .find(|e| e.source.id == policy)
            .unwrap()
            .roles
            .iter()
            .any(|r| r == "policy_scope")
    );
    assert!(
        entries
            .iter()
            .find(|e| e.source.id == policy)
            .unwrap()
            .roles
            .iter()
            .any(|r| r == "rollout_stage")
    );
    let hidden = c
        .account(&[P::InventoryRead, P::GroupRead, P::GroupWrite])
        .await?;
    let hidden = c.authenticate(&hidden).await?;
    let page = owners
        .groups
        .references(
            &hidden,
            root,
            &group::references::Query::parse("limit=20")?,
            &c.request(&hidden)?,
        )
        .await?;
    assert!(page.deletion_blocked);
    assert!(page.items.iter().any(|entry| entry.source.id == child));
    assert!(
        page.items
            .iter()
            .all(|e| e.source.kind == group::references::Kind::Group)
    );
    assert!(matches!(
        owners
            .groups
            .execute(
                &group::Command::Group {
                    id: root,
                    change: Box::new(group::operation::Operation {
                        operation_id: Uuid::new_v4(),
                        expected_revision: 1,
                        input: group::GroupChange::Delete
                    })
                },
                &c.request(&hidden)?,
                &hidden
            )
            .await,
        Err(group::Error::Conflict)
    ));
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: a hidden Scope reference alone blocks Group deletion with an explicit reference conflict"]
async fn hidden_scope_reference_alone_blocks_group_deletion() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[P::InventoryRead, P::GroupRead, P::GroupWrite])
        .await?;
    let proof = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let root = owners.create(&c, &proof, None).await?;
    scope(&c, &[root]).await?;
    let page = owners
        .groups
        .references(
            &proof,
            root,
            &group::references::Query::parse("limit=20")?,
            &c.request(&proof)?,
        )
        .await?;
    assert!(page.items.is_empty());
    assert!(page.next_cursor.is_none());
    assert!(page.deletion_blocked);
    let deletion = owners
        .groups
        .execute(
            &group::Command::Group {
                id: root,
                change: Box::new(group::operation::Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 1,
                    input: group::GroupChange::Delete,
                }),
            },
            &c.request(&proof)?,
            &proof,
        )
        .await;
    assert!(matches!(deletion, Err(group::Error::Conflict)));
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: bounded Inventory changes bind runtime, tenant and fixed cut; Resource reference readers reject foreign runtimes too"]
async fn fact_readers_reject_cross_runtime_and_tenant_and_keep_the_frozen_cut() -> Result<()> {
    use rss_mdm_inventory_service::assets::{cut, planning::SnapshotReader};
    let c = Context::open("shared", &[]).await?;
    let owners = Owners::open(&c).await?;
    let other = planning::owner(&c, "mdm_inventory_runtime").await?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let before = cut::capture(&c.audit, c.tenant, &budget).await?;
    let first = planning::endpoint(&c).await?;
    let at = cut::capture(&c.audit, c.tenant, &budget).await?;
    let later = planning::endpoint(&c).await?;
    let reader = SnapshotReader::bind(owners.storage.runtime.clone(), c.tenant);
    let wrong = SnapshotReader::bind(other.runtime.clone(), c.tenant);
    let foreign = SnapshotReader::bind(
        owners.storage.runtime.clone(),
        rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?,
    );
    let refs = rss_mdm_resource_postgres::FieldReferences::bind(other.runtime.clone(), c.tenant);
    group::transaction::inspect(
        &owners.storage.runtime,
        c.tenant,
        (reader, wrong, foreign, refs, before, at),
        |ctx, tx| {
            Box::pin(async move {
                let catalog = rss_mdm_inventory::Catalog::new(rss_mdm_inventory::builtin::fields())
                    .expect("builtin catalog");
                assert!(
                    ctx.1
                        .summary_devices_in(tx, &ctx.5, &[], &catalog)
                        .await
                        .is_err()
                );
                assert!(
                    ctx.2
                        .summary_devices_in(tx, &ctx.5, &[], &catalog)
                        .await
                        .is_err()
                );
                assert!(
                    ctx.1
                        .changes_exist_in(tx, Some(&ctx.4), None)
                        .await
                        .is_err()
                );
                assert!(
                    ctx.2
                        .changes_exist_in(tx, Some(&ctx.4), None)
                        .await
                        .is_err()
                );
                assert!(ctx.3.counts_in(tx, "device.os.name").await.is_err());
                let changes = ctx
                    .0
                    .changes_page_in(tx, Some(&ctx.4), &ctx.5, 0, None, 1000)
                    .await?;
                assert!(
                    changes
                        .iter()
                        .any(|e| e.device.as_deref() == Some(first.members[0].device.as_str()))
                );
                assert!(
                    !changes
                        .iter()
                        .any(|e| e.device.as_deref() == Some(later.members[0].device.as_str()))
                );
                assert!(changes.windows(2).all(|w| w[0].revision < w[1].revision));
                Ok(())
            })
        },
    )
    .await?;
    drop(other);
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: concurrent Group deletion and reference creation serialize, and field retirement fences new conditions"]
async fn reference_creation_serializes_with_group_delete_and_catalog_retirement() -> Result<()> {
    use rss_mdm_inventory::*;
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[P::InventoryRead, P::GroupRead, P::GroupWrite])
        .await?;
    let proof = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let root = owners.create(&c, &proof, None).await?;
    let condition = serde_json::from_value(
        json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"group","groupId":root,"op":"member_of"}}),
    )?;
    let delete = group::Command::Group {
        id: root,
        change: Box::new(group::operation::Operation {
            operation_id: Uuid::new_v4(),
            expected_revision: 1,
            input: group::GroupChange::Delete,
        }),
    };
    let audit = c.request(&proof)?;
    let (deleted, created) = tokio::join!(
        owners.groups.execute(&delete, &audit, &proof),
        owners.create(&c, &proof, Some(condition))
    );
    assert_ne!(
        deleted.is_ok(),
        created.is_ok(),
        "exactly one incompatible mutation may commit: delete={deleted:?}, create={created:?}"
    );

    let field = FieldDefinition {
        time_series: None,
        key: FieldKey::parse("custom.owner.race")?,
        version: 1,
        value_type: ValueType::Boolean,
        nullable: false,
        manual: false,
        sources: [(Source::AgentScript, 0)].into(),
        platforms: [Platform::Windows].into(),
        sensitivity: Sensitivity::Standard,
        unit: None,
        searchable: true,
        item_key: None,
    };
    let mut seed = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    assert!(rss_mdm_inventory_postgres::publish_field_in(&mut seed, c.tenant, 0, &field).await?);
    seed.commit().await?;
    // Hold the actual catalog writer's fence after retirement until the competing reader waits.
    let mut retirement = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    rss_mdm_inventory_postgres::lock_catalog_write_in(&mut retirement, c.tenant).await?;
    assert!(
        rss_mdm_inventory_postgres::retire_field_in(&mut retirement, c.tenant, field.key, 1)
            .await?
    );
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *retirement)
        .await?;
    let condition = serde_json::from_value(
        json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":field.key,"op":"eq","value":{"kind":"boolean","value":true}}}),
    )?;
    let release = async {
        let wait=tokio::time::timeout(std::time::Duration::from_secs(4),async {
            loop {
                let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))").bind(pid).fetch_one(&c.operator).await?;
                if blocked {return Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await;
        retirement.commit().await?;
        wait??;
        Ok::<_, anyhow::Error>(())
    };
    let (created, released) = tokio::join!(owners.create(&c, &proof, Some(condition)), release);
    released?;
    assert!(
        created.is_err(),
        "a new condition cannot retain a retired field"
    );
    drop(owners);
    c.close().await;
    Ok(())
}
