//! Request-local previews exercise real authorization, frozen facts and Group storage.
use super::*;
use group::preview::{Editing, Request};
use rss_mdm_group::AssetContext;
use rss_mdm_inventory_service::objects::ObjectRef;

fn membership(id: Uuid, op: &str) -> Result<group::criteria::Condition> {
    Ok(serde_json::from_value(
        json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"group","groupId":id,"op":op}}),
    )?)
}
fn request(criteria: group::criteria::Condition) -> Request {
    Request {
        criteria,
        asset_context: AssetContext::Endpoint,
        editing: None,
    }
}
// Snapshot all tenant rows in business-owned schemas, including task/outbox/member
// tables. Preview may read/lock these rows, but cannot create or alter any of them.
async fn business_state(c: &Context) -> Result<serde_json::Value> {
    let tables: Vec<(String,String)> = sqlx::query_as("SELECT schemaname,tablename FROM pg_tables WHERE schemaname IN ('mdm_assets','mdm_group','mdm_scope','mdm_policy','mdm_devices','rss_reconcile','rss_messaging') AND EXISTS(SELECT FROM information_schema.columns WHERE table_schema=schemaname AND table_name=tablename AND column_name='tenant_id') ORDER BY schemaname,tablename").fetch_all(&c.operator).await?;
    let mut state = serde_json::Map::new();
    for (schema, table) in tables {
        // Identifiers come from PostgreSQL's catalog; restrict them before interpolation.
        anyhow::ensure!(
            [&schema, &table]
                .iter()
                .all(|s| s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        );
        let sql = format!(
            "SELECT coalesce(jsonb_agg(r ORDER BY r::text),'[]'::jsonb) FROM (SELECT to_jsonb(t) r FROM \"{schema}\".\"{table}\" t WHERE tenant_id=$1::uuid) rows"
        );
        let rows: serde_json::Value = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(c.tenant.to_string())
            .fetch_one(&c.operator)
            .await?;
        state.insert(format!("{schema}.{table}"), rows);
    }
    Ok(state.into())
}

#[tokio::test]
#[ignore = "T2: unsaved preview returns bounded definite matches without persisting any business state"]
async fn unsaved_preview_is_read_only_and_bounded() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[P::GroupRead, P::GroupWrite, P::InventoryRead])
        .await?;
    let proof = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let empty = owners.create(&c, &proof, None).await?;
    let first = planning::endpoint(&c).await?;
    let input = request(membership(empty, "not_member_of")?);
    let before = business_state(&c).await?;
    let result = owners
        .groups
        .preview(&proof, &input, &c.request(&proof)?)
        .await?;
    assert_eq!(result.items, vec![first.object]);
    assert!(result.scan_complete);
    assert!(result.object_snapshot.is_none());
    assert_eq!(result.sources.len(), 1);
    assert_eq!(
        result.input_fingerprint,
        rss_mdm_query::cursor::fingerprint(&input)?
    );
    assert_eq!(business_state(&c).await?, before);
    let no_matches = request(membership(empty, "member_of")?);
    let result = owners
        .groups
        .preview(&proof, &no_matches, &c.request(&proof)?)
        .await?;
    assert!(result.items.is_empty() && result.scan_complete);
    for _ in 0..21 {
        planning::endpoint(&c).await?;
    }
    let before = business_state(&c).await?;
    let result = owners
        .groups
        .preview(&proof, &input, &c.request(&proof)?)
        .await?;
    assert_eq!(result.items.len(), 20);
    assert!(!result.scan_complete);
    assert!(
        result
            .items
            .iter()
            .all(|v| matches!(v, ObjectRef::Endpoint(_)))
    );
    assert_eq!(business_state(&c).await?, before);
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: preview uses live read grants and rejects stale editing, static owners, missing or cyclic references"]
async fn preview_authorization_and_definition_checks() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[P::GroupRead, P::GroupWrite, P::InventoryRead])
        .await?;
    let proof = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let empty = owners.create(&c, &proof, None).await?;
    let condition = membership(empty, "not_member_of")?;
    let dynamic = owners.create(&c, &proof, Some(condition.clone())).await?;
    let readonly = c.account(&[P::GroupRead, P::InventoryRead]).await?;
    let readproof = c.authenticate(&readonly).await?;
    let mut input = request(condition);
    input.editing = Some(Editing {
        group_id: dynamic,
        expected_revision: 1,
    });
    let before = business_state(&c).await?;
    owners
        .groups
        .preview(&readproof, &input, &c.request(&readproof)?)
        .await?;
    input.editing.as_mut().unwrap().expected_revision = 0;
    assert!(matches!(
        owners
            .groups
            .preview(&proof, &input, &c.request(&proof)?)
            .await,
        Err(group::Error::Conflict)
    ));
    input.editing = Some(Editing {
        group_id: empty,
        expected_revision: 1,
    });
    assert!(matches!(
        owners
            .groups
            .preview(&proof, &input, &c.request(&proof)?)
            .await,
        Err(group::Error::Malformed)
    ));
    input.editing = Some(Editing {
        group_id: dynamic,
        expected_revision: 1,
    });
    input.criteria = membership(dynamic, "member_of")?;
    assert!(matches!(
        owners
            .groups
            .preview(&proof, &input, &c.request(&proof)?)
            .await,
        Err(group::Error::Malformed)
    ));
    input.editing = None;
    input.criteria = membership(Uuid::new_v4(), "member_of")?;
    assert!(
        owners
            .groups
            .preview(&proof, &input, &c.request(&proof)?)
            .await
            .is_err()
    );
    assert_eq!(business_state(&c).await?, before);
    for permissions in [&[P::GroupRead][..], &[P::InventoryRead][..]] {
        let denied = c.account(permissions).await?;
        let denied = c.authenticate(&denied).await?;
        assert!(matches!(
            owners
                .groups
                .preview(&denied, &input, &c.request(&denied)?)
                .await,
            Err(group::Error::Forbidden)
        ));
    }
    // The proof still carries old grants; the transaction must read their revocation.
    sqlx::query("UPDATE mdm_access.authorization_rules SET document=NULL, revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(readonly.rule).execute(&c.operator).await?;
    assert!(matches!(
        owners
            .groups
            .preview(&readproof, &input, &c.request(&readproof)?)
            .await,
        Err(group::Error::Forbidden)
    ));
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: missing facts remain Unknown and cannot appear as matching preview examples"]
async fn preview_excludes_unknown_facts() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c.account(&[P::GroupRead, P::InventoryRead]).await?;
    let proof = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    planning::endpoint(&c).await?;
    let field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.os.name")
        .unwrap();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    assert!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &field).await?);
    tx.commit().await?;
    let input = request(serde_json::from_value(
        json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"device.os.name","op":"eq","value":{"kind":"string","value":"Windows"}}}),
    )?);
    let before = business_state(&c).await?;
    let result = owners
        .groups
        .preview(&proof, &input, &c.request(&proof)?)
        .await?;
    assert!(result.items.is_empty() && result.scan_complete);
    assert_eq!(business_state(&c).await?, before);
    drop(owners);
    c.close().await;
    Ok(())
}

async fn publish(
    owners: &Owners,
    c: &Context,
    proof: &AuthorizedPrincipal,
    id: Uuid,
) -> Result<Uuid> {
    let accepted = owners
        .groups
        .execute(
            &group::Command::Group {
                id,
                change: Box::new(group::operation::Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 1,
                    input: group::GroupChange::Recompute {},
                }),
            },
            &c.request(proof)?,
            proof,
        )
        .await?;
    let task = Uuid::parse_str(accepted["task"].as_str().context("calculation task")?)?;
    owners.settle(c, task).await?;
    let published: Uuid = sqlx::query_scalar(
        "SELECT member_set FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(published, task);
    Ok(published)
}

async fn os_fact(c: &Context, registration: Uuid) -> Result<()> {
    use rss_mdm_inventory::*;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    let field = builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.os.name")
        .unwrap();
    assert!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &field).await?);
    let key = field.key;
    let definition = CollectionDefinition::new(
        "preview-os",
        1,
        Source::MdmWindows,
        vec![CollectionField {
            definition: field,
            scope: CollectionScope::Device,
        }],
    )?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, c.tenant, &definition).await?;
    let epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND source='mdm.windows'").bind(c.tenant.to_string()).bind(registration).fetch_one(&mut *tx).await?;
    let scope = rss_mdm_registration_service::device::scope_dataset(
        rss_mdm_install_support::StorageProfile::Mdm,
        c.tenant,
        registration,
        "mdm.windows",
        epoch,
        "preview-os",
    )?;
    let (sequence, _) = rss_mdm_registration_service::device::store::allocate_report_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        &c.tenant.to_string(),
        &registration.to_string(),
        ReportSource::MdmWindows,
        &epoch.to_string(),
        1,
        i64::from(u32::MAX),
    )
    .await?
    .context("report sequence")?;
    let projection = rss_mdm_inventory_postgres::projection_scope(c.tenant);
    let at = time::OffsetDateTime::now_utc().unix_timestamp();
    sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence,field_scope) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$9,'known',$10,'mdm.windows',$11,$12,$13)")
        .bind(c.tenant.to_string()).bind(projection.source().source()).bind(projection.generation()).bind(scope.encode()?).bind(serde_json::to_string(&definition.coverage()?)?).bind(key.as_str()).bind(serde_json::to_string(&Scalar::String("Windows".into()))?).bind(Uuid::new_v4().to_string()).bind(at).bind(registration.to_string()).bind(epoch.to_string()).bind(sequence).bind(CollectionScope::Device.canonical()?).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: real scalar facts produce the same preview and published members; associated preview reads only its existing cut"]
async fn positive_facts_and_associated_cut_share_formal_evaluation() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            P::GroupRead,
            P::GroupWrite,
            P::GroupRecompute,
            P::InventoryRead,
        ])
        .await?;
    let proof = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let object = planning::endpoint(&c).await?;
    os_fact(&c, object.members[0].registration_id).await?;
    let condition: group::criteria::Condition = serde_json::from_value(
        json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"device.os.name","op":"eq","value":{"kind":"string","value":"Windows"}}}),
    )?;
    let mut input = request(condition.clone());
    let preview = owners
        .groups
        .preview(&proof, &input, &c.request(&proof)?)
        .await?;
    assert_eq!(preview.items, vec![object.object.clone()]);
    assert!(preview.scan_complete);
    let id = owners.create(&c, &proof, Some(condition)).await?;
    let run = publish(&owners, &c, &proof, id).await?;
    let page = owners
        .groups
        .execute(
            &group::Command::GroupPage {
                group: id,
                result: run,
                projection: group::pages::GroupPageKind::Members,
                query: group::pages::SCHEMA.parse("")?.0,
            },
            &c.request(&proof)?,
            &proof,
        )
        .await?;
    assert_eq!(page["page"]["items"], serde_json::to_value(&preview.items)?);
    // Minimal legal Device-owned fixed projection. A standalone endpoint is also
    // an object in AssociatedDevice context; no association workflow is under test.
    let snapshot = Uuid::new_v4();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_devices.object_cuts(tenant_id,id,asset_cut,through) VALUES($1::uuid,$2,$3,1)").bind(c.tenant.to_string()).bind(snapshot).bind(preview.asset_cut.to_json()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_devices.object_versions(tenant_id,object,revision,input,devices) VALUES($1::uuid,$2,1,$3,$4)").bind(c.tenant.to_string()).bind(object.object.key()).bind(serde_json::to_value(&object)?).bind(vec![object.members[0].device.clone()]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_devices.checkpoints(tenant_id,from_cut,rebuilding,object_revision,current_cut) VALUES($1::uuid,$2,false,1,$3)").bind(c.tenant.to_string()).bind(preview.asset_cut.to_json()).bind(snapshot).execute(&mut *tx).await?;
    tx.commit().await?;
    input.asset_context = AssetContext::AssociatedDevice;
    let before = business_state(&c).await?;
    let result = owners
        .groups
        .preview(&proof, &input, &c.request(&proof)?)
        .await?;
    assert_eq!(result.items, preview.items);
    assert_eq!(result.object_snapshot, Some(snapshot));
    assert_eq!(result.asset_cut, preview.asset_cut);
    assert_eq!(business_state(&c).await?, before);
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: preview narrows an oversized source evidence page and preserves all matching objects"]
async fn source_evidence_budget_retries_a_smaller_page() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            P::GroupRead,
            P::GroupWrite,
            P::GroupRecompute,
            P::InventoryRead,
        ])
        .await?;
    let proof = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let empty = owners.create(&c, &proof, None).await?;
    for _ in 0..17 {
        planning::endpoint(&c).await?;
    }
    let id = owners
        .create(&c, &proof, Some(membership(empty, "not_member_of")?))
        .await?;
    let run = publish(&owners, &c, &proof, id).await?;
    // Valid JSON whitespace makes 17 individually legal 1 MiB records exceed
    // the 16 MiB batch budget without inventing another rule-evaluation fixture.
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    let changed=sqlx::query("UPDATE mdm_group.member_rows SET evidence=evidence||convert_to(repeat(' ',1048576-octet_length(evidence)),'UTF8'),evidence_digest=sha256(evidence||convert_to(repeat(' ',1048576-octet_length(evidence)),'UTF8')) WHERE tenant_id=$1::uuid AND run_id=$2").bind(c.tenant.to_string()).bind(run).execute(&mut *tx).await?.rows_affected();
    assert_eq!(changed, 17);
    tx.commit().await?;
    let result = owners
        .groups
        .preview(
            &proof,
            &request(membership(id, "member_of")?),
            &c.request(&proof)?,
        )
        .await?;
    assert_eq!(result.items.len(), 17);
    assert!(result.scan_complete);
    drop(owners);
    c.close().await;
    Ok(())
}
