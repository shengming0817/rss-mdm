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
