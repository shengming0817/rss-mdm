//! Device predicates use the same scope, operator and preview paths as inventory predicates.
use super::*;
use crate::administration::user_profiles::device_fields::Refresh;
use crate::command_runtime_t2_support::seed_transaction;
use group::runtime::DeviceFieldRefresh;

fn condition(actor: &str, field: &str, id: &str) -> Result<group::preview::Request> {
    let (op, operand) = if field.ends_with("ids") {
        (
            "contains_any",
            json!({"values":[{"kind":"string","value":id}]}),
        )
    } else {
        ("eq", json!({"value":{"kind":"string","value":id}}))
    };
    let mut predicate =
        json!({"kind":"predicate","field":format!("device.{actor}.{field}"),"op":op});
    predicate
        .as_object_mut()
        .unwrap()
        .extend(operand.as_object().unwrap().clone());
    Ok(serde_json::from_value(
        json!({"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":predicate},"assetContext":"endpoint","editing":null}),
    )?)
}

#[tokio::test]
#[ignore = "T2: ordinary device predicates qualify account attribution and reject revoked group inputs"]
async fn registration_and_current_fields_share_preview_and_revoke_local_membership() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            P::InventoryRead,
            P::GroupRead,
            P::GroupWrite,
            P::Enrollment,
            P::InventorySensitiveRead,
            P::UserGroupRead,
        ])
        .await?;
    let denied = c
        .account(&[P::InventoryRead, P::GroupRead, P::Enrollment])
        .await?;
    let proof = c.authenticate(&account).await?;
    let denied = c.authenticate(&denied).await?;
    let owners = Owners::open(&c).await?;
    let endpoint = planning::endpoint(&c).await?;
    let group = Uuid::new_v4();
    let mut tx = seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_access.registration_users(tenant_id,device,revision,instance,principal) VALUES($1::uuid,$2,1,$3,$4) ON CONFLICT(tenant_id,device) DO UPDATE SET revision=registration_users.revision+1,instance=excluded.instance,principal=excluded.principal")
        .bind(c.tenant.to_string()).bind(endpoint.members[0].device.into_uuid()).bind(&account.user.instance_id).bind(&account.user.principal_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.user_groups(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3,1,$4)").bind(c.tenant.to_string()).bind(&account.user.instance_id).bind(group)
        .bind(json!({"name":"engineering","enabled":true,"members":[account.user]})).execute(&mut *tx).await?;
    tx.commit().await?;
    let refresh = Refresh {
        runtime: owners.storage.runtime.clone(),
        identity: c.authority.clone(),
        federation: None,
        platform: serde_json::Value::Null,
        max_age: 3600u32.try_into()?,
    };
    refresh.advance(c.execution()).await?;
    let principal = condition(
        "registration_user",
        "principal_id",
        &account.user.principal_id,
    )?;
    assert_eq!(
        owners
            .groups
            .preview(&proof, &principal, &c.request(&proof)?)
            .await?
            .items,
        vec![endpoint.object]
    );
    let current = condition("current_user", "principal_id", &account.user.principal_id)?;
    assert!(
        owners
            .groups
            .preview(&proof, &current, &c.request(&proof)?)
            .await?
            .items
            .is_empty()
    );
    let membership = condition("registration_user", "local_group_ids", &group.to_string())?;
    assert_eq!(
        owners
            .groups
            .preview(&proof, &membership, &c.request(&proof)?)
            .await?
            .items,
        vec![endpoint.object]
    );
    assert!(matches!(
        owners
            .groups
            .preview(&denied, &membership, &c.request(&denied)?)
            .await,
        Err(group::Error::Forbidden)
    ));
    let saved = owners
        .create(&c, &proof, Some(membership.criteria.clone()))
        .await?;
    let task = sqlx::query_scalar("SELECT id FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND target=$2 AND kind='group' AND NOT completed")
        .bind(c.tenant.to_string()).bind(saved).fetch_one(&c.operator).await?;
    owners.settle(&c, task).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT member_count FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(saved)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(count, 1);
    let mut tx = seed_transaction(&c).await?;
    sqlx::query("UPDATE mdm_access.user_groups SET document=jsonb_set(document,'{members}','[]'),revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(group).execute(&mut *tx).await?;
    sqlx::query("UPDATE mdm_assets.personnel_cursor SET next_scan=clock_timestamp() WHERE tenant_id=$1::uuid")
        .bind(c.tenant.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    refresh.advance(c.execution()).await?;
    assert!(
        owners
            .groups
            .preview(&proof, &membership, &c.request(&proof)?)
            .await?
            .items
            .is_empty()
    );
    drop(owners);
    c.close().await;
    Ok(())
}
