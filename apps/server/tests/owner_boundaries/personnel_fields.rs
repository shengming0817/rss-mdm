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
    while refresh.advance(c.execution()).await? {}
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
    let (agent, grant) = crate::device_material_support::seed_registration(&c).await?;
    crate::device_material_support::authenticated_agent(&c, grant, &agent, vec![]).await?;
    let (peer, certificate, _, trust) = crate::device_material_support::qualified_peer_material(
        &c,
        &agent,
        rss_mdm_agent_wire::pki::Purpose::Agent,
    )
    .await?;
    let meta = peer.metadata();
    let mut tx = seed_transaction(&c).await?;
    sqlx::query(
        "INSERT INTO mdm_pki.trust(tenant_id,purpose,revision,body) VALUES($1::uuid,'agent',1,$2)",
    )
    .bind(c.tenant.to_string())
    .bind(serde_json::to_vec(&trust)?)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO mdm_pki.certificates(tenant_id,purpose,fingerprint,issuer,serial,device,not_after,certificate,verification_version,verification_trust,verification_start,verification_end) SELECT tenant_id,purpose,sha256($2::bytea),encode($3,'hex'),encode($4,'hex'),$5,$6,$2,1,sha256(body),$7,$6 FROM mdm_pki.trust WHERE tenant_id=$1::uuid AND purpose='agent'")
        .bind(c.tenant.to_string()).bind(&certificate).bind(meta.issuer.as_slice()).bind(&meta.serial).bind(agent.into_uuid()).bind(meta.not_after).bind(meta.not_before).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.current_users(tenant_id,device,revision,session_reference,confirmed_at) VALUES($1::uuid,$2,1,$3,extract(epoch FROM statement_timestamp())::bigint)")
        .bind(c.tenant.to_string()).bind(agent.into_uuid()).bind(serde_json::to_value(proof.session()?.reference()?)?).execute(&mut *tx).await?;
    sqlx::query("UPDATE mdm_access.user_groups SET document=jsonb_set(document,'{members}','[]'),revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(group).execute(&mut *tx).await?;
    sqlx::query("UPDATE mdm_assets.personnel_cursor SET next_scan=clock_timestamp() WHERE tenant_id=$1::uuid")
        .bind(c.tenant.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    while refresh.advance(c.execution()).await? {}
    assert!(
        owners
            .groups
            .preview(&proof, &membership, &c.request(&proof)?)
            .await?
            .items
            .is_empty()
    );
    assert_eq!(
        owners
            .groups
            .preview(&proof, &current, &c.request(&proof)?)
            .await?
            .items,
        vec![rss_mdm_agent_wire::ObjectRef::Endpoint(agent)]
    );
    let revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(saved)
    .fetch_one(&c.operator)
    .await?;
    let accepted = owners
        .groups
        .execute(
            &group::Command::Group {
                id: saved,
                change: Box::new(group::operation::Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: revision as u64,
                    input: group::GroupChange::Recompute {},
                }),
            },
            &c.request(&proof)?,
            &proof,
        )
        .await?;
    owners
        .settle(
            &c,
            Uuid::parse_str(accepted["task"].as_str().context("recompute")?)?,
        )
        .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT member_count FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(saved)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(count, 0);
    drop(owners);
    c.close().await;
    Ok(())
}
