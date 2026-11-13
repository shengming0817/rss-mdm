//! Owner-local accepted metadata, consumed by the assembled browser routes.
use super::*;
use crate::{command_runtime_t2_support::seed_transaction, planning_t2_support as planning};
#[expect(
    clippy::cognitive_complexity,
    reason = "One linear legal fixture batch preserves the original owner coordinates and collects real directory consumer proofs"
)]
pub(super) async fn seed(
    c: &Context,
    p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    cases: &mut Vec<(String, String, Value)>,
) -> Result<()> {
    let endpoint = planning::endpoint(c).await?;
    let device = &endpoint.members[0].device;
    let mut tx = seed_transaction(c).await?;
    let tenant = Uuid::parse_str(&c.tenant.to_string())?;
    let group = Uuid::from_u128(1002);
    let user = access::User {
        tenant_id: c.tenant.to_string(),
        instance_id: p.instance_id().into(),
        principal_id: p.principal_id().into(),
    };
    sqlx::query("UPDATE mdm_access.user_groups SET document=jsonb_set(document,'{members}',$3) WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(group).bind(json!([user])).execute(&mut *tx).await?;
    let rule:Uuid=sqlx::query_scalar("SELECT id FROM mdm_access.authorization_rules WHERE tenant_id=$1 AND instance=$2::uuid AND document->'subject'->'user'->>'principalId'=$3 LIMIT 1").bind(tenant).bind(p.instance_id()).bind(p.principal_id()).fetch_one(&mut *tx).await?;
    cases.push((
        "/api/v1/authorization/rules".into(),
        format!("id=={rule};deleted==false"),
        json!(rule),
    ));
    cases.push((
        format!("/api/v1/authorization/user-groups/{group}/members"),
        format!("principalId=={};tenantId=={tenant}", p.principal_id()),
        json!(p.principal_id()),
    ));
    let mut deliveries = Vec::new();
    for index in 0..2 {
        let id = Uuid::new_v4();
        let policy = Uuid::new_v4();
        let event = if index == 0 {
            "directory-sentinel"
        } else {
            "directory-target"
        };
        sqlx::query("INSERT INTO mdm_policy.requests(tenant_id,id,fingerprint,receipt) VALUES($1,$2,$3,$4)").bind(tenant).bind(id).bind(vec![17u8;32]).bind(json!({"operationId":id,"policyId":policy,"versionId":Uuid::new_v4(),"deadline":1700000010})).execute(&mut *tx).await?;
        let caller = rss_mdm_policy_service::events::Caller::Management { actor: p.actor() };
        sqlx::query("INSERT INTO mdm_policy.event_batches(tenant_id,id,request,actor,caller,device,input,fingerprint,created_at,deadline) VALUES($1,$2,$2,$3,$4,$5,$6,$7,1700000000,1700000010)")
            .bind(tenant).bind(id).bind(serde_json::to_string(&caller)?).bind(serde_json::to_value(caller)?).bind(device.into_uuid()).bind(json!({"operationId":id,"event":event,"source":{"kind":"human"},"executionContext":null})).bind(vec![17u8;32]).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_policy.event_members(tenant_id,batch,id,policy,revision,version,target,authority,decision) VALUES($1,$2,$2,$3,1,$4,$5,$6,$7)")
            .bind(tenant).bind(id).bind(policy).bind(Uuid::new_v4()).bind(json!({"device":device})).bind(json!({"permissions":[],"retirement_target":null})).bind(json!({"state":"expired"})).execute(&mut *tx).await?;
        let subscription =
            rss_mdm_webhook_service::storage::get(&mut tx, tenant, Uuid::from_u128(1000 + index))
                .await?;
        let event = rss_mdm_webhook_service::model::Event {
            event_id: Uuid::new_v4(),
            event_type: rss_mdm_webhook_service::model::EventType::Test,
            version: 1,
            occurred_at: time::OffsetDateTime::now_utc().unix_timestamp(),
            tenant_id: tenant,
            device_id: *device,
            data: rss_mdm_webhook_service::model::EventData::Test,
        };
        event.validate()?;
        sqlx::query(
            "INSERT INTO mdm_webhook.events(tenant_id,id,document,body) VALUES($1,$2,$3,$4)",
        )
        .bind(tenant)
        .bind(event.event_id)
        .bind(serde_json::to_value(&event)?)
        .bind(serde_json::to_vec(&event)?)
        .execute(&mut *tx)
        .await?;
        let operation = Uuid::new_v4();
        let delivery = rss_mdm_webhook_service::events::identity(
            event.event_id,
            &format!(
                "{}:{}:{}",
                subscription.id, subscription.target_version, operation
            ),
        );
        deliveries.push((event.clone(), subscription.clone(), operation));
        if index == 1 {
            cases.push((
                format!("/api/v1/devices/{device}/policy-event-batches"),
                "event==directory-target;createdAt==1700000000;admission.expired==1".into(),
                json!(id),
            ));
            cases.push((
                format!("/api/v1/devices/{device}/policy-event-batches/{id}/members"),
                format!("policyId=={policy};decision.state==expired"),
                json!(id),
            ));
            cases.push((
                "/api/v1/webhooks/deliveries".into(),
                format!(
                    "subscriptionId=={};eventId=={}",
                    subscription.id, event.event_id
                ),
                json!(delivery),
            ));
        }
    }
    tx.commit().await?;
    for (event, subscription, operation) in deliveries {
        c.runtime
            .local_tx(
                c.tenant,
                rss_mdm_inventory_service::transaction::deadline(),
                move |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |connection| {
                            Box::pin(async move {
                                Ok(rss_mdm_webhook_service::fanout::queue(
                                    connection,
                                    &event,
                                    &subscription,
                                    Some(operation),
                                    None,
                                )
                                .await)
                            })
                        })
                        .await?
                        .map_err(rss_mdm_webhook_service::PgError::from)
                    })
                },
            )
            .await
            .fold(
                |_| Ok(()),
                |e| Err(anyhow::anyhow!("{e:?}")),
                |e| Err(anyhow::anyhow!("{e:?}")),
                |_| Err(anyhow::anyhow!("queue rollback unknown")),
                |_| Err(anyhow::anyhow!("queue commit unknown")),
                |e| Err(anyhow::anyhow!("{e:?}")),
            )?;
    }
    Ok(())
}
