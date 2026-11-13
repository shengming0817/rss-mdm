//! Actual live views and immutable list continuations under unrelated writes and revocation.
use crate::{
    authority_t2_support::Context, command_runtime_t2_support::seed_transaction,
    planning_t2_support,
};
use anyhow::Result;
use rss_mdm_agent_wire::ObjectRef;
use rss_mdm_authorization_service::Permission;
use rss_mdm_device_service::{Associations, personnel::Reader};
use rss_mdm_inventory::{Evidence, FieldDefinition, FieldKey, Scalar, Source, State};
use serde_json::{Value, json};
use std::time::Duration;
use uuid::Uuid;

fn evidence(actor: &str) -> Evidence {
    Evidence {
        scope: rss_mdm_inventory::CollectionScope::Device,
        source: Source::Manual,
        dataset: None,
        device_id: None,
        epoch: None,
        snapshot_id: Uuid::new_v4().to_string(),
        observed_at: 1,
        received_at: 2,
        actor: Some(actor.into()),
    }
}
async fn assign(
    c: &Context,
    device: &rss_mdm_agent_wire::DeviceId,
    field: FieldKey,
    expected: i64,
    values: Vec<i64>,
    actor: &str,
) -> Result<()> {
    let mut tx = seed_transaction(c).await?;
    let actual = rss_mdm_inventory_postgres::assign_in(
        &mut tx,
        c.tenant,
        device,
        field,
        expected,
        &State::Known(Scalar::Array(
            values.into_iter().map(Scalar::Integer).collect(),
        )),
        &evidence(actor),
    )
    .await?;
    assert_eq!(actual, Some(expected + 1));
    tx.commit().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "T2: real view selection survives an unrelated write mid-read; fixed lists retain their version and reject revoked authority"]
async fn live_view_and_fixed_list_keep_distinct_read_semantics() -> Result<()> {
    let c = Context::open("query_reads", &[]).await?;
    let result=async {
        let a=planning_t2_support::endpoint(&c).await?.members[0].device;
        let b=planning_t2_support::endpoint(&c).await?.members[0].device;
        let account=c.account(&[Permission::InventoryRead,Permission::InventorySensitiveRead]).await?;
        let proof=c.authenticate(&account).await?;
        let service=Associations::new(c.audit.clone(),c.tenant,&[9;32])?;
        let field=FieldKey::parse("custom.query_list")?;
        let definition:FieldDefinition=serde_json::from_value(json!({"key":field,"version":1,"valueType":{"kind":"array","items":{"kind":"integer"},"maxItems":1000},"nullable":true,"manual":true,"sources":{"manual":0},"platforms":["macos","windows"],"sensitivity":"standard","unit":null,"searchable":true,"itemKey":null}))?;
        let mut tx=seed_transaction(&c).await?;
        assert!(rss_mdm_inventory_postgres::publish_field_in(&mut tx,c.tenant,0,&definition).await?);
        tx.commit().await?;
        assign(&c,&a,field,0,vec![1,2,3],proof.principal_id()).await?;
        assign(&c,&b,field,0,vec![8],proof.principal_id()).await?;
        let timer=rss_mdm_audit_integration::budget::RuntimeTimer;
        let personnel=Reader::new(&c.authority,c.access().now()+Duration::from_secs(30),&timer,None);
        let reference=ObjectRef::Endpoint(a);
        let detail:Value=serde_json::to_value(service.view(&proof,&reference,&personnel).await?)?;
        let token=detail["lists"][field.as_str()]["sources"][0]["cursor"].as_str().expect("manual array source cursor");
        let first:Value=serde_json::to_value(service.list_items(&proof,&reference,field,token,2,&personnel).await?)?;
        assert_eq!(first["items"],json!([{"kind":"integer","value":1},{"kind":"integer","value":2}]));
        let next=first["nextCursor"].as_str().unwrap();
        assign(&c,&a,field,1,vec![7,8],proof.principal_id()).await?;
        assign(&c,&b,field,1,vec![9],proof.principal_id()).await?;
        let second:Value=serde_json::to_value(service.list_items(&proof,&reference,field,next,2,&personnel).await?)?;
        assert_eq!(second["items"],json!([{"kind":"integer","value":3}]));
        for sort in ["reference.id", "-reference.id", "-reference.kind,reference.id"] {
            let mut ids = Vec::new();
            let mut cursor: Option<String> = None;
            loop {
                let mut parameters = url::form_urlencoded::Serializer::new(String::new());
                parameters.append_pair("sort", sort).append_pair("limit", "1");
                if let Some(token) = &cursor { parameters.append_pair("cursor", token); }
                let query = rss_mdm_device_service::directory::parse(&parameters.finish())?;
                let page: Value = serde_json::to_value(service.views(&proof, &query, &personnel).await?)?;
                ids.extend(page["items"].as_array().unwrap().iter().map(|v| v["reference"]["id"].as_str().unwrap().to_owned()));
                assert!(ids.len() <= 2, "directory seek repeated a UUID");
                cursor = page["nextCursor"].as_str().map(str::to_owned);
                if cursor.is_none() { break; }
            }
            let mut expected = [a,b]; expected.sort();
            if sort == "-reference.id" { expected.reverse(); }
            assert_eq!(ids, expected.map(|id| id.to_string()), "{sort}");
        }
        let query=rss_mdm_device_service::directory::SCHEMA.parse("limit=1")?;
        let page:Value=serde_json::to_value(service.views(&proof,&query,&personnel).await?)?;
        let continuation=page["nextCursor"].as_str().expect("nonempty second page");
        // This dedicated database permits a deterministic relation-lock barrier without
        // blocking another test's reads. The writer changes a different relation.
        let mut blocker=c.operator.begin().await?;
        sqlx::query("LOCK TABLE mdm.inventory_history IN ACCESS EXCLUSIVE MODE").execute(&mut *blocker).await?;
        let pid:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await?;
        let read=service.view(&proof,&reference,&personnel);
        let write=async {
            tokio::time::timeout(Duration::from_secs(5),async {
                loop {
                    let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))").bind(pid).fetch_one(&c.operator).await?;
                    if blocked {break;}
                    tokio::task::yield_now().await;
                }
                Ok::<_,anyhow::Error>(())
            }).await??;
            assign(&c,&b,field,2,vec![10],proof.principal_id()).await?;
            blocker.rollback().await?;
            Ok::<_,anyhow::Error>(())
        };
        let (detail,())=tokio::try_join!(async{Ok::<_,anyhow::Error>(read.await?)},write)?;
        assert_eq!(serde_json::to_value(detail)?["reference"]["id"],a.to_string());
        let mut q=url::form_urlencoded::Serializer::new(String::new());q.append_pair("limit","1").append_pair("cursor",continuation);
        let continued:Value=serde_json::to_value(service.views(&proof,&rss_mdm_device_service::directory::SCHEMA.parse(&q.finish())?,&personnel).await?)?;
        assert_eq!(continued["items"].as_array().unwrap().len(),1);
        let statistics:Value=serde_json::to_value(service.statistics(&proof,&rss_mdm_device_service::directory::SCHEMA.parse("")?,&personnel).await?)?;
        assert!(statistics["asOf"].is_number());
        sqlx::query("DELETE FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(account.rule).execute(&c.operator).await?;
        assert!(service.list_items(&proof,&reference,field,next,2,&personnel).await.is_err());
        Ok::<_,anyhow::Error>(())
    }.await;
    c.close().await;
    result
}
