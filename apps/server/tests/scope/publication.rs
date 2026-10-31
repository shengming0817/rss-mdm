use crate::{authority_t2_support::Context, planning_t2_support as fixture};
use anyhow::Result;
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_scope_service::{Scopes, transaction};
use std::sync::Arc;
use uuid::Uuid;
async fn open(c: &Context) -> Result<Arc<Scopes>> {
    let owner = fixture::owner(c, "mdm_scope_runtime").await?;
    let pool = c.inputs.pool("shared", "mdm_scope_runtime").await?;
    Ok(crate::scopes::open(
        owner.runtime,
        c.tenant,
        Arc::new(crate::clock::SystemClock),
        owner.audit,
        vec![7; 32],
        pool,
    )
    .await?)
}
async fn advance(
    s: &Scopes,
    id: Uuid,
    cut: &rss_mdm_inventory::AssetCut,
    rollback: bool,
) -> Result<(), rss_mdm_scope_service::Error> {
    let audit = RequestAudit::new(
        s.tenant.to_string(),
        "scope_reconcile",
        AuditIntent::Management,
    );
    audit.identify_service("scope-test");
    transaction::run(
        &s.audit_store,
        &s.runtime,
        s.tenant,
        &audit,
        (s, id, cut, rollback, &audit),
        |ctx, tx| {
            Box::pin(async move {
                ctx.0.audit_store.prepare_in(tx, ctx.4, &[]).await?;
                ctx.0.advance_in(tx, ctx.1, ctx.2).await?;
                if ctx.3 {
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            sqlx::query("SELECT 1/0").execute(c).await?;
                            Ok(())
                        })
                    })
                    .await?;
                }
                Ok(())
            })
        },
    )
    .await
}
async fn snapshot(
    c: &Context,
    scope: Uuid,
    run: Uuid,
) -> Result<(Uuid, i64, i64, String, String, bool, i64)> {
    Ok(sqlx::query_as("SELECT s.resolution,s.resolution_revision,s.calculation_revision,p.phase,r.phase,t.completed,(SELECT count(*) FROM mdm_policy.work w WHERE w.tenant_id=s.tenant_id AND w.id=$3) FROM mdm_scope.scopes s JOIN mdm_scope.scope_projection_runs p ON(p.tenant_id,p.id)=(s.tenant_id,$3) JOIN mdm_scope.scope_runs r ON(r.tenant_id,r.id)=(p.tenant_id,p.id) JOIN mdm_scope.tasks t ON(t.tenant_id,t.id)=(s.tenant_id,p.id) WHERE s.tenant_id=$1::uuid AND s.id=$2").bind(c.tenant.to_string()).bind(scope).bind(run).fetch_one(&c.operator).await?)
}
async fn admission(
    s: &Scopes,
    scope: Uuid,
    device: &str,
) -> Result<(serde_json::Value, serde_json::Value)> {
    Ok(transaction::inspect(&s.runtime, s.tenant, (scope, device.to_owned()), |ctx, tx| Box::pin(async move {
        let (scope, device) = ctx.clone();
        Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_as("SELECT mdm_scope.scope_state($1,NULL),mdm_scope.channel_admission($1,'mdm',$2)")
                .bind(scope).bind(device).fetch_one(c).await
        })).await?)
    })).await?)
}
#[tokio::test]
#[ignore = "T2: real Scope publication and Policy notification in one transaction"]
async fn publication_is_atomic_replayable_and_rejects_stale_definition() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let object = fixture::endpoint(&c).await?;
    let old = fixture::published(&c, &object).await?;
    let run = fixture::staged(&c, &old, &object).await?;
    let s = open(&c).await?;
    let device = &object.members[0].device;
    let eligible = (
        serde_json::json!({"state":"fresh"}),
        serde_json::json!({"state":"eligible","entry":1}),
    );
    assert_eq!(admission(&s, old.scope, device).await?, eligible);
    let before = snapshot(&c, old.scope, run).await?;
    assert!(advance(&s, run, &old.cut, true).await.is_err());
    assert_eq!(snapshot(&c, old.scope, run).await?, before);
    assert_eq!(admission(&s, old.scope, device).await?, eligible);
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_scope.scope_versions SELECT tenant_id,id,2,definition FROM mdm_scope.scope_versions WHERE tenant_id=$1::uuid AND id=$2 AND revision=1").bind(c.tenant.to_string()).bind(old.scope).execute(&mut *tx).await?;
    sqlx::query("UPDATE mdm_scope.scopes SET revision=2 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(old.scope)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert!(matches!(
        advance(&s, run, &old.cut, false).await,
        Err(rss_mdm_scope_service::Error::Conflict)
    ));
    assert_eq!(snapshot(&c, old.scope, run).await?, before);
    assert_eq!(
        admission(&s, old.scope, device).await?,
        (
            serde_json::json!({"state":"pending"}),
            serde_json::json!({"state":"pending"})
        )
    );
    sqlx::query("UPDATE mdm_scope.scopes SET revision=1 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(old.scope)
        .execute(&c.operator)
        .await?;
    advance(&s, run, &old.cut, false).await?;
    assert_eq!(admission(&s, old.scope, device).await?, eligible);
    let committed = snapshot(&c, old.scope, run).await?;
    assert_eq!(
        committed,
        (run, 1, 2, "published".into(), "published".into(), true, 1)
    );
    let rows:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_scope.scope_channel_results r JOIN mdm_scope.scopes s ON(s.tenant_id,s.resolution)=(r.tenant_id,r.run) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.device=$3 AND r.matched AND NOT r.pending AND r.entry_revision=1").bind(c.tenant.to_string()).bind(old.scope).bind(&object.members[0].device).fetch_one(&c.operator).await?;
    assert_eq!(rows, 1);
    drop(s);
    let restarted = open(&c).await?;
    advance(&restarted, run, &old.cut, false).await?;
    assert_eq!(snapshot(&c, old.scope, run).await?, committed);
    assert_eq!(admission(&restarted, old.scope, device).await?, eligible);
    drop(restarted);
    c.close().await;
    Ok(())
}
