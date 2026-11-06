use crate::{authority_t2_support::Context, planning_t2_support as fixture};
use anyhow::Result;
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_scope_service::{Scopes, transaction};
use std::sync::Arc;
use uuid::Uuid;
pub(crate) async fn open(c: &Context) -> Result<Arc<Scopes>> {
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
pub(crate) async fn advance(
    s: &Scopes,
    id: Uuid,
    cut: &rss_mdm_inventory::AssetCut,
    rollback: bool,
) -> Result<(), rss_mdm_scope_service::Error> {
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
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

#[tokio::test]
#[ignore = "T2: explicit recalculation fences every unfinished phase, preserves authored CAS and replays one task"]
async fn recompute_replaces_inflight_tasks_without_changing_definition() -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_scope_service::{Command, ScopeChange, operation::Operation};
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            Permission::ScopeRead,
            Permission::ScopeWrite,
            Permission::InventoryRead,
        ])
        .await?;
    let p = c.authenticate(&account).await?;
    let object = fixture::endpoint(&c).await?;
    let s = open(&c).await?;
    for phase in ["sources", "project", "ready"] {
        let old = fixture::published(&c, &object).await?;
        let unfinished = fixture::staged(&c, &old, &object).await?;
        sqlx::query("UPDATE mdm_scope.scope_runs SET phase=$3 WHERE tenant_id=$1::uuid AND id=$2")
            .bind(c.tenant.to_string())
            .bind(unfinished)
            .bind(phase)
            .execute(&c.operator)
            .await?;
        let command = Command::Scope {
            id: old.scope,
            change: Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 1,
                input: ScopeChange::Recompute,
            },
        };
        let receipt = s.execute(&command, &c.request(&p)?, &p).await?;
        assert_eq!(receipt["revision"], 1);
        let task = Uuid::parse_str(receipt["task"].as_str().unwrap())?;
        assert_ne!(task, unfinished);
        let replaced:(bool,Option<String>,Option<Uuid>)=sqlx::query_as("SELECT completed,failure,replacement_task FROM mdm_scope.tasks WHERE tenant_id=$1::uuid AND id=$2")
            .bind(c.tenant.to_string()).bind(unfinished).fetch_one(&c.operator).await?;
        assert_eq!(replaced, (true, Some("superseded".into()), Some(task)));
        assert_eq!(
            s.execute(&command, &c.request(&p)?, &p).await?,
            receipt,
            "lost response recovery must not create another task"
        );
        advance(&s, unfinished, &old.cut, false).await?;
        let before:(i64,Uuid,i64)=sqlx::query_as("SELECT revision,resolution,calculation_revision FROM mdm_scope.scopes WHERE tenant_id=$1::uuid AND id=$2")
            .bind(c.tenant.to_string()).bind(old.scope).fetch_one(&c.operator).await?;
        assert_eq!(before, (1, old.run, 1));
        let mut wrong = Command::Scope {
            id: old.scope,
            change: Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 2,
                input: ScopeChange::Recompute,
            },
        };
        assert!(matches!(
            s.execute(&wrong, &c.request(&p)?, &p).await,
            Err(rss_mdm_scope_service::Error::Conflict)
        ));
        for _ in 0..20 {
            advance(&s, task, &old.cut, false).await?;
        }
        let completed:(i64,Uuid,i64,i64,bool)=sqlx::query_as("SELECT s.revision,s.resolution,s.calculation_revision,s.resolution_revision,t.completed FROM mdm_scope.scopes s JOIN mdm_scope.tasks t ON(t.tenant_id,t.id)=(s.tenant_id,$3) WHERE s.tenant_id=$1::uuid AND s.id=$2")
            .bind(c.tenant.to_string()).bind(old.scope).bind(task).fetch_one(&c.operator).await?;
        assert_eq!(
            (completed.0, completed.1, completed.2, completed.4),
            (1, task, 2, true)
        );
        // A new operation performs a fresh calculation; an unchanged result keeps its semantic revision.
        wrong = Command::Scope {
            id: old.scope,
            change: Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 1,
                input: ScopeChange::Recompute,
            },
        };
        let next = s.execute(&wrong, &c.request(&p)?, &p).await?;
        let next = Uuid::parse_str(next["task"].as_str().unwrap())?;
        for _ in 0..20 {
            advance(&s, next, &old.cut, false).await?;
        }
        let current:(i64,i64,i64)=sqlx::query_as("SELECT revision,calculation_revision,resolution_revision FROM mdm_scope.scopes WHERE tenant_id=$1::uuid AND id=$2")
            .bind(c.tenant.to_string()).bind(old.scope).fetch_one(&c.operator).await?;
        assert_eq!(current, (1, 3, completed.3));
    }
    drop(s);
    c.close().await;
    Ok(())
}
