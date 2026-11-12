//! The actual diagnostic route must settle under its original read authority and budget.
use super::*;
use crate::authority_t2_support::Account;

async fn blocked_read(c: &Context, pid: i32) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE 'SELECT phase,blocked,manifest,completed%')")
                .bind(pid).fetch_one(&c.operator).await?;
            if waiting { return Ok::<_, anyhow::Error>(()); }
            tokio::task::yield_now().await;
        }
    }).await?
}

pub(super) async fn exercise(
    c: &Context,
    manager: &access::context::AuthorizedPrincipal,
    reader: &Account,
    http: &Http,
    authorized: &Http,
) -> Result<()> {
    revocation(c, manager, reader, http).await?;
    deadline(c, authorized).await
}

async fn revocation(
    c: &Context,
    manager: &access::context::AuthorizedPrincipal,
    reader: &Account,
    http: &Http,
) -> Result<()> {
    // A table lock is a controlled PostgreSQL read barrier, not a mocked source.
    // It is held only by this bounded test and always rolled back before asserting.
    let mut blocker = c.operator.begin().await?;
    sqlx::query("LOCK TABLE mdm_initialization.baselines IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let revoke = async {
        let result = async {
            blocked_read(c, pid).await?;
            access::store::change_rule(
                &c.audit,
                manager,
                reader.rule,
                access::Change::<access::Rule> {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 1,
                    value: None,
                },
                &c.request(manager)?,
            )
            .await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        blocker.rollback().await?;
        result
    };
    let (response, revoked) = tokio::join!(http.get("/api/v1/runtime/diagnostics", &[]), revoke);
    revoked?;
    let (status, body) = response?;
    assert_eq!(
        status, 409,
        "committed authority changes invalidate the collected snapshot: {body}"
    );
    assert!(body.get("components").is_none());
    assert_eq!(http.get("/api/v1/runtime/diagnostics", &[]).await?.0, 403);

    Ok(())
}

async fn deadline(c: &Context, authorized: &Http) -> Result<()> {
    // The baseline probe has its own two-second SQL budget. First-use reads have
    // a six-second budget; together they must not renew the route's eight seconds.
    let mut blocker = c.operator.begin().await?;
    sqlx::query(
        "LOCK TABLE mdm_initialization.baselines, mdm_first_use.intents IN ACCESS EXCLUSIVE MODE",
    )
    .execute(&mut *blocker)
    .await?;
    let response = tokio::time::timeout(
        Duration::from_secs(11),
        authorized.get("/api/v1/runtime/diagnostics", &[]),
    )
    .await;
    blocker.rollback().await?;
    let (status, body) = response??;
    assert_eq!(
        status, 503,
        "exhausted diagnostic request must not return partial success: {body}"
    );
    assert_eq!(body["code"], "service_unavailable");
    assert!(body.get("components").is_none());
    assert_eq!(
        authorized.get("/api/v1/runtime/diagnostics", &[]).await?.0,
        200
    );
    Ok(())
}
