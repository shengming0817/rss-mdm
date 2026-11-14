//! The owner's fixed input target, borrowed into the original message transaction.
use rss_reconcile::{ResourceSet, Scope, Target};
use rss_reconcile_postgres::PgMessagingStore;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};

pub async fn wake_in(
    store: &PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
) -> Result<(), PgError> {
    if binding.tenant() != tx.tenant_id() {
        return Err(sqlx::Error::Protocol("compliance input binding mismatch".into()).into());
    }

    let tenant = tx.tenant_id();
    let epoch = binding.epoch().get();
    let t = tenant.to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_compliance.dispatch(tenant_id,expected_epoch) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING")
            .bind(&t).bind(epoch).execute(&mut *c).await?;
        let accepted: i64 = sqlx::query_scalar("SELECT expected_epoch FROM mdm_compliance.dispatch WHERE tenant_id=$1::uuid")
            .bind(t).fetch_one(c).await?;
        if accepted != epoch { return Err(sqlx::Error::Protocol("compliance input epoch mismatch".into())); }
        Ok(())
    })).await?;
    let target = Target::new(
        Scope::new(tenant, rss_mdm_compliance_postgres::INPUT_DOMAIN).expect("constant scope"),
        "inputs",
    )
    .expect("constant target");
    store
        .wake_in(tx, &target, &ResourceSet::empty(tenant), (), |_, tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("SELECT pg_notify('mdm_work','compliance')")
                            .execute(c)
                            .await?;
                        Ok(())
                    })
                })
                .await
            })
        })
        .await
}
