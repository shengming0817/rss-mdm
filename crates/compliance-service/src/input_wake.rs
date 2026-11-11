//! The owner's fixed input target, borrowed into the original message transaction.
use rss_reconcile::{ResourceSet, Scope, Target};
use rss_reconcile_postgres::PgMessagingStore;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};

pub async fn wake_in(store: &PgMessagingStore, tx: &mut PgTransaction<'_>) -> Result<(), PgError> {
    let tenant = tx.tenant_id();
    let target = Target::new(Scope::new(tenant, "mdm.compliance").expect("constant scope"), "inputs").expect("constant target");
    store.wake_in(tx, &target, &ResourceSet::empty(tenant), (), |_, tx| Box::pin(async move {
        tx.with_connection(|c| Box::pin(async move {
            sqlx::query("SELECT pg_notify('mdm_work_'||replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'compliance')").execute(c).await?;
            Ok(())
        })).await
    })).await
}
