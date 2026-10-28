//! Host-owned shared cursor material, injected into business services.
use crate::{Error, Failure};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgRuntime;
// Immutable tenant secret shared by all instances. A retry always reads the
// committed winner, including when the original initialization commit was unknown.
pub(crate) async fn load(
    runtime: &PgRuntime,
    tenant: TenantId,
) -> std::result::Result<Vec<u8>, Error> {
    let mut candidate = vec![0; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut candidate)
        .map_err(|_| Error::Unavailable(Failure::CursorAdmission))?;
    for _ in 0..3 {
        let result=runtime.local_tx_with_context(tenant,rss_transactional_messaging::policy::OperationDeadline::from_remaining(std::time::Duration::from_secs(6)),&candidate,|candidate,tx| Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            let candidate=candidate.to_vec();
            tx.with_connection(move |c| Box::pin(async move {
                if let Some(key)=sqlx::query_scalar::<_,Vec<u8>>("SELECT secret FROM public.mdm_cursor_keys WHERE tenant_id=$1::uuid").bind(&tenant).fetch_optional(&mut *c).await? { return Ok(key); }
                sqlx::query("INSERT INTO public.mdm_cursor_keys(tenant_id,secret) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(&tenant).bind(candidate).execute(&mut *c).await?;
                sqlx::query_scalar("SELECT secret FROM public.mdm_cursor_keys WHERE tenant_id=$1::uuid").bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(Some, |_|None, |_|None, |_|None, |_|None, |_|None);
        if let Some(key) = result {
            return Ok(key);
        }
    }
    Err(Error::Unavailable(Failure::CursorAdmission))
}
