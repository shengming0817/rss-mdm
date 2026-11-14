//! 固定原钥验证，不重签、不换链，也不降级 Plain。
use rss_audit_postgres::Integrity;
use rss_mdm_install_support::maintenance::{Error, Result};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Head {
    pub tenant: String,
    pub key_id: Option<String>,
    pub sequence: Option<i64>,
    pub tag: Option<Vec<u8>>,
    pub verified_records: Option<u64>,
}
/// The trusted deployment operator connects before adopting the existing reader identity.
/// Both session_user and current_user must satisfy Audit/Ledger admission.
/// This permits integrity verification while ordinary runtime CONNECT privileges are fenced.
pub async fn verify_operator(
    profile: rss_mdm_install_support::StorageProfile,
    integrity: Integrity,
    key_id: Option<&str>,
    tenants: &[String],
    database: &sqlx::postgres::PgConnectOptions,
    budget: &crate::budget::AuditBudget,
    limit: rss_ledger_postgres::ReadLimit,
) -> Result<Vec<Head>> {
    use rss_request_context::CancellationObserver;
    let control = budget.control();
    let connecting = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(control.total_remaining())
        .after_connect(move |c, _| {
            Box::pin(async move {
                sqlx::query(match profile {
                    rss_mdm_install_support::StorageProfile::Mdm => {
                        "SET SESSION AUTHORIZATION mdm_access"
                    }
                    rss_mdm_install_support::StorageProfile::Da => {
                        "SET SESSION AUTHORIZATION da_access"
                    }
                })
                .execute(c)
                .await?;
                Ok(())
            })
        })
        .connect_with(database.clone());
    let pool = tokio::select! { biased;
        () = budget.cancelled() => return Err(Error::Storage),
        value = tokio::time::timeout(control.total_remaining(), connecting) => value.map_err(|_| Error::Storage)?.map_err(|_| Error::Storage)?,
    };
    verify_pool(integrity, key_id, tenants, pool, budget, limit).await
}
async fn verify_pool(
    integrity: Integrity,
    key_id: Option<&str>,
    tenants: &[String],
    pool: sqlx::PgPool,
    budget: &crate::budget::AuditBudget,
    limit: rss_ledger_postgres::ReadLimit,
) -> Result<Vec<Head>> {
    let result=async {
        let store=crate::AuditReadStore::new(pool.clone(),integrity.clone(),&budget.control()).await.map_err(|_|Error::Corrupt)?;
        let mut heads=Vec::new();
        for tenant in tenants {
            let id=rss_request_context::TenantId::parse(tenant).map_err(|_|Error::Input)?;
            match &integrity {
                Integrity::Plain=>{
                    store.validate_tenant(id,&budget.control()).await.map_err(|_|Error::Corrupt)?;
                    heads.push(Head {tenant:tenant.clone(),key_id:None,sequence:None,tag:None,verified_records:None});
                }
                Integrity::Ledger(_)=>{
                    let key_id=key_id.ok_or(Error::Input)?;
                    let head = store.read(id, &budget.control(), tenant, |tenant, tx| Box::pin(async move {
                        tx.with_connection_context(tenant, |tenant, c| Box::pin(async move {
                            sqlx::query_as::<_, (String, Option<i64>, Vec<u8>)>("SELECT key_id,seq,tag FROM rss_ledger.heads WHERE tenant_id=$1::uuid AND chain_id='rss.audit.v1'")
                                .bind(*tenant).fetch_optional(c).await.map_err(crate::Error::from)
                        })).await
                    })).await.fold(Ok, |_| Err(Error::Storage), |_| Err(Error::Storage), |_| Err(Error::Storage), |_| Err(Error::Storage), |_| Err(Error::Storage))?;


                    let (stored,sequence,tag)=head.unwrap_or((key_id.to_owned(),None,vec![0u8;32]));
                    if stored!=key_id || sequence.is_some_and(|s|s<0) {return Err(Error::Conflict)}
                    let tag:[u8;32]=tag.try_into().map_err(|_|Error::Corrupt)?;
                    let verified=store.verify_history_to(id,sequence.map(|s|s as u64),&tag,&budget.control(),limit).await.map_err(|_|Error::Corrupt)?;
                    heads.push(Head {tenant:tenant.clone(),key_id:Some(stored),sequence,tag:Some(tag.to_vec()),verified_records:Some(verified)});
                }
            }
        }
        Ok(heads)
    }.await;
    let closed = tokio::time::timeout(budget.control().total_remaining(), pool.close())
        .await
        .is_ok();
    match result {
        Ok(value) if closed => Ok(value),
        Ok(_) => Err(Error::Storage),
        Err(error) => Err(error),
    }
}
