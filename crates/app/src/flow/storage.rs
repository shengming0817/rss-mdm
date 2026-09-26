//! Host storage identity, capability contract checks and shared cursor secret.
use crate::{Error, Failure, transaction::*};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use serde_json::Value;
pub(crate) async fn admit(runtime: &PgRuntime, tenant: TenantId) -> std::result::Result<(), Error> {
    runtime
        .local_tx(tenant, deadline(), |tx| {
            Box::pin(async move {
                admit_in(tx)
                    .await
                    .map_err(|_| sqlx::Error::Protocol("host storage admission".into()).into())
            })
        })
        .await
        .fold(
            |_| Ok(()),
            |_| Err(Error::Unavailable(Failure::FlowAdmission)),
            |_| Err(Error::Unavailable(Failure::FlowAdmission)),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::FlowAdmission)),
        )
}
pub(crate) async fn admit_in(tx: &mut PgTransaction<'_>) -> Result<()> {
    let valid = tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar::<_, bool>(include_str!("storage/admission.sql"))
                    .fetch_one(c)
                    .await
            })
        })
        .await?;
    if !valid {
        return Err(Error::Unavailable(Failure::FlowAdmission).into());
    }
    let contracts = [
        (
            "execution handoff",
            include_str!("../execution/catalog.sql"),
            include_str!("../execution/catalog.json"),
            include_str!("storage/handoff-admission.sql"),
        ),
        (
            "authorization and execution dependencies",
            include_str!("../execution/dependencies.sql"),
            include_str!("../execution/dependencies.json"),
            include_str!("storage/handoff-admission.sql"),
        ),
        (
            "planning",
            include_str!("../planning/catalog.sql"),
            include_str!("../planning/catalog.json"),
            include_str!("../planning/admission.sql"),
        ),
        (
            "assets",
            include_str!("../assets/catalog.sql"),
            include_str!("../assets/catalog.json"),
            include_str!("../assets/admission.sql"),
        ),
        (
            "automation",
            include_str!("../automation/catalog.sql"),
            include_str!("../automation/catalog.json"),
            include_str!("../automation/admission.sql"),
        ),
        (
            "resource_catalog",
            include_str!("../resource_catalog/catalog.sql"),
            include_str!("../resource_catalog/catalog.json"),
            include_str!("../resource_catalog/admission.sql"),
        ),
        (
            "flow",
            include_str!("storage/catalog.sql"),
            include_str!("storage/catalog.json"),
            include_str!("storage/admission.sql"),
        ),
        (
            "publication",
            include_str!("../software_publication/http_catalog.sql"),
            include_str!("../software_publication/http_catalog.json"),
            include_str!("../software_publication/http_admission.sql"),
        ),
    ];
    for (owner, query, expected, admission) in contracts {
        let valid = tx
            .with_connection(move |c| {
                Box::pin(async move { sqlx::query_scalar::<_, bool>(admission).fetch_one(c).await })
            })
            .await?;
        if !valid {
            return Err(Error::Unavailable(Failure::FlowAdmission).into());
        }
        let raw = tx
            .with_connection(move |c| {
                Box::pin(async move { sqlx::query_scalar::<_, String>(query).fetch_one(c).await })
            })
            .await?;
        let actual: Value =
            serde_json::from_str(&raw).map_err(|_| Error::Unavailable(Failure::FlowAdmission))?;
        let expected: Value = serde_json::from_str(expected).expect("checked owner contract");
        if actual != expected {
            eprintln!(
                "{}",
                serde_json::json!({"event":"capability_admission_rejected","owner":owner})
            );
            return Err(Error::Unavailable(Failure::FlowAdmission).into());
        }
    }
    Ok(())
}
// Immutable tenant secret shared by all instances. A retry always reads the
// committed winner, including when the original initialization commit was unknown.
pub(crate) async fn cursor_key(
    runtime: &PgRuntime,
    tenant: TenantId,
) -> std::result::Result<Vec<u8>, Error> {
    let mut candidate = vec![0; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut candidate)
        .map_err(|_| Error::Unavailable(Failure::FlowAdmission))?;
    for _ in 0..3 {
        let result=runtime.local_tx_with_context(tenant,deadline(),&candidate,|candidate,tx| Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            let candidate=candidate.to_vec();
            tx.with_connection(move |c| Box::pin(async move {
                if let Some(key)=sqlx::query_scalar::<_,Vec<u8>>("SELECT secret FROM mdm_flow.cursor_keys WHERE tenant_id=$1::uuid").bind(&tenant).fetch_optional(&mut *c).await? { return Ok(key); }
                sqlx::query("INSERT INTO mdm_flow.cursor_keys(tenant_id,secret) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(&tenant).bind(candidate).execute(&mut *c).await?;
                sqlx::query_scalar("SELECT secret FROM mdm_flow.cursor_keys WHERE tenant_id=$1::uuid").bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(Some, |_|None, |_|None, |_|None, |_|None, |_|None);
        if let Some(key) = result {
            return Ok(key);
        }
    }
    Err(Error::Unavailable(Failure::FlowAdmission))
}
