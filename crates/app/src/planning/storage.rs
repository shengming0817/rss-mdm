use super::*;
use sha2::{Digest, Sha256};

pub(super) fn identity(command: &Command, audit: &RequestAudit) -> Result<(Option<Uuid>, Vec<u8>)> {
    let id = match command {
        Command::Group { change, .. } => Some(change.operation_id),
        Command::GroupPreview { operation, .. } => Some(*operation),
        Command::Scope { change, .. } => Some(change.operation_id),
        Command::Policy { change, .. } => Some(change.operation_id),
        Command::Preview { request, .. } => Some(request.operation_id),
        Command::Save { request, .. } => Some(request.operation_id),
        _ => None,
    };
    if id.is_some_and(|id| id.is_nil()) {
        return Err(Error::Malformed.into());
    }
    let who = audit.snapshot();
    let bytes = input(serde_json::to_vec(&(
        audit.tenant(),
        who.actor,
        who.instance,
        command,
    )))?;
    Ok((id, Sha256::digest(bytes).to_vec()))
}
pub(crate) async fn require_device(tx: &mut PgTransaction<'_>, id: &str) -> Result<()> {
    input(rss_mdm_scope::DeviceId::new(tx.tenant_id(), id))?;
    let tenant = tx.tenant_id().to_string();
    let id = id.to_owned();
    let registered = tx
        .with_connection(move |c| Box::pin(crate::device::read::registered(c, tenant, id)))
        .await?;
    if !registered {
        return Err(Error::ObjectNotFound(Missing::Device).into());
    }
    Ok(())
}

pub(crate) async fn admit(runtime: &PgRuntime, tenant: TenantId) -> std::result::Result<(), Error> {
    let attempt = runtime
        .local_tx(tenant, deadline(), |tx| {
            Box::pin(async move {
                let (ok, raw) = tx
                    .with_connection(|c| {
                        Box::pin(async move {
                            let ok = sqlx::query_scalar::<_, bool>(include_str!("admission.sql"))
                                .fetch_one(&mut *c)
                                .await?;
                            let raw = sqlx::query_scalar::<_, String>(include_str!("catalog.sql"))
                                .fetch_one(c)
                                .await?;
                            Ok((ok, raw))
                        })
                    })
                    .await?;
                let actual = serde_json::from_str::<Value>(&raw)
                    .map_err(|_| sqlx::Error::Protocol("planning catalog invalid".into()))?;
                let expected: Value = serde_json::from_str(include_str!("catalog.json"))
                    .expect("checked planning catalog");
                if !ok || actual != expected {
                    eprintln!("{}",serde_json::json!({"event":"management_admission_rejected","authority":ok,"catalog":actual==expected}));
                    return Err(
                        sqlx::Error::Protocol("planning admission rejected".into()).into(),
                    );
                }
                Ok(())
            })
        })
        .await;
    attempt.fold(
        |_| Ok(()),
        |_| Err(Error::Unavailable(Failure::ManagementAdmission)),
        |_| Err(Error::Unavailable(Failure::ManagementAdmission)),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(Failure::ManagementAdmission)),
    )
}

// Immutable tenant secret shared by all instances. A retry always reads the
// committed winner, including when the original initialization commit was unknown.
pub(crate) async fn cursor_key(
    runtime: &PgRuntime,
    tenant: TenantId,
) -> std::result::Result<Vec<u8>, Error> {
    let mut candidate = vec![0; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut candidate)
        .map_err(|_| Error::Unavailable(Failure::ManagementAdmission))?;
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
    Err(Error::Unavailable(Failure::ManagementAdmission))
}
