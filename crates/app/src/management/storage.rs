use super::*;
use sha2::{Digest, Sha256};
use sqlx::Row;

pub(super) async fn lock(tx: &mut PgTransaction<'_>) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2390))")
                .bind(tenant)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
pub(super) fn identity(command: &Command, audit: &Audit) -> Result<(Option<Uuid>, Vec<u8>)> {
    let id = match command {
        Command::PublicationIntent { request, .. } => Some(request.operation_id),
        Command::Resource { change, .. } => Some(change.operation_id),
        Command::Group { change, .. } => Some(change.operation_id),
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
        who.client,
        command,
    )))?;
    Ok((id, Sha256::digest(bytes).to_vec()))
}
pub(super) async fn audit(tx: &mut PgTransaction<'_>, audit: &Audit) -> Result<()> {
    let audit = audit.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            crate::access_store::append_on_connection(c, &audit, 200, "success", None)
                .await
                .map_err(|_| sqlx::Error::Protocol("management audit failed".into()))
        })
    })
    .await
    .map_err(|_| Error::Unavailable(Failure::Audit))?;
    Ok(())
}
pub(super) async fn replay(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    fingerprint: &[u8],
) -> Result<Option<Value>> {
    let tenant = tx.tenant_id().to_string();
    let row = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT fingerprint,response::text FROM mdm_management.operations WHERE tenant_id=$1::uuid AND id=$2::uuid")
            .bind(tenant).bind(id.to_string()).fetch_optional(c).await
    })).await?;
    if let Some(row) = row {
        if row.try_get::<Vec<u8>, _>("fingerprint")? != fingerprint {
            return Err(Error::Conflict.into());
        }
        return Ok(Some(input(serde_json::from_str(
            &row.try_get::<String, _>("response")?,
        ))?));
    }
    Ok(None)
}
pub(super) async fn receipt(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    fingerprint: &[u8],
    value: &Value,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let digest = fingerprint.to_vec();
    let response = value.to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO mdm_management.operations VALUES($1::uuid,$2::uuid,$3,$4::jsonb)",
            )
            .bind(tenant)
            .bind(id.to_string())
            .bind(digest)
            .bind(response)
            .execute(c)
            .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
pub(super) async fn preview(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Option<Preview>> {
    let tenant = tx.tenant_id().to_string();
    let raw=tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar::<_,String>("SELECT document::text FROM mdm_management.previews WHERE tenant_id=$1::uuid AND id=$2::uuid")
            .bind(tenant).bind(id.to_string()).fetch_optional(c).await
    })).await?;
    raw.map(|v| input(serde_json::from_str(&v))).transpose()
}
pub(super) async fn device(tx: &mut PgTransaction<'_>, id: &str) -> Result<u64> {
    input(rss_mdm_scope::DeviceId::new(tx.tenant_id(), id))?;
    let tenant = tx.tenant_id().to_string();
    let id = id.to_owned();
    let rows=tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT id::text,generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND state='active' ORDER BY id FOR SHARE")
            .bind(tenant).bind(id).fetch_all(c).await
    })).await?;
    if rows.is_empty() {
        return Err(Error::NotFound.into());
    }
    // A direct source always contains exactly its stable device; generation is
    // independently revalidated, and is never treated as a replacement device ID.
    Ok(1)
}

pub(super) async fn admit(runtime: &PgRuntime, tenant: TenantId) -> std::result::Result<(), Error> {
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
                    .map_err(|_| sqlx::Error::Protocol("management catalog invalid".into()))?;
                let expected: Value = serde_json::from_str(include_str!("catalog.json"))
                    .expect("checked management catalog");
                if !ok || actual != expected {
                    return Err(
                        sqlx::Error::Protocol("management admission rejected".into()).into(),
                    );
                }
                Ok(())
            })
        })
        .await;
    attempt.fold(
        |_| Ok(()),
        |_| Err(Error::Unavailable(Failure::Runtime)),
        |_| Err(Error::Unavailable(Failure::Runtime)),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(Failure::Runtime)),
    )
}
