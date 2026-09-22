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
        Command::Asset { command } => command.operation(),
        Command::PublicationIntent { request, .. } => Some(request.operation_id),
        Command::Resource { change, .. } => Some(change.operation_id),
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
pub(super) async fn audit(tx: &mut PgTransaction<'_>, audit: &Audit) -> Result<()> {
    let audit = audit.clone();
    let admitted = audit
        .snapshot()
        .software
        .as_ref()
        .is_some_and(|f| f.stage == "management_admission");
    let (status, result) = if admitted {
        (202, "unknown")
    } else {
        (
            200,
            audit
                .snapshot()
                .management_result
                .map_or("success", |r| r.audit_tag()),
        )
    };
    tx.with_connection(move |c| {
        Box::pin(async move {
            crate::access_store::append_on_connection(c, &audit, status, result, None)
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
        return Ok(Some(stored(serde_json::from_str(
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
pub(super) async fn device(tx: &mut PgTransaction<'_>, id: &str) -> Result<DeviceIdentity> {
    input(rss_mdm_scope::DeviceId::new(tx.tenant_id(), id))?;
    let tenant = tx.tenant_id().to_string();
    let id = id.to_owned();
    let rows=tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT id::text,generation,channel FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND state='active' ORDER BY id")
            .bind(tenant).bind(id).fetch_all(c).await
    })).await?;
    if rows.is_empty() {
        return Err(Error::ManagementNotFound(Missing::Device).into());
    }
    let registrations = rows
        .into_iter()
        .map(|row| {
            Ok(Registration {
                id: row.try_get("id")?,
                channel: row.try_get("channel")?,
                generation: row.try_get::<i64, _>("generation")? as u64,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let revision = registrations
        .iter()
        .map(|r| r.generation)
        .max()
        .ok_or(Error::ManagementNotFound(Missing::Device))?;
    Ok(DeviceIdentity {
        revision,
        registrations,
    })
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
        |_| Err(Error::Unavailable(Failure::ManagementAdmission)),
        |_| Err(Error::Unavailable(Failure::ManagementAdmission)),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(Failure::ManagementAdmission)),
    )
}
