//! Definitions, CAS receipts and redacted Audit settle in one existing host transaction.
use super::*;
use rss_mdm_audit_integration::{AuditStore, Fact, budget::AuditBudget};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::time::Duration;
fn tenant(p: &AuthorizedPrincipal) -> Result<rss_request_context::TenantId, Error> {
    rss_request_context::TenantId::parse(p.tenant_id()).map_err(|_| Error::Forbidden)
}
async fn authorize(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    permission: Option<Permission>,
    writing: bool,
) -> Result<bool, Error> {
    // Only writes need the source guard. Audit reads are READ ONLY and consume
    // Identity views validated before entering this host-only transaction.
    if writing {
        rss_identity_postgres::admit_profile_source_on(
            c,
            rss_identity_core::InstanceId::parse(p.instance_id()).map_err(|_| Error::Forbidden)?,
            tenant(p)?,
            rss_identity_postgres::ProfileSource::IdentityLocal,
        )
        .await
        .map_err(admission)?;
    }
    rss_mdm_authorization_service::lock_on(c, p.tenant_id(), p.instance_id()).await?;
    let rules =
        rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id()).await?;
    if let Some(permission) = permission {
        rules.require(p, permission, None)?;
    } else {
        p.session()?;
        p.check_live()?;
    }
    Ok(rules.require(p, Permission::UserProfilesRead, None).is_ok())
}
fn admission(e: rss_identity_postgres::ProfileSourceAdmissionError) -> Error {
    match e {
        rss_identity_postgres::ProfileSourceAdmissionError::Rejected => Error::Conflict,
        _ => Error::Unavailable(Failure::IdentityStorage),
    }
}
fn decode(row: sqlx::postgres::PgRow) -> Result<Definition, Error> {
    let value: Option<Value> = row.try_get("value").map_err(database)?;
    let value = value
        .map(serde_json::from_value::<DefinitionValue>)
        .transpose()
        .map_err(|_| unavailable())?;
    if let Some(value) = &value {
        model::validate(value).map_err(|_| unavailable())?;
    }
    Ok(Definition {
        field_id: row.try_get("field_id").map_err(database)?,
        revision: row.try_get("revision").map_err(database)?,
        collected_after_micros: row.try_get("collected_after_micros").map_err(database)?,
        value,
    })
}
async fn get(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    id: Uuid,
) -> Result<Option<Definition>, Error> {
    sqlx::query(
        "SELECT * FROM mdm_user_profiles.definitions WHERE tenant_id=$1::uuid AND field_id=$2",
    )
    .bind(p.tenant_id())
    .bind(id)
    .fetch_optional(c)
    .await
    .map_err(database)?
    .map(decode)
    .transpose()
}
async fn receipt(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    id: Uuid,
) -> Result<Option<(Vec<u8>, Receipt)>, Error> {
    let row=sqlx::query("SELECT instance_id::text,fingerprint,receipt FROM mdm_user_profiles.operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3")
        .bind(p.tenant_id()).bind(p.principal_id()).bind(id).fetch_optional(c).await.map_err(database)?;
    row.map(|r| {
        if r.try_get::<String, _>("instance_id").map_err(database)? != p.instance_id() {
            return Err(Error::Conflict);
        }
        Ok((
            r.try_get("fingerprint").map_err(database)?,
            serde_json::from_value(r.try_get("receipt").map_err(database)?)
                .map_err(|_| unavailable())?,
        ))
    })
    .transpose()
}
pub(super) async fn definitions(
    store: &AuditStore,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    permission: Option<Permission>,
    enabled_only: bool,
    after: Option<Uuid>,
) -> Result<(Vec<Definition>, bool), Error> {
    let budget = AuditBudget::new(Duration::from_secs(8));
    let attempt=store.read(tenant(p)?,&budget.control(),(p,permission,enabled_only,after),|ctx,tx|Box::pin(async move {
        tx.with_connection_context(ctx,|(p,permission,enabled,after),c|Box::pin(async move {
            let profiles_read=authorize(c,p,*permission,false).await?;
            let rows=sqlx::query("SELECT * FROM mdm_user_profiles.definitions WHERE tenant_id=$1::uuid AND value IS NOT NULL AND (NOT $2 OR value->>'enabled'='true') AND ($3::uuid IS NULL OR field_id>$3) ORDER BY field_id LIMIT 129")
                .bind(p.tenant_id()).bind(*enabled).bind(*after).fetch_all(c).await.map_err(database)?;
            Ok::<_,Error>((rows.into_iter().map(decode).collect::<Result<Vec<_>,Error>>()?,profiles_read))
        })).await
    })).await;
    settle(attempt, audit, false)
}
pub(super) async fn definition(store: &AuditStore, p: &AuthorizedPrincipal, audit: &RequestAudit, id: Uuid) -> Result<Definition, Error> {
    let budget = AuditBudget::new(Duration::from_secs(8));
    let attempt = store.read(tenant(p)?, &budget.control(), (p,id), |ctx,tx| Box::pin(async move {
        tx.with_connection_context(ctx, |(p,id),c| Box::pin(async move {
            authorize(c,p,Some(Permission::UserAttributeDefinitionsRead),false).await?;
            get(c, p, *id).await?.ok_or(Error::NotFound)
        })).await
    })).await;
    settle(attempt,audit,false)
}
pub(super) async fn operation(store: &AuditStore, p: &AuthorizedPrincipal, audit: &RequestAudit, id: Uuid) -> Result<Receipt, Error> {
    let budget = AuditBudget::new(Duration::from_secs(8));
    let attempt = store.read(tenant(p)?, &budget.control(), (p,id), |ctx,tx| Box::pin(async move {
        tx.with_connection_context(ctx, |(p,id),c| Box::pin(async move {
            authorize(c,p,Some(Permission::UserAttributeDefinitionsWrite),false).await?;
            Ok(receipt(c, p, *id).await?.ok_or(Error::NotFound)?.1)
        })).await
    })).await;
    settle(attempt,audit,false)
}
pub(super) async fn change(
    store: &AuditStore,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
    input: &Change,
) -> Result<Receipt, Error> {
    if id.is_nil()
        || input.operation_id.is_nil()
        || input.expected_revision < 0
        || input.expected_revision == i64::MAX
    {
        return Err(Error::Malformed);
    }
    if let Some(v) = &input.value {
        model::validate(v)?;
    }
    let fingerprint = Sha256::digest(
        serde_json::to_vec(&(
            "user-attribute.v1",
            p.instance_id(),
            p.tenant_id(),
            p.principal_id(),
            id,
            input,
        ))
        .map_err(|_| Error::Malformed)?,
    )
    .to_vec();
    let budget = AuditBudget::new(Duration::from_secs(8));
    let attempt=store.write(tenant(p)?,&budget.source_control(),(store,p,audit,id,input,&fingerprint),|ctx,tx|Box::pin(async move {
        let (store,p,audit,id,input,fingerprint)=*ctx;
        let mut context=(p,id,input,fingerprint);
        let (result,replayed)=tx.with_connection_context(&mut context,|(p,id,input,fingerprint),c|Box::pin(async move {
            authorize(c,p,Some(Permission::UserAttributeDefinitionsWrite),true).await?;
            // Definitions and the enabled-field ceiling are tenant-wide, including across identity instances.
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2890))")
                .bind(p.tenant_id()).execute(&mut *c).await.map_err(database)?;
            if let Some((previous,result))=receipt(c,p,input.operation_id).await? {if previous.as_slice()!=fingerprint.as_slice(){return Err(Error::Conflict);}return Ok::<_,Error>((result,true));}
            let old=get(c,p,*id).await?;
            if old.as_ref().map_or(0,|d|d.revision)!=input.expected_revision {return Err(Error::Conflict);}
            let gate=gate(c,p,old.as_ref(),input.value.as_ref()).await?;
            let result=Receipt {operation_id:input.operation_id,definition:Definition {field_id:*id,revision:input.expected_revision+1,collected_after_micros:gate,value:input.value.clone()}};
            sqlx::query("INSERT INTO mdm_user_profiles.definitions(tenant_id,field_id,revision,collected_after_micros,value) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT(tenant_id,field_id) DO UPDATE SET revision=excluded.revision,collected_after_micros=excluded.collected_after_micros,value=excluded.value")
                .bind(p.tenant_id()).bind(*id).bind(result.definition.revision).bind(gate).bind(input.value.as_ref().map(serde_json::to_value).transpose().map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(database)?;
            sqlx::query("INSERT INTO mdm_user_profiles.operations(tenant_id,actor,instance_id,operation_id,fingerprint,receipt) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6)")
                .bind(p.tenant_id()).bind(p.principal_id()).bind(p.instance_id()).bind(input.operation_id).bind(*fingerprint).bind(serde_json::to_value(&result).map_err(|_|unavailable())?).execute(c).await.map_err(database)?;
            p.check_live()?;Ok((result,false))
        })).await?;
        let fact=Fact::business(audit, &format!("user-attribute:{}:{}:{}",p.instance_id(),p.principal_id(),input.operation_id), 200, "success", None)?;
        (if replayed { Ok(()) } else { store.append(tx, &fact).await })?;
        p.check_live()?;
        audit.mark_commit_started();
        Ok::<_,Error>(result)
    })).await;
    settle(attempt, audit, true)
}
async fn gate(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    old: Option<&Definition>,
    value: Option<&DefinitionValue>,
) -> Result<i64, Error> {
    let Some(value) = value else {
        return Ok(old.map_or(0, |d| d.collected_after_micros));
    };
    if value.enabled
        || old
            .and_then(|d| d.value.as_ref())
            .is_none_or(|previous| model::mapping_changed(previous, value))
    {
        let source = rss_identity_postgres::admit_profile_source_on(
            c,
            rss_identity_core::InstanceId::parse(p.instance_id()).map_err(|_| Error::Forbidden)?,
            tenant(p)?,
            model::source(&value.source)?,
        )
        .await
        .map_err(admission)?;
        if (value.pointer == "/extensions" || value.pointer.starts_with("/extensions/"))
            && source.extensions_root.is_none()
        {
            return Err(Error::Conflict);
        }
    }
    if value.enabled {
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_user_profiles.definitions WHERE tenant_id=$1::uuid AND value->>'enabled'='true'").bind(p.tenant_id()).fetch_one(&mut *c).await.map_err(database)?;
        if count >= 128
            && old
                .and_then(|d| d.value.as_ref())
                .is_none_or(|d| !d.enabled)
        {
            return Err(Error::Conflict);
        }
    }
    if let Some(old) = old
        && let Some(previous) = &old.value
        && !model::mapping_changed(previous, value)
    {
        return Ok(old.collected_after_micros);
    }
    if value.use_existing_observation {
        Ok(0)
    } else {
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(c)
            .await
            .map_err(database)
    }
}
fn transaction(e: rss_mdm_audit_integration::TransactionError<Error>) -> Error {
    match e {
        rss_mdm_audit_integration::TransactionError::Operation(e) => e,
        rss_mdm_audit_integration::TransactionError::Storage(e) => e.into(),
        rss_mdm_audit_integration::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
pub(super) fn settle<T>(
    attempt: rss_transactional_messaging::transaction::LocalTxAttempt<
        T,
        rss_mdm_audit_integration::TransactionError<Error>,
    >,
    audit: &RequestAudit,
    write: bool,
) -> Result<T, Error> {
    attempt.fold(
        |v| {
            if write {
                audit.mark_committed();
            }
            Ok(v)
        },
        |e| Err(transaction(e)),
        |e| {
            if write {
                audit.mark_rolled_back();
            }
            Err(transaction(e))
        },
        |_| {
            if write {
                audit.mark_rollback_failed();
            }
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |e| Err(transaction(e)),
    )
}
