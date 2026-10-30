//! Intent, immutable receipts and Audit share one tenant-scoped transaction.
use super::*;
use rss_mdm_audit_integration::{AuditStore, Fact, ManagementResult, budget::AuditBudget};
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::time::Duration;
use uuid::Uuid;

pub(super) fn fingerprint(p: &AuthorizedPrincipal, input: &Update) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(&(
        "first_use.v1",
        p.tenant_id(),
        p.instance_id(),
        p.principal_id(),
        input,
    ))
    .map_err(|_| Error::Malformed)?;
    Ok(Sha256::digest(bytes).to_vec())
}
async fn authorize(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    permission: Permission,
) -> Result<(), Error> {
    p.session()?;
    rss_mdm_authorization_service::lock_on(c, p.tenant_id(), p.instance_id()).await?;
    rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id())
        .await?
        .require(p, permission, None)?;
    Ok(())
}
async fn saved(c: &mut PgConnection, tenant: &str) -> Result<Saved, Error> {
    let row =
        sqlx::query("SELECT revision,intent FROM mdm_first_use.intents WHERE tenant_id=$1::uuid")
            .bind(tenant)
            .fetch_optional(c)
            .await
            .map_err(database)?;
    let Some(row) = row else {
        return Ok(Saved {
            revision: 0,
            intent: Intent::default(),
        });
    };
    let value = Saved {
        revision: row.try_get("revision").map_err(database)?,
        intent: serde_json::from_value(row.try_get("intent").map_err(database)?)
            .map_err(|_| Error::Unavailable(Failure::Database))?,
    };
    value
        .intent
        .validate()
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    Ok(value)
}
async fn find(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    id: Uuid,
) -> Result<Option<(Vec<u8>, Receipt)>, Error> {
    let row=sqlx::query("SELECT instance_id::text,fingerprint,receipt FROM mdm_first_use.operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3")
        .bind(p.tenant_id()).bind(p.principal_id()).bind(id).fetch_optional(c).await.map_err(database)?;
    row.map(|row| {
        if row.try_get::<String, _>("instance_id").map_err(database)? != p.instance_id() {
            return Err(Error::Conflict);
        }
        let value: Receipt = serde_json::from_value(row.try_get("receipt").map_err(database)?)
            .map_err(|_| Error::Unavailable(Failure::Database))?;
        if value.operation_id != id || value.saved.revision <= 0 {
            return Err(Error::Unavailable(Failure::Database));
        }
        Ok((row.try_get("fingerprint").map_err(database)?, value))
    })
    .transpose()
}
fn tenant(p: &AuthorizedPrincipal) -> Result<TenantId, Error> {
    TenantId::parse(p.tenant_id()).map_err(|_| Error::Forbidden)
}

pub(super) async fn read(
    store: &AuditStore,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
) -> Result<Saved, Error> {
    let budget = AuditBudget::new(Duration::from_secs(6));
    let attempt = store
        .read(tenant(p)?, &budget.control(), p, |p, tx| {
            Box::pin(async move {
                tx.with_connection_context(p, |p, c| {
                    Box::pin(async move {
                        authorize(c, p, Permission::RegistrationConfigurationRead).await?;
                        saved(c, p.tenant_id()).await
                    })
                })
                .await
            })
        })
        .await;
    settle(attempt, audit, false)
}
pub(super) async fn operation(
    store: &AuditStore,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
    permission: Permission,
) -> Result<Option<Receipt>, Error> {
    let budget = AuditBudget::new(Duration::from_secs(6));
    let attempt = store
        .read(tenant(p)?, &budget.control(), (p, id), |(p, id), tx| {
            Box::pin(async move {
                let mut ctx = (*p, *id, permission);
                tx.with_connection_context(&mut ctx, |(p, id, permission), c| {
                    Box::pin(async move {
                        authorize(c, p, *permission).await?;
                        Ok::<_, Error>(find(c, p, *id).await?.map(|(_, value)| value))
                    })
                })
                .await
            })
        })
        .await;
    settle(attempt, audit, false)
}
pub(super) async fn update(
    store: &AuditStore,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
    input: &Update,
    fingerprint: &[u8],
    observed: Option<&Progress>,
) -> Result<Receipt, Error> {
    let budget = AuditBudget::new(Duration::from_secs(8));
    let attempt=store.write(tenant(p)?,&budget.source_control(),(store,p,audit,id,input,fingerprint,observed),|ctx,tx|Box::pin(async move {
        let (store,p,audit,id,input,fingerprint,observed)=*ctx;
        let mut sql=(p,id,input,fingerprint,observed);
        let (receipt,replayed)=tx.with_connection_context(&mut sql,|(p,id,input,fingerprint,observed),c|Box::pin(async move {
            authorize(c,p,Permission::RegistrationConfigurationWrite).await?;
            // A tenant lock also serializes first inserts; no missing-row CAS race.
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2831))").bind(p.tenant_id()).execute(&mut *c).await.map_err(database)?;
            if let Some((old,value))=find(c,p,*id).await? {
                if old!=*fingerprint {return Err(Error::Conflict);}
                return Ok::<_,Error>((value,true));
            }
            let current=saved(c,p.tenant_id()).await?;
            if current.revision!=input.expected_revision {return Err(Error::Conflict);}
            if input.intent.completion_requested {
                completion_permissions(c,p,&input.intent).await?;
                if observed.is_none_or(|v|!v.can_complete) {return Err(Error::FirstUseNotReady);}
            }
            let value=Saved {revision:current.revision+1,intent:input.intent.clone()};
            sqlx::query("INSERT INTO mdm_first_use.intents(tenant_id,revision,intent) VALUES($1::uuid,$2,$3) ON CONFLICT(tenant_id) DO UPDATE SET revision=EXCLUDED.revision,intent=EXCLUDED.intent")
                .bind(p.tenant_id()).bind(value.revision).bind(serde_json::to_value(&value.intent).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(database)?;
            let receipt=Receipt {operation_id:*id,saved:value};
            sqlx::query("INSERT INTO mdm_first_use.operations(tenant_id,actor,operation_id,instance_id,fingerprint,receipt) VALUES($1::uuid,$2,$3,$4::uuid,$5,$6)")
                .bind(p.tenant_id()).bind(p.principal_id()).bind(*id).bind(p.instance_id()).bind(*fingerprint).bind(serde_json::to_value(&receipt).map_err(|_|Error::Malformed)?).execute(c).await.map_err(database)?;
            p.check_live()?;
            Ok((receipt,false))
        })).await?;
        let fact=Fact::business(audit, &format!("first-use:{}:{}:{id}",p.instance_id(),p.principal_id()), 200, "success", None)?;
        (if replayed { Ok(()) } else { store.append(tx, &fact).await })?;
        if replayed {audit.management_result(ManagementResult::Replayed);}
        audit.mark_commit_started();
        Ok::<_,Error>(receipt)
    })).await;
    settle(attempt, audit, true)
}
fn transaction(error: rss_mdm_audit_integration::TransactionError<Error>) -> Error {
    match error {
        rss_mdm_audit_integration::TransactionError::Operation(error) => error,
        rss_mdm_audit_integration::TransactionError::Storage(error) => error.into(),
        rss_mdm_audit_integration::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
fn settle<T>(
    attempt: rss_transactional_messaging::transaction::LocalTxAttempt<
        T,
        rss_mdm_audit_integration::TransactionError<Error>,
    >,
    audit: &RequestAudit,
    write: bool,
) -> Result<T, Error> {
    attempt.fold(
        |value| {
            if write {
                audit.mark_committed();
            }
            Ok(value)
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

async fn completion_permissions(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    intent: &Intent,
) -> Result<(), Error> {
    let rules =
        rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id()).await?;
    let mut ids = Vec::new();
    if intent.channels.contains(&Channel::Agent) {
        ids.push("registration");
    }
    if intent.channels.contains(&Channel::MacosMdm) {
        ids.extend_from_slice(&["apns-cert", "profile-cert"]);
    }
    for (capability, decision) in &intent.capabilities {
        if matches!(decision, Decision::Configure) {
            ids.extend_from_slice(capability.items());
        }
    }
    for id in ids {
        let item = settings::model::CATALOG
            .iter()
            .find(|item| item.id == id)
            .ok_or(Error::Malformed)?;
        if item.permission.device() {
            rules.require_all_devices(p, item.permission)?;
        } else {
            rules.require(p, item.permission, None)?;
        }
    }
    Ok(())
}
