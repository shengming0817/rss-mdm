use super::*;
use crate::{
    Error, context::AuthorizedPrincipal, database::db, operations::Actor, operations::Operation,
};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

pub async fn authorization_snapshot(
    database: &crate::Store,
    proof: &AuthorizedPrincipal,
) -> Result<Snapshot, Error> {
    use sqlx::Acquire;
    let mut connection = None;
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        proof.check_live()?;
        connection = Some(database.acquire().await?);
        let mut tx = connection
            .as_mut()
            .expect("acquired connection")
            .begin()
            .await
            .map_err(db)?;
        crate::Store::configure_transaction(&mut tx, proof.tenant_id()).await?;
        let snapshot = read_snapshot(&mut tx, proof).await?;
        tx.rollback().await.map_err(db)?;
        proof.check_live()?;
        Ok(snapshot)
    })
    .await;
    if !matches!(result, Ok(Ok(_)))
        && let Some(connection) = &mut connection
    {
        // SQLx cancellation queues rollback. Do not return a stalled protocol stream to the pool.
        // ref: sqlx-core 0.9.0 src/pool/connection.rs close_on_drop (bounded close).
        connection.close_on_drop();
    }
    result.map_err(|_| Error::Deadline)?
}
pub async fn change_rule(
    store: &rss_mdm_audit_integration::AuditStore,
    proof: &AuthorizedPrincipal,
    id: Uuid,
    change: Change<Rule>,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    proof.require(Permission::AuthorizationWrite, None)?;
    if let Some(value) = &change.value {
        value.validate(proof.tenant_id(), proof.instance_id())?;
    }
    crate::store::change_authorization(store, proof, Table::Rules, id, change, audit).await
}
pub async fn change_group(
    store: &rss_mdm_audit_integration::AuditStore,
    proof: &AuthorizedPrincipal,
    id: Uuid,
    change: Change<UserGroup>,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    proof.require(Permission::UserGroupWrite, None)?;
    proof.require(Permission::AuthorizationWrite, None)?;
    if let Some(value) = &change.value {
        value.validate(proof.tenant_id(), proof.instance_id())?;
    }
    crate::store::change_authorization(store, proof, Table::Groups, id, change, audit).await
}
async fn change_authorization<T: serde::Serialize + Sync>(
    store: &rss_mdm_audit_integration::AuditStore,
    proof: &AuthorizedPrincipal,
    table: Table,
    id: Uuid,
    change: Change<T>,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    if id.is_nil() || change.operation_id.is_nil() || change.expected_revision >= i64::MAX as u64 {
        return Err(Error::Malformed);
    }
    let value = change
        .value
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| Error::Malformed)?;
    if value.as_ref().is_some_and(|v| v.len() > 2 * 1024 * 1024) {
        return Err(Error::Malformed);
    }
    let digest = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(table.name(), id, &change)).map_err(|_| Error::Malformed)?
        )
    );
    let operation = Operation {
        actor: Actor::from_authorized(proof),
        key: change.operation_id,
        digest: &digest,
    };
    audit.operation(change.operation_id, "authorization_write");
    audit.target(&id.to_string());
    let fact = rss_mdm_audit_integration::Fact::business(
        audit,
        &format!(
            "authorization_write:{}:{}",
            proof.principal_id(),
            change.operation_id
        ),
        digest.as_bytes(),
        200,
        "success",
        None,
    )
    .map_err(Error::from)?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let context = ChangeContext {
        proof,
        table,
        id,
        change: &change,
        value: &value,
        operation: &operation,
        audit,
    };
    let attempt = store
        .write(
            rss_request_context::TenantId::parse(proof.tenant_id())
                .map_err(|_| Error::Malformed)?,
            &control,
            (store, context, fact),
            |(store, context, fact), tx| {
                Box::pin(async move {
                    let (receipt, replayed) = tx
                        .with_connection_context(context, |context, c| {
                            Box::pin(change_authorization_on(c, context))
                        })
                        .await?;
                    store
                        .append(tx, fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    if replayed {
                        context.audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    context.audit.mark_commit_started();
                    Ok(receipt)
                })
            },
        )
        .await;
    crate::operations::settle(attempt, audit)
}

struct ChangeContext<'a, T> {
    proof: &'a AuthorizedPrincipal,
    table: Table,
    id: Uuid,
    change: &'a Change<T>,
    value: &'a Option<String>,
    operation: &'a Operation<'a>,
    audit: &'a RequestAudit,
}
async fn change_authorization_on<T: serde::Serialize + Sync>(
    tx: &mut sqlx::PgConnection,
    context: &ChangeContext<'_, T>,
) -> Result<(Receipt, bool), Error> {
    let ChangeContext {
        proof,
        table,
        id,
        change,
        value,
        operation,
        audit,
    } = context;
    let table = *table;
    let id = *id;
    lock(tx, proof.tenant_id(), proof.instance_id()).await?;
    let replay = crate::operations::replay(tx, operation).await?;
    // The tenant/instance lock serializes writes; authorize the version now locked.
    let current = read_snapshot(tx, proof).await?;
    authorize_change(&current, proof, table)?;
    if let Some(result) = replay {
        return Ok((decode(&result)?, true));
    }
    let query = format!(
        "SELECT revision,document IS NULL AS deleted FROM mdm_access.{} WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3::uuid FOR UPDATE",
        table.name()
    );
    let old = sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
        .bind(proof.tenant_id())
        .bind(proof.instance_id())
        .bind(id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
    let revision = old
        .as_ref()
        .map(|r| r.try_get::<i64, _>("revision"))
        .transpose()
        .map_err(db)?
        .unwrap_or(0);
    if revision as u64 != change.expected_revision
        || old.as_ref().is_some_and(|r| r.get::<bool, _>("deleted"))
        || (revision == 0 && value.is_none())
    {
        return Err(Error::Conflict);
    }
    if revision == 0 {
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM mdm_access.{} WHERE tenant_id=$1::uuid AND instance=$2::uuid",
            table.name()
        )))
        .bind(proof.tenant_id())
        .bind(proof.instance_id())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if count >= 10000 {
            return Err(Error::Conflict);
        }
    }
    let query = format!(
        "INSERT INTO mdm_access.{}(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::jsonb) ON CONFLICT(tenant_id,instance,id) DO UPDATE SET revision=excluded.revision,document=excluded.document",
        table.name()
    );
    sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
        .bind(proof.tenant_id())
        .bind(proof.instance_id())
        .bind(id.to_string())
        .bind(revision + 1)
        .bind(value)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    let bounded: bool = sqlx::query_scalar("SELECT (SELECT coalesce(sum(octet_length(document::text)),0) FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND instance=$2::uuid)+(SELECT coalesce(sum(octet_length(document::text)),0) FROM mdm_access.user_groups WHERE tenant_id=$1::uuid AND instance=$2::uuid)<=8388608").bind(proof.tenant_id()).bind(proof.instance_id()).fetch_one(&mut *tx).await.map_err(db)?;
    if !bounded {
        return Err(Error::Conflict);
    }
    authorize_change(&current, proof, table)?;
    let receipt = Receipt {
        id,
        revision: (revision + 1) as u64,
        deleted: change.value.is_none(),
    };
    crate::operations::save(
        tx,
        operation,
        &serde_json::to_string(&receipt).map_err(|_| Error::Malformed)?,
        audit,
    )
    .await?;
    Ok((receipt, false))
}

async fn read_snapshot(
    tx: &mut sqlx::PgConnection,
    proof: &AuthorizedPrincipal,
) -> Result<Snapshot, Error> {
    let snapshot = snapshot_on(tx, proof.tenant_id(), proof.instance_id()).await?;
    proof.check_live()?;
    Ok(snapshot)
}
pub async fn snapshot_on(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    instance: &str,
) -> Result<Snapshot, Error> {
    let json: String = sqlx::query_scalar("WITH rules AS MATERIALIZED (SELECT * FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND instance=$2::uuid ORDER BY id LIMIT 10001), groups AS MATERIALIZED (SELECT * FROM mdm_access.user_groups WHERE tenant_id=$1::uuid AND instance=$2::uuid ORDER BY id LIMIT 10001) SELECT CASE WHEN (SELECT coalesce(sum(octet_length(document::text)),0) FROM rules)+(SELECT coalesce(sum(octet_length(document::text)),0) FROM groups)<=8388608 THEN jsonb_build_object('rules',coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'revision',revision,'value',document)) FROM rules),'[]'::jsonb),'groups',coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'revision',revision,'value',document)) FROM groups),'[]'::jsonb)) ELSE NULL END::text")
            .bind(tenant).bind(instance).fetch_one(&mut *tx).await.map_err(db)?;
    let snapshot: Snapshot = decode(&json)?;
    snapshot.validate(tenant, instance)?;
    Ok(snapshot)
}

fn authorize_change(
    snapshot: &Snapshot,
    proof: &AuthorizedPrincipal,
    table: Table,
) -> Result<(), Error> {
    snapshot.require(proof, Permission::AuthorizationWrite, None)?;
    if matches!(table, Table::Groups) {
        snapshot.require(proof, Permission::UserGroupWrite, None)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
// SQL identifiers originate only from this closed enum; every request value is bound.
enum Table {
    Rules,
    Groups,
}
impl Table {
    fn name(self) -> &'static str {
        match self {
            Self::Rules => "authorization_rules",
            Self::Groups => "user_groups",
        }
    }
}
fn decode<T: DeserializeOwned>(value: &str) -> Result<T, Error> {
    serde_json::from_str(value).map_err(|_| Error::Storage)
}
pub async fn lock(tx: &mut sqlx::PgConnection, tenant: &str, instance: &str) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2363))")
        .bind(format!("{tenant}:{instance}"))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    Ok(())
}

#[cfg(any(test, feature = "integration"))]
pub async fn initialize_authorization(
    store: &rss_mdm_audit_integration::AuditStore,
    user: User,
    key: Uuid,
) -> Result<Receipt, Error> {
    let audit = RequestAudit::new(user.tenant_id.clone(), "authorization_initialize");
    let result = crate::store::initialize_verified_user(store, user, key, &audit).await;
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    result
}
pub(crate) async fn initialize_verified_user(
    store: &rss_mdm_audit_integration::AuditStore,
    user: User,
    key: Uuid,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    canonical_uuid(&user.instance_id)?;
    canonical_uuid(&user.tenant_id)?;
    user.validate(&user.tenant_id, &user.instance_id)?;
    if key.is_nil() {
        return Err(Error::Malformed);
    }
    audit.set_principal(&user.principal_id, &user.instance_id);
    audit.operation(key, "authorization_initialize");
    let digest = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&("authorization_initialize", &user))
                .map_err(|_| Error::Malformed)?
        )
    );
    let operation = Operation {
        actor: Actor::for_initialization(&user),
        key,
        digest: &digest,
    };
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let fact = rss_mdm_audit_integration::Fact::business(
        audit,
        &format!("authorization_initialize:{}:{}", user.principal_id, key),
        digest.as_bytes(),
        200,
        "success",
        None,
    )
    .map_err(Error::from)?;
    let attempt = store
        .write(
            rss_request_context::TenantId::parse(&user.tenant_id).map_err(|_| Error::Malformed)?,
            &control,
            (store, &user, &operation, audit, fact),
            |(store, user, operation, audit, fact), tx| {
                Box::pin(async move {
                    let (receipt, replayed) = tx
                        .with_connection_context(
                            &mut (*user, *operation, *audit),
                            |(user, operation, audit), c| {
                                Box::pin(initialize_on(c, user, operation, audit))
                            },
                        )
                        .await?;
                    store
                        .append(tx, fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    if replayed {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    audit.mark_commit_started();
                    Ok(receipt)
                })
            },
        )
        .await;
    crate::operations::settle(attempt, audit)
}
async fn initialize_on(
    tx: &mut sqlx::PgConnection,
    user: &User,
    operation: &Operation<'_>,
    audit: &RequestAudit,
) -> Result<(Receipt, bool), Error> {
    let key = operation.key;
    lock(tx, &user.tenant_id, &user.instance_id).await?;
    if let Some(receipt) = crate::operations::replay(tx, operation).await? {
        return Ok((decode(&receipt)?, true));
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.authorization_initializations WHERE tenant_id=$1::uuid AND instance=$2::uuid)").bind(&user.tenant_id).bind(&user.instance_id).fetch_one(&mut *tx).await.map_err(db)?;
    if exists {
        return Err(Error::Conflict);
    }
    let id = Uuid::new_v4();
    let rule = Rule {
        subject: Subject::User { user: user.clone() },
        grants: [
            Permission::AuthorizationRead,
            Permission::AuthorizationWrite,
            Permission::UserGroupRead,
            Permission::UserGroupWrite,
            Permission::DepartmentRead,
        ]
        .into_iter()
        .map(|operation| Grant {
            operation,
            scope: Scope::Tenant,
        })
        .collect(),
    };
    sqlx::query("INSERT INTO mdm_access.authorization_initializations(tenant_id,instance,operation_id,principal) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid)").bind(&user.tenant_id).bind(&user.instance_id).bind(key.to_string()).bind(&user.principal_id).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3::uuid,1,$4::jsonb)").bind(&user.tenant_id).bind(&user.instance_id).bind(id.to_string()).bind(serde_json::to_string(&rule).map_err(|_| Error::Malformed)?).execute(&mut *tx).await.map_err(db)?;
    let receipt = Receipt {
        id,
        revision: 1,
        deleted: false,
    };
    crate::operations::save(
        tx,
        operation,
        &serde_json::to_string(&receipt).map_err(|_| Error::Malformed)?,
        audit,
    )
    .await?;
    Ok((receipt, false))
}

use rss_mdm_audit_integration::RequestAudit;

#[cfg(any(test, feature = "integration"))]
pub async fn initialize_fixture_audited(
    store: &rss_mdm_audit_integration::AuditStore,
    user: User,
    key: Uuid,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    initialize_verified_user(store, user, key, audit).await
}
