//! Host-owned operation receipts and transaction settlement.
use crate::{Error, database::db};
use sqlx::Row;
use uuid::Uuid;
pub async fn replay(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    operation: &Operation<'_>,
) -> Result<Option<String>, Error> {
    if profile != operation.profile() {
        return Err(Error::Forbidden);
    }

    let Operation {
        actor: proof,
        key,
        digest: _,
    } = operation;
    let lock = format!(
        "registration:{}:{}:{}:{}",
        proof.tenant,
        proof.subject.len(),
        proof.subject,
        key
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2347))")
        .bind(lock)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    read(profile, tx, operation).await
}

/// Receipt lookup without acquiring a product lock, safe before Identity admission.
pub async fn read(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    operation: &Operation<'_>,
) -> Result<Option<String>, Error> {
    if profile != operation.profile() {
        return Err(Error::Forbidden);
    }

    let Operation {
        actor: proof,
        key,
        digest,
    } = operation;
    let old = sqlx::query(crate::storage_profile::sql(profile).operations_read_1)
        .bind(proof.tenant)
        .bind(proof.subject)
        .bind(key.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
    old.map(|old| {
        if old.try_get::<String, _>("digest").map_err(db)? != *digest
            || old.try_get::<String, _>("instance").map_err(db)? != proof.instance
        {
            return Err(Error::Conflict);
        }
        old.try_get("result").map_err(db)
    })
    .transpose()
}
pub async fn save(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    operation: &Operation<'_>,
    result: &str,
    audit: &RequestAudit,
) -> Result<(), Error> {
    if profile != operation.profile() {
        return Err(Error::Forbidden);
    }

    save_result(profile, tx, operation, result, None, audit).await
}
pub(crate) async fn save_issuance_recovery(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    operation: &Operation<'_>,
    id: Uuid,
    audit: &RequestAudit,
) -> Result<(), Error> {
    if profile != operation.profile() {
        return Err(Error::Forbidden);
    }

    save_result(
        profile,
        tx,
        operation,
        &serde_json::to_string(&id).map_err(|_| Error::Corrupt)?,
        Some(id),
        audit,
    )
    .await
}
async fn save_result(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    operation: &Operation<'_>,
    result: &str,
    issuance: Option<Uuid>,
    audit: &RequestAudit,
) -> Result<(), Error> {
    if profile != operation.profile() {
        return Err(Error::Forbidden);
    }

    let Operation {
        actor: proof,
        key,
        digest,
    } = operation;
    let facts = audit.snapshot();
    if audit.tenant() != proof.tenant
        || facts.actor.as_deref() != Some(proof.subject)
        || facts.instance.as_deref() != Some(proof.instance)
        || facts.operation_id != Some(*key)
    {
        return Err(Error::Forbidden);
    }
    sqlx::query(crate::storage_profile::sql(profile).operations_save_result_1)
        .bind(proof.tenant)
        .bind(proof.subject)
        .bind(key.to_string())
        .bind(*digest)
        .bind(result)
        .bind(proof.instance)
        .bind(issuance)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    Ok(())
}

pub(crate) fn settle<R>(
    attempt: rss_transactional_messaging::transaction::LocalTxAttempt<
        R,
        rss_mdm_audit_integration::TransactionError<Error>,
    >,
    audit: &RequestAudit,
) -> Result<R, Error> {
    attempt.fold(
        |value| {
            // Optional protocol branches can commit only admission reads and return
            // control to another producer. Only that producer's marked write phase
            // changes the request's business outcome.
            if audit.snapshot().write_outcome == rss_mdm_audit_integration::WriteOutcome::Unknown {
                audit.mark_committed();
            }
            Ok(value)
        },
        |error| Err(transaction_error(error)),
        |error| {
            audit.mark_rolled_back();
            Err(transaction_error(error))
        },
        |_| {
            audit.mark_rollback_failed();
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |error| Err(transaction_error(error)),
    )
}

#[derive(Clone, Copy)]
pub(crate) struct Actor<'a> {
    profile: rss_mdm_install_support::StorageProfile,
    tenant: &'a str,
    subject: &'a str,
    instance: &'a str,
}
pub struct Operation<'a> {
    pub(crate) actor: Actor<'a>,
    pub(crate) key: Uuid,
    pub(crate) digest: &'a str,
}

impl<'a> Actor<'a> {
    pub(crate) fn from_authorized(
        proof: &'a rss_mdm_authorization_service::context::AuthorizedPrincipal,
    ) -> Self {
        Self {
            profile: proof.profile(),
            tenant: proof.tenant_id(),
            subject: proof.principal_id(),
            instance: proof.instance_id(),
        }
    }
}

use rss_mdm_audit_integration::RequestAudit;

fn transaction_error(error: rss_mdm_audit_integration::TransactionError<Error>) -> Error {
    match error {
        rss_mdm_audit_integration::TransactionError::Operation(error) => error,
        rss_mdm_audit_integration::TransactionError::Storage(error) => error.into(),
        rss_mdm_audit_integration::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}

impl<'a> Operation<'a> {
    pub fn new(
        proof: &'a rss_mdm_authorization_service::context::AuthorizedPrincipal,
        key: Uuid,
        digest: &'a str,
    ) -> Result<Self, Error> {
        proof.check_live()?;
        if key.is_nil() || digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Malformed);
        }
        Ok(Self {
            actor: Actor::from_authorized(proof),
            key,
            digest,
        })
    }
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.actor.profile
    }
}
